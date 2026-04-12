import ipaddress
import os
import socket
import stat
import subprocess
import sys
import json as json_module
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import psutil

CRITICAL_INFRASTRUCTURE_PORTS = (21, 22, 23, 80, 443, 445, 3389, 5432, 3306, 8080)
REMOTE_TCP_PROBE_TIMEOUT_SECONDS = 0.75


def resolve_service_label_for_port(port_number, protocol_name):
    try:
        return socket.getservbyport(int(port_number), protocol_name)
    except OSError:
        return 'unknown'


def probe_tcp_port_accepting_connections(host_string, port_integer):
    try:
        socket_object = socket.create_connection((host_string, int(port_integer)), timeout=REMOTE_TCP_PROBE_TIMEOUT_SECONDS)
    except OSError:
        return False
    else:
        try:
            socket_object.close()
        except OSError:
            pass
        return True


def build_remote_endpoint_record(host_string, port_integer):
    protocol_name = 'tcp'
    service_label = resolve_service_label_for_port(port_integer, protocol_name)
    return {
        'ip': host_string,
        'port': int(port_integer),
        'protocol': protocol_name,
        'service_guess': service_label,
        'process_id': None,
        'process_name': None,
    }


def evaluate_remote_endpoint_task(host_string, port_integer):
    if probe_tcp_port_accepting_connections(host_string, port_integer):
        return build_remote_endpoint_record(host_string, port_integer)
    return None


def merge_listening_socket_records_without_duplicates(primary_records, secondary_records):
    seen_pairs = set()
    merged_records = []
    for socket_record in primary_records + secondary_records:
        port_value = int(socket_record['port'])
        ip_value = str(socket_record.get('ip'))
        protocol_name = str(socket_record.get('protocol'))
        dedupe_key = (ip_value, port_value, protocol_name)
        if dedupe_key in seen_pairs:
            continue
        seen_pairs.add(dedupe_key)
        merged_records.append(socket_record)
    return merged_records


def collect_remote_subnet_tcp_records(cidr_string):
    try:
        network_object = ipaddress.ip_network(cidr_string, strict=False)
    except ValueError:
        return []
    if network_object.prefixlen == network_object.max_prefixlen:
        host_strings = [str(network_object.network_address)]
    else:
        host_strings = [str(host_object) for host_object in network_object.hosts()]
    task_pairs = []
    for host_string in host_strings:
        for port_integer in CRITICAL_INFRASTRUCTURE_PORTS:
            task_pairs.append((host_string, port_integer))
    if not task_pairs:
        return []
    maximum_worker_threads = min(512, max(8, len(task_pairs)))
    discovered_records = []
    with ThreadPoolExecutor(max_workers=maximum_worker_threads) as executor_object:
        future_to_pair = {
            executor_object.submit(evaluate_remote_endpoint_task, host_string, port_integer): (host_string, port_integer)
            for host_string, port_integer in task_pairs
        }
        for completed_future in as_completed(future_to_pair):
            record_candidate = completed_future.result()
            if record_candidate is not None:
                discovered_records.append(record_candidate)
    return discovered_records


def collect_listening_socket_records():
    records = []
    seen_pairs = set()
    for network_connection in psutil.net_connections(kind='inet'):
        connection_status = getattr(network_connection, 'status', None)
        if connection_status != psutil.CONN_LISTEN:
            continue
        local_address = network_connection.laddr
        if local_address is None:
            continue
        port_value = int(local_address.port)
        ip_value = local_address.ip
        protocol_name = 'tcp' if network_connection.type == socket.SOCK_STREAM else 'udp'
        dedupe_key = (ip_value, port_value, protocol_name)
        if dedupe_key in seen_pairs:
            continue
        seen_pairs.add(dedupe_key)
        process_name = None
        process_identifier = getattr(network_connection, 'pid', None)
        if process_identifier:
            try:
                process_object = psutil.Process(process_identifier)
                process_name = process_object.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = 'access_denied'
        service_label = resolve_service_label_for_port(port_value, protocol_name)
        records.append(
            {
                'ip': ip_value,
                'port': port_value,
                'protocol': protocol_name,
                'service_guess': service_label,
                'process_id': process_identifier,
                'process_name': process_name,
            }
        )
    return records


def build_sensitive_path_candidates():
    candidates = []
    if os.name == 'nt':
        windir_value = os.environ.get('WINDIR', 'C:\\Windows')
        programdata_value = os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
        candidates.extend(
            [
                Path(windir_value).joinpath('System32', 'config', 'SAM'),
                Path(windir_value).joinpath('System32', 'drivers', 'etc', 'hosts'),
                Path(programdata_value).joinpath('ssh', 'sshd_config'),
            ]
        )
    else:
        candidates.extend(
            [
                Path('/etc/shadow'),
                Path('/etc/passwd'),
                Path('/etc/sudoers'),
                Path('/etc/ssh/sshd_config'),
            ]
        )
    home_override = os.environ.get('HOME') or os.environ.get('USERPROFILE')
    if home_override:
        candidates.append(Path(home_override).joinpath('.ssh', 'authorized_keys'))
    return candidates


def evaluate_world_writable_unix_path(path_object):
    try:
        mode_bits = path_object.stat().st_mode
    except OSError:
        return None
    if mode_bits & stat.S_IWOTH:
        return {
            'path': str(path_object),
            'issue': 'world_writable_path',
            'mode_octal': oct(mode_bits & 0o777),
        }
    return None


def evaluate_windows_acl_risk(path_object):
    if os.name != 'nt':
        return None
    try:
        icacls_executable = str(Path(os.environ.get('WINDIR', 'C:\\Windows')).joinpath('System32', 'icacls.exe'))
        completed_process = subprocess.run(
            [icacls_executable, str(path_object)],
            capture_output=True,
            text=True,
            timeout=12,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output_text = (completed_process.stdout or '') + (completed_process.stderr or '')
    normalized_output = output_text.upper()
    if 'EVERYONE:' in normalized_output and '(F)' in normalized_output:
        return {
            'path': str(path_object),
            'issue': 'everyone_full_control_hint',
            'detail_snippet': output_text[:400],
        }
    if 'BUILTIN\\USERS:' in normalized_output and '(M)' in normalized_output:
        return {
            'path': str(path_object),
            'issue': 'users_modify_hint',
            'detail_snippet': output_text[:400],
        }
    return None


def path_exists_accessible(path_object):
    try:
        return path_object.exists()
    except OSError:
        return False


def scan_weak_permission_paths():
    findings = []
    for candidate_path in build_sensitive_path_candidates():
        if not path_exists_accessible(candidate_path):
            continue
        if os.name == 'nt':
            acl_finding = evaluate_windows_acl_risk(candidate_path)
            if acl_finding:
                findings.append(acl_finding)
        else:
            unix_finding = evaluate_world_writable_unix_path(candidate_path)
            if unix_finding:
                findings.append(unix_finding)
    return findings


def collect_outdated_python_packages():
    try:
        completed_process = subprocess.run(
            [sys.executable, '-m', 'pip', 'list', '--outdated', '--format=json'],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {'parse_error': 'pip_invocation_failed', 'packages': []}
    if completed_process.returncode != 0:
        return {'parse_error': 'pip_nonzero_exit', 'stderr': completed_process.stderr[:800], 'packages': []}
    try:
        payload = json_module.loads(completed_process.stdout or '[]')
    except json_module.JSONDecodeError:
        return {'parse_error': 'json_decode_failed', 'packages': []}
    simplified = []
    for entry in payload:
        package_name = entry.get('name')
        current_version = entry.get('version')
        latest_version = entry.get('latest_version')
        if package_name:
            simplified.append(
                {
                    'name': package_name,
                    'installed_version': current_version,
                    'latest_version': latest_version,
                }
            )
    return {'packages': simplified}


def summarize_configuration_drift_hints():
    hints = []
    if os.name == 'nt':
        auto_update_path = Path(os.environ.get('WINDIR', 'C:\\Windows')).joinpath(
            'SoftwareDistribution', 'ReportingEvents.log'
        )
        if not auto_update_path.exists():
            hints.append(
                {
                    'category': 'patch_visibility',
                    'detail': 'windows_update_activity_log_not_found_at_expected_path',
                    'path_checked': str(auto_update_path),
                }
            )
    else:
        unattended_upgrade_path = Path('/etc/apt/apt.conf.d/50unattended-upgrades')
        if unattended_upgrade_path.exists() is False:
            hints.append(
                {
                    'category': 'patch_visibility',
                    'detail': 'unattended_upgrades_configuration_not_detected',
                    'path_checked': str(unattended_upgrade_path),
                }
            )
    return hints


def run_full_system_surface_scan(subnet_cidr_string=None):
    listening_records = collect_listening_socket_records()
    trimmed_subnet = (subnet_cidr_string or '').strip()
    if trimmed_subnet:
        remote_records = collect_remote_subnet_tcp_records(trimmed_subnet)
        listening_records = merge_listening_socket_records_without_duplicates(listening_records, remote_records)
    permission_findings = scan_weak_permission_paths()
    outdated_payload = collect_outdated_python_packages()
    drift_hints = summarize_configuration_drift_hints()
    return {
        'listening_sockets': listening_records,
        'weak_permission_findings': permission_findings,
        'python_package_outdated_report': outdated_payload,
        'configuration_drift_hints': drift_hints,
    }
