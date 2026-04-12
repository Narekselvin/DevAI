import os
import re
import subprocess
from collections import deque
from pathlib import Path


def detect_host_operating_system_family():
    if os.name == 'nt':
        return 'windows'
    return 'unix'


def read_text_file_tail_lines(file_path, maximum_lines, maximum_bytes):
    collected_lines = deque(maxlen=maximum_lines)
    try:
        with open(file_path, 'rb') as binary_stream:
            binary_stream.seek(0, os.SEEK_END)
            remaining_bytes = binary_stream.tell()
            buffer_chunks = []
            chunk_size = 4096
            while remaining_bytes > 0 and sum(len(c) for c in buffer_chunks) < maximum_bytes:
                read_size = min(chunk_size, remaining_bytes)
                binary_stream.seek(remaining_bytes - read_size)
                data_chunk = binary_stream.read(read_size)
                buffer_chunks.insert(0, data_chunk)
                remaining_bytes -= read_size
            combined_bytes = b''.join(buffer_chunks)
    except OSError:
        return []
    try:
        decoded_text = combined_bytes.decode('utf-8', errors='replace')
    except UnicodeDecodeError:
        decoded_text = combined_bytes.decode('latin-1', errors='replace')
    for line in decoded_text.splitlines():
        collected_lines.append(line.rstrip('\r\n'))
    return list(collected_lines)


def run_powershell_event_extraction(log_name_value, maximum_events):
    powershell_script_text = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-WinEvent -LogName '"
        + log_name_value
        + "' -MaxEvents "
        + str(maximum_events)
        + " | Where-Object { $_.Level -in 2,3 } "
        + "| ForEach-Object { $_.TimeCreated.ToString('o') + '|' + $_.Id + '|' + ($_.Message -replace \"`r`n\",' ') }"
    )
    command_arguments = [
        'powershell',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        powershell_script_text,
    ]
    try:
        completed_process = subprocess.run(
            command_arguments,
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    output_text = completed_process.stdout or ''
    return [line.strip() for line in output_text.splitlines() if line.strip()]


def run_powershell_security_event_extraction(maximum_events):
    command_arguments = [
        'powershell',
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        (
            "$ErrorActionPreference='SilentlyContinue'; "
            'Get-WinEvent -LogName Security -MaxEvents '
            + str(maximum_events)
            + " | Where-Object { $_.Id -eq 4625 -or $_.Id -eq 4776 } | ForEach-Object { "
            "$_.TimeCreated.ToString('o') + '|' + $_.Id + '|' + ($_.Message -replace \"`r`n\",' ') }"
        ),
    ]
    try:
        completed_process = subprocess.run(
            command_arguments,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    output_text = completed_process.stdout or ''
    return [line.strip() for line in output_text.splitlines() if line.strip()]


def parse_windows_event_line(event_line):
    parts = event_line.split('|', 2)
    if len(parts) < 3:
        return None
    timestamp_text, identifier_text, message_text = parts[0], parts[1], parts[2]
    return {
        'timestamp': timestamp_text,
        'event_code': identifier_text,
        'message_excerpt': message_text[:1200],
        'source_os': 'windows',
    }


def build_linux_auth_log_candidates():
    return [
        Path('/var/log/auth.log'),
        Path('/var/log/secure'),
    ]


def build_linux_system_log_candidates():
    return [
        Path('/var/log/syslog'),
        Path('/var/log/messages'),
    ]


def scan_unix_logs_for_patterns(line_list):
    critical_failure_patterns = [
        re.compile(r'(?i)segfault|out of memory|oom|kernel panic|I/O error|critical'),
        re.compile(r'(?i)failed to start|start request repeated|stopped the target'),
    ]
    unauthorized_patterns = [
        re.compile(r'(?i)failed password|authentication failure|invalid user|possible break-in'),
        re.compile(r'(?i)brute|too many authentication|disconnecting invalid user'),
    ]
    downtime_patterns = [
        re.compile(r'(?i)network.*unreachable|link is down|timed out|connection reset'),
    ]
    crash_service_patterns = [
        re.compile(r'(?i)service.*(failed|crash)|systemd\[\d+\].*failed|killed process'),
    ]
    critical_failures = []
    unauthorized_access_indicators = []
    downtime_indicators = []
    service_crash_events = []
    for raw_line in line_list:
        for pattern_object in critical_failure_patterns:
            if pattern_object.search(raw_line):
                critical_failures.append({'line': raw_line, 'matched_pattern': pattern_object.pattern})
                break
        for pattern_object in unauthorized_patterns:
            if pattern_object.search(raw_line):
                unauthorized_access_indicators.append({'line': raw_line, 'matched_pattern': pattern_object.pattern})
                break
        for pattern_object in downtime_patterns:
            if pattern_object.search(raw_line):
                downtime_indicators.append({'line': raw_line, 'matched_pattern': pattern_object.pattern})
                break
        for pattern_object in crash_service_patterns:
            if pattern_object.search(raw_line):
                service_crash_events.append(
                    {
                        'timestamp': None,
                        'error_code': 'UNIX_LOG_PATTERN',
                        'message_excerpt': raw_line[:1200],
                        'source_os': 'unix',
                    }
                )
                break
    return critical_failures, unauthorized_access_indicators, downtime_indicators, service_crash_events


def classify_windows_parsed_events(parsed_events):
    critical_failures = []
    unauthorized_access_indicators = []
    downtime_indicators = []
    service_crash_events = []
    crash_identifier_values = {'1000', '1001', '7031', '7034', '7011'}
    auth_identifier_values = {'4625', '4776', '4648'}
    for event_payload in parsed_events:
        if event_payload is None:
            continue
        identifier_value = str(event_payload.get('event_code', ''))
        message_text = event_payload.get('message_excerpt', '') or ''
        if identifier_value in crash_identifier_values:
            service_crash_events.append(event_payload)
            critical_failures.append({'line': message_text, 'matched_pattern': 'windows_event_' + identifier_value})
        elif identifier_value in auth_identifier_values:
            unauthorized_access_indicators.append({'line': message_text, 'matched_pattern': 'windows_security_' + identifier_value})
        if re.search(r'(?i)network|link is down|unreachable|timeout', message_text):
            downtime_indicators.append({'line': message_text, 'matched_pattern': 'windows_network_hint'})
    return critical_failures, unauthorized_access_indicators, downtime_indicators, service_crash_events


def collect_operating_system_log_insights():
    host_family = detect_host_operating_system_family()
    if host_family == 'windows':
        system_event_lines = run_powershell_event_extraction('System', 60)
        application_event_lines = run_powershell_event_extraction('Application', 60)
        security_event_lines = run_powershell_security_event_extraction(80)
        combined_lines = []
        combined_lines.extend(system_event_lines)
        combined_lines.extend(application_event_lines)
        combined_lines.extend(security_event_lines)
        parsed_events = []
        for raw_line in combined_lines:
            parsed_events.append(parse_windows_event_line(raw_line))
        critical_failures, unauthorized_access_indicators, downtime_indicators, service_crash_events = (
            classify_windows_parsed_events(parsed_events)
        )
        return {
            'host_family': host_family,
            'critical_failure_events': critical_failures,
            'unauthorized_access_indicators': unauthorized_access_indicators,
            'downtime_indicators': downtime_indicators,
            'service_crash_events': service_crash_events,
            'raw_event_line_count': len(combined_lines),
        }
    auth_lines = []
    for candidate_path in build_linux_auth_log_candidates():
        if candidate_path.exists() and candidate_path.is_file():
            auth_lines.extend(read_text_file_tail_lines(candidate_path, 400, 512000))
    system_lines = []
    for candidate_path in build_linux_system_log_candidates():
        if candidate_path.exists() and candidate_path.is_file():
            system_lines.extend(read_text_file_tail_lines(candidate_path, 400, 512000))
    merged_lines = []
    merged_lines.extend(auth_lines)
    merged_lines.extend(system_lines)
    critical_failures, unauthorized_access_indicators, downtime_indicators, service_crash_events = scan_unix_logs_for_patterns(
        merged_lines
    )
    return {
        'host_family': host_family,
        'critical_failure_events': critical_failures,
        'unauthorized_access_indicators': unauthorized_access_indicators,
        'downtime_indicators': downtime_indicators,
        'service_crash_events': service_crash_events,
        'raw_event_line_count': len(merged_lines),
    }
