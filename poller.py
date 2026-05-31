import time
import asyncio
import ipaddress
import platform
import logging
import sys
from datetime import datetime
from pathlib import Path

_log_handlers = [logging.StreamHandler(sys.stdout), logging.FileHandler(str(Path(__file__).resolve().parent.joinpath('devai_polling.log')))]
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=_log_handlers, force=True)
_poll_logger = logging.getLogger('devai.poller')

def _log_poll(level, target_ip, message):
    _poll_logger.log(level, '[' + str(target_ip or 'SYSTEM') + '] ' + str(message))

def _snmp_varbind_is_missing(value):
    if value is None:
        return True
    try:
        from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

        return isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView))
    except Exception:
        type_name = type(value).__name__
        return 'NoSuch' in type_name or 'EndOfMib' in type_name

try:
    from apscheduler.schedulers.background import BackgroundScheduler
except Exception:
    BackgroundScheduler = None

try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        getCmd,
        usmAesCfb128Protocol,
        usmDESPrivProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
    )
except Exception:
    CommunityData = None
    ContextData = None
    ObjectIdentity = None
    ObjectType = None
    SnmpEngine = None
    UdpTransportTarget = None
    UsmUserData = None
    getCmd = None
    usmAesCfb128Protocol = None
    usmDESPrivProtocol = None
    usmHMACMD5AuthProtocol = None
    usmHMACSHAAuthProtocol = None

from template_registry import resolve_enterprise_template

try:
    import requests
except Exception:
    requests = None


def _map_snmpv3_protocols(auth_algo, priv_algo):
    auth_upper = str(auth_algo or 'SHA').strip().upper()
    priv_upper = str(priv_algo or 'AES').strip().upper()
    if auth_upper == 'MD5' and usmHMACMD5AuthProtocol is not None:
        mapped_auth = usmHMACMD5AuthProtocol
    else:
        mapped_auth = usmHMACSHAAuthProtocol
    if priv_upper == 'DES' and usmDESPrivProtocol is not None:
        mapped_priv = usmDESPrivProtocol
    else:
        mapped_priv = usmAesCfb128Protocol
    return mapped_auth, mapped_priv


def _host_poll_interval_elapsed(cursor, host_id, interval_seconds):
    cursor.execute(
        'SELECT polled_at FROM metrics_history WHERE host_id = ? ORDER BY datetime(polled_at) DESC, id DESC LIMIT 1',
        (int(host_id),),
    )
    row = cursor.fetchone()
    if not row or not row[0]:
        return True
    raw_text = str(row[0]).strip().replace('T', ' ')[:19]
    try:
        parsed_ts = datetime.strptime(raw_text, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return True
    delta_seconds = (datetime.now() - parsed_ts).total_seconds()
    return delta_seconds >= float(interval_seconds)


def _is_website_http_probe(canonical_device_type, poll_protocol):
    protocol_upper = str(poll_protocol or 'SNMP').strip().upper()
    if str(canonical_device_type) == 'Website':
        return True
    if protocol_upper in ('HTTP', 'HTTPS'):
        return True
    return False


def _offline_host_metrics(ip_address, hostname_hint, vendor_template_key, snmp_profile_label):
    hostname_clean = str(hostname_hint or '').strip() or str(ip_address or '')
    return {
        'ip': str(ip_address or ''),
        'hostname': hostname_clean,
        'device_type': snmp_profile_label,
        'vendor_template': str(vendor_template_key or ''),
        'status': 'offline',
        'cpu_utilization': None,
        'ram_usage': None,
        'disk_usage': None,
        'temperature_c': None,
        'interface_health_percent': None,
        'warnings': [],
        'mock_data': False,
        'latency_ms': None,
        'http_status_code': None,
    }


def _is_valid_ipv4_target(ip_string):
    token = str(ip_string or '').strip()
    if not token:
        return False
    try:
        parsed = ipaddress.ip_address(token)
        return parsed.version == 4
    except ValueError:
        return False


def _resolve_http_probe_url(hostname, ip_address, poll_protocol):
    hostname_stripped = str(hostname or '').strip()
    lower_hostname = hostname_stripped.lower()
    if lower_hostname.startswith(('http://', 'https://')):
        return hostname_stripped
    protocol_upper = str(poll_protocol or 'HTTP').strip().upper()
    scheme = 'https' if protocol_upper == 'HTTPS' else 'http'
    target = hostname_stripped or str(ip_address or '').strip()
    if not target:
        target = str(ip_address or '').strip()
    return scheme + '://' + target


def _poll_http_endpoint(hostname, ip_address, poll_protocol):
    if requests is None:
        return {
            'ip': str(ip_address or ''),
            'hostname': str(hostname or '').strip() or str(ip_address or ''),
            'status': 'offline',
            'cpu_utilization': None,
            'ram_usage': None,
            'disk_usage': None,
            'temperature_c': None,
            'warnings': [],
            'mock_data': False,
            'latency_ms': None,
            'http_status_code': None,
        }
    url = _resolve_http_probe_url(hostname, ip_address, poll_protocol)
    started = time.perf_counter()
    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        code = int(response.status_code)
        if code >= 500:
            status_label = 'offline'
        elif code >= 400:
            status_label = 'degraded'
        else:
            status_label = 'online'
        return {
            'ip': str(ip_address or ''),
            'hostname': str(hostname or '').strip() or str(ip_address or ''),
            'status': status_label,
            'cpu_utilization': None,
            'ram_usage': None,
            'disk_usage': None,
            'temperature_c': None,
            'warnings': [],
            'mock_data': False,
            'latency_ms': elapsed_ms,
            'http_status_code': code,
        }
    except Exception:
        return {
            'ip': str(ip_address or ''),
            'hostname': str(hostname or '').strip() or str(ip_address or ''),
            'status': 'offline',
            'cpu_utilization': None,
            'ram_usage': None,
            'disk_usage': None,
            'temperature_c': None,
            'warnings': [],
            'mock_data': False,
            'latency_ms': None,
            'http_status_code': None,
        }


class EnterpriseSnmpPoller:
    def __init__(
        self,
        community='public',
        timeout=2,
        retries=1,
        snmp_port=161,
        snmp_version='v2c',
        snmpv3_user='',
        snmpv3_auth_algo='SHA',
        snmpv3_auth_key='',
        snmpv3_priv_algo='AES',
        snmpv3_priv_key='',
    ):
        self.community = community
        self.timeout = timeout
        self.retries = retries
        try:
            self.snmp_port = int(snmp_port)
        except Exception:
            self.snmp_port = 161
        if self.snmp_port <= 0 or self.snmp_port > 65535:
            self.snmp_port = 161
        self.snmp_version = str(snmp_version or 'v2c').strip().lower()
        self.snmpv3_user = str(snmpv3_user or '').strip()
        self.snmpv3_auth_algo = str(snmpv3_auth_algo or 'SHA').strip()
        self.snmpv3_auth_key = str(snmpv3_auth_key or '')
        self.snmpv3_priv_algo = str(snmpv3_priv_algo or 'AES').strip()
        self.snmpv3_priv_key = str(snmpv3_priv_key or '')
        self.last_error_message = ''

    def _set_last_error(self, message_text):
        self.last_error_message = str(message_text or '')

    def _clear_last_error(self):
        self.last_error_message = ''

    def _auth_identity(self):
        if self.snmp_version == 'v3':
            if UsmUserData is None or not self.snmpv3_user:
                return None
            auth_p, priv_p = _map_snmpv3_protocols(self.snmpv3_auth_algo, self.snmpv3_priv_algo)
            if auth_p is None or priv_p is None:
                return None
            return UsmUserData(
                userName=self.snmpv3_user,
                authKey=self.snmpv3_auth_key,
                privKey=self.snmpv3_priv_key,
                authProtocol=auth_p,
                privProtocol=priv_p,
            )
        if CommunityData is None:
            return None
        return CommunityData(self.community, mpModel=1)

    def _snmp_agent_responds(self, ip_address):
        if getCmd is None:
            self._set_last_error('Timeout or Firewall Blocked')
            return False
        self._clear_last_error()
        probe = self._get_scalar(ip_address, '1.3.6.1.2.1.1.3.0')
        return probe is not None

    def _get_scalar(self, ip_address, oid_string):
        if getCmd is None:
            self._set_last_error('Timeout or Firewall Blocked')
            return None
        auth_identity = self._auth_identity()
        if auth_identity is None:
            self._set_last_error('SNMP Auth/Logic Failed')
            _log_poll(logging.WARNING, ip_address, 'SNMP auth identity unavailable for OID ' + str(oid_string))
            return None
        _log_poll(logging.INFO, ip_address, 'SNMP GET attempt OID ' + str(oid_string))
        try:
            iterator = getCmd(
                SnmpEngine(),
                auth_identity,
                UdpTransportTarget((ip_address, self.snmp_port), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid_string)),
            )
            error_indication, error_status, _, var_binds = next(iterator)
        except Exception as exc:
            self._set_last_error('Timeout or Firewall Blocked')
            _log_poll(logging.ERROR, ip_address, 'SNMP exception OID ' + str(oid_string) + ': ' + str(exc))
            return None
        if error_indication:
            self._set_last_error('Timeout or Firewall Blocked')
            _log_poll(logging.WARNING, ip_address, 'Timeout or Firewall Blocked OID ' + str(oid_string) + ': ' + str(error_indication))
            return None
        if error_status is not None:
            try:
                if int(error_status) != 0:
                    self._set_last_error('SNMP Auth/Logic Failed')
                    _log_poll(logging.WARNING, ip_address, 'SNMP Auth/Logic Failed OID ' + str(oid_string) + ' status ' + str(error_status))
                    return None
            except Exception:
                self._set_last_error('SNMP Auth/Logic Failed')
                _log_poll(logging.WARNING, ip_address, 'SNMP Auth/Logic Failed OID ' + str(oid_string))
                return None
        if not var_binds:
            return None
        cell = var_binds[0][1]
        if _snmp_varbind_is_missing(cell):
            return None
        return cell

    def _safe_int(self, value, fallback=0):
        try:
            return int(float(str(value)))
        except Exception:
            return fallback

    def _walk_numeric_max(self, ip_address, base_oid, maximum_index=48):
        best_value = None
        for index in range(1, maximum_index + 1):
            candidate = self._get_scalar(ip_address, base_oid + '.' + str(index))
            if candidate is None:
                continue
            parsed = self._safe_int(candidate, None)
            if parsed is None:
                continue
            if best_value is None or parsed > best_value:
                best_value = parsed
        return best_value

    def _ucd_memory_percent(self, ip_address, oids):
        total_raw = self._get_scalar(ip_address, oids.get('memory_total_oid', ''))
        if total_raw is None:
            return 0
        total_val = max(self._safe_int(total_raw, 0), 1)
        avail_raw = self._get_scalar(ip_address, oids.get('memory_avail_oid', ''))
        if avail_raw is None:
            free_fallback = self._get_scalar(ip_address, oids.get('memory_total_free_oid', '1.3.6.1.4.1.2021.4.11.0'))
            if free_fallback is not None:
                avail_val = min(max(self._safe_int(free_fallback, 0), 0), total_val)
            else:
                buffer_raw = self._get_scalar(ip_address, oids.get('memory_buffer_oid', '1.3.6.1.4.1.2021.4.14.0'))
                cached_raw = self._get_scalar(ip_address, oids.get('memory_cached_oid', '1.3.6.1.4.1.2021.4.15.0'))
                partial = 0
                if buffer_raw is not None:
                    partial += self._safe_int(buffer_raw, 0)
                if cached_raw is not None:
                    partial += self._safe_int(cached_raw, 0)
                if partial <= 0:
                    return 0
                avail_val = min(max(partial, 0), total_val)
        else:
            avail_val = min(max(self._safe_int(avail_raw, 0), 0), total_val)
        used_val = total_val - avail_val
        if used_val < 0:
            used_val = 0
        return int(round((used_val / float(total_val)) * 100))

    def _dell_global_status_proxy(self, ip_address, oids):
        raw_value = self._get_scalar(ip_address, oids.get('dell_global_system_status', ''))
        if raw_value is None:
            return 0
        status_code = self._safe_int(raw_value, 3)
        mapping = {1: 12, 2: 35, 3: 55, 4: 88, 5: 95, 6: 100}
        return mapping.get(status_code, min(95, 20 + status_code * 10))

    def _dell_memory_proxy_percent(self, ip_address, oids):
        raw_value = self._get_scalar(ip_address, oids.get('memory_status_oid', ''))
        if raw_value is None:
            return 0
        code = self._safe_int(raw_value, 1)
        return min(99, code * 12)

    def _dell_disk_proxy_percent(self, ip_address, oids):
        raw_value = self._get_scalar(ip_address, oids.get('disk_status_oid', ''))
        if raw_value is None:
            return 0
        code = self._safe_int(raw_value, 1)
        return min(99, code * 14)

    def _ratio_percent(self, ip_address, used_oid, total_oid):
        total_raw = self._get_scalar(ip_address, total_oid)
        used_raw = self._get_scalar(ip_address, used_oid)
        if total_raw is None or used_raw is None:
            return 0
        total_val = max(self._safe_int(total_raw, 0), 1)
        used_val = min(max(self._safe_int(used_raw, 0), 0), total_val)
        return int(round((used_val / float(total_val)) * 100))

    def _cisco_memory_ratio(self, ip_address, oids):
        used_raw = self._get_scalar(ip_address, oids.get('memory_used_oid', ''))
        free_raw = self._get_scalar(ip_address, oids.get('memory_free_oid', ''))
        if used_raw is None or free_raw is None:
            return 0
        used_val = max(self._safe_int(used_raw, 0), 0)
        free_val = max(self._safe_int(free_raw, 0), 0)
        denom = used_val + free_val
        if denom <= 0:
            return 0
        return int(round((used_val / float(denom)) * 100))

    def _cisco_pool_disk_ratio(self, ip_address, oids):
        if 'disk_used_oid' in oids and 'disk_free_oid' in oids:
            return self._cisco_memory_ratio(ip_address, {'memory_used_oid': oids['disk_used_oid'], 'memory_free_oid': oids['disk_free_oid']})
        return self._ratio_percent(ip_address, oids.get('disk_used_oid', ''), oids.get('disk_total_oid', ''))

    def _resolve_cpu(self, ip_address, oids):
        strategy = oids.get('cpu_strategy', '')
        if strategy == 'ucd_cpu_raw':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'cisco_cpumib_5min' or strategy == 'cisco_cpumib_1min':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'fortigate_scalar':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'mikrotik_scalar':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'ftos_cpu_util_5s':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'hpe_cpq_cpu_util':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'jnx_operating_cpu':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'ucs_blade_cpu_util':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'pan_cpu_active_sessions_proxy':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'dell_global_system_status_proxy':
            return self._dell_global_status_proxy(ip_address, oids)
        if strategy == 'apc_output_load_percent':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'hr_processor_max_walk':
            base = oids.get('cpu_walk_base', '1.3.6.1.2.1.25.3.3.1.2')
            walked = self._walk_numeric_max(ip_address, base)
            return min(100, max(0, walked or 0))
        if strategy == 'scalar_percent_optional':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        if strategy == 'direct_percent':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('cpu_oid', '')), 0)))
        return 0

    def _resolve_memory(self, ip_address, oids):
        strategy = oids.get('memory_strategy', '')
        if strategy == 'ucd_mem_ratio':
            return self._ucd_memory_percent(ip_address, oids)
        if strategy == 'cisco_memory_pool_ratio':
            return self._cisco_memory_ratio(ip_address, oids)
        if strategy == 'fortigate_scalar':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('memory_oid', '')), 0)))
        if strategy == 'mikrotik_mem_ratio':
            return self._ratio_percent(ip_address, oids.get('memory_used_oid', ''), oids.get('memory_total_oid', ''))
        if strategy == 'ftos_mem_util':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('memory_oid', '')), 0)))
        if strategy == 'hpe_mem_util':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('memory_oid', '')), 0)))
        if strategy == 'jnx_operating_buffer':
            return self._ratio_percent(ip_address, oids.get('memory_used_oid', ''), oids.get('memory_total_oid', ''))
        if strategy == 'ucs_memory_available_ratio':
            return self._ratio_percent(ip_address, oids.get('memory_used_oid', ''), oids.get('memory_total_oid', ''))
        if strategy == 'hr_memory_bytes_ratio':
            return self._ratio_percent(ip_address, oids.get('memory_used_oid', ''), oids.get('memory_total_oid', ''))
        if strategy == 'hpicf_cpu_mem':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('memory_oid', '')), 0)))
        if strategy == 'dell_memory_device_status_scalar':
            return self._dell_memory_proxy_percent(ip_address, oids)
        if strategy == 'apc_battery_capacity_percent':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('memory_oid', '')), 0)))
        if strategy == 'scalar_percent_optional':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('memory_oid', '')), 0)))
        if strategy == 'direct_percent':
            total_raw = self._get_scalar(ip_address, oids.get('memory_total_oid', ''))
            avail_raw = self._get_scalar(ip_address, oids.get('memory_avail_oid', ''))
            if total_raw is None or avail_raw is None:
                return 0
            total_val = max(self._safe_int(total_raw, 0), 1)
            avail_val = min(max(self._safe_int(avail_raw, 0), 0), total_val)
            used_val = total_val - avail_val
            if used_val < 0:
                used_val = 0
            return int(round((used_val / float(total_val)) * 100))
        return 0

    def _resolve_disk(self, ip_address, oids):
        strategy = oids.get('disk_strategy', '')
        if strategy == 'ucd_dsk_percent':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('disk_oid', '')), 0)))
        if strategy == 'hr_storage_used_ratio':
            return self._ratio_percent(ip_address, oids.get('disk_used_oid', ''), oids.get('disk_total_oid', ''))
        if strategy == 'cisco_flash_partition_ratio':
            return self._cisco_pool_disk_ratio(ip_address, oids)
        if strategy == 'fortigate_scalar':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('disk_oid', '')), 0)))
        if strategy == 'netapp_df_percent':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('disk_oid', '')), 0)))
        if strategy == 'synology_volume_percent':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('disk_oid', '')), 0)))
        if strategy == 'hpe_logical_drive_percent':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('disk_oid', '')), 0)))
        if strategy == 'dell_physical_disk_smart_status_scalar':
            return self._dell_disk_proxy_percent(ip_address, oids)
        if strategy == 'dell_controller_component_status_scalar':
            return self._dell_disk_proxy_percent(ip_address, oids)
        if strategy == 'apc_output_load_percent':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('disk_oid', '')), 0)))
        if strategy == 'scalar_percent_optional':
            return min(100, max(0, self._safe_int(self._get_scalar(ip_address, oids.get('disk_oid', '')), 0)))
        return 0

    def _resolve_temperature(self, ip_address, oids, has_thermal):
        if not has_thermal:
            return 0
        strategy = oids.get('temperature_strategy', '')
        if strategy == 'none':
            return 0
        oid_target = oids.get('temperature_oid', '')
        if not oid_target:
            return 0
        raw_value = self._get_scalar(ip_address, oid_target)
        if raw_value is None:
            return 0
        if strategy == 'lm_sensors_table':
            tenths = self._safe_int(raw_value, 0)
            if tenths > 1000:
                return tenths // 1000
            if tenths > 200:
                return tenths // 10
            return min(120, max(-40, tenths))
        if strategy == 'dell_cooling_probe_reading':
            tenths = self._safe_int(raw_value, 0)
            if tenths > 200:
                return tenths // 10
            return min(120, max(0, tenths))
        if strategy == 'cisco_entity_sensor' or strategy == 'entity_sensor_optional':
            milli = self._safe_int(raw_value, 0)
            if abs(milli) > 200:
                return int(round(milli / 1000.0))
            return min(120, max(0, milli))
        if strategy == 'fortigate_sensor':
            return min(120, max(0, self._safe_int(raw_value, 0)))
        if strategy == 'mikrotik_board_temp':
            return min(120, max(0, self._safe_int(raw_value, 0)))
        if strategy == 'jnx_operating_temp':
            return min(120, max(0, self._safe_int(raw_value, 0)))
        if strategy == 'hpe_thermal_zone':
            return min(120, max(0, self._safe_int(raw_value, 0)))
        if strategy == 'vmware_env_hw':
            return min(120, max(0, self._safe_int(raw_value, 0)))
        if strategy == 'netapp_enclosure_temp':
            return min(120, max(0, self._safe_int(raw_value, 0)))
        if strategy == 'synology_system_status':
            return min(120, max(0, self._safe_int(raw_value, 0) * 7))
        if strategy == 'ubnt_loadavg_proxy':
            text_value = str(raw_value)
            parts = text_value.replace(',', '.').split('.')
            if parts and parts[0].isdigit():
                return min(100, int(parts[0]) * 9)
            return min(100, max(0, self._safe_int(raw_value, 0)))
        if strategy == 'ubnt_radio_temp':
            return min(120, max(0, self._safe_int(raw_value, 0)))
        if strategy == 'scalar_tenths_celsius':
            tenths = self._safe_int(raw_value, 0)
            if tenths > 200:
                return tenths // 10
            return min(120, max(0, tenths))
        if strategy == 'apc_battery_temp_celsius':
            return min(120, max(0, self._safe_int(raw_value, 0)))
        return min(120, max(0, self._safe_int(raw_value, 0)))

    def _interface_up_ratio(self, ip_address, base_oid):
        if not base_oid:
            return 100
        up_count = 0
        total = 0
        for index in range(1, 49):
            raw = self._get_scalar(ip_address, base_oid + '.' + str(index))
            if raw is None:
                continue
            total += 1
            if self._safe_int(raw, 0) == 1:
                up_count += 1
        if total <= 0:
            return 100
        return int(round((up_count / float(total)) * 100))

    def collect_host_metrics(self, ip_address, template_key, hostname_hint, has_thermal, snmp_profile):
        self._clear_last_error()
        if not self._snmp_agent_responds(ip_address):
            offline_payload = _offline_host_metrics(ip_address, hostname_hint, template_key, snmp_profile)
            offline_payload['last_error_message'] = self.last_error_message
            return offline_payload
        template_bundle = resolve_enterprise_template(template_key)
        oids = template_bundle.get('oids', {})
        hostname_value = str(self._get_scalar(ip_address, oids.get('sys_name', '1.3.6.1.2.1.1.5.0')) or '').strip()
        if not hostname_value:
            hostname_value = str(hostname_hint or '').strip() or ip_address
        cpu_value = self._resolve_cpu(ip_address, oids)
        memory_value = self._resolve_memory(ip_address, oids)
        disk_value = self._resolve_disk(ip_address, oids)
        temperature_value = self._resolve_temperature(ip_address, oids, has_thermal)
        interface_ratio = self._interface_up_ratio(ip_address, oids.get('if_operstatus_base', '1.3.6.1.2.1.2.2.1.8'))
        if interface_ratio < 40 and disk_value < 90:
            disk_value = min(99, disk_value + 5)
        macros = template_bundle.get('macros') or {}
        cpu_thr = int(macros.get('CPU_UTIL_MAX', 90))
        ram_thr = int(macros.get('MEMORY_UTIL_MAX', macros.get('RAM_UTIL_MAX', 90)))
        disk_thr = int(macros.get('DISK_UTIL_MAX', 95))
        temp_thr = int(macros.get('TEMP_C_MAX', 80))
        warnings = []
        if cpu_value > cpu_thr:
            warnings.append('cpu_high')
        if memory_value > ram_thr:
            warnings.append('ram_high')
        if disk_value > disk_thr:
            warnings.append('disk_critical')
        if has_thermal and temperature_value >= temp_thr:
            warnings.append('temp_critical')
        bat_min = macros.get('BATTERY_CAPACITY_MIN_WARN')
        ups_temp_max = macros.get('UPS_TEMP_MAX_WARN')
        if bat_min is not None and str(oids.get('memory_strategy')) == 'apc_battery_capacity_percent' and memory_value < int(bat_min):
            warnings.append('battery_low')
        if ups_temp_max is not None and str(oids.get('temperature_strategy')) == 'apc_battery_temp_celsius' and temperature_value >= int(ups_temp_max):
            warnings.append('ups_battery_temp_critical')
        if interface_ratio < 50:
            warnings.append('interface_degraded')
        value_maps_all = template_bundle.get('value_maps') or {}
        for logical_metric, oid_field in (template_bundle.get('value_map_sources') or {}).items():
            oid_path = oids.get(oid_field)
            if not oid_path:
                continue
            raw_vm = self._get_scalar(ip_address, oid_path)
            if raw_vm is None:
                continue
            code_vm = self._safe_int(raw_vm, None)
            if code_vm is None:
                continue
            row_vm = value_maps_all.get(logical_metric) or {}
            if code_vm in row_vm:
                warnings.append('value_map:' + str(logical_metric) + ':' + str(row_vm[code_vm]))
        return {
            'ip': ip_address,
            'hostname': hostname_value,
            'device_type': snmp_profile,
            'vendor_template': str(template_key or ''),
            'status': 'online',
            'cpu_utilization': int(cpu_value),
            'ram_usage': int(memory_value),
            'disk_usage': int(disk_value),
            'temperature_c': int(temperature_value),
            'interface_health_percent': int(interface_ratio),
            'warnings': warnings,
            'mock_data': False,
            'last_error_message': '',
        }


def run_single_poll_cycle(connection, community='public', timeout=2, retries=1, device_type_filter=None):
    from engine import notify_predictive_anomaly_after_poll

    cursor = connection.cursor()
    base_sql = (
        'SELECT h.id, h.hostname, h.ip_address, h.device_type, COALESCE(h.vendor_template, ?), '
        'COALESCE(h.poll_protocol, \'SNMP\'), COALESCE(h.polling_interval_seconds, 60), COALESCE(h.maintenance_mode, 0), '
        'COALESCE(h.snmp_community, ?), COALESCE(h.snmp_port, 161), COALESCE(h.snmp_version, \'v2c\'), '
        'COALESCE(h.snmpv3_user, \'\'), COALESCE(h.snmpv3_auth_algo, \'SHA\'), COALESCE(h.snmpv3_auth_key, \'\'), '
        'COALESCE(h.snmpv3_priv_algo, \'AES\'), COALESCE(h.snmpv3_priv_key, \'\') FROM hosts h'
    )
    if device_type_filter and device_type_filter in ('Server', 'Switch', 'VM', 'Website'):
        cursor.execute(base_sql + ' WHERE h.device_type = ? ORDER BY h.id', ('generic_linux_net_snmp', 'public', device_type_filter))
    else:
        cursor.execute(base_sql + ' ORDER BY h.id', ('generic_linux_net_snmp', 'public'))
    rows = cursor.fetchall()
    results = []
    for (
        host_id,
        hostname,
        ip_address,
        device_type,
        vendor_template,
        poll_protocol,
        polling_interval_seconds,
        maintenance_mode,
        snmp_community,
        snmp_port,
        snmp_version,
        snmpv3_user,
        snmpv3_auth_algo,
        snmpv3_auth_key,
        snmpv3_priv_algo,
        snmpv3_priv_key,
    ) in rows:
        interval_value = int(polling_interval_seconds or 60)
        if not _host_poll_interval_elapsed(cursor, int(host_id), interval_value):
            continue
        canonical = str(device_type)
        snmp_profile = 'switches' if canonical == 'Switch' else 'vm' if canonical == 'VM' else 'servers'
        has_thermal = canonical in ('Server', 'Switch')
        protocol_upper = str(poll_protocol or 'SNMP').strip().upper()
        if int(maintenance_mode or 0) == 1:
            connection.execute(
                'INSERT INTO metrics_history (host_id, status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data, latency_ms, http_status_code) '
                'VALUES (?, ?, NULL, NULL, NULL, NULL, 0, NULL, NULL)',
                (int(host_id), 'paused'),
            )
            connection.execute(
                'DELETE FROM metrics_history WHERE host_id = ? AND id NOT IN ('
                'SELECT id FROM ('
                'SELECT id FROM metrics_history WHERE host_id = ? ORDER BY datetime(polled_at) DESC, id DESC LIMIT 800'
                ')'
                ')',
                (int(host_id), int(host_id)),
            )
            results.append(
                {
                    'host_id': int(host_id),
                    'ip': str(ip_address or ''),
                    'hostname': str(hostname or ''),
                    'status': 'paused',
                    'cpu_utilization': None,
                    'ram_usage': None,
                    'disk_usage': None,
                    'temperature_c': None,
                    'latency_ms': None,
                    'http_status_code': None,
                    'mock_data': False,
                }
            )
            continue
        if _is_website_http_probe(canonical, poll_protocol):
            metrics = _poll_http_endpoint(hostname, ip_address, poll_protocol)
            metrics['vendor_template'] = str(vendor_template or 'generic_linux_net_snmp')
        elif not _is_website_http_probe(canonical, poll_protocol) and not _is_valid_ipv4_target(ip_address):
            metrics = _offline_host_metrics(str(ip_address), str(hostname), str(vendor_template), snmp_profile)
        elif protocol_upper == 'SNMP' and getCmd is not None:
            host_community = str(snmp_community or '').strip() or str(community or 'public').strip() or 'public'
            try:
                host_snmp_port = int(snmp_port)
            except Exception:
                host_snmp_port = 161
            if host_snmp_port <= 0 or host_snmp_port > 65535:
                host_snmp_port = 161
            ver_raw = str(snmp_version or 'v2c').strip().lower()
            host_version = 'v3' if ver_raw == 'v3' else 'v2c'
            host_poller = EnterpriseSnmpPoller(
                host_community,
                timeout,
                retries,
                host_snmp_port,
                host_version,
                snmpv3_user,
                snmpv3_auth_algo,
                snmpv3_auth_key,
                snmpv3_priv_algo,
                snmpv3_priv_key,
            )
            metrics = host_poller.collect_host_metrics(str(ip_address), str(vendor_template), str(hostname), has_thermal, snmp_profile)
            error_text = str(metrics.get('last_error_message') or host_poller.last_error_message or '')
            if str(metrics.get('status', '')).lower() == 'online':
                connection.execute('UPDATE hosts SET last_error_message = ? WHERE id = ?', ('', int(host_id)))
            elif error_text:
                connection.execute('UPDATE hosts SET last_error_message = ? WHERE id = ?', (error_text, int(host_id)))
        else:
            metrics = _offline_host_metrics(str(ip_address), str(hostname), str(vendor_template), snmp_profile)
        mock_flag = 1 if metrics.get('mock_data') else 0
        row_status = str(metrics.get('status', 'online'))
        if _is_website_http_probe(canonical, poll_protocol):
            connection.execute(
                'INSERT INTO metrics_history (host_id, status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data, latency_ms, http_status_code) '
                'VALUES (?, ?, NULL, NULL, NULL, NULL, ?, ?, ?)',
                (
                    int(host_id),
                    row_status,
                    mock_flag,
                    metrics.get('latency_ms'),
                    metrics.get('http_status_code'),
                ),
            )
        elif row_status == 'offline':
            connection.execute(
                'INSERT INTO metrics_history (host_id, status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data, latency_ms, http_status_code) '
                'VALUES (?, ?, NULL, NULL, NULL, NULL, ?, NULL, NULL)',
                (int(host_id), row_status, mock_flag),
            )
        else:
            cpu_part = metrics.get('cpu_utilization')
            ram_part = metrics.get('ram_usage')
            disk_part = metrics.get('disk_usage')
            temp_part = metrics.get('temperature_c')
            connection.execute(
                'INSERT INTO metrics_history (host_id, status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data, latency_ms, http_status_code) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)',
                (
                    int(host_id),
                    row_status,
                    int(cpu_part) if cpu_part is not None else None,
                    int(ram_part) if ram_part is not None else None,
                    int(disk_part) if disk_part is not None else None,
                    int(temp_part) if temp_part is not None else None,
                    mock_flag,
                ),
            )
        connection.execute(
            'DELETE FROM metrics_history WHERE host_id = ? AND id NOT IN ('
            'SELECT id FROM ('
            'SELECT id FROM metrics_history WHERE host_id = ? ORDER BY datetime(polled_at) DESC, id DESC LIMIT 800'
            ')'
            ')',
            (int(host_id), int(host_id)),
        )
        notify_predictive_anomaly_after_poll(connection, int(host_id), str(hostname), str(ip_address), None)
        results.append({'host_id': int(host_id), **metrics})
    connection.commit()
    return results


async def _ping_one_ip(ip_string):
    system_token = platform.system().lower()
    if system_token == 'windows':
        proc = await asyncio.create_subprocess_exec(
            'ping',
            '-n',
            '1',
            '-w',
            '900',
            ip_string,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    else:
        proc = await asyncio.create_subprocess_exec(
            'ping',
            '-c',
            '1',
            '-W',
            '1',
            ip_string,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    await proc.wait()
    return proc.returncode == 0


async def sweep_subnet(cidr_value):
    network_object = ipaddress.ip_network(str(cidr_value).strip(), strict=False)
    if network_object.version != 4:
        raise ValueError('ipv4_only')
    if network_object.num_addresses > 256:
        raise ValueError('subnet_too_large')
    address_strings = [str(host_item) for host_item in network_object.hosts()]
    if not address_strings and network_object.prefixlen >= 31:
        address_strings = [str(network_object.network_address)]
    semaphore_object = asyncio.Semaphore(40)
    results_lock = asyncio.Lock()
    active_ips = []

    async def guarded_ping(single_ip):
        async with semaphore_object:
            ok_flag = await _ping_one_ip(single_ip)
            if ok_flag:
                async with results_lock:
                    active_ips.append(single_ip)

    await asyncio.gather(*[guarded_ping(ip_token) for ip_token in address_strings])
    return sorted(set(active_ips))


_scheduler_singleton = None


def start_background_poller(db_path=None, interval_seconds=120):
    global _scheduler_singleton
    if BackgroundScheduler is None:
        return None
    if _scheduler_singleton is not None:
        return _scheduler_singleton
    from knowledge_db import ensure_database

    def job_callable():
        db_inner = ensure_database(db_path)
        try:
            run_single_poll_cycle(db_inner)
        finally:
            db_inner.close()

    scheduler_object = BackgroundScheduler()
    scheduler_object.add_job(job_callable, 'interval', seconds=int(interval_seconds), max_instances=1, coalesce=True)
    scheduler_object.start()
    _scheduler_singleton = scheduler_object
    return scheduler_object


if __name__ == '__main__':
    from knowledge_db import ensure_database

    db = ensure_database()
    try:
        run_single_poll_cycle(db)
    finally:
        db.close()
    start_background_poller(interval_seconds=180)
    while True:
        time.sleep(3600)
