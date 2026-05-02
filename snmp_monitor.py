import hashlib
import random
import socket
import time

try:
    from pysnmp.hlapi import CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, getCmd
except Exception:
    CommunityData = None
    ContextData = None
    ObjectIdentity = None
    ObjectType = None
    SnmpEngine = None
    UdpTransportTarget = None
    getCmd = None


class SNMPMonitor:
    def __init__(self, community='public', timeout=2, retries=1):
        self.community = community
        self.timeout = timeout
        self.retries = retries

    def poll_hosts_from_database(self, connection, device_type_filter=None):
        cursor = connection.cursor()
        if device_type_filter and device_type_filter in ('Server', 'Switch', 'VM'):
            cursor.execute(
                'SELECT id, hostname, ip_address, device_type FROM hosts WHERE device_type = ? ORDER BY id',
                (device_type_filter,),
            )
        else:
            cursor.execute('SELECT id, hostname, ip_address, device_type FROM hosts ORDER BY id')
        rows = cursor.fetchall()
        results = []
        for host_id, hostname, ip_address, device_type in rows:
            canonical = str(device_type)
            snmp_profile = self._map_device_type(canonical)
            has_thermal = canonical in ('Server', 'Switch')
            metrics = self.poll_target(str(ip_address), snmp_profile, str(hostname), has_thermal)
            self._insert_metrics_history(connection, int(host_id), metrics)
            results.append({'host_id': int(host_id), **metrics})
        connection.commit()
        return results

    def poll_target(self, ip_address, device_type='servers', hostname_hint=None, has_thermal=True):
        live_metrics = self._query_live_snmp(ip_address, device_type, hostname_hint, has_thermal)
        if live_metrics is not None:
            return live_metrics
        return self.mock_snmp_data(ip_address, device_type, hostname_hint, has_thermal)

    def mock_snmp_data(self, ip_address, device_type='servers', hostname_hint=None, has_thermal=True):
        seed_value = int(hashlib.md5(ip_address.encode('utf-8')).hexdigest()[:8], 16)
        random_generator = random.Random(seed_value + int(time.time() // 300))
        if device_type == 'switches':
            cpu_value = random_generator.randint(18, 76)
            ram_value = random_generator.randint(28, 84)
            disk_value = random_generator.randint(22, 58)
            temp_value = random_generator.randint(33, 71) if has_thermal else 0
        elif device_type == 'vm' or not has_thermal:
            cpu_value = random_generator.randint(25, 98)
            ram_value = random_generator.randint(34, 96)
            disk_value = random_generator.randint(20, 99)
            temp_value = 0
        else:
            cpu_value = random_generator.randint(25, 98)
            ram_value = random_generator.randint(34, 96)
            disk_value = random_generator.randint(20, 99)
            temp_value = random_generator.randint(35, 92)
        host_label = str(hostname_hint).strip() if hostname_hint else 'Device-' + ip_address.replace('.', '-')
        return self._compose_metric_payload(
            ip_address=ip_address,
            hostname=host_label,
            cpu_value=cpu_value,
            ram_usage=ram_value,
            disk_usage=disk_value,
            temperature=temp_value,
            device_type=device_type,
            status='online',
            mock_data=True,
            has_thermal=has_thermal,
        )

    def _query_live_snmp(self, ip_address, device_type, hostname_hint=None, has_thermal=True):
        if getCmd is None:
            return None
        oid_map = {
            'hostname': '1.3.6.1.2.1.1.5.0',
            'cpu': '1.3.6.1.4.1.2021.11.9.0',
            'ram_total': '1.3.6.1.4.1.2021.4.5.0',
            'ram_avail': '1.3.6.1.4.1.2021.4.6.0',
            'disk': '1.3.6.1.4.1.2021.9.1.9.1',
            'temp': '1.3.6.1.4.1.2021.13.16.5.1.3.1',
        }
        values = {}
        for metric_key, oid_value in oid_map.items():
            if metric_key == 'temp' and not has_thermal:
                values[metric_key] = 0
                continue
            metric_result = self._single_oid_query(ip_address, oid_value)
            if metric_result is None:
                return None
            values[metric_key] = metric_result
        hostname_value = str(values['hostname']).strip() or (str(hostname_hint).strip() if hostname_hint else '') or self._fallback_hostname(ip_address)
        cpu_value = self._safe_int(values['cpu'], 0)
        ram_total = max(self._safe_int(values['ram_total'], 0), 1)
        ram_avail = min(max(self._safe_int(values['ram_avail'], 0), 0), ram_total)
        ram_usage = int(round(((ram_total - ram_avail) / float(ram_total)) * 100))
        disk_usage = self._safe_int(values['disk'], 0)
        temperature = 0 if not has_thermal else self._safe_int(values['temp'], 0)
        return self._compose_metric_payload(
            ip_address=ip_address,
            hostname=hostname_value,
            cpu_value=cpu_value,
            ram_usage=ram_usage,
            disk_usage=disk_usage,
            temperature=temperature,
            device_type=device_type,
            status='online',
            mock_data=False,
            has_thermal=has_thermal,
        )

    def _single_oid_query(self, ip_address, oid_value):
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(self.community),
                UdpTransportTarget((ip_address, 161), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid_value)),
            )
            error_indication, error_status, _, var_binds = next(iterator)
        except Exception:
            return None
        if error_indication or error_status:
            return None
        if not var_binds:
            return None
        return var_binds[0][1]

    def _compose_metric_payload(
        self,
        ip_address,
        hostname,
        cpu_value,
        ram_usage,
        disk_usage,
        temperature,
        device_type,
        status,
        mock_data,
        has_thermal=True,
    ):
        warnings = []
        if cpu_value > 85:
            warnings.append('cpu_high')
        if disk_usage > 95:
            warnings.append('disk_critical')
        if has_thermal and temperature >= 80:
            warnings.append('temp_critical')
        return {
            'ip': ip_address,
            'hostname': hostname,
            'device_type': device_type,
            'status': status,
            'cpu_utilization': int(cpu_value),
            'ram_usage': int(ram_usage),
            'disk_usage': int(disk_usage),
            'temperature_c': int(temperature),
            'warnings': warnings,
            'mock_data': bool(mock_data),
        }

    def _safe_int(self, value, fallback):
        try:
            return int(float(str(value)))
        except Exception:
            return fallback

    def _fallback_hostname(self, ip_address):
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except Exception:
            return 'Device-' + ip_address.replace('.', '-')

    def _map_device_type(self, device_type):
        if device_type == 'Switch':
            return 'switches'
        if device_type == 'VM':
            return 'vm'
        return 'servers'

    def _insert_metrics_history(self, connection, host_id, metrics):
        connection.execute(
            'INSERT INTO metrics_history (host_id, status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (
                int(host_id),
                str(metrics.get('status', 'online')),
                int(metrics.get('cpu_utilization', 0)),
                int(metrics.get('ram_usage', 0)),
                int(metrics.get('disk_usage', 0)),
                int(metrics.get('temperature_c', 0)),
                1 if metrics.get('mock_data') else 0,
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
