from flask import Flask, jsonify, render_template, request

from engine import (
    build_query_text_from_log_payload,
    build_query_text_from_scanner_payload,
    generate_ai_decisions_from_metrics_history,
    generate_structured_remediation_plan,
    match_vulnerability_advisories,
    merge_query_streams,
    normalize_free_text_for_matching,
)
from knowledge_db import ensure_database
from log_analyzer import collect_operating_system_log_insights
from scanner import run_full_system_surface_scan
from snmp_monitor import SNMPMonitor

flask_application = Flask(__name__)
SAFE_WHITELIST_PORTS = {53, 135, 139, 389, 445, 3389}


def _normalize_language(language_value):
    return language_value if language_value in ('en', 'ru', 'hy') else 'en'


def _filter_anomalous_ports(socket_rows):
    filtered_rows = []
    for row in socket_rows or []:
        try:
            port_value = int(row.get('port'))
        except Exception:
            port_value = None
        if port_value in SAFE_WHITELIST_PORTS:
            continue
        filtered_rows.append(row)
    return filtered_rows


def _parse_json_request():
    return request.get_json(silent=True) or {}


@flask_application.route('/')
def landing():
    return render_template('landing.html')


@flask_application.route('/audit')
def audit_page():
    return render_template('audit.html')


@flask_application.route('/monitoring')
def monitoring_page():
    return render_template('monitoring.html')


@flask_application.route('/api/audit/run', methods=['POST'])
def api_audit_run():
    request_payload = _parse_json_request()
    language = _normalize_language(request_payload.get('language'))
    subnet_value = normalize_free_text_for_matching(str(request_payload.get('subnet') or '')).strip() or None
    scanner_payload = run_full_system_surface_scan(subnet_value)
    scanner_payload['listening_sockets'] = _filter_anomalous_ports(scanner_payload.get('listening_sockets', []))
    log_payload = collect_operating_system_log_insights()
    db_connection = ensure_database()
    try:
        scanner_query = build_query_text_from_scanner_payload(scanner_payload)
        log_query = build_query_text_from_log_payload(log_payload)
        remediation_query = merge_query_streams(scanner_query, log_query, '')
        remediation_plan = generate_structured_remediation_plan(db_connection, remediation_query, 7, language)
        vulnerability_advisories = match_vulnerability_advisories(db_connection, scanner_payload, language)
    finally:
        db_connection.close()
    return jsonify(
        {
            'language': language,
            'scanner_results': scanner_payload,
            'log_analysis': log_payload,
            'remediation_plan': remediation_plan,
            'vulnerability_advisories': vulnerability_advisories,
        }
    )


@flask_application.route('/api/hosts', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_hosts():
    request_payload = _parse_json_request()
    db = ensure_database()
    try:
        if request.method == 'GET':
            cursor = db.cursor()
            cursor.execute('SELECT id, hostname, ip_address, device_type, date_added FROM hosts ORDER BY id')
            rows = cursor.fetchall()
            hosts = [
                {'id': int(r[0]), 'hostname': r[1], 'ip_address': r[2], 'device_type': r[3], 'date_added': r[4]}
                for r in rows
            ]
            return jsonify({'hosts': hosts})
        if request.method == 'POST':
            hostname = str(request_payload.get('hostname') or '').strip()
            ip_address = str(request_payload.get('ip_address') or '').strip()
            device_type = str(request_payload.get('device_type') or '').strip()
            if device_type not in ('Server', 'Switch', 'VM'):
                device_type = 'Server'
            if not hostname or not ip_address:
                return jsonify({'error': 'invalid_input'}), 400
            db.execute('INSERT INTO hosts (hostname, ip_address, device_type) VALUES (?, ?, ?)', (hostname, ip_address, device_type))
            db.commit()
            return jsonify({'status': 'created'})
        if request.method == 'PUT':
            host_id = int(request_payload.get('id') or 0)
            hostname = str(request_payload.get('hostname') or '').strip()
            ip_address = str(request_payload.get('ip_address') or '').strip()
            device_type = str(request_payload.get('device_type') or '').strip()
            if device_type not in ('Server', 'Switch', 'VM'):
                device_type = 'Server'
            if host_id <= 0 or not hostname or not ip_address:
                return jsonify({'error': 'invalid_input'}), 400
            db.execute(
                'UPDATE hosts SET hostname = ?, ip_address = ?, device_type = ? WHERE id = ?',
                (hostname, ip_address, device_type, host_id),
            )
            db.commit()
            return jsonify({'status': 'updated'})
        host_id = int(request_payload.get('id') or 0)
        if host_id <= 0:
            return jsonify({'error': 'invalid_input'}), 400
        db.execute('DELETE FROM metrics_history WHERE host_id = ?', (host_id,))
        db.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
        db.commit()
        return jsonify({'status': 'deleted'})
    finally:
        db.close()


@flask_application.route('/api/metrics/poll', methods=['POST'])
def api_metrics_poll():
    request_payload = _parse_json_request()
    device_type_filter = str(request_payload.get('device_type') or '').strip()
    db = ensure_database()
    try:
        snmp_monitor = SNMPMonitor()
        metrics = snmp_monitor.poll_hosts_from_database(db, device_type_filter if device_type_filter in ('Server', 'Switch', 'VM') else None)
        return jsonify({'metrics': metrics})
    finally:
        db.close()


@flask_application.route('/api/metrics/latest', methods=['GET'])
def api_metrics_latest():
    db = ensure_database()
    try:
        cursor = db.cursor()
        cursor.execute(
            'SELECT h.id, h.hostname, h.ip_address, h.device_type, '
            'm.status, m.cpu_utilization, m.ram_usage, m.disk_usage, m.temperature_c, m.mock_data, m.polled_at '
            'FROM hosts h LEFT JOIN metrics_history m ON m.id = ('
            'SELECT id FROM metrics_history WHERE host_id = h.id ORDER BY datetime(polled_at) DESC, id DESC LIMIT 1'
            ') ORDER BY h.id'
        )
        rows = cursor.fetchall()
        metrics = []
        for r in rows:
            device_label = str(r[3] or '')
            temperature_output = None if device_label == 'VM' else int(r[8] or 0)
            metrics.append(
                {
                    'host_id': int(r[0]),
                    'hostname': r[1],
                    'ip_address': r[2],
                    'device_type': device_label,
                    'status': r[4] or 'unknown',
                    'cpu_utilization': int(r[5] or 0),
                    'ram_usage': int(r[6] or 0),
                    'disk_usage': int(r[7] or 0),
                    'temperature_c': temperature_output,
                    'mock_data': bool(int(r[9] or 0)),
                    'polled_at': r[10],
                }
            )
        return jsonify({'metrics': metrics})
    finally:
        db.close()


@flask_application.route('/api/ai/decisions', methods=['POST'])
def api_ai_decisions():
    request_payload = _parse_json_request()
    language = _normalize_language(request_payload.get('language'))
    db = ensure_database()
    try:
        decisions = generate_ai_decisions_from_metrics_history(db, language, 25)
        return jsonify({'language': language, 'decisions': decisions})
    finally:
        db.close()


def _sanitize_timestamp_query_fragment(raw_value):
    if not raw_value:
        return None
    token = str(raw_value).strip().replace('T', ' ')
    if len(token) == 16:
        token = token + ':00'
    return token


@flask_application.route('/api/metrics/history', methods=['GET', 'POST'])
def api_metrics_history():
    if request.method == 'GET':
        host_id_value = int(request.args.get('host_id', 0) or 0)
        start_stamp = request.args.get('start')
        end_stamp = request.args.get('end')
    else:
        parsed_body = _parse_json_request()
        host_id_value = int(parsed_body.get('host_id') or 0)
        start_stamp = parsed_body.get('start')
        end_stamp = parsed_body.get('end')
    if host_id_value <= 0:
        return jsonify({'error': 'invalid_input'}), 400
    db = ensure_database()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT device_type FROM hosts WHERE id = ?', (host_id_value,))
        host_row = cursor.fetchone()
        if not host_row:
            return jsonify({'error': 'not_found'}), 404
        device_type_value = str(host_row[0] or '')
        if start_stamp and end_stamp:
            start_token = _sanitize_timestamp_query_fragment(start_stamp)
            end_token = _sanitize_timestamp_query_fragment(end_stamp)
            cursor.execute(
                'SELECT polled_at, cpu_utilization, ram_usage, disk_usage, temperature_c, status, mock_data '
                'FROM metrics_history WHERE host_id = ? '
                'AND datetime(polled_at) >= datetime(?) AND datetime(polled_at) <= datetime(?) '
                'ORDER BY datetime(polled_at) ASC, id ASC',
                (host_id_value, start_token, end_token),
            )
        else:
            cursor.execute(
                'SELECT polled_at, cpu_utilization, ram_usage, disk_usage, temperature_c, status, mock_data '
                'FROM metrics_history WHERE host_id = ? '
                'ORDER BY datetime(polled_at) ASC, id ASC '
                'LIMIT 900',
                (host_id_value,),
            )
        history_rows = cursor.fetchall()
        series = []
        for polled_at_value, cpu_part, ram_part, disk_part, temp_part, status_part, mock_part in history_rows:
            series.append(
                {
                    'polled_at': str(polled_at_value),
                    'cpu_utilization': int(cpu_part or 0),
                    'ram_usage': int(ram_part or 0),
                    'disk_usage': int(disk_part or 0),
                    'temperature_c': None if device_type_value == 'VM' else int(temp_part or 0),
                    'status': str(status_part or 'unknown'),
                    'mock_data': bool(int(mock_part or 0)),
                }
            )
        return jsonify({'host_id': host_id_value, 'device_type': device_type_value, 'series': series})
    finally:
        db.close()


if __name__ == '__main__':
    flask_application.run(host='127.0.0.1', port=5000, debug=False)
