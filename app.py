from flask import Flask, jsonify, render_template, request

from engine import (
    build_query_text_from_log_payload,
    build_query_text_from_scanner_payload,
    generate_ai_decisions_from_metrics_history,
    generate_structured_remediation_plan,
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
    finally:
        db_connection.close()
    return jsonify({'language': language, 'scanner_results': scanner_payload, 'log_analysis': log_payload, 'remediation_plan': remediation_plan})


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
            metrics.append(
                {
                    'host_id': int(r[0]),
                    'hostname': r[1],
                    'ip_address': r[2],
                    'device_type': r[3],
                    'status': r[4] or 'unknown',
                    'cpu_utilization': int(r[5] or 0),
                    'ram_usage': int(r[6] or 0),
                    'disk_usage': int(r[7] or 0),
                    'temperature_c': int(r[8] or 0),
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


if __name__ == '__main__':
    flask_application.run(host='127.0.0.1', port=5000, debug=False)
