import asyncio
import logging
import os
from functools import wraps
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', force=True)

from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user

from engine import (
    build_query_text_from_log_payload,
    build_query_text_from_scanner_payload,
    compute_poll_sla_percent,
    generate_ai_decisions_from_metrics_history,
    generate_predictive_manual_suggestions,
    generate_structured_remediation_plan,
    match_vulnerability_advisories,
    merge_query_streams,
    normalize_free_text_for_matching,
)
from knowledge_db import (
    ensure_database,
    get_system_setting_value,
    get_user_by_id,
    get_user_by_username,
    get_user_settings_row,
    insert_action_audit_log,
    list_action_audit_logs,
    list_alert_logs,
    normalize_ssh_storage_triplet,
    set_system_setting_value,
    update_user_password_hash,
    upsert_user_settings_row,
)
from poller import sweep_subnet
from log_analyzer import collect_operating_system_log_insights
from models import hash_password, verify_password
from scanner import run_full_system_surface_scan
from snmp_monitor import SNMPMonitor
from template_registry import ENTERPRISE_TEMPLATES

flask_application = Flask(__name__)
flask_application.config['SECRET_KEY'] = os.environ.get('DEVAI_SECRET_KEY', os.environ.get('SENTINEL_SECRET_KEY', 'devai-local-secret-key'))
SAFE_WHITELIST_PORTS = {53, 135, 139, 389, 445, 3389}

login_manager = LoginManager()
login_manager.init_app(flask_application)
login_manager.login_view = 'login'


class DevAIUser(UserMixin):
    def __init__(self, user_id, username, role):
        self.id = int(user_id)
        self.username = str(username)
        self.role = str(role)


@login_manager.user_loader
def load_user(user_id):
    db = ensure_database()
    try:
        row = get_user_by_id(db, int(user_id))
        if not row:
            return None
        return DevAIUser(row['user_id'], row['username'], row['role'])
    finally:
        db.close()


@login_manager.unauthorized_handler
def handle_unauthorized():
    if request.path.startswith('/api/'):
        return jsonify({'error': 'unauthorized'}), 401
    return redirect(url_for('login', next=request.url))


def _normalize_language(language_value):
    return language_value if language_value in ('en', 'ru', 'hy') else 'en'


def _normalize_theme(theme_value):
    token = str(theme_value or '').strip()
    if token not in ('vibrant_dark', 'slate_dark', 'light'):
        return 'vibrant_dark'
    return token


def _normalize_vendor_template(template_value):
    candidate = str(template_value or '').strip()
    if candidate in ENTERPRISE_TEMPLATES:
        return candidate
    return 'generic_linux_net_snmp'


def _normalize_polling_interval(raw_value):
    try:
        parsed = int(raw_value)
    except Exception:
        parsed = 60
    if parsed not in (15, 30, 60, 300):
        return 60
    return parsed


def _normalize_poll_protocol(raw_value):
    token = str(raw_value or 'SNMP').strip().upper()
    if token not in ('SNMP', 'SSH', 'HTTP', 'HTTPS'):
        return 'SNMP'
    return token


def _normalize_snmp_community(raw_value):
    token = str(raw_value or '').strip()
    return token if token else 'public'


def _normalize_snmp_port(raw_value):
    try:
        parsed = int(raw_value)
    except Exception:
        return 161
    if parsed <= 0 or parsed > 65535:
        return 161
    return parsed


def _normalize_snmp_version(raw_value):
    token = str(raw_value or 'v2c').strip().lower()
    return 'v3' if token == 'v3' else 'v2c'


def _normalize_snmpv3_auth_algo(raw_value):
    token = str(raw_value or 'SHA').strip().upper()
    return 'MD5' if token == 'MD5' else 'SHA'


def _normalize_snmpv3_priv_algo(raw_value):
    token = str(raw_value or 'AES').strip().upper()
    return 'DES' if token == 'DES' else 'AES'


def _snmpv3_credentials_for_payload(db, host_id, request_payload):
    user = str(request_payload.get('snmpv3_user') or '').strip()
    auth_algo = _normalize_snmpv3_auth_algo(request_payload.get('snmpv3_auth_algo'))
    priv_algo = _normalize_snmpv3_priv_algo(request_payload.get('snmpv3_priv_algo'))
    auth_key = str(request_payload.get('snmpv3_auth_key') or '')
    priv_key = str(request_payload.get('snmpv3_priv_key') or '')
    if host_id is not None and int(host_id) > 0:
        if bool(request_payload.get('preserve_snmpv3_auth_key')) and not auth_key.strip():
            cur_keep = db.cursor()
            cur_keep.execute('SELECT COALESCE(snmpv3_auth_key, \'\') FROM hosts WHERE id = ? LIMIT 1', (int(host_id),))
            row_keep = cur_keep.fetchone()
            auth_key = str(row_keep[0] or '') if row_keep else ''
        if bool(request_payload.get('preserve_snmpv3_priv_key')) and not priv_key.strip():
            cur_keep = db.cursor()
            cur_keep.execute('SELECT COALESCE(snmpv3_priv_key, \'\') FROM hosts WHERE id = ? LIMIT 1', (int(host_id),))
            row_keep = cur_keep.fetchone()
            priv_key = str(row_keep[0] or '') if row_keep else ''
    return user, auth_algo, priv_algo, auth_key, priv_key


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


def admin_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not getattr(current_user, 'is_authenticated', False):
            return jsonify({'error': 'unauthorized'}), 401
        if str(getattr(current_user, 'role', '')) != 'Admin':
            return jsonify({'error': 'forbidden'}), 403
        return view_function(*args, **kwargs)

    return wrapped_view


def _audit_log(db_connection, description_text):
    try:
        insert_action_audit_log(db_connection, str(current_user.username), str(description_text)[:3800])
    except Exception:
        pass


def _normalize_device_type(device_value):
    token = str(device_value or '').strip()
    if token in ('Server', 'Switch', 'VM', 'Website'):
        return token
    return 'Server'


def _normalize_ssh_port(raw_value):
    try:
        parsed_port = int(raw_value)
    except Exception:
        return 22
    if parsed_port <= 0 or parsed_port > 65535:
        return 22
    return parsed_port


def _ssh_triplet_for_payload(db, host_id, device_type, request_payload):
    dt = str(device_type or '')
    if dt in ('Switch', 'Website'):
        return normalize_ssh_storage_triplet(dt, '', '', 22)
    ssh_username = str(request_payload.get('ssh_username') or '').strip()
    ssh_password = str(request_payload.get('ssh_password') or '')
    if host_id is not None and int(host_id) > 0 and bool(request_payload.get('preserve_ssh_password')) and not ssh_password.strip():
        cur_keep = db.cursor()
        cur_keep.execute('SELECT COALESCE(ssh_password, \'\') FROM hosts WHERE id = ? LIMIT 1', (int(host_id),))
        row_keep = cur_keep.fetchone()
        ssh_password = str(row_keep[0] or '') if row_keep else ''
    return normalize_ssh_storage_triplet(dt, ssh_username, ssh_password, request_payload.get('ssh_port'))


def _normalize_maintenance_mode(raw_value):
    try:
        flag = int(raw_value)
    except Exception:
        return 0
    return 1 if flag else 0


def _ssh_command_allowed(command_string):
    stripped = str(command_string or '').strip()
    if not stripped or len(stripped) > 4000:
        return False
    if '\n' in stripped or '\r' in stripped or '\x00' in stripped:
        return False
    lower_piece = stripped.lower()
    for forbidden_token in (
        'rm -rf /',
        'rm -rf /*',
        'mkfs',
        'dd if=/dev',
        ':(){',
        '/dev/sd',
        '/dev/nvme',
        'shutdown',
        'init 0',
        'init 6',
        'format c:',
        'diskpart',
        'wget -o-',
        'curl -fs',
    ):
        if forbidden_token in lower_piece:
            return False
    return True


def _ssh_execute_on_host(ip_address, port_value, username_value, password_value, command_string):
    try:
        import paramiko
    except Exception:
        return False, 'paramiko_unavailable'
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=str(ip_address),
            port=int(port_value),
            username=str(username_value),
            password=str(password_value),
            timeout=18,
            banner_timeout=18,
            auth_timeout=18,
            allow_agent=False,
            look_for_keys=False,
        )
        stdin_handle, stdout_handle, stderr_handle = client.exec_command(str(command_string), timeout=42)
        out_bytes = stdout_handle.read() + stderr_handle.read()
        text_out = out_bytes.decode('utf-8', errors='replace')
        exit_status = stdout_handle.channel.recv_exit_status()
        client.close()
        return True, text_out[:120000] + ('' if exit_status == 0 else '\n[exit ' + str(exit_status) + ']')
    except Exception as exc_object:
        try:
            client.close()
        except Exception:
            pass
        return False, str(exc_object)


def _safe_internal_redirect(target_url):
    if not target_url:
        return None
    parsed = urlparse(target_url)
    if parsed.scheme or parsed.netloc:
        return None
    if not target_url.startswith('/') or target_url.startswith('//'):
        return None
    return target_url


@flask_application.route('/', methods=['GET', 'POST'])
def login():
    if getattr(current_user, 'is_authenticated', False):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username_input = str(request.form.get('username') or '').strip()
        password_input = str(request.form.get('password') or '').strip()
        remember_flag = request.form.get('remember') in ('on', '1', 'true', 'yes')
        db = ensure_database()
        try:
            row = get_user_by_username(db, username_input)
            if row and verify_password(row['password_hash'], password_input):
                login_user(DevAIUser(row['user_id'], row['username'], row['role']), remember=remember_flag)
                next_raw = request.args.get('next') or request.form.get('next')
                safe_next = _safe_internal_redirect(next_raw)
                return redirect(safe_next or url_for('dashboard'))
        finally:
            db.close()
        return render_template('login.html', auth_failed=True)
    return render_template('login.html', auth_failed=False)


@flask_application.route('/logout')
def logout_route():
    logout_user()
    return redirect(url_for('login'))


@flask_application.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@flask_application.route('/landing')
@login_required
def landing_redirect():
    return redirect(url_for('dashboard'))


@flask_application.route('/audit')
@login_required
def audit_page():
    return redirect(url_for('dashboard') + '#view-audit')


@flask_application.route('/monitoring')
@login_required
def monitoring_page():
    return redirect(url_for('dashboard') + '#view-monitoring')


@flask_application.route('/api/me', methods=['GET'])
@login_required
def api_me():
    return jsonify({'user_id': int(current_user.id), 'username': current_user.username, 'role': current_user.role})


@flask_application.route('/api/settings', methods=['GET', 'POST'])
@login_required
def api_settings():
    db = ensure_database()
    try:
        if request.method == 'GET':
            row = get_user_settings_row(db, int(current_user.id))
            return jsonify(
                {
                    'theme_choice': row['theme_choice'],
                    'default_language': row['default_language'],
                    'sidebar_collapsed': int(row['sidebar_collapsed']),
                }
            )
        payload = _parse_json_request()
        existing = get_user_settings_row(db, int(current_user.id))
        theme_choice = _normalize_theme(payload.get('theme_choice', existing['theme_choice']))
        default_language = _normalize_language(payload.get('default_language', existing['default_language']))
        try:
            sidebar_collapsed = 1 if int(payload.get('sidebar_collapsed', existing['sidebar_collapsed'])) else 0
        except Exception:
            sidebar_collapsed = int(existing['sidebar_collapsed'])
        upsert_user_settings_row(db, int(current_user.id), theme_choice, default_language, sidebar_collapsed)
        _audit_log(
            db,
            'User UI settings theme=' + str(theme_choice) + ' language=' + str(default_language) + ' sidebar_collapsed=' + str(sidebar_collapsed),
        )
        return jsonify(
            {
                'theme_choice': theme_choice,
                'default_language': default_language,
                'sidebar_collapsed': sidebar_collapsed,
            }
        )
    finally:
        db.close()


@flask_application.route('/api/system-settings', methods=['GET', 'POST'])
@login_required
def api_system_settings():
    db = ensure_database()
    try:
        if request.method == 'GET':
            return jsonify(
                {
                    'telegram_bot_token': get_system_setting_value(db, 'telegram_bot_token'),
                    'telegram_chat_id': get_system_setting_value(db, 'telegram_chat_id'),
                }
            )
        if str(current_user.role) != 'Admin':
            return jsonify({'error': 'forbidden'}), 403
        payload = _parse_json_request()
        set_system_setting_value(db, 'telegram_bot_token', str(payload.get('telegram_bot_token') or ''))
        set_system_setting_value(db, 'telegram_chat_id', str(payload.get('telegram_chat_id') or ''))
        _audit_log(db, 'System Telegram settings updated')
        return jsonify({'status': 'saved'})
    finally:
        db.close()


@flask_application.route('/api/alert-logs', methods=['GET'])
@login_required
def api_alert_logs():
    db = ensure_database()
    try:
        return jsonify({'logs': list_alert_logs(db, 300)})
    finally:
        db.close()


@flask_application.route('/api/profile/password', methods=['POST'])
@login_required
def api_profile_password():
    payload = _parse_json_request()
    current_plain = str(payload.get('current_password') or '')
    new_plain = str(payload.get('new_password') or '')
    if len(new_plain) < 6:
        return jsonify({'error': 'weak_password'}), 400
    db = ensure_database()
    try:
        row = get_user_by_id(db, int(current_user.id))
        if not row or not verify_password(row['password_hash'], current_plain):
            return jsonify({'error': 'invalid_current'}), 400
        update_user_password_hash(db, int(current_user.id), hash_password(new_plain))
        _audit_log(db, 'User password changed')
        return jsonify({'status': 'updated'})
    finally:
        db.close()


@flask_application.route('/api/audit/run', methods=['POST'])
@login_required
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


def _execute_host_update(db, host_id, request_payload):
    hostname = str(request_payload.get('hostname') or '').strip()
    ip_address = str(request_payload.get('ip_address') or '').strip()
    device_type = _normalize_device_type(request_payload.get('device_type'))
    vendor_template = _normalize_vendor_template(request_payload.get('vendor_template'))
    polling_interval_seconds = _normalize_polling_interval(request_payload.get('polling_interval_seconds'))
    poll_protocol = _normalize_poll_protocol(request_payload.get('poll_protocol'))
    ssh_username, ssh_password, ssh_port = _ssh_triplet_for_payload(db, host_id, device_type, request_payload)
    snmp_community = _normalize_snmp_community(request_payload.get('snmp_community'))
    snmp_port = _normalize_snmp_port(request_payload.get('snmp_port'))
    snmp_version = _normalize_snmp_version(request_payload.get('snmp_version'))
    snmpv3_user, snmpv3_auth_algo, snmpv3_priv_algo, snmpv3_auth_key, snmpv3_priv_key = _snmpv3_credentials_for_payload(
        db, host_id, request_payload
    )
    maintenance_mode = _normalize_maintenance_mode(request_payload.get('maintenance_mode'))
    if host_id <= 0 or not hostname or not ip_address:
        return False
    db.execute(
        'UPDATE hosts SET hostname = ?, ip_address = ?, device_type = ?, vendor_template = ?, polling_interval_seconds = ?, '
        'poll_protocol = ?, ssh_username = ?, ssh_password = ?, ssh_port = ?, snmp_community = ?, snmp_port = ?, '
        'snmp_version = ?, snmpv3_user = ?, snmpv3_auth_algo = ?, snmpv3_auth_key = ?, snmpv3_priv_algo = ?, snmpv3_priv_key = ?, maintenance_mode = ? '
        'WHERE id = ?',
        (
            hostname,
            ip_address,
            device_type,
            vendor_template,
            polling_interval_seconds,
            poll_protocol,
            ssh_username,
            ssh_password,
            ssh_port,
            snmp_community,
            snmp_port,
            snmp_version,
            snmpv3_user,
            snmpv3_auth_algo,
            snmpv3_auth_key,
            snmpv3_priv_algo,
            snmpv3_priv_key,
            maintenance_mode,
            host_id,
        ),
    )
    db.commit()
    return True


@flask_application.route('/api/hosts', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def api_hosts():
    request_payload = _parse_json_request()
    db = ensure_database()
    try:
        if request.method == 'GET':
            cursor = db.cursor()
            cursor.execute(
                'SELECT id, hostname, ip_address, device_type, COALESCE(vendor_template, ?) AS vendor_template, '
                'COALESCE(polling_interval_seconds, 60), COALESCE(poll_protocol, \'SNMP\'), date_added, '
                'COALESCE(ssh_username, \'\'), COALESCE(ssh_port, 22), '
                'CASE WHEN length(trim(COALESCE(ssh_password, \'\'))) > 0 THEN 1 ELSE 0 END, '
                'COALESCE(maintenance_mode, 0), COALESCE(snmp_community, \'public\'), COALESCE(snmp_port, 161), '
                'COALESCE(snmp_version, \'v2c\'), COALESCE(snmpv3_user, \'\'), COALESCE(snmpv3_auth_algo, \'SHA\'), '
                'COALESCE(snmpv3_priv_algo, \'AES\'), '
                'CASE WHEN length(trim(COALESCE(snmpv3_auth_key, \'\'))) > 0 THEN 1 ELSE 0 END, '
                'CASE WHEN length(trim(COALESCE(snmpv3_priv_key, \'\'))) > 0 THEN 1 ELSE 0 END '
                'FROM hosts ORDER BY id',
                ('generic_linux_net_snmp',),
            )
            rows = cursor.fetchall()
            hosts = [
                {
                    'id': int(r[0]),
                    'hostname': r[1],
                    'ip_address': r[2],
                    'device_type': r[3],
                    'vendor_template': r[4],
                    'polling_interval_seconds': int(r[5] or 60),
                    'poll_protocol': str(r[6] or 'SNMP'),
                    'date_added': r[7],
                    'ssh_username': str(r[8] or ''),
                    'ssh_port': int(r[9] or 22),
                    'ssh_password_set': bool(int(r[10] or 0)),
                    'maintenance_mode': int(r[11] or 0),
                    'snmp_community': str(r[12] or 'public'),
                    'snmp_port': int(r[13] or 161),
                    'snmp_version': str(r[14] or 'v2c'),
                    'snmpv3_user': str(r[15] or ''),
                    'snmpv3_auth_algo': str(r[16] or 'SHA'),
                    'snmpv3_priv_algo': str(r[17] or 'AES'),
                    'snmpv3_auth_key_set': bool(int(r[18] or 0)),
                    'snmpv3_priv_key_set': bool(int(r[19] or 0)),
                }
                for r in rows
            ]
            return jsonify({'hosts': hosts})
        if request.method == 'POST':
            hostname = str(request_payload.get('hostname') or '').strip()
            ip_address = str(request_payload.get('ip_address') or '').strip()
            device_type = _normalize_device_type(request_payload.get('device_type'))
            vendor_template = _normalize_vendor_template(request_payload.get('vendor_template'))
            polling_interval_seconds = _normalize_polling_interval(request_payload.get('polling_interval_seconds'))
            poll_protocol = _normalize_poll_protocol(request_payload.get('poll_protocol'))
            ssh_username, ssh_password, ssh_port = _ssh_triplet_for_payload(db, None, device_type, request_payload)
            snmp_community = _normalize_snmp_community(request_payload.get('snmp_community'))
            snmp_port = _normalize_snmp_port(request_payload.get('snmp_port'))
            snmp_version = _normalize_snmp_version(request_payload.get('snmp_version'))
            snmpv3_user, snmpv3_auth_algo, snmpv3_priv_algo, snmpv3_auth_key, snmpv3_priv_key = _snmpv3_credentials_for_payload(
                db, None, request_payload
            )
            maintenance_mode = _normalize_maintenance_mode(request_payload.get('maintenance_mode'))
            if not hostname or not ip_address:
                return jsonify({'error': 'invalid_input'}), 400
            cur_ins = db.cursor()
            cur_ins.execute(
                'INSERT INTO hosts (hostname, ip_address, device_type, vendor_template, polling_interval_seconds, poll_protocol, ssh_username, ssh_password, ssh_port, snmp_community, snmp_port, '
                'snmp_version, snmpv3_user, snmpv3_auth_algo, snmpv3_auth_key, snmpv3_priv_algo, snmpv3_priv_key, maintenance_mode) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    hostname,
                    ip_address,
                    device_type,
                    vendor_template,
                    polling_interval_seconds,
                    poll_protocol,
                    ssh_username,
                    ssh_password,
                    ssh_port,
                    snmp_community,
                    snmp_port,
                    snmp_version,
                    snmpv3_user,
                    snmpv3_auth_algo,
                    snmpv3_auth_key,
                    snmpv3_priv_algo,
                    snmpv3_priv_key,
                    maintenance_mode,
                ),
            )
            db.commit()
            new_host_id = int(cur_ins.lastrowid or 0)
            _audit_log(db, 'Host created id=' + str(new_host_id) + ' ip=' + ip_address)
            return jsonify({'status': 'created'})
        if request.method == 'PUT':
            host_id = int(request_payload.get('id') or 0)
            if not _execute_host_update(db, host_id, request_payload):
                return jsonify({'error': 'invalid_input'}), 400
            _audit_log(db, 'Host updated id=' + str(host_id))
            return jsonify({'status': 'updated'})
        host_id = int(request_payload.get('id') or 0)
        if host_id <= 0:
            return jsonify({'error': 'invalid_input'}), 400
        db.execute('DELETE FROM metrics_history WHERE host_id = ?', (host_id,))
        db.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
        db.commit()
        _audit_log(db, 'Host deleted id=' + str(host_id))
        return jsonify({'status': 'deleted'})
    finally:
        db.close()


@flask_application.route('/api/hosts/<int:host_id>', methods=['PUT'])
@login_required
def api_hosts_by_id(host_id):
    request_payload = _parse_json_request()
    db = ensure_database()
    try:
        if not _execute_host_update(db, int(host_id), request_payload):
            return jsonify({'error': 'invalid_input'}), 400
        _audit_log(db, 'Host updated id=' + str(int(host_id)))
        return jsonify({'status': 'updated'})
    finally:
        db.close()


@flask_application.route('/api/metrics/poll', methods=['POST'])
@login_required
def api_metrics_poll():
    request_payload = _parse_json_request()
    device_type_filter = str(request_payload.get('device_type') or '').strip()
    db = ensure_database()
    try:
        snmp_monitor = SNMPMonitor()
        metrics = snmp_monitor.poll_hosts_from_database(
            db, device_type_filter if device_type_filter in ('Server', 'Switch', 'VM', 'Website') else None
        )
        return jsonify({'metrics': metrics})
    finally:
        db.close()


@flask_application.route('/api/metrics/latest', methods=['GET'])
@login_required
def api_metrics_latest():
    db = ensure_database()
    try:
        cursor = db.cursor()
        cursor.execute(
            'SELECT h.id, h.hostname, h.ip_address, h.device_type, COALESCE(h.vendor_template, ?) AS vendor_template, '
            'COALESCE(h.maintenance_mode, 0), m.status, m.cpu_utilization, m.ram_usage, m.disk_usage, m.temperature_c, m.mock_data, m.polled_at, '
            'm.latency_ms, m.http_status_code, COALESCE(h.last_error_message, \'\') '
            'FROM hosts h LEFT JOIN metrics_history m ON m.id = ('
            'SELECT id FROM metrics_history WHERE host_id = h.id ORDER BY datetime(polled_at) DESC, id DESC LIMIT 1'
            ') ORDER BY h.id',
            ('generic_linux_net_snmp',),
        )
        rows = cursor.fetchall()
        metrics = []
        for r in rows:
            device_label = str(r[3] or '')
            vendor_label = str(r[4] or '')
            maintenance_flag = int(r[5] or 0)
            raw_status = str(r[6] or 'unknown')
            display_status = 'paused' if maintenance_flag else raw_status
            cpu_raw = r[7]
            ram_raw = r[8]
            disk_raw = r[9]
            temp_raw = r[10]
            mock_part = r[11]
            polled_part = r[12]
            latency_part = r[13]
            http_part = r[14]
            last_error_part = r[15]
            is_website = device_label == 'Website'
            temperature_output = None if device_label in ('VM', 'Website') else (None if temp_raw is None else int(temp_raw))
            metrics.append(
                {
                    'host_id': int(r[0]),
                    'hostname': r[1],
                    'ip_address': r[2],
                    'device_type': device_label,
                    'vendor_template': vendor_label,
                    'maintenance_mode': maintenance_flag,
                    'status': display_status,
                    'cpu_utilization': None if is_website else (None if cpu_raw is None else int(cpu_raw)),
                    'ram_usage': None if is_website else (None if ram_raw is None else int(ram_raw)),
                    'disk_usage': None if is_website else (None if disk_raw is None else int(disk_raw)),
                    'temperature_c': temperature_output,
                    'mock_data': bool(int(mock_part or 0)),
                    'polled_at': polled_part,
                    'latency_ms': None if latency_part is None else int(latency_part),
                    'http_status_code': None if http_part is None else int(http_part),
                    'last_error_message': str(last_error_part or ''),
                    'sla_uptime_percent': compute_poll_sla_percent(db, int(r[0])),
                }
            )
        return jsonify({'metrics': metrics})
    finally:
        db.close()


@flask_application.route('/api/ai/decisions', methods=['POST'])
@login_required
def api_ai_decisions():
    request_payload = _parse_json_request()
    language = _normalize_language(request_payload.get('language'))
    db = ensure_database()
    try:
        all_rows = generate_ai_decisions_from_metrics_history(db, language, 40)
        anomaly_alerts = [d for d in all_rows if not d.get('predictive_alert')]
        predictive_alerts = [d for d in all_rows if d.get('predictive_alert')]
        manual_suggestions = generate_predictive_manual_suggestions(db, language, 14)
        return jsonify(
            {
                'language': language,
                'anomaly_alerts': anomaly_alerts,
                'predictive_alerts': predictive_alerts,
                'manual_suggestions': manual_suggestions,
            }
        )
    finally:
        db.close()


def _sanitize_timestamp_query_fragment(raw_value):
    if not raw_value:
        return None
    token = str(raw_value).strip().replace('T', ' ')
    if len(token) == 16:
        token = token + ':00'
    return token


def _topology_graph_payload(db):
    cursor = db.cursor()
    cursor.execute(
        'SELECT id, hostname, ip_address, device_type, COALESCE(vendor_template, ?) FROM hosts ORDER BY id',
        ('generic_linux_net_snmp',),
    )
    host_rows = cursor.fetchall()
    cursor.execute('SELECT dependent_host_id, depends_on_host_id FROM service_dependencies')
    dependency_rows = cursor.fetchall()
    valid_ids = {int(h[0]) for h in host_rows}
    nodes_output = []
    for host_id_val, hostname_val, ip_val, dtype_val, vendor_val in host_rows:
        nodes_output.append(
            {
                'id': int(host_id_val),
                'label': str(hostname_val) + '\n' + str(ip_val),
                'group': str(dtype_val),
                'title': str(dtype_val) + ' · ' + str(vendor_val),
            }
        )
    edges_output = []
    edge_keys = set()

    def register_edge(from_id, to_id):
        pair_key = (int(from_id), int(to_id))
        if pair_key in edge_keys:
            return
        edge_keys.add(pair_key)
        edges_output.append({'from': int(from_id), 'to': int(to_id)})

    for dependent_id, upstream_id in dependency_rows:
        dep_int = int(dependent_id)
        up_int = int(upstream_id)
        if dep_int in valid_ids and up_int in valid_ids:
            register_edge(dep_int, up_int)

    def ip_prefix_three(ip_text):
        parts = str(ip_text).split('.')
        if len(parts) < 3:
            return None
        return parts[0] + '.' + parts[1] + '.' + parts[2]

    switch_rows = [h for h in host_rows if str(h[3]) == 'Switch']
    vm_rows = [h for h in host_rows if str(h[3]) == 'VM']
    website_rows = [h for h in host_rows if str(h[3]) == 'Website']
    for vm_entry in vm_rows:
        vm_id_int = int(vm_entry[0])
        vm_ip_text = str(vm_entry[2])
        prefix_token = ip_prefix_three(vm_ip_text)
        chosen_switch = None
        if prefix_token:
            for sw_entry in switch_rows:
                if ip_prefix_three(str(sw_entry[2])) == prefix_token:
                    chosen_switch = sw_entry
                    break
        if chosen_switch is None and switch_rows:
            chosen_switch = switch_rows[0]
        if chosen_switch:
            register_edge(vm_id_int, int(chosen_switch[0]))
    if website_rows and switch_rows:
        anchor_switch_id = int(switch_rows[0][0])
        for web_entry in website_rows:
            register_edge(int(web_entry[0]), anchor_switch_id)
    return {'nodes': nodes_output, 'edges': edges_output}


@flask_application.route('/api/discovery/run', methods=['POST'])
@login_required
@admin_required
def api_discovery_run():
    payload = _parse_json_request()
    cidr_token = str(payload.get('cidr') or '').strip()
    db = ensure_database()
    try:
        try:
            active_list = asyncio.run(sweep_subnet(cidr_token))
        except Exception as exc:
            return jsonify({'error': 'discovery_failed', 'detail': str(exc)}), 400
        _audit_log(db, 'Discovery sweep ' + cidr_token + ' count=' + str(len(active_list)))
        return jsonify({'active_ips': active_list})
    finally:
        db.close()


@flask_application.route('/api/discovery/import', methods=['POST'])
@login_required
@admin_required
def api_discovery_import():
    payload = _parse_json_request()
    entries = payload.get('hosts')
    if not isinstance(entries, list) or not entries:
        return jsonify({'error': 'invalid_input'}), 400
    db = ensure_database()
    imported_count = 0
    try:
        default_device = _normalize_device_type(payload.get('default_device_type'))
        default_vendor = _normalize_vendor_template(payload.get('default_vendor_template'))
        default_interval = _normalize_polling_interval(payload.get('default_polling_interval_seconds'))
        default_protocol = _normalize_poll_protocol(payload.get('default_poll_protocol'))
        name_prefix = str(payload.get('hostname_prefix') or 'discovered').strip() or 'discovered'
        cur_imp = db.cursor()
        for item in entries:
            if not isinstance(item, dict):
                continue
            ip_part = str(item.get('ip_address') or item.get('ip') or '').strip()
            if not ip_part:
                continue
            host_label = str(item.get('hostname') or '').strip() or (name_prefix + '-' + ip_part.replace('.', '-'))
            dtype_item = _normalize_device_type(item.get('device_type') or default_device)
            vendor_item = _normalize_vendor_template(item.get('vendor_template') or default_vendor)
            interval_item = _normalize_polling_interval(item.get('polling_interval_seconds') or default_interval)
            protocol_item = _normalize_poll_protocol(item.get('poll_protocol') or default_protocol)
            mini_ssh_payload = {
                'ssh_username': item.get('ssh_username'),
                'ssh_password': item.get('ssh_password'),
                'ssh_port': item.get('ssh_port'),
                'preserve_ssh_password': False,
            }
            ssh_user, ssh_pass, ssh_port_val = _ssh_triplet_for_payload(db, None, dtype_item, mini_ssh_payload)
            snmp_comm_item = _normalize_snmp_community(item.get('snmp_community'))
            snmp_port_item = _normalize_snmp_port(item.get('snmp_port'))
            snmp_version_item = _normalize_snmp_version(item.get('snmp_version'))
            snmpv3_user_item = str(item.get('snmpv3_user') or '').strip()
            snmpv3_auth_algo_item = _normalize_snmpv3_auth_algo(item.get('snmpv3_auth_algo'))
            snmpv3_priv_algo_item = _normalize_snmpv3_priv_algo(item.get('snmpv3_priv_algo'))
            snmpv3_auth_key_item = str(item.get('snmpv3_auth_key') or '')
            snmpv3_priv_key_item = str(item.get('snmpv3_priv_key') or '')
            cur_imp.execute(
                'INSERT OR IGNORE INTO hosts (hostname, ip_address, device_type, vendor_template, polling_interval_seconds, poll_protocol, ssh_username, ssh_password, ssh_port, snmp_community, snmp_port, '
                'snmp_version, snmpv3_user, snmpv3_auth_algo, snmpv3_auth_key, snmpv3_priv_algo, snmpv3_priv_key, maintenance_mode) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)',
                (
                    host_label,
                    ip_part,
                    dtype_item,
                    vendor_item,
                    interval_item,
                    protocol_item,
                    ssh_user,
                    ssh_pass,
                    ssh_port_val,
                    snmp_comm_item,
                    snmp_port_item,
                    snmp_version_item,
                    snmpv3_user_item,
                    snmpv3_auth_algo_item,
                    snmpv3_auth_key_item,
                    snmpv3_priv_algo_item,
                    snmpv3_priv_key_item,
                ),
            )
            if cur_imp.rowcount:
                imported_count += 1
        db.commit()
        _audit_log(db, 'Discovery bulk import count=' + str(imported_count))
        return jsonify({'imported': imported_count})
    finally:
        db.close()


@flask_application.route('/api/topology', methods=['GET'])
@login_required
def api_topology():
    db = ensure_database()
    try:
        return jsonify(_topology_graph_payload(db))
    finally:
        db.close()


@flask_application.route('/api/execute_remediation', methods=['POST'])
@login_required
@admin_required
def api_execute_remediation():
    payload = _parse_json_request()
    host_pk = int(payload.get('host_id') or 0)
    command_string = str(payload.get('command_string') or '').strip()
    if host_pk <= 0 or not command_string:
        return jsonify({'error': 'invalid_input'}), 400
    if not _ssh_command_allowed(command_string):
        return jsonify({'error': 'command_blocked'}), 400
    db = ensure_database()
    try:
        cursor = db.cursor()
        cursor.execute(
            'SELECT ip_address, COALESCE(ssh_username, \'\'), COALESCE(ssh_password, \'\'), COALESCE(ssh_port, 22) FROM hosts WHERE id = ? LIMIT 1',
            (host_pk,),
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'not_found'}), 404
        ip_val, ssh_user, ssh_pass, ssh_port_val = str(row[0]), str(row[1]), str(row[2]), int(row[3] or 22)
        if not ssh_user or not ssh_pass:
            return jsonify({'error': 'ssh_credentials_missing'}), 400
        ok_flag, output_text = _ssh_execute_on_host(ip_val, ssh_port_val, ssh_user, ssh_pass, command_string)
        _audit_log(
            db,
            'SSH remediation host_id=' + str(host_pk) + ' ok=' + str(ok_flag) + ' cmd_len=' + str(len(command_string)),
        )
        return jsonify({'ok': ok_flag, 'output': output_text})
    finally:
        db.close()


@flask_application.route('/api/audit-trail', methods=['GET'])
@login_required
def api_audit_trail():
    db = ensure_database()
    try:
        rows = list_action_audit_logs(
            db,
            400,
            viewer_username=str(current_user.username),
            viewer_role=str(current_user.role),
        )
        return jsonify({'entries': rows})
    finally:
        db.close()


@flask_application.route('/api/metrics/history', methods=['GET', 'POST'])
@login_required
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
                'SELECT polled_at, cpu_utilization, ram_usage, disk_usage, temperature_c, status, mock_data, latency_ms, http_status_code '
                'FROM metrics_history WHERE host_id = ? '
                'AND datetime(polled_at) >= datetime(?) AND datetime(polled_at) <= datetime(?) '
                'ORDER BY datetime(polled_at) ASC, id ASC',
                (host_id_value, start_token, end_token),
            )
        else:
            cursor.execute(
                'SELECT polled_at, cpu_utilization, ram_usage, disk_usage, temperature_c, status, mock_data, latency_ms, http_status_code '
                'FROM metrics_history WHERE host_id = ? '
                'ORDER BY datetime(polled_at) ASC, id ASC '
                'LIMIT 900',
                (host_id_value,),
            )
        history_rows = cursor.fetchall()
        series = []
        for polled_at_value, cpu_part, ram_part, disk_part, temp_part, status_part, mock_part, latency_part, http_part in history_rows:
            is_website = device_type_value == 'Website'
            series.append(
                {
                    'polled_at': str(polled_at_value),
                    'cpu_utilization': None if is_website else (None if cpu_part is None else int(cpu_part)),
                    'ram_usage': None if is_website else (None if ram_part is None else int(ram_part)),
                    'disk_usage': None if is_website else (None if disk_part is None else int(disk_part)),
                    'temperature_c': None if device_type_value in ('VM', 'Website') else (None if temp_part is None else int(temp_part)),
                    'status': str(status_part or 'unknown'),
                    'mock_data': bool(int(mock_part or 0)),
                    'latency_ms': None if latency_part is None else int(latency_part),
                    'http_status_code': None if http_part is None else int(http_part),
                }
            )
        return jsonify({'host_id': host_id_value, 'device_type': device_type_value, 'series': series})
    finally:
        db.close()


if __name__ == '__main__':
    flask_application.run(host='127.0.0.1', port=5000, debug=False)
