import sqlite3
from pathlib import Path


def get_connection(db_path=None):
    if db_path is None:
        db_path = Path(__file__).resolve().parent.joinpath('sysadmin_knowledge.db')
    return sqlite3.connect(str(db_path))


def _remediations_table_needs_rebuild(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='remediations'")
    if cursor.fetchone() is None:
        return False
    cursor.execute('PRAGMA table_info(remediations)')
    column_names = {row[1] for row in cursor.fetchall()}
    return 'title_en' not in column_names


def _rebuild_remediations_branch(connection):
    connection.execute('DROP TABLE IF EXISTS error_codes')
    connection.execute('DROP TABLE IF EXISTS known_vulnerabilities')
    connection.execute('DROP TABLE IF EXISTS remediations')
    connection.commit()


def initialize_schema(connection):
    if _remediations_table_needs_rebuild(connection):
        _rebuild_remediations_branch(connection)
    connection.execute(
        'CREATE TABLE IF NOT EXISTS remediations ('
        'remediation_id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'title_en TEXT NOT NULL,'
        'title_ru TEXT NOT NULL,'
        'title_hy TEXT NOT NULL,'
        'mapped_symptoms TEXT NOT NULL,'
        'steps_en TEXT NOT NULL,'
        'steps_ru TEXT NOT NULL,'
        'steps_hy TEXT NOT NULL,'
        'nlp_baseline_en TEXT NOT NULL'
        ')'
    )
    connection.execute(
        'CREATE TABLE IF NOT EXISTS manuals ('
        'manual_id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'title TEXT NOT NULL,'
        'topic TEXT,'
        'body_text TEXT NOT NULL'
        ')'
    )
    connection.execute(
        'CREATE TABLE IF NOT EXISTS error_codes ('
        'error_code TEXT PRIMARY KEY,'
        'description TEXT NOT NULL,'
        'remediation_id INTEGER NOT NULL,'
        'FOREIGN KEY (remediation_id) REFERENCES remediations(remediation_id)'
        ')'
    )
    connection.execute(
        'CREATE TABLE IF NOT EXISTS known_vulnerabilities ('
        'vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'identifier TEXT UNIQUE NOT NULL,'
        'summary TEXT NOT NULL,'
        'severity TEXT,'
        'remediation_id INTEGER NOT NULL,'
        'FOREIGN KEY (remediation_id) REFERENCES remediations(remediation_id)'
        ')'
    )
    connection.execute(
        'CREATE TABLE IF NOT EXISTS hardware_playbooks ('
        'playbook_id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'issue_key TEXT UNIQUE NOT NULL,'
        'title_en TEXT NOT NULL,'
        'title_ru TEXT NOT NULL,'
        'title_hy TEXT NOT NULL,'
        'symptoms_en TEXT NOT NULL,'
        'remediation_en TEXT NOT NULL,'
        'remediation_ru TEXT NOT NULL,'
        'remediation_hy TEXT NOT NULL,'
        'nlp_baseline_en TEXT NOT NULL'
        ')'
    )
    connection.execute(
        'CREATE TABLE IF NOT EXISTS hosts ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'hostname TEXT NOT NULL,'
        'ip_address TEXT NOT NULL UNIQUE,'
        'device_type TEXT NOT NULL,'
        'date_added TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP'
        ')'
    )
    connection.execute(
        'CREATE TABLE IF NOT EXISTS metrics_history ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'host_id INTEGER NOT NULL,'
        'status TEXT NOT NULL,'
        'cpu_utilization INTEGER,'
        'ram_usage INTEGER,'
        'disk_usage INTEGER,'
        'temperature_c INTEGER,'
        'mock_data INTEGER NOT NULL,'
        'polled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,'
        'latency_ms INTEGER,'
        'http_status_code INTEGER,'
        'FOREIGN KEY (host_id) REFERENCES hosts(id)'
        ')'
    )
    connection.execute(
        'CREATE TABLE IF NOT EXISTS vulnerability_playbooks ('
        'playbook_id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'match_signature TEXT UNIQUE NOT NULL,'
        'cve_identifier TEXT NOT NULL,'
        'advice_en TEXT NOT NULL,'
        'advice_ru TEXT NOT NULL,'
        'advice_hy TEXT NOT NULL,'
        'powershell_script TEXT NOT NULL'
        ')'
    )
    connection.execute(
        'CREATE TABLE IF NOT EXISTS service_dependencies ('
        'dependency_id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'dependent_host_id INTEGER NOT NULL,'
        'depends_on_host_id INTEGER NOT NULL,'
        'FOREIGN KEY (dependent_host_id) REFERENCES hosts(id),'
        'FOREIGN KEY (depends_on_host_id) REFERENCES hosts(id),'
        'UNIQUE(dependent_host_id, depends_on_host_id)'
        ')'
    )
    _ensure_hosts_vendor_template_column(connection)
    _ensure_hosts_poll_columns(connection)
    _ensure_system_settings_table(connection)
    _ensure_users_and_auth_tables(connection)
    _ensure_user_settings_table(connection)
    _ensure_alert_logs_table(connection)
    _ensure_action_audit_log_table(connection)
    _ensure_hosts_ssh_columns(connection)
    _ensure_hosts_snmp_community_column(connection)
    _ensure_hosts_snmp_port_column(connection)
    _ensure_hosts_snmpv3_columns(connection)
    _ensure_hosts_maintenance_mode_column(connection)
    _ensure_hosts_last_error_message_column(connection)
    _ensure_system_manuals_schema(connection)
    _ensure_hardware_playbooks_script_column(connection)
    _ensure_metrics_history_nullable_schema(connection)
    connection.commit()


def _ensure_hosts_vendor_template_column(connection):
    cursor = connection.cursor()
    cursor.execute('PRAGMA table_info(hosts)')
    column_names = {row[1] for row in cursor.fetchall()}
    if 'vendor_template' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN vendor_template TEXT NOT NULL DEFAULT 'generic_linux_net_snmp'")
        connection.commit()


def _ensure_hosts_poll_columns(connection):
    cursor = connection.cursor()
    cursor.execute('PRAGMA table_info(hosts)')
    column_names = {row[1] for row in cursor.fetchall()}
    if 'polling_interval_seconds' not in column_names:
        connection.execute('ALTER TABLE hosts ADD COLUMN polling_interval_seconds INTEGER NOT NULL DEFAULT 60')
        connection.commit()
    if 'poll_protocol' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN poll_protocol TEXT NOT NULL DEFAULT 'SNMP'")
        connection.commit()


def _ensure_system_settings_table(connection):
    connection.execute(
        'CREATE TABLE IF NOT EXISTS system_settings ('
        'setting_key TEXT PRIMARY KEY NOT NULL,'
        'setting_value TEXT NOT NULL DEFAULT \'\''
        ')'
    )
    connection.commit()


def _ensure_users_and_auth_tables(connection):
    connection.execute(
        'CREATE TABLE IF NOT EXISTS users ('
        'user_id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'username TEXT UNIQUE NOT NULL,'
        'password_hash TEXT NOT NULL,'
        'role TEXT NOT NULL DEFAULT \'User\''
        ')'
    )
    connection.commit()


def _ensure_user_settings_table(connection):
    connection.execute(
        'CREATE TABLE IF NOT EXISTS user_settings ('
        'user_id INTEGER PRIMARY KEY NOT NULL,'
        'theme_choice TEXT NOT NULL DEFAULT \'vibrant_dark\','
        'default_language TEXT NOT NULL DEFAULT \'en\','
        'sidebar_collapsed INTEGER NOT NULL DEFAULT 0,'
        'FOREIGN KEY (user_id) REFERENCES users(user_id)'
        ')'
    )
    connection.commit()


def _ensure_alert_logs_table(connection):
    connection.execute(
        'CREATE TABLE IF NOT EXISTS alert_logs ('
        'log_id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,'
        'host_id INTEGER,'
        'alert_type TEXT NOT NULL,'
        'message_text TEXT NOT NULL,'
        'delivery_status TEXT NOT NULL'
        ')'
    )
    connection.commit()


def _ensure_action_audit_log_table(connection):
    connection.execute(
        'CREATE TABLE IF NOT EXISTS action_audit_log ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,'
        'username TEXT NOT NULL,'
        'action_description TEXT NOT NULL'
        ')'
    )
    connection.commit()


def _ensure_hosts_ssh_columns(connection):
    cursor = connection.cursor()
    cursor.execute('PRAGMA table_info(hosts)')
    column_names = {row[1] for row in cursor.fetchall()}
    if 'ssh_username' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN ssh_username TEXT NOT NULL DEFAULT ''")
        connection.commit()
    if 'ssh_password' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN ssh_password TEXT NOT NULL DEFAULT ''")
        connection.commit()
    if 'ssh_port' not in column_names:
        connection.execute('ALTER TABLE hosts ADD COLUMN ssh_port INTEGER NOT NULL DEFAULT 22')
        connection.commit()


def _ensure_hosts_snmp_community_column(connection):
    cursor = connection.cursor()
    cursor.execute('PRAGMA table_info(hosts)')
    column_names = {row[1] for row in cursor.fetchall()}
    if 'snmp_community' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN snmp_community TEXT NOT NULL DEFAULT 'public'")
        connection.commit()


def _ensure_hosts_snmp_port_column(connection):
    cursor = connection.cursor()
    cursor.execute('PRAGMA table_info(hosts)')
    column_names = {row[1] for row in cursor.fetchall()}
    if 'snmp_port' not in column_names:
        connection.execute('ALTER TABLE hosts ADD COLUMN snmp_port INTEGER NOT NULL DEFAULT 161')
        connection.commit()


def _ensure_hosts_snmpv3_columns(connection):
    cursor = connection.cursor()
    cursor.execute('PRAGMA table_info(hosts)')
    column_names = {row[1] for row in cursor.fetchall()}
    if 'snmp_version' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN snmp_version TEXT NOT NULL DEFAULT 'v2c'")
        connection.commit()
    if 'snmpv3_user' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN snmpv3_user TEXT NOT NULL DEFAULT ''")
        connection.commit()
    if 'snmpv3_auth_algo' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN snmpv3_auth_algo TEXT NOT NULL DEFAULT 'SHA'")
        connection.commit()
    if 'snmpv3_auth_key' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN snmpv3_auth_key TEXT NOT NULL DEFAULT ''")
        connection.commit()
    if 'snmpv3_priv_algo' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN snmpv3_priv_algo TEXT NOT NULL DEFAULT 'AES'")
        connection.commit()
    if 'snmpv3_priv_key' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN snmpv3_priv_key TEXT NOT NULL DEFAULT ''")
        connection.commit()


def normalize_ssh_storage_triplet(device_type, ssh_username, ssh_password, ssh_port_raw):
    if str(device_type or '') in ('Switch', 'Website'):
        return '', '', 22
    username_clean = str(ssh_username or '').strip()
    password_clean = '' if ssh_password is None else str(ssh_password)
    try:
        port_int = int(ssh_port_raw)
    except Exception:
        port_int = 22
    if port_int <= 0 or port_int > 65535:
        port_int = 22
    return username_clean, password_clean, port_int


def _ensure_hosts_last_error_message_column(connection):
    cursor = connection.cursor()
    cursor.execute('PRAGMA table_info(hosts)')
    column_names = {row[1] for row in cursor.fetchall()}
    if 'last_error_message' not in column_names:
        connection.execute("ALTER TABLE hosts ADD COLUMN last_error_message TEXT NOT NULL DEFAULT ''")
        connection.commit()


def _seed_vendor_playbooks(cursor):
    cursor.execute('SELECT COUNT(*) FROM vulnerability_playbooks')
    if cursor.fetchone()[0] > 0:
        return
    rows = [
        (
            'hpe officeconnect switch snmp',
            'HPE-OFFICECONNECT-SNMP',
            "Default SNMP strings often left as 'public'. Manual requires SNMPv3 migration or strictly applying ACLs to UDP 161. Ref: HPE OfficeConnect Security Guide.",
            "Строки SNMP по умолчанию часто остаются 'public'. Руководство требует миграции на SNMPv3 или строгих ACL для UDP 161. См.: HPE OfficeConnect Security Guide.",
            "SNMP լռելյայն տողերը հաճախ մնում են 'public'. Ձեռնարկը պահանջում է SNMPv3 միգրացիա կամ UDP 161-ի ACL-ներ: Ref: HPE OfficeConnect Security Guide.",
            '$ProgressPreference = \'SilentlyContinue\'; Get-NetFirewallRule | Where-Object {$_.DisplayName -like \'*SNMP*\'}',
        ),
        (
            'mikrotik routeros winbox',
            'MIKROTIK-WINBOX-EXPOSURE',
            'Winbox port 8291 exposed. Ensure IP whitelisting in /ip services. Ref: MikroTik Hardening Guide.',
            'Порт Winbox 8291 открыт. Настройте белый список IP в /ip services. См.: MikroTik Hardening Guide.',
            'Winbox 8291 պորտը բաց է: Կարգավորեք IP whitelist /ip services-ում: Ref: MikroTik Hardening Guide.',
            '/ip service print',
        ),
        (
            'apc smart-ups nmc default',
            'APC-NMC-DEFAULT-CREDS',
            "Default NMC credentials 'apc/apc' must be changed immediately via SSH. Ref: APC Network Management Card Manual.",
            "Учетные данные NMC по умолчанию 'apc/apc' необходимо немедленно сменить через SSH. См.: APC Network Management Card Manual.",
            "NMC լռելյայն 'apc/apc' հավատարմագրերը պետք է անմիջապես փոխել SSH-ով: Ref: APC Network Management Card Manual.",
            'ssh admin@ups-host',
        ),
    ]
    insert_sql = (
        'INSERT INTO vulnerability_playbooks (match_signature, cve_identifier, advice_en, advice_ru, advice_hy, powershell_script) '
        'VALUES (?, ?, ?, ?, ?, ?)'
    )
    for row in rows:
        cursor.execute(insert_sql, row)


def _ensure_hosts_maintenance_mode_column(connection):
    cursor = connection.cursor()
    cursor.execute('PRAGMA table_info(hosts)')
    column_names = {row[1] for row in cursor.fetchall()}
    if 'maintenance_mode' not in column_names:
        connection.execute('ALTER TABLE hosts ADD COLUMN maintenance_mode INTEGER NOT NULL DEFAULT 0')
        connection.commit()


def _metrics_history_requires_nullable_rebuild(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metrics_history'")
    if cursor.fetchone() is None:
        return False
    cursor.execute('PRAGMA table_info(metrics_history)')
    for row in cursor.fetchall():
        if row[1] == 'cpu_utilization' and int(row[3] or 0) == 1:
            return True
    return False


def _ensure_metrics_history_nullable_schema(connection):
    if not _metrics_history_requires_nullable_rebuild(connection):
        cursor = connection.cursor()
        cursor.execute('PRAGMA table_info(metrics_history)')
        names = {row[1] for row in cursor.fetchall()}
        if 'latency_ms' not in names:
            connection.execute('ALTER TABLE metrics_history ADD COLUMN latency_ms INTEGER')
            connection.commit()
        if 'http_status_code' not in names:
            connection.execute('ALTER TABLE metrics_history ADD COLUMN http_status_code INTEGER')
            connection.commit()
        return
    connection.execute('ALTER TABLE metrics_history RENAME TO metrics_history_legacy')
    connection.execute(
        'CREATE TABLE metrics_history ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'host_id INTEGER NOT NULL,'
        'status TEXT NOT NULL,'
        'cpu_utilization INTEGER,'
        'ram_usage INTEGER,'
        'disk_usage INTEGER,'
        'temperature_c INTEGER,'
        'mock_data INTEGER NOT NULL,'
        'polled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,'
        'latency_ms INTEGER,'
        'http_status_code INTEGER,'
        'FOREIGN KEY (host_id) REFERENCES hosts(id)'
        ')'
    )
    cursor = connection.cursor()
    cursor.execute('PRAGMA table_info(metrics_history_legacy)')
    legacy_cols = {row[1] for row in cursor.fetchall()}
    lat_src = 'latency_ms' if 'latency_ms' in legacy_cols else 'NULL'
    http_src = 'http_status_code' if 'http_status_code' in legacy_cols else 'NULL'
    connection.execute(
        'INSERT INTO metrics_history (host_id, status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data, polled_at, latency_ms, http_status_code) '
        'SELECT host_id, status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data, polled_at, '
        + lat_src
        + ', '
        + http_src
        + ' FROM metrics_history_legacy'
    )
    connection.execute('DROP TABLE metrics_history_legacy')
    connection.commit()


def insert_action_audit_log(connection, username, action_description):
    connection.execute(
        'INSERT INTO action_audit_log (username, action_description) VALUES (?, ?)',
        (str(username or ''), str(action_description or '')[:4000]),
    )
    connection.commit()


def list_action_audit_logs(connection, limit_value=200, viewer_username=None, viewer_role=None):
    cursor = connection.cursor()
    limit_int = max(1, min(int(limit_value or 200), 500))
    if str(viewer_role or '') == 'Admin':
        cursor.execute(
            'SELECT id, timestamp, username, action_description FROM action_audit_log '
            'ORDER BY datetime(timestamp) DESC, id DESC LIMIT ?',
            (limit_int,),
        )
    else:
        cursor.execute(
            'SELECT id, timestamp, username, action_description FROM action_audit_log '
            'WHERE username = ? ORDER BY datetime(timestamp) DESC, id DESC LIMIT ?',
            (str(viewer_username or ''), limit_int),
        )
    rows = []
    for row_id, ts, uname, desc in cursor.fetchall():
        rows.append(
            {
                'id': int(row_id),
                'timestamp': str(ts),
                'username': str(uname or ''),
                'action_description': str(desc or ''),
            }
        )
    return rows


def seed_default_users(connection):
    from models import hash_password

    cursor = connection.cursor()
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] > 0:
        return
    password_hash_value = hash_password('admin')
    connection.execute(
        "INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'Admin')",
        (password_hash_value,),
    )
    connection.commit()
    cursor.execute("SELECT user_id FROM users WHERE username = 'admin' LIMIT 1")
    row = cursor.fetchone()
    if not row:
        return
    uid = int(row[0])
    connection.execute(
        'INSERT OR IGNORE INTO user_settings (user_id, theme_choice, default_language, sidebar_collapsed) VALUES (?, ?, ?, 0)',
        (uid, 'vibrant_dark', 'en'),
    )
    connection.commit()


def seed_system_settings_defaults(connection):
    for key_token, value_token in (('telegram_bot_token', ''), ('telegram_chat_id', '')):
        connection.execute(
            'INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES (?, ?)',
            (key_token, value_token),
        )
    connection.commit()


def get_user_by_username(connection, username):
    cursor = connection.cursor()
    cursor.execute(
        'SELECT user_id, username, password_hash, role FROM users WHERE username = ? LIMIT 1',
        (str(username or '').strip(),),
    )
    row = cursor.fetchone()
    if not row:
        return None
    return {'user_id': int(row[0]), 'username': str(row[1]), 'password_hash': str(row[2]), 'role': str(row[3])}


def get_user_by_id(connection, user_id):
    cursor = connection.cursor()
    cursor.execute(
        'SELECT user_id, username, password_hash, role FROM users WHERE user_id = ? LIMIT 1',
        (int(user_id),),
    )
    row = cursor.fetchone()
    if not row:
        return None
    return {'user_id': int(row[0]), 'username': str(row[1]), 'password_hash': str(row[2]), 'role': str(row[3])}


def update_user_password_hash(connection, user_id, new_hash):
    connection.execute('UPDATE users SET password_hash = ? WHERE user_id = ?', (str(new_hash), int(user_id)))
    connection.commit()


def get_user_settings_row(connection, user_id):
    cursor = connection.cursor()
    cursor.execute(
        'SELECT theme_choice, default_language, sidebar_collapsed FROM user_settings WHERE user_id = ? LIMIT 1',
        (int(user_id),),
    )
    row = cursor.fetchone()
    if not row:
        return {'theme_choice': 'vibrant_dark', 'default_language': 'en', 'sidebar_collapsed': 0}
    return {
        'theme_choice': str(row[0] or 'vibrant_dark'),
        'default_language': str(row[1] or 'en'),
        'sidebar_collapsed': int(row[2] or 0),
    }


def upsert_user_settings_row(connection, user_id, theme_choice, default_language, sidebar_collapsed):
    connection.execute(
        'INSERT INTO user_settings (user_id, theme_choice, default_language, sidebar_collapsed) VALUES (?, ?, ?, ?) '
        'ON CONFLICT(user_id) DO UPDATE SET theme_choice = excluded.theme_choice, '
        'default_language = excluded.default_language, sidebar_collapsed = excluded.sidebar_collapsed',
        (int(user_id), str(theme_choice), str(default_language), int(sidebar_collapsed)),
    )
    connection.commit()


def insert_alert_log_row(connection, host_id, alert_type, message_text, delivery_status):
    connection.execute(
        'INSERT INTO alert_logs (host_id, alert_type, message_text, delivery_status) VALUES (?, ?, ?, ?)',
        (
            int(host_id) if host_id is not None else None,
            str(alert_type or 'unknown'),
            str(message_text or ''),
            str(delivery_status or 'unknown'),
        ),
    )
    connection.commit()


def list_alert_logs(connection, limit_value=200):
    cursor = connection.cursor()
    cursor.execute(
        'SELECT log_id, timestamp, host_id, alert_type, message_text, delivery_status '
        'FROM alert_logs ORDER BY datetime(timestamp) DESC, log_id DESC LIMIT ?',
        (int(limit_value),),
    )
    rows = []
    for log_id, ts, hid, atype, msg, status in cursor.fetchall():
        rows.append(
            {
                'log_id': int(log_id),
                'timestamp': str(ts),
                'host_id': int(hid) if hid is not None else None,
                'alert_type': str(atype or ''),
                'message_text': str(msg or ''),
                'delivery_status': str(status or ''),
            }
        )
    return rows


def get_system_setting_value(connection, key_name):
    cursor = connection.cursor()
    cursor.execute('SELECT setting_value FROM system_settings WHERE setting_key = ? LIMIT 1', (str(key_name),))
    row = cursor.fetchone()
    return str(row[0]) if row else ''


def set_system_setting_value(connection, key_name, value_text):
    connection.execute(
        'INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?) '
        'ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value',
        (str(key_name), str(value_text or '')),
    )
    connection.commit()
    cursor = connection.cursor()
    defaults = [('telegram_bot_token', ''), ('telegram_chat_id', '')]
    for key_part, value_part in defaults:
        cursor.execute(
            'INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES (?, ?)',
            (key_part, value_part),
        )
    connection.commit()


def _ensure_system_manuals_schema(connection):
    connection.execute(
        'CREATE TABLE IF NOT EXISTS system_manuals ('
        'manual_id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'vendor_key TEXT UNIQUE NOT NULL,'
        'title_en TEXT NOT NULL,'
        'title_ru TEXT NOT NULL,'
        'title_hy TEXT NOT NULL,'
        'body_en TEXT NOT NULL,'
        'body_ru TEXT NOT NULL,'
        'body_hy TEXT NOT NULL,'
        'nlp_baseline_en TEXT NOT NULL'
        ')'
    )


def seed_system_manuals(connection):
    cursor = connection.cursor()
    cursor.execute('SELECT COUNT(*) FROM system_manuals')
    if cursor.fetchone()[0] > 0:
        return
    rows = [
        (
            'dell_idrac9_thermal',
            'Dell PowerEdge iDRAC 9 thermal and airflow playbook',
            'Dell PowerEdge iDRAC 9: тепловой режим и воздушный поток',
            'Dell PowerEdge iDRAC 9 ջերմային և օդային հոսք',
            'When iDRAC 9 reports rising inlet or exhaust differentials, validate bezel integrity, cable arm management, and fan redundancy groups inside OpenManage Enterprise or iDRAC GUI before swapping parts. Compare SNMP coolingDeviceReading against chassis intrusion flags and power supply load sharing. Escalate to Dell SupportAssist collections if PERC HBA queues coincide with thermal ramps.',
            'При росте перепада температур на iDRAC 9 проверьте целостность безеля, кабельный менеджмент и группы резервирования вентиляторов в OpenManage Enterprise или iDRAC. Сравните SNMP coolingDeviceReading с флагами вскрытия корпуса и балансировкой БП. Эскалируйте в SupportAssist если очереди PERC совпадают с ростом температуры.',
            'Երբ iDRAC 9-ը ցույց է տալիս մուտքային/ելքային ջերմաստիճանի տարբերության աճ, ստուգեք առաջնային բեզելը, մալուխի կառավարումը և հովացուցիչների կրկնակի խմբերը OpenManage Enterprise կամ iDRAC-ում։ Համեմատեք SNMP coolingDeviceReading-ը պատուհանի ներխուժման դրոշակների հետ։',
            'dell poweredge idrac9 thermal cooling openmanage bezel airflow perc queue snmp 674.10892.5',
        ),
        (
            'cisco_nexus_stp',
            'Cisco Nexus spanning-tree and fabric stability',
            'Cisco Nexus spanning-tree и стабильность фабрики',
            'Cisco Nexus spanning-tree և ֆաբրիկայի կայունություն',
            'For NX-OS platforms, correlate SNMP dot1dStpTopChanges with interface ifOperStatus transitions on vPC member ports. Use Ethanalyzer captures on supervisors for BPDU inconsistencies, verify VPC role consistency, and ensure MST region alignment across VDCs before changing root bridge priorities.',
            'На NX-OS сопоставьте SNMP dot1dStpTopChanges с переходами ifOperStatus на портах vPC. Используйте Ethanalyzer на супервизорах для BPDU, проверьте роли vPC и выравнивание MST между VDC перед сменой приоритетов корня.',
            'NX-OS-ում համադրեք SNMP dot1dStpTopChanges-ը vPC պորտերի ifOperStatus փոփոխությունների հետ։ Սուպերվիզորներում օգտագործեք Ethanalyzer BPDU անհամապատասխանությունների համար։',
            'cisco nexus nxos spanning tree vpc bpdu mst vdc ethanalyzer snmp dot1dStpTopChanges',
        ),
        (
            'dell_perc_battery',
            'Dell PERC RAID battery and cache destage',
            'Dell PERC батарея кэша и сброс',
            'Dell PERC cache մարտկոց և destage',
            'If virtualDiskState SNMP counters show degraded write-back while batteryLearnCycleStatus is active, expect forced write-through until learn completes. Inspect physicalDiskSmartAlert for predictive failures, flash NV cache modules on 12G/13G PERC H730/H740, and schedule controlled reboot only after verifying redundancy.',
            'Если virtualDiskState деградировал в write-through при активном batteryLearnCycleStatus, дождитесь learn. Проверьте physicalDiskSmartAlert, NV-кэш модули PERC H730/H740 и планируйте перезагрузку после проверки избыточности.',
            'Եթե virtualDiskState-ը write-back-ից անցել է write-through batteryLearnCycleStatus ակտիվ լինելու պայմաններում, սպասեք learn ավարտին։ Ստուգեք physicalDiskSmartAlert և NV cache մոդուլները PERC H730/H740-ում։',
            'dell perc raid battery learn cycle virtualDiskState physicalDiskSmartAlert h730 h740 nv cache snmp',
        ),
        (
            'fortinet_ha',
            'FortiGate FortiOS HA cluster integrity',
            'FortiGate FortiOS кластер HA',
            'FortiGate FortiOS HA կլաստեր',
            'Monitor fgHaStatsIndex via SNMP for heartbeat skew. If fgSysSesCount diverges between cluster members while fgHaSystemMode reports active-active, validate dedicated HA links, session sync kernel timers, and checksum split-brain counters before executing ha failover commands.',
            'Следите за fgHaStatsIndex на предмет дрейфа heartbeat. При расхождении fgSysSesCount при active-active проверьте выделенные HA линки и таймеры синхронизации сессий до failover.',
            'Հետևեք fgHaStatsIndex-ին heartbeat շեղման համար։ active-active fgHaSystemMode-ում fgSysSesCount տարբերության դեպքում ստուգեք HA հատուկ հղումները։',
            'fortinet fortigate fortios ha fgHaStatsIndex fgSysSesCount snmp cluster split brain',
        ),
        (
            'paloalto_dataplane',
            'Palo Alto PAN-OS dataplane saturation',
            'Palo Alto PAN-OS насыщение dataplane',
            'Palo Alto PAN-OS dataplane հագեցում',
            'Track panVsysActiveOtherIpCps alongside panSessionSslProxyUtilization. When SSL proxy and threat processing exceed dataplane core budgets, redistribute security profiles, enable offload features on DP2/DP3 cards, and validate log card backpressure via SNMP resource meters.',
            'Отслеживайте panVsysActiveOtherIpCps и panSessionSslProxyUtilization. При превышении бюджета ядер dataplane перераспределите профили, включите offload на DP2/DP3 и проверьте давление логов SNMP.',
            'Հետևեք panVsysActiveOtherIpCps և panSessionSslProxyUtilization-ին։ SSL պրոքսի overload-ի դեպքում վերաբաշխեք պրոֆիլները և ստուգեք log card backpressure-ը։',
            'palo alto panos dataplane ssl proxy panSessionSslProxyUtilization panVsysActiveOtherIpCps snmp',
        ),
        (
            'synology_raid',
            'Synology DSM RAID and volume health',
            'Synology DSM RAID и тома',
            'Synology DSM RAID և volumes',
            'Cross-check synoDiskSMARTStatus with synoRAID RAIDStatus via SNMP when synoSystemStatus reports warning. Plan disk group rebuild windows, verify BTRFS scrub schedules, and ensure expansion units maintain redundant paths before swapping drives.',
            'Сопоставьте synoDiskSMARTStatus и synoRAID RAIDStatus при предупреждении synoSystemStatus. Планируйте rebuild, проверьте BTRFS scrub и избыточность путей расширения перед заменой дисков.',
            'Համադրեք synoDiskSMARTStatus-ը synoRAID RAIDStatus-ի հետ synoSystemStatus warning-ի դեպքում։ Պլանավորեք rebuild և BTRFS scrub։',
            'synology dsm raid smart synoDiskSMARTStatus synoRAID RAIDStatus btrfs scrub expansion snmp',
        ),
    ]
    insert_sql = (
        'INSERT INTO system_manuals (vendor_key, title_en, title_ru, title_hy, body_en, body_ru, body_hy, nlp_baseline_en) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    )
    for row in rows:
        cursor.execute(insert_sql, row)
    connection.commit()


def _ensure_hardware_playbooks_script_column(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hardware_playbooks'")
    if cursor.fetchone() is None:
        return
    cursor.execute('PRAGMA table_info(hardware_playbooks)')
    column_names = {row[1] for row in cursor.fetchall()}
    if 'remediation_script' not in column_names:
        connection.execute("ALTER TABLE hardware_playbooks ADD COLUMN remediation_script TEXT NOT NULL DEFAULT ''")
        connection.commit()


def seed_sample_manual_entries(connection):
    cursor = connection.cursor()
    cursor.execute('SELECT COUNT(*) FROM remediations')
    if cursor.fetchone()[0] > 0:
        return
    remediation_payloads = [
        (
            'Stabilize identity services after authentication failure storms',
            'Стабилизация служб идентификации после всплесков сбоев аутентификации',
            'Հաստատունացրեք ինքնության ծառայությունները հավաստիացման ձախողման ալիքներից հետո',
            'authentication failure brute force ssh pam service crash lockout password policy',
            (
                'Establish a coordinated incident bridge and freeze non-essential account changes until the blast radius is understood. '
                'Correlate authentication logs across domain controllers, VPN gateways, and bastion hosts to identify source addresses, user cohorts, and shared factors such as reused passwords or legacy protocols. '
                'Tighten account lockout thresholds and enable progressive delays or CAPTCHA-style friction only after validating legitimate service accounts will not be impacted. '
                'Enforce multi-factor authentication on every externally reachable entry point, rotate any credentials that showed successful access during the anomaly window, and schedule a privileged access review. '
                'Document indicators, containment actions, and monitoring improvements so operational playbooks and aviation-grade change controls stay aligned.'
            ),
            (
                'Сформируйте единый инцидентный мост и приостановите необязательные изменения учетных записей, пока не будет понятен масштаб воздействия. '
                'Сопоставьте журналы аутентификации на контроллерах домена, шлюзах VPN и бастионных хостах, чтобы выявить исходные адреса, группы пользователей и общие факторы вроде повторно используемых паролей или устаревших протоколов. '
                'Ужесточите пороги блокировки учетных записей и внедряйте прогрессивные задержки или дополнительное трение только после проверки, что служебные учетные записи не пострадают. '
                'Включите многофакторную аутентификацию на каждой внешней точке входа, смените учетные данные, которые получили успешный доступ в окне аномалии, и запланируйте пересмотр привилегированного доступа. '
                'Зафиксируйте индикаторы, меры сдерживания и улучшения мониторинга, чтобы операционные сценарии и авиационный контроль изменений оставались согласованными.'
            ),
            (
                'Կազմակերպեք համակարգված միջադեպի կամուրջ և սառեցրեք ոչ անհրաժեշտ հաշվի փոփոխությունները, մինչև հասկանալի լինի ազդեցության շրջանակը։ '
                'Համադրեք վավերացման մատյանները դոմենի կառավարիչների, VPN դարպասների և բաստիոն հոսթերի վրա՝ աղբյուրի հասցեները, օգտվողների խմբերը և ընդհանուր գործոնները հայտնաբերելու համար, ինչպիսիք են կրկնակի օգտագործվող գաղտնաբառերը կամ հնացած արձանագրությունները։ '
                'Խստացրեք հաշվի կողպման շեմերը և աստիճանական ուշացումներ կամ լրացուցիչ խոչընդոտներ մտցրեք միայն այն բանից հետո, երբ հաստատեք, որ ծառայողական հաշիվները չեն տուժի։ '
                'Միացրեք բազմ գործոնային վավերացումը յուրաքանչյուրը արտաքինից հասանելի մուտքի կետում, պտտեցրեք հավատարմագրերը, որոնք անոմալիայի պատուհանում հաջող մուտք են ունեցել, և պլանավորեք արտոնյալ մուտքի վերանայում։ '
                'Փաստագրեք ցուցանիշները, զսպման գործողությունները և մոնիտորինգի բարելավումները, որպեսզի գործառնական սցենարները և ավիացիոն փոփոխությունների վերահսկողությունը համաձայնեցված մնան։'
            ),
            (
                'authentication failure brute force ssh pam pluggable authentication module account lockout password policy '
                'multi-factor mfa perimeter firewall credential rotation privileged access review vpn gateway domain controller '
                'bastion host repeated login failures service crash identity anomaly burst containment monitoring'
            ),
        ),
        (
            'Reduce unauthorized network listener and unexpected service exposure',
            'Снижение несанкционированных сетевых прослушивателей и неожиданной экспозиции сервисов',
            'Նվազեցրեք չարտոնված ցանցային լսողների և անսպասելի ծառայությունների բացահայտվածությունը',
            'open port listener unexpected service exposure bind socket unauthorized',
            (
                'Inventory every listening socket with process identity, binary path, and startup mechanism before changing firewall rules. '
                'For each unexpected listener, determine whether it is an approved agent, a shadow IT tool, or potential malware persistence, and capture packet captures if lateral movement is suspected. '
                'Restrict inbound access using host-based firewalls and network segmentation so only approved administrative planes can reach sensitive ports. '
                'Remove or reconfigure services that lack a documented owner, rotate secrets bound to those services, and add configuration drift detection to alert when new listeners appear. '
                'Close the change record with updated architecture diagrams and UAV or aviation ground-segment interface classifications where applicable.'
            ),
            (
                'Перед изменением правил межсетевого экрана инвентаризируйте каждый прослушивающий сокет с идентификатором процесса, путем к бинарному файлу и механизмом автозапуска. '
                'Для каждого неожиданного прослушивателя определите, является ли он утвержденным агентом, несанкционированным инструментом или потенциальной закрепленной малварью, и при подозрении на горизонтальное перемещение выполните захват трафика. '
                'Ограничьте входящий доступ с помощью межсетевых экранов на хостах и сегментации сети так, чтобы только утвержденные административные плоскости достигали чувствительных портов. '
                'Удалите или перенастройте сервисы без задокументированного владельца, смените секреты, связанные с этими сервисами, и добавьте обнаружение дрейфа конфигурации для оповещения о появлении новых прослушивателей. '
                'Завершите запись об изменении обновленными диаграммами архитектуры и классификацией интерфейсов наземного сегмента БПЛА или авиации при необходимости.'
            ),
            (
                'Նախքան firewall կանոնների փոփոխությունը գույքագրեք յուրաքանչյուր լսող սոկետը՝ գործընթացի նույնականությամբ, բինարային ուղով և մեկնարկի մեխանիզմով։ '
                'Անսպասելի լսողի համար որոշեք՝ դա հաստատված գործակալ է, ստվերային IT գործիք, թե հնարավոր վնասակար ծրագրի կայունություն, և կասկածելի լայնակի տեղաշարժի դեպքում կատարեք փաթեթների բռնում։ '
                'Սահմանափակեք ներհոսքի մուտքը հոսթի firewall-ներով և ցանցի սեգմենտացիայով, որպեսզի միայն հաստատված վարչական հարթությունները հասնեն զգայուն պորտերին։ '
                'Հեռացրեք կամ վերակոնֆիգուրացրեք ծառայությունները, որոնք չունեն փաստագրված սեփականատեր, պտտեցրեք այդ ծառայություններին կապված գաղտնիքները և ավելացրեք կոնֆիգուրացիայի շեղման հայտնաբերում՝ նոր լսողների համար։ '
                'Փակեք փոփոխության գրառումը՝ թարմացված ճարտարապետության գծագրերով և, որտեղ կիրառելի է, ԱԹՍ կամ ավիացիայի գրունտ սեգմենտի միջերեսների դասակարգմամբ։'
            ),
            (
                'open port listener unexpected service exposure bind socket tcp udp process name service guess '
                'host firewall segmentation bastion administrative plane lateral movement packet capture '
                'configuration drift persistence malware shadow it inventory ground segment uav interface'
            ),
        ),
        (
            'Remediate outdated interpreter packages and supply-chain risk in application stacks',
            'Устранение устаревших пакетов интерпретатора и рисков цепочки поставок в прикладных стеках',
            'Վերացրեք հնացած ինտերպրետատորի փաթեթները և հավելվածների ստեկերում մատակարարման շղթայի ռիսկը',
            'outdated pip package vulnerable dependency supply chain cve python',
            (
                'Stand up a repeatable vulnerability management cadence that pairs software bill of materials review with patch testing in staging environments that mirror production networking constraints. '
                'Prioritize upgrades for packages with active exploitation intelligence, transitive dependencies that widen blast radius, and anything exposed to untrusted input paths. '
                'Pin versions only after automated tests and manual smoke checks pass, then propagate changes through your change advisory board workflow. '
                'Remove dormant dependencies, enable integrity verification on package indexes used offline, and schedule quarterly rescans to catch newly disclosed issues. '
                'Record risk acceptance decisions with expiry dates so aviation or UAV mission software baselines remain defensible under audit.'
            ),
            (
                'Внедрите повторяемый ритм управления уязвимостями, сочетающий обзор программного состава с тестированием патчей на стендах, повторяющих сетевые ограничения продуктива. '
                'Приоритизируйте обновления для пакетов с признаками активной эксплуатации, транзитивных зависимостей, расширяющих зону поражения, и всего, что соприкасается с недоверенными входными путями. '
                'Фиксируйте версии только после успешных автоматических тестов и ручных дымовых проверок, затем проводите изменения через процесс совета по изменениям. '
                'Удалите неиспользуемые зависимости, включите проверку целостности для офлайн-индексов пакетов и планируйте ежеквартальные пересканирования для новых уязвимостей. '
                'Фиксируйте решения о принятии риска со сроками действия, чтобы базовые линии ПО для авиации или БПЛА оставались обоснованными при аудите.'
            ),
            (
                'Կառուցեք կրկնվող խոցելիության կառավարման ռիթմ, որը միավորում է ծրագրային կազմի փաստաթղթերի վերանայումը patch-երի փորձարկման հետ՝ փորձարարական միջավայրերում, որոնք կրկնում են արտադրական ցանցի սահմանափակումները։ '
                'Առաջնահերթություն տվեք թարմացումներին այն փաթեթների համար, որոնք ունեն ակտիվ շահագործման հետախուզություն, տրանզիտիվ կախվածություններ, որոնք ընդլայնում են ազդեցության շրջանակը, և ամեն ինչ, ինչը շփվում է անվստահելի մուտքի ուղիների հետ։ '
                'Փակեք տարբերակները միայն ավտոմատ թեստերից և ձեռքով ստուգումներից հետո, ապա փոփոխությունները տարածեք փոփոխությունների խորհրդատվական գործընթացով։ '
                'Հեռացրեք չօգտագործվող կախվածությունները, միացրեք ամբողջականության ստուգումը օֆլայն փաթեթների ինդեքսների համար և եռամսյակային վերասկանավորում պլանավորեք նոր բացահայտված խնդիրների համար։ '
                'Ռիսկի ընդունման որոշումները գրանցեք ժամկետներով, որպեսզի ավիացիայի կամ ԱԹՍ առաքելության ծրագրային բազային գծերը աուդիտի ժամանակ պաշտպանելի լինեն։'
            ),
            (
                'outdated pip package vulnerable dependency supply chain cve python requirements pin '
                'staging production parity software bill of materials sbom transitive dependency blast radius '
                'untrusted input integrity verification offline index quarterly rescan mission software baseline'
            ),
        ),
        (
            'Correct excessive file permissions on sensitive configuration and credential stores',
            'Исправление избыточных прав доступа к файлам на чувствительных конфигурациях и хранилищах учетных данных',
            'Ուղղեք զգայուն կոնֆիգուրացիայի և հավատարմագրերի պահոցների վրա ավելցուկային ֆայլային թույլտվությունները',
            'world writable permission sensitive file misconfiguration acl',
            (
                'Treat world-writable findings on configuration trees as potential evidence of compromise or negligent automation. '
                'Immediately snapshot current ACLs and compare them against hardened baselines maintained by your configuration management platform. '
                'Revoke global write bits, enforce group separation for service accounts, and validate that backup jobs and orchestration agents still function under least privilege. '
                'Investigate who modified permissions using centralized logging or filesystem auditing, and rotate secrets that might have been exposed while permissions were lax. '
                'Add automated compliance checks in CI/CD and on-host agents so regressions trigger tickets before UAV or safety-critical workloads restart.'
            ),
            (
                'Рассматривайте находки с правами записи для всех на деревьях конфигурации как потенциальные признаки компрометации или небрежной автоматизации. '
                'Немедленно снимите снимок текущих ACL и сравните их с ужесточенными базовыми линиями из платформы управления конфигурацией. '
                'Отзовите глобальные биты записи, обеспечьте разделение групп для сервисных учетных записей и убедитесь, что задания резервного копирования и агенты оркестрации работают при минимальных привилегиях. '
                'Выясните, кто менял права, используя централизованное журналирование или аудит файловой системы, и смените секреты, которые могли быть раскрыты при слабых правах. '
                'Добавьте автоматические проверки соответствия в CI/CD и на хостовых агентах, чтобы регрессии создавали заявки до перезапуска нагрузок БПЛА или критичных для безопасности систем.'
            ),
            (
                'Կոնֆիգուրացիայի ծառերի վրա համաշխարհային գրելիության արդյունքները դիտարկեք որպես հնարավոր կոմպրոմետացիայի կամ անուշադրության ավտոմատացման ապացույց։ '
                'Անմիջապես նկարահանեք ընթացիկ ACL-ները և համեմատեք դրանք ձեր կոնֆիգուրացիայի կառավարման հարթակում պահվող խստացված բազային գծերի հետ։ '
                'Հանեք համաշխարհային գրելիության բիթերը, կիրառեք խմբային բաժանում ծառայողական հաշիվների համար և հաստատեք, որ կրկնօրինակման աշխատանքները և օրկեստրացիայի գործակալները գործում են նվազագույն արտոնություններով։ '
                'Հետաքննեք, թե ով է փոխել թույլտվությունները՝ կենտրոնացված մատյանավորման կամ ֆայլային համակարգի աուդիտի միջոցով, և պտտեցրեք գաղտնիքները, որոնք կարող էին բացահայտվել թույլ թույլտվությունների ժամանակ։ '
                'Ավելացրեք ավտոմատ համապատասխանության ստուգումներ CI/CD-ում և հոսթի գործակալներում, որպեսզի հետխաչերը թիկետներ ստեղծեն մինչ ԱԹՍ կամ անվտանգության կրիտիկական բեռների վերամեկնարկը։'
            ),
            (
                'world writable permission sensitive configuration credential store acl misconfiguration '
                'least privilege service account backup orchestration centralized logging filesystem audit secret rotation '
                'compliance check ci cd regression safety critical workload'
            ),
        ),
        (
            'Execute structured response to suspicious hash matches and integrity violations',
            'Выполните структурированный ответ на подозрительные совпадения хешей и нарушения целостности',
            'Կատարեք կառուցվածքային արձագանք կասկածելի հեշերի համընկնումներին և ամբողջականության խախտումներին',
            'hash mismatch suspicious binary unauthorized modification yara malware',
            (
                'Isolate affected hosts from production VLANs while preserving volatile memory if your policy permits forensic imaging. '
                'Validate hashes against vendor-published checksums and internal golden images, and escalate to full reimage when discrepancies cannot be explained by approved patching. '
                'Hunt for lateral movement indicators such as new scheduled tasks, WMI subscriptions, or abnormal service creations tied to the same timeframe. '
                'Preserve chain-of-custody notes for regulators or airworthiness authorities if the system participates in flight operations support. '
                'After recovery, reinforce application control policies and deploy continuous integrity monitoring on critical paths.'
            ),
            (
                'Изолируйте затронутые хосты от продуктивных VLAN, сохраняя энергозависимую память, если политика допускает форензическое образование. '
                'Сверяйте хеши с опубликованными контрольными суммами вендоров и внутренними эталонными образами, и переходите к полной переустановке, когда расхождения нельзя объяснить утвержденными патчами. '
                'Ищите признаки горизонтального перемещения: новые запланированные задания, подписки WMI или подозрительное создание служб в тот же период. '
                'Сохраняйте заметки о цепочке хранения для регуляторов или органов летной годности, если система участвует в поддержке полетных операций. '
                'После восстановления усильте политики контроля приложений и внедрите непрерывный мониторинг целостности на критических путях.'
            ),
            (
                'Առանձնացրեք տուժած հոսթերը արտադրական VLAN-ներից՝ պահելով անկայուն հիշողությունը, եթե քաղաքականությունը թույլ է տալիս դատաբժշկական պատկերացում։ '
                'Հաստատեք հեշերը վաճառողի հրապարակված checksum-ների և ներքին ոսկե պատկերների դեմ, և անցեք լրիվ վերատեղադրման, երբ տարաձայնությունները չեն բացատրվում հաստատված patch-երով։ '
                'Որոնեք լայնակի տեղաշարժի ցուցանիշներ՝ նոր պլանավորված առաջադրանքներ, WMI բաժանորդագրություններ կամ անսովոր ծառայությունների ստեղծումներ նույն ժամանակահատվածում։ '
                'Պահպանեք պահպանման շղթայի նշումները կարգավորողների կամ թռիչքի պատրաստության մարմինների համար, եթե համակարգը մասնակցում է թռիչքային գործողությունների աջակցությանը։ '
                'Վերականգնումից հետո ուժեղացրեք հավելվածների վերահսկողության քաղաքականությունները և տեղադրեք անընդհատ ամբողջականության մոնիտորինգ կրիտիկական ուղիներում։'
            ),
            (
                'hash mismatch suspicious binary unauthorized modification yara malware quarantine forensic '
                'golden image vendor checksum lateral movement scheduled task wmi subscription service creation '
                'chain of custody airworthiness flight operations application control continuous integrity monitoring'
            ),
        ),
        (
            'Restore reliability after critical service crashes and unexpected terminations',
            'Восстановите надежность после критических сбоев служб и неожиданных завершений',
            'Վերականգնեք հուսալիությունը կրիտիկական ծառայության վթարներից և անսպասելի ավարտներից հետո',
            'service stopped unexpectedly event id crash termination timeout',
            (
                'Assemble a timeline that stitches together operating system logs, hypervisor events, and hardware telemetry covering five minutes before and after the fault. '
                'Validate dependencies such as storage latency, DNS resolution, and certificate expiration that commonly cascade into service termination. '
                'Apply vendor-recommended hotfixes, increase watchdog sensitivity with sane restart policies, and load-test the service under simulated peak traffic. '
                'Document the root cause, residual risks, and monitoring gaps in your knowledge base so on-call engineers can recognize recurrence quickly. '
                'For aviation datalink or UAV ground services, align recovery testing with maintenance windows governed by your continuing airworthiness program.'
            ),
            (
                'Соберите временную шкалу, объединяющую журналы ОС, события гипервизора и аппаратную телеметрию за пять минут до и после сбоя. '
                'Проверьте зависимости вроде задержек хранилища, разрешения DNS и истечения сертификатов, которые часто каскадно приводят к завершению службы. '
                'Примените рекомендованные вендором исправления, повысьте чувствительность сторожевых таймеров с разумной политикой перезапуска и нагрузочно протестируйте службу при пиковом трафике. '
                'Задокументируйте первопричину, остаточные риски и пробелы мониторинга в базе знаний, чтобы дежурные инженеры быстро распознали повтор. '
                'Для авиационных каналов данных или наземных сервисов БПЛА согласуйте тесты восстановления с техническими окнами в рамках программы поддержания летной годности.'
            ),
            (
                'Ժամանակագրություն կազմեք, որը միավորում է օՀ մատյանները, հիպերվիզորի իրադարձությունները և ապարատային հեռաչափությունը վթարից հինգ րոպե առաջ և հետո։ '
                'Ստուգեք կախվածությունները, ինչպիսիք են պահեստի ուշացումը, DNS-ի լուծումը և վկայագրի ժամկետի ավարտը, որոնք հաճախ շղթայակապ են հանգեցնում ծառայության ավարտին։ '
                'Կիրառեք վաճառողի խորհուրդ տված շտկումները, բարձրացրեք պահակային տայմերների զգայունությունը՝ ուղղակի վերամեկնարկի քաղաքականությամբ, և բեռնվածության թեստավորեք ծառայությունը գագաթնային տրաֆիկի սիմուլյացիայով։ '
                'Փաստագրեք արմատային պատճառը, մնացորդային ռիսկերը և մոնիտորինգի բացերը ձեր գիտելիքների բազայում, որպեսզի հերթապահ ինժեներները արագ ճանաչեն կրկնությունը։ '
                'Ավիացիայի տվյալների կապի կամ ԱԹՍ գրունտ ծառայությունների համար համաձայնեցրեք վերականգնման թեստերը տեխնիկական պատուհանների հետ՝ ձեր շարունակական թռիչքի պատրաստության ծրագրի շրջանակներում։'
            ),
            (
                'service stopped unexpectedly event id crash termination timeout service control manager '
                'application fault access violation memory fault storage latency dns certificate expiration '
                'watchdog restart load test root cause monitoring gap datalink uav ground service airworthiness maintenance window'
            ),
        ),
    ]
    insert_sql = (
        'INSERT INTO remediations ('
        'title_en, title_ru, title_hy, mapped_symptoms, steps_en, steps_ru, steps_hy, nlp_baseline_en'
        ') VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    )
    for payload_tuple in remediation_payloads:
        title_en, title_ru, title_hy, symptoms, se, sr, sh, nlp_en = payload_tuple
        cursor.execute(
            insert_sql,
            (title_en, title_ru, title_hy, symptoms, se, sr, sh, nlp_en),
        )
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title_en LIKE ?',
        ('%identity services%',),
    )
    auth_row = cursor.fetchone()
    auth_remediation_id = auth_row[0] if auth_row else 1
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title_en LIKE ?',
        ('%network listener%',),
    )
    port_row = cursor.fetchone()
    port_remediation_id = port_row[0] if port_row else 2
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title_en LIKE ?',
        ('%interpreter packages%',),
    )
    pkg_row = cursor.fetchone()
    pkg_remediation_id = pkg_row[0] if pkg_row else 3
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title_en LIKE ?',
        ('%file permissions%',),
    )
    perm_row = cursor.fetchone()
    perm_remediation_id = perm_row[0] if perm_row else 4
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title_en LIKE ?',
        ('%hash matches%',),
    )
    hash_row = cursor.fetchone()
    hash_remediation_id = hash_row[0] if hash_row else 5
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title_en LIKE ?',
        ('%service crashes%',),
    )
    crash_row = cursor.fetchone()
    crash_remediation_id = crash_row[0] if crash_row else 6
    manual_rows = [
        (
            'Hardening network listeners after discovery review',
            'network_services',
            (
                'Document every listening socket and justify business need. '
                'Prefer loopback binding for administrative tools. '
                'Segment sensitive workloads using VLANs or host firewalls.'
            ),
        ),
        (
            'Operational response to authentication anomaly bursts',
            'identity_security',
            (
                'Correlate authentication logs across sources. '
                'Temporarily throttle repeated failures at the edge. '
                'Notify security operations for coordinated containment.'
            ),
        ),
    ]
    for title, topic, body in manual_rows:
        cursor.execute(
            'INSERT INTO manuals (title, topic, body_text) VALUES (?, ?, ?)',
            (title, topic, body),
        )
    error_rows = [
        ('0xC0000005', 'Access violation style fault in protected service memory space', crash_remediation_id),
        ('7011', 'Service control manager timeout waiting for service response', crash_remediation_id),
        ('1000', 'Application fault reported in Windows Application log', crash_remediation_id),
        ('SSH_AUTH_FAIL_BURST', 'Repeated SSH authentication failures indicating brute force activity', auth_remediation_id),
        ('PAM_AUTH_ERROR', 'Pluggable authentication module reported authentication errors', auth_remediation_id),
    ]
    for code, description, remediation_id in error_rows:
        cursor.execute(
            'INSERT OR REPLACE INTO error_codes (error_code, description, remediation_id) VALUES (?, ?, ?)',
            (code, description, remediation_id),
        )
    vulnerability_rows = [
        (
            'EXPOSED-LISTENER-UNAPPROVED',
            'Unexpected listening socket detected without change approval',
            'high',
            port_remediation_id,
        ),
        (
            'OUTDATED-PYTHON-PACKAGE',
            'Package manager reports outdated dependency with potential CVE exposure',
            'medium',
            pkg_remediation_id,
        ),
        (
            'WORLD-WRITABLE-SENSITIVE',
            'Sensitive configuration path is writable by non-owner principals',
            'high',
            perm_remediation_id,
        ),
        (
            'SUSPICIOUS-HASH-MATCH',
            'File hash matches known suspicious fingerprint',
            'critical',
            hash_remediation_id,
        ),
    ]
    for identifier, summary, severity, remediation_id in vulnerability_rows:
        cursor.execute(
            'INSERT INTO known_vulnerabilities (identifier, summary, severity, remediation_id) VALUES (?, ?, ?, ?)',
            (identifier, summary, severity, remediation_id),
        )
    hardware_rows = [
        (
            'HIGH_TEMP',
            'Critical Device Temperature',
            'Критическая температура устройства',
            'Կրիտիկական ջերմաստիճան սարքի վրա',
            'temperature above threshold, fan degradation, airflow blockage, thermal stress',
            'Temperature is critical. Verify rack airflow, clean dust filters, inspect fans, and replace thermal paste where needed.',
            'Температура критическая. Проверьте воздушный поток в стойке, очистите фильтры, проверьте вентиляторы и при необходимости замените термопасту.',
            'Ջերմաստիճանը կրիտիկական է։ Ստուգեք դարակների օդահոսքը, մաքրեք փոշու ֆիլտրերը, ստուգեք հովացուցիչները և անհրաժեշտության դեպքում փոխարինեք թերմոպաստան։',
            'high temperature thermal stress fan failure airflow dust thermal paste replacement cooling remediation',
            'echo \"Verify fans and airflow; schedule hardware maintenance\"',
        ),
        (
            'DISK_FULL',
            'Disk Capacity Exhaustion',
            'Переполнение дискового пространства',
            'Սկավառակի տարողության սպառում',
            'disk usage above 95 percent, capacity exhaustion, write failure risk',
            'Disk usage is critical. Clear obsolete logs, expand storage, and rebalance data across nodes.',
            'Использование диска критическое. Очистите устаревшие логи, расширьте хранилище и перераспределите данные по узлам.',
            'Սկավառակի օգտագործումը կրիտիկական է։ Մաքրեք հնացած լոգերը, ընդլայնեք պահեստը և վերաբաշխեք տվյալները հանգույցների միջև։',
            'disk full capacity critical storage expansion data rebalance cleanup logs',
            'rm -rf /tmp/*',
        ),
        (
            'HIGH_CPU',
            'Sustained High CPU Utilization',
            'Устойчиво высокая загрузка CPU',
            'Կայուն բարձր CPU բեռ',
            'cpu above 85 percent, compute saturation, workload pressure',
            'CPU utilization is elevated. Scale workloads horizontally, tune background jobs, and optimize hot queries.',
            'Загрузка CPU повышена. Масштабируйте нагрузки горизонтально, оптимизируйте фоновые задачи и горячие запросы.',
            'CPU բեռը բարձր է։ Մասշտաբավորեք բեռները հորիզոնական, օպտիմիզացրեք ֆոնային առաջադրանքները և ծանր հարցումները։',
            'high cpu utilization compute saturation workload scale out performance tuning query optimization',
            'Restart-Service -Name W3SVC',
        ),
        (
            'OFFLINE',
            'Device Offline',
            'Устройство недоступно',
            'Սարքը անհասանելի է',
            'device offline, unreachable host, network path failure, power outage',
            'Device is offline. Verify power state, switch uplink, and management network reachability.',
            'Устройство недоступно. Проверьте питание, аплинк коммутатора и доступность управляющей сети.',
            'Սարքը անհասանելի է։ Ստուգեք սնուցումը, սվիչի uplink-ը և կառավարման ցանցի հասանելիությունը։',
            'offline device unreachable host network outage power remediation recovery',
            'ping -c 2 127.0.0.1',
        ),
    ]
    for row in hardware_rows:
        cursor.execute(
            'INSERT OR IGNORE INTO hardware_playbooks (issue_key, title_en, title_ru, title_hy, symptoms_en, remediation_en, remediation_ru, remediation_hy, nlp_baseline_en, remediation_script) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            row,
        )
    connection.commit()


def seed_monitoring_topology_and_vulnerability_playbooks(connection):
    cursor = connection.cursor()
    cursor.execute('SELECT COUNT(*) FROM vulnerability_playbooks')
    if cursor.fetchone()[0] == 0:
        connection.execute(
            'INSERT INTO vulnerability_playbooks (match_signature, cve_identifier, advice_en, advice_ru, advice_hy, powershell_script) VALUES (?,?,?,?,?,?)',
            (
                'nginx/',
                'CVE-PREFIX-WARN',
                'The discovered HTTP daemon banner reports an Nginx branch that warrants patch alignment with your hardened baseline.',
                'HTTP-баннер указывает на ветку Nginx; сверьтесь с укрепленной базовой линией и планом патчей.',
                'HTTP տողը ցույց տալիս է Nginx ճյուղ, որը պիտի համեմատել ձեր կոշտացված վիճակի հետ։',
                '$ProgressPreference = \'SilentlyContinue\'; nginx -v 2>&1',
            ),
        )
        connection.execute(
            'INSERT INTO vulnerability_playbooks (match_signature, cve_identifier, advice_en, advice_ru, advice_hy, powershell_script) VALUES (?,?,?,?,?,?)',
            (
                'nginx/1.2.3',
                'CVE-202X-YYYY',
                'Nginx 1.2.3 is vulnerable to CVE-202X-YYYY. Upgrade the package through your approved change window as soon as you complete a staging validation. Prefer vendor maintained packages rather than rebuilding from source.',
                'Nginx 1.2.3 уязвим к CVE-202X-YYYY. Обновите пакет в утвержденном окне изменений после проверки на стенде. Предпочитайте пакеты поставщика вместо сборки из исходников.',
                'Nginx 1.2.3-ը խոցելի է CVE-202X-YYYY-ի նկատմամբ։ Թարմացրեք փաթեթը փոխման հաստատված պատուհանում՝ փորձարարական համակարգում ստուգումից հետո։ Նախընտրեք մատակառուցչի պահվող փաթեթները, և խուսափեք աղբյուրից կառուցումից, երբ հասանելի է պաշտոնական փաթեթ։',
                '$ProgressPreference = \'SilentlyContinue\'; Invoke-WebRequest -Uri https://nginx.org/download/ -UseBasicParsing | Select-Object -ExpandProperty Links | Where-Object {$_.href -like \'nginx-*.tar.gz\'} | Select-Object -First 5 href',
            ),
        )
        connection.execute(
            'INSERT INTO vulnerability_playbooks (match_signature, cve_identifier, advice_en, advice_ru, advice_hy, powershell_script) VALUES (?,?,?,?,?,?)',
            (
                'openssh 7.6',
                'CVE-FAKE-REMOTE-LOGIN',
                'OpenSSH 7.6 is far behind current hardened baselines and may lack modern key exchange safeguards. Rotate host keys during upgrade, tighten allowed algorithms via configuration policy, and ensure jump hosts terminate sessions correctly.',
                'OpenSSH 7.6 заметно отстает от современных укрепленных базовых уровней. Во время обновления смените ключи узла, ограничьте допустимые алгоритмы политикой конфигурации и убедитесь что бастионные хосты корректно завершают сессии.',
                'OpenSSH 7.6-ը զգալիորեն հետամնացած է ժամանակակից կոշտացված բազային պահանջների համեմատ։ Բանալիները պտտեցրեք թարմացման ընթացքում, սահմանափակեք թույլատրելի ալգորիթմները կոնֆիգուրացիայի քաղաքականությամբ և համոզվեք, որ անցումային հոսթերը ճշգրիտ ավարտում են աշխատաշրջանները։',
                '$ProgressPreference = \'SilentlyContinue\'; ssh -V 2>&1; Get-Service sshd | Select-Object Status,Name',
            ),
        )
    cursor.execute(
        '''SELECT COUNT(*) FROM service_dependencies'''
    )
    if cursor.fetchone()[0] == 0:
        cursor.execute("SELECT id, hostname FROM hosts WHERE hostname IN ('Web01','DB01')")
        id_by_name = {str(r[1]): int(r[0]) for r in cursor.fetchall()}
        wid = id_by_name.get('Web01')
        did = id_by_name.get('DB01')
        if wid and did:
            connection.execute(
                'INSERT OR IGNORE INTO service_dependencies (dependent_host_id, depends_on_host_id) VALUES (?, ?)',
                (wid, did),
            )
    connection.commit()


def ensure_database(db_path=None):
    connection = get_connection(db_path)
    initialize_schema(connection)
    seed_default_users(connection)
    seed_system_settings_defaults(connection)
    seed_sample_manual_entries(connection)
    seed_system_manuals(connection)
    cursor = connection.cursor()
    _seed_vendor_playbooks(cursor)
    connection.commit()
    seed_monitoring_topology_and_vulnerability_playbooks(connection)
    return connection
