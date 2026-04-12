import sqlite3
from pathlib import Path


def get_connection(db_path=None):
    if db_path is None:
        db_path = Path(__file__).resolve().parent.joinpath('sysadmin_knowledge.db')
    return sqlite3.connect(str(db_path))


def initialize_schema(connection):
    connection.execute(
        'CREATE TABLE IF NOT EXISTS remediations ('
        'remediation_id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'title TEXT NOT NULL,'
        'mapped_symptoms TEXT NOT NULL,'
        'resolution_steps TEXT NOT NULL'
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
    connection.commit()


def seed_sample_manual_entries(connection):
    cursor = connection.cursor()
    cursor.execute('SELECT COUNT(*) FROM remediations')
    if cursor.fetchone()[0] > 0:
        return
    remediation_payloads = [
        (
            'Stabilize crashing authentication service after repeated failures',
            'authentication failure brute force ssh pam service crash',
            (
                'Verify account lockout thresholds and password policy alignment. '
                'Review PAM or Windows Account Lockout Policy. '
                'Enable multi-factor authentication for exposed services. '
                'Block offending source addresses at the perimeter firewall. '
                'Rotate compromised credentials and audit privileged accounts.'
            ),
        ),
        (
            'Mitigate listener exposure on unexpected network ports',
            'open port listener unexpected service exposure bind',
            (
                'Identify the owning process for each unexpected listener. '
                'Stop or reconfigure unnecessary services. '
                'Restrict inbound rules to required subnets only. '
                'Apply host-based firewall policies matching least privilege. '
                'Document approved services and monitor for drift.'
            ),
        ),
        (
            'Address outdated interpreter packages with known exploit history',
            'outdated pip package vulnerable dependency supply chain',
            (
                'Create a maintenance window for package upgrades. '
                'Use isolated test environments before production rollout. '
                'Pin versions in requirements files after verification. '
                'Run vulnerability scanners against installed packages regularly. '
                'Remove unused dependencies to shrink attack surface.'
            ),
        ),
        (
            'Remediate world-writable sensitive configuration exposure',
            'world writable permission sensitive file misconfiguration',
            (
                'Revoke world write access from sensitive paths. '
                'Restore vendor-recommended ownership and mode bits. '
                'Validate integrity using checksum baselines. '
                'Investigate unauthorized changes via centralized logging. '
                'Apply configuration management to prevent regression.'
            ),
        ),
        (
            'Investigate suspicious executable integrity anomalies',
            'hash mismatch suspicious binary unauthorized modification',
            (
                'Quarantine affected files pending forensic review. '
                'Compare hashes against trusted distribution sources. '
                'Rebuild systems from known-good media when integrity fails. '
                'Hunt related persistence mechanisms across the host. '
                'Escalate to incident response if malware is confirmed.'
            ),
        ),
        (
            'Recover from critical system service termination events',
            'service stopped unexpectedly event id crash termination',
            (
                'Collect supporting logs around the failure window. '
                'Validate dependent resources such as storage and networking. '
                'Apply vendor patches addressing the faulting component. '
                'Increase resilience using supervised restarts and health checks. '
                'Document root cause and monitoring improvements.'
            ),
        ),
    ]
    for title, symptoms, steps in remediation_payloads:
        cursor.execute(
            'INSERT INTO remediations (title, mapped_symptoms, resolution_steps) VALUES (?, ?, ?)',
            (title, symptoms, steps),
        )
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title LIKE ?',
        ('%authentication service%',),
    )
    auth_row = cursor.fetchone()
    auth_remediation_id = auth_row[0] if auth_row else 1
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title LIKE ?',
        ('%listener exposure%',),
    )
    port_row = cursor.fetchone()
    port_remediation_id = port_row[0] if port_row else 2
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title LIKE ?',
        ('%outdated interpreter%',),
    )
    pkg_row = cursor.fetchone()
    pkg_remediation_id = pkg_row[0] if pkg_row else 3
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title LIKE ?',
        ('%world-writable%',),
    )
    perm_row = cursor.fetchone()
    perm_remediation_id = perm_row[0] if perm_row else 4
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title LIKE ?',
        ('%integrity anomalies%',),
    )
    hash_row = cursor.fetchone()
    hash_remediation_id = hash_row[0] if hash_row else 5
    cursor.execute(
        'SELECT remediation_id FROM remediations WHERE title LIKE ?',
        ('%service termination%',),
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
    connection.commit()


def ensure_database(db_path=None):
    connection = get_connection(db_path)
    initialize_schema(connection)
    seed_sample_manual_entries(connection)
    return connection
