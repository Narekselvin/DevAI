import hashlib
import os
from pathlib import Path

try:
    import yara

    yara_module_available = True
except ImportError:
    yara = None
    yara_module_available = False


def compute_sha256_hexdigest(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as input_stream:
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b''):
                hasher.update(chunk)
    except OSError:
        return None
    return hasher.hexdigest()


def build_default_suspicious_sha256_set():
    return {
        '13db60afb914a2ee9b3649d1947d58046d1a9e9b8e4114d80b1d5c142b4ed7fa',
    }


def build_yara_rules_compilation():
    if not yara_module_available:
        return None
    rule_source = (
        'rule suspicious_eicar_marker { strings: $m = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $m } '
        'rule suspicious_powershell_encoded { strings: $b = "-encodedcommand" nocase condition: $b }'
    )
    try:
        return yara.compile(source=rule_source)
    except Exception:
        return None


def build_critical_directory_roots():
    roots = []
    if os.name == 'nt':
        windir_value = os.environ.get('WINDIR', 'C:\\Windows')
        system_root = Path(windir_value)
        roots.extend(
            [
                system_root.joinpath('System32', 'Tasks'),
                system_root.joinpath('Temp'),
                Path(os.environ.get('TEMP', system_root.joinpath('Temp'))),
            ]
        )
        programdata_value = os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
        roots.append(Path(programdata_value).joinpath('Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'))
    else:
        roots.extend([Path('/tmp'), Path('/var/tmp'), Path('/dev/shm')])
    filtered_roots = []
    for root_path in roots:
        if root_path.exists() and root_path.is_dir():
            filtered_roots.append(root_path)
    return filtered_roots


def walk_limited_filesystem_entries(root_path, maximum_files, maximum_depth):
    collected_paths = []
    stack = [(root_path, 0)]
    while stack and len(collected_paths) < maximum_files:
        current_path, depth_value = stack.pop()
        try:
            iterator = current_path.iterdir()
        except OSError:
            continue
        for child_path in iterator:
            if len(collected_paths) >= maximum_files:
                break
            try:
                if child_path.is_file():
                    collected_paths.append(child_path)
                elif child_path.is_dir() and depth_value < maximum_depth:
                    stack.append((child_path, depth_value + 1))
            except OSError:
                continue
    return collected_paths


def match_yara_against_file(rules_object, file_path):
    if rules_object is None:
        return []
    try:
        matches = rules_object.match(str(file_path))
    except Exception:
        return []
    return [match.rule for match in matches]


def scan_filesystem_for_integrity_anomalies(maximum_files_per_root=400, maximum_depth=4):
    suspicious_sha256_values = build_default_suspicious_sha256_set()
    yara_rules = build_yara_rules_compilation()
    isolated_paths = []
    hash_hits = []
    yara_hits = []
    for root_path in build_critical_directory_roots():
        candidate_files = walk_limited_filesystem_entries(root_path, maximum_files_per_root, maximum_depth)
        for file_path in candidate_files:
            try:
                size_bytes = file_path.stat().st_size
            except OSError:
                continue
            if size_bytes > 25 * 1024 * 1024:
                continue
            digest_hex = compute_sha256_hexdigest(file_path)
            if digest_hex and digest_hex.lower() in suspicious_sha256_values:
                hash_hits.append({'path': str(file_path), 'sha256': digest_hex.lower(), 'reason': 'known_bad_hash'})
                isolated_paths.append(str(file_path))
            if yara_rules:
                rule_names = match_yara_against_file(yara_rules, file_path)
                for rule_name in rule_names:
                    yara_hits.append({'path': str(file_path), 'rule': rule_name, 'reason': 'yara_signature'})
                    isolated_paths.append(str(file_path))
    deduplicated_isolated = sorted(set(isolated_paths))
    return {
        'hash_signature_hits': hash_hits,
        'yara_signature_hits': yara_hits,
        'isolated_suspicious_paths': deduplicated_isolated,
        'yara_engine_active': bool(yara_rules),
    }
