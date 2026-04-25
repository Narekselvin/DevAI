import json
import urllib.error
import urllib.request


def main():
    payload = {
        'language': 'en',
        'snmp_targets': '127.0.0.1',
        'snmp_device_type': 'servers',
    }
    data = json.dumps(payload).encode('utf-8')
    request = urllib.request.Request(
        'http://127.0.0.1:5000/api/run_audit',
        data=data,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode('utf-8', errors='replace')
            parsed = json.loads(body)
    except urllib.error.HTTPError as exc:
        text = exc.read().decode('utf-8', errors='replace')
        print(json.dumps({'ok': False, 'error': 'http_error', 'status': exc.code, 'body': text}, ensure_ascii=False))
        return 1
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
        return 1
    ok = isinstance(parsed, dict) and 'global_health_score' in parsed and 'scanner_results' in parsed
    print(
        json.dumps(
            {
                'ok': bool(ok),
                'global_health_score': parsed.get('global_health_score') if isinstance(parsed, dict) else None,
                'scanner_socket_count': len(parsed.get('scanner_results', {}).get('listening_sockets', [])) if isinstance(parsed, dict) else None,
                'snmp_device_count': len(parsed.get('snmp_results', {}).get('devices', [])) if isinstance(parsed, dict) else None,
            },
            ensure_ascii=False,
        )
    )
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
