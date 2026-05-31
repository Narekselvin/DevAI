import pathlib
import sys

import requests

MIB_SOURCES = [
    ('https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/ietf/IF-MIB.txt', 'IF-MIB.txt'),
    ('https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/ietf/IP-MIB.txt', 'IP-MIB.txt'),
    ('https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/ietf/TCP-MIB.txt', 'TCP-MIB.txt'),
    ('https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/ietf/UDP-MIB.txt', 'UDP-MIB.txt'),
    ('https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/ietf/ENTITY-MIB.txt', 'ENTITY-MIB.txt'),
    ('https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/ietf/HOST-RESOURCES-MIB.txt', 'HOST-RESOURCES-MIB.txt'),
    ('https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/ietf/SNMPv2-MIB.txt', 'SNMPv2-MIB.txt'),
    ('https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/ietf/IANAifType-MIB.txt', 'IANAifType-MIB.txt'),
    ('https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/ietf/BRIDGE-MIB.txt', 'BRIDGE-MIB.txt'),
    ('https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/ietf/ETHERLIKE-MIB.txt', 'ETHERLIKE-MIB.txt'),
]


def main():
    root_dir = pathlib.Path(__file__).resolve().parent
    target_dir = root_dir.joinpath('mibs')
    target_dir.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers.update({'User-Agent': 'DevAI-MIBSetup/1.0'})
    failures = 0
    for url, filename in MIB_SOURCES:
        destination = target_dir.joinpath(filename)
        try:
            response = session.get(url, timeout=60)
            response.raise_for_status()
            destination.write_bytes(response.content)
            sys.stdout.write('saved ' + str(destination) + '\n')
        except Exception:
            failures += 1
            sys.stderr.write('failed ' + url + '\n')
    if failures:
        sys.exit(1)


if __name__ == '__main__':
    main()
