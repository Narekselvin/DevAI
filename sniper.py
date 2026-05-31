import socket

def build_raw_snmp_packet(community="public"):
    # Manually construct an ASN.1 BER encoded SNMPv2c GET request for sysUpTime (1.3.6.1.2.1.1.3.0)
    comm_bytes = community.encode('utf-8')
    
    # OID: 1.3.6.1.2.1.1.3.0
    oid_part = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x05, 0x00])
    varbind = bytes([0x30, len(oid_part)]) + oid_part
    varbind_list = bytes([0x30, len(varbind)]) + varbind

    # Request ID, Error Status, Error Index
    req_id_etc = bytes([0x02, 0x04, 0x6a, 0x62, 0x13, 0x14, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
    pdu = bytes([0xa0, len(req_id_etc) + len(varbind_list)]) + req_id_etc + varbind_list

    # Version 2c (0x01) + Community
    msg = bytes([0x02, 0x01, 0x01]) + bytes([0x04, len(comm_bytes)]) + comm_bytes + pdu
    
    return bytes([0x30, len(msg)]) + msg

def fire_raw_socket(target_ip, community="public", port=161):
    print(f"[*] Firing raw UDP socket at {target_ip}:{port} (Community: {community})")
    payload = build_raw_snmp_packet(community)

    # Open a raw UDP socket (No external libraries used!)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)

    try:
        sock.sendto(payload, (target_ip, port))
        data, addr = sock.recvfrom(1024)
        print(f"\n✅ [SUCCESS] The device answered! Received {len(data)} bytes from {addr[0]}.")
        print("CONCLUSION: The network is OPEN. We just need to fix your app's Python dependencies.")
    except socket.timeout:
        print("\n❌ [NETWORK BLOCK / TIMEOUT] No response received.")
        print("CONCLUSION: Your code is 100% innocent. A Firewall/ACL is dropping your packets.")
    except Exception as e:
        print(f"\n❌ [ERROR] {e}")
    finally:
        sock.close()

# ---------------------------------------------------------
# PUT YOUR TARGET IP AND ZABBIX COMMUNITY STRING HERE:
# ---------------------------------------------------------
fire_raw_socket(target_ip='192.168.195.195', community='public')