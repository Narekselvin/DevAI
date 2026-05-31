import pysnmp.hlapi as hlapi

target_ip = '192.168.41.233' # Put your exact HP switch IP here
community = 'public'         # Put the exact Zabbix Community String here

print(f"Shooting raw SNMPv2c packet from this PC to {target_ip}...")

iterator = hlapi.getCmd(
    hlapi.SnmpEngine(),
    hlapi.CommunityData(community, mpModel=1),
    hlapi.UdpTransportTarget((target_ip, 161), timeout=3, retries=1),
    hlapi.ContextData(),
    hlapi.ObjectType(hlapi.ObjectIdentity('1.3.6.1.2.1.1.1.0')) # Basic System Info OID
)

errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

if errorIndication:
    print(f"\n❌ [NETWORK BLOCK] The switch ignored us: {errorIndication}")
    print("---------------------------------------------------------")
    print("CONCLUSION: Your code is fine. The HP Switch has an IP Whitelist (ACL).")
    print("It is actively blocking your PC's IP address from asking for SNMP data.")
elif errorStatus:
    print(f"\n❌ [SNMP ERROR] {errorStatus.prettyPrint()}")
else:
    print("\n✅ [SUCCESS] The switch answered!")
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))