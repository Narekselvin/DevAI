import logging
import sys
from pathlib import Path

_log_handlers = [logging.StreamHandler(sys.stdout), logging.FileHandler(str(Path(__file__).resolve().parent.joinpath('devai_polling.log')))]
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=_log_handlers, force=True)
_monitor_logger = logging.getLogger('devai.snmp_monitor')

try:
    from pysnmp.hlapi import CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, getCmd
except Exception:
    CommunityData = None
    ContextData = None
    ObjectIdentity = None
    ObjectType = None
    SnmpEngine = None
    UdpTransportTarget = None
    getCmd = None


class SNMPMonitor:
    def __init__(self, community='public', timeout=2, retries=1):
        self.community = community
        self.timeout = timeout
        self.retries = retries

    def poll_hosts_from_database(self, connection, device_type_filter=None):
        from poller import run_single_poll_cycle

        _monitor_logger.info('[SYSTEM] poll cycle start')
        try:
            return run_single_poll_cycle(connection, self.community, self.timeout, self.retries, device_type_filter)
        except Exception as exc:
            _monitor_logger.error('[SYSTEM] poll cycle failed: ' + str(exc))
            raise
