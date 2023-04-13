import logging
from getpass import getpass

from hostadmin.core.v_scanner_interface import GmpVScannerInterface
from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.risk_assessor import assess_host_risk
from hostadmin.util import periodic_mail_body

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)


if __name__ == "__main__":
    logger.info('Start!')
    username = 'DETERRERS'
    __password = getpass('Greenbone Password: ')
    with GmpVScannerInterface(username, __password, 'hulk.rz.uni-osnabrueck.de') as scanner:
        with ProteusIPAMInterface('nwintering', getpass('IPAM Password: '), 'proteus.rz.uos.de') as ipam:

            test_report_uuid = "a7b68dd7-9ce1-43a2-a1cb-906b477a6d3b"

            report_xml = scanner.get_report_xml(test_report_uuid)
            _, _, results = scanner.extract_report_data(report_xml)

            for host_ipv4, vulnerabilities in results.items():
                host = ipam.get_host_info_from_ip(host_ipv4)
                if not host or not host.is_valid():
                    logger.error("Invalid host during risk assessment: %s", str(host))
                    continue
                block_reasons, notify_reasons = assess_host_risk(host, vulnerabilities)

                if len(block_reasons) != 0 or len(notify_reasons) != 0:
                    logger.info(periodic_mail_body(host, block_reasons, notify_reasons))
