import os
import getpass
import logging


from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.v_scanner_interface import GmpVScannerInterface
from hostadmin.core.fw_interface import PaloAltoInterface, PaloAltoAddressGroup
from hostadmin.core.contracts import HostServiceContract, HostStatusContract


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)


HOST_IPv4s = [
    
]


if __name__ == "__main__":
    ipam_username = os.environ.get('IPAM_USERNAME', input('IPAM username: '))
    ipam_password = os.environ.get('IPAM_SECRET_KEY', getpass.getpass('IPAM password: '))
    ipam_url = os.environ.get('IPAM_URL', input('IPAM URL: '))
    with ProteusIPAMInterface(ipam_username, ipam_password, ipam_url) as ipam:
        v_scanner_username = os.environ.get('V_SCANNER_USERNAME', input('V-Scanner username: '))
        v_scanner_password = os.environ.get('V_SCANNER_SECRET_KEY', getpass.getpass('V-Scanner password: '))
        v_scanner_url = os.environ.get('V_SCANNER_URL', input('V-Scanner URL: '))
        with GmpVScannerInterface(v_scanner_username, v_scanner_password, v_scanner_url) as scanner:
            fw_username = os.environ.get('FW_USERNAME', input('FW username: '))
            fw_password = os.environ.get('FW_SECRET_KEY', getpass.getpass('FW password: '))
            fw_url = os.environ.get('FW_URL', input('FW URL: '))
            with PaloAltoInterface(fw_username, fw_password, fw_url) as fw:

                for host_ipv4 in HOST_IPv4s:
                    logger.info("%s", host_ipv4)
                    host = ipam.get_host_info_from_ip(host_ipv4)
                    if not host.is_valid() or host.service_profile is HostServiceContract.EMPTY:
                        logger.error("Can not set host '%s' online.", str(host))
                        exit()

                    # add only the IPv4 address to periodic vulnerability scan
                    response_url = ""
                    if not scanner.add_host_to_periodic_scans(host_ip=host_ipv4, deterrers_url=response_url):
                        logger.error("Couldn't add host %s to periodic scan!", host_ipv4)
                        exit()
            
                    # get IPv6 address to all IPv4 address
                    ips_to_update = ipam.get_IP6Address_if_linked(host.entity_id)
                    ips_to_update.add(str(host.ipv4_addr))

                    # first make sure ip is not already in any AddressGroups
                    suc = fw.remove_addr_objs_from_addr_grps(ips_to_update, {ag for ag in PaloAltoAddressGroup})
                    if not suc:
                        logger.error("Couldn't update firewall configuration!")
                        exit()
                    match host.service_profile:
                        case HostServiceContract.HTTP:
                            suc = fw.add_addr_objs_to_addr_grps(ips_to_update, {PaloAltoAddressGroup.HTTP,})
                        case HostServiceContract.SSH:
                            suc = fw.add_addr_objs_to_addr_grps(ips_to_update, {PaloAltoAddressGroup.SSH,})
                        case HostServiceContract.MULTIPURPOSE:
                            suc = fw.add_addr_objs_to_addr_grps(ips_to_update, {PaloAltoAddressGroup.OPEN,})
                        case HostServiceContract.HTTP_SSH:
                            suc = fw.add_addr_objs_to_addr_grps(ips_to_update, {PaloAltoAddressGroup.HTTP, PaloAltoAddressGroup.SSH})
                        case _:
                            logger.error("Unknown service profile: %s", str(host.service_profile))
                            exit()
                    if not suc:
                        logger.error("Couldn't update firewall configuration!")
                        exit()
                
                    # update host info in IPAM
                    host.status = HostStatusContract.ONLINE
                    if not ipam.update_host_info(host):
                        logger.error("Couldn't update host information!")
                        exit()