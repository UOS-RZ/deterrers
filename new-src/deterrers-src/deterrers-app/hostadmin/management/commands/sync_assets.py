from django.core.management.base import BaseCommand, CommandError
import os
import getpass
import ipaddress
import logging

from django.conf import settings

from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.v_scanner_interface import GmpVScannerInterface
from hostadmin.core.fw_interface import PaloAltoInterface, PaloAltoAddressGroup
from hostadmin.core.contracts import HostStatusContract, HostServiceContract
from hostadmin.util import set_host_online

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Compares data in IPAM with data in V-Scanner and perimeter FW.'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        while True:
            ipam_username = os.environ.get('IPAM_USERNAME')
            ipam_password = os.environ.get('IPAM_SECRET_KEY',)
            ipam_url = os.environ.get('IPAM_URL')
            # ipam_username = settings.IPAM_USERNAME
            # ipam_password = settings.IPAM_SECRET_KEY
            # ipam_url = settings.IPAM_URL
            with ProteusIPAMInterface(ipam_username, ipam_password, ipam_url) as ipam:
                if not ipam.enter_ok:
                    continue
                while True:
                    v_scanner_username = os.environ.get('V_SCANNER_USERNAME')
                    v_scanner_password = os.environ.get('V_SCANNER_SECRET_KEY')
                    v_scanner_url = os.environ.get('V_SCANNER_URL')
                    # v_scanner_username = settings.V_SCANNER_USERNAME
                    # v_scanner_password = settings.V_SCANNER_SECRET_KEY
                    # v_scanner_url = settings.V_SCANNER_URL
                    with GmpVScannerInterface(v_scanner_username, v_scanner_password, v_scanner_url) as scanner:
                        if not scanner.enter_ok:
                            continue
                        while True:
                            fw_username = os.environ.get('FIREWALL_USERNAME')
                            fw_password = os.environ.get('FIREWALL_SECRET_KEY')
                            fw_url = os.environ.get('FIREWALL_URL')
                            # fw_username = settings.FIREWALL_USERNAME
                            # fw_password = settings.FIREWALL_SECRET_KEY
                            # fw_url = settings.FIREWALL_URL
                            with PaloAltoInterface(fw_username, fw_password, fw_url) as fw:
                                if not fw.enter_ok:
                                    continue

                                #### GET DATA ####

                                # get all hosts in IPAM
                                logger.info("Get assets from IPAM!")
                                ipam_hosts_total = {}
                                ipam_ipv4s_online = set()
                                ipam_ipv6s_online = set()
                                ipam_hosts_under_review = set()
                                admin_tag_names = ipam.get_admin_tag_names()
                                for a_tag_name in admin_tag_names:
                                    hosts = ipam.get_hosts_of_admin(admin_rz_id=a_tag_name)
                                    for host in hosts:
                                        ipam_hosts_total[str(host.ipv4_addr)] = host
                                        if host.status == HostStatusContract.ONLINE:
                                            ipam_ipv4s_online.add(str(host.ipv4_addr))
                                            ipam_ipv6s_online.update(ipam.get_IP6Addresses(ipam.get_id_of_addr(str(host.ipv4_addr))))
                                        elif host.status == HostStatusContract.UNDER_REVIEW:
                                            ipam_hosts_under_review.add(str(host.ipv4_addr))
                                
                                # get all hosts in periodic scan
                                logger.info('Get assets in periodic scan!')
                                try:
                                    v_scanner_hosts = set()
                                    # get periodic task info, get target info, get hosts
                                    filter_str = f'"{scanner.PERIODIC_TASK_NAME}" rows=-1 first=1'
                                    response = scanner.gmp.get_tasks(filter_string=filter_str)
                                    response_status = int(response.xpath('@status')[0])
                                    if response_status != 200:
                                        raise RuntimeError(f"Couldn't get tasks! Status: {response_status}")
                                    # get task uuid and uuid of the existing target
                                    target_uuid = response.xpath('//target/@id')[0]
                                    response = scanner.gmp.get_target(target_uuid)
                                    response_status = int(response.xpath('@status')[0])
                                    if response_status != 200:
                                        raise RuntimeError(f"Couldn't get target! Status: {response_status}")
                                    hosts_str = response.xpath('//hosts')[0].text
                                    v_scanner_hosts = {h.strip() for h in hosts_str.split(',')}
                                except:
                                    logger.exception("")

                                # get all hosts that are online in FW
                                logger.info('Get assets unblocked by FW!')
                                fw_ipv4s = set()
                                fw_web_ipv4s = set()
                                fw_ssh_ipv4s = set()
                                fw_open_ipv4s = set()
                                fw_ipv6s = set()
                                fw_web_ipv6s = set()
                                fw_ssh_ipv6s = set()
                                fw_open_ipv6s = set()
                                for ag in PaloAltoAddressGroup:
                                    addr_objs = fw.get_addr_objs_in_addr_grp(ag)
                                    for addr_obj in addr_objs:
                                        # check if IPv4
                                        try:
                                            ipv4 = ipaddress.IPv4Address(addr_obj.replace('-', '.'))
                                            fw_ipv4s.add(str(ipv4))
                                            match ag:
                                                case PaloAltoAddressGroup.HTTP:
                                                    fw_web_ipv4s.add(str(ipv4))
                                                case PaloAltoAddressGroup.SSH:
                                                    fw_ssh_ipv4s.add(str(ipv4))
                                                case PaloAltoAddressGroup.OPEN:
                                                    fw_open_ipv4s.add(str(ipv4))
                                            continue
                                        except:
                                            pass
                                        # check if IPv6
                                        try:
                                            ipv6 = ipaddress.IPv6Address(addr_obj.replace('-', ':')).exploded
                                            fw_ipv6s.add(str(ipv6))
                                            match ag:
                                                case PaloAltoAddressGroup.HTTP:
                                                    fw_web_ipv6s.add(str(ipv6))
                                                case PaloAltoAddressGroup.SSH:
                                                    fw_ssh_ipv6s.add(str(ipv6))
                                                case PaloAltoAddressGroup.OPEN:
                                                    fw_open_ipv6s.add(str(ipv6))
                                        except:
                                            logger.exception(f"Could not parse {addr_obj}")


                                logger.info('---------------------------------------------------------------------')
                                logger.info(f"IPAM Hosts total: {len(ipam_hosts_total.keys())}")
                                logger.info(f"IPAM Hosts under review: {len(ipam_hosts_under_review)} ({ipam_hosts_under_review})")
                                logger.info(f"IPAM IPs online: {len(ipam_ipv4s_online.union(ipam_ipv6s_online))}")
                                logger.info(f"Scanner hosts online: {len(v_scanner_hosts)}")
                                logger.info(f"FW IPs online: {len(fw_ipv4s.union(fw_ipv6s))}")
                                logger.info('')
                                logger.info('Diff:')
                                logger.info(f"IPAM IPv4s - Scanner: {ipam_ipv4s_online.difference(v_scanner_hosts)}")
                                logger.info(f"Scanner - IPAM IPv4s: {v_scanner_hosts.difference(ipam_ipv4s_online)}")
                                logger.info('')
                                logger.info(f"IPAM - FW: {ipam_ipv4s_online.union(ipam_ipv6s_online).difference(fw_ipv4s.union(fw_ipv6s))}")
                                logger.info(f"FW - IPAM: {fw_ipv4s.union(fw_ipv6s).difference(ipam_ipv4s_online.union(ipam_ipv6s_online))}")
                                logger.info('')
                                logger.info(f"Scanner - FW IPv4s: {v_scanner_hosts.difference(fw_ipv4s)}")
                                logger.info(f"FW IPv4s - Scanner: {fw_ipv4s.difference(v_scanner_hosts)}")
                                logger.info('')

                                

                                #### RESTORE CONSISTENCY ####

                                for ipv4, host in ipam_hosts_total.items():
                                    ipv6s = ipam.get_IP6Addresses(ipam.get_id_of_addr(ipv4))
                                    if len(ipv6s) > 1:
                                        logger.info(f"---> {ipv4} is linked to {ipv6s}")

                                    # RESTORE CONSISTENCY FOR HOSTS THAT ARE ONLINE IN IPAM
                                    if host.status == HostStatusContract.ONLINE:
                                        # consistency IPAM <-> FW
                                        match host.service_profile:
                                            case HostServiceContract.HTTP:
                                                if ipv4 not in fw_web_ipv4s:
                                                    fw.add_addr_objs_to_addr_grps([ipv4,], {PaloAltoAddressGroup.HTTP,})
                                                if ipv4 in fw_ssh_ipv4s:
                                                    fw.remove_addr_objs_from_addr_grps([ipv4,], {PaloAltoAddressGroup.SSH,})
                                                if ipv4 in fw_open_ipv4s:
                                                    fw.remove_addr_objs_from_addr_grps([ipv4,], {PaloAltoAddressGroup.OPEN,})
                                                for ipv6 in ipv6s:
                                                    if ipv6 not in fw_web_ipv6s:
                                                        fw.add_addr_objs_to_addr_grps([ipv6,], {PaloAltoAddressGroup.HTTP,})
                                                    if ipv6 in fw_ssh_ipv6s:
                                                        fw.remove_addr_objs_from_addr_grps([ipv6,], {PaloAltoAddressGroup.SSH,})
                                                    if ipv6 in fw_open_ipv6s:
                                                        fw.remove_addr_objs_from_addr_grps([ipv6,], {PaloAltoAddressGroup.OPEN,})

                                            case HostServiceContract.SSH:
                                                if ipv4 in fw_web_ipv4s:
                                                    fw.remove_addr_objs_from_addr_grps([ipv4,], {PaloAltoAddressGroup.HTTP,})
                                                if ipv4 not in fw_ssh_ipv4s:
                                                    fw.add_addr_objs_to_addr_grps([ipv4,], {PaloAltoAddressGroup.SSH,})
                                                if ipv4 in fw_open_ipv4s:
                                                    fw.remove_addr_objs_from_addr_grps([ipv4,], {PaloAltoAddressGroup.OPEN,})
                                                for ipv6 in ipv6s:
                                                    if ipv6 in fw_web_ipv6s:
                                                        fw.remove_addr_objs_from_addr_grps([ipv6,], {PaloAltoAddressGroup.HTTP,})
                                                    if ipv6 not in fw_ssh_ipv6s:
                                                        fw.add_addr_objs_to_addr_grps([ipv6,], {PaloAltoAddressGroup.SSH,})
                                                    if ipv6 in fw_open_ipv6s:
                                                        fw.remove_addr_objs_from_addr_grps([ipv6,], {PaloAltoAddressGroup.OPEN,})
                                            case HostServiceContract.HTTP_SSH:
                                                if ipv4 not in fw_web_ipv4s:
                                                    fw.add_addr_objs_to_addr_grps([ipv4,], {PaloAltoAddressGroup.HTTP,})
                                                if ipv4 not in fw_ssh_ipv4s:
                                                    fw.add_addr_objs_to_addr_grps([ipv4,], {PaloAltoAddressGroup.SSH,})
                                                if ipv4 in fw_open_ipv4s:
                                                    fw.remove_addr_objs_from_addr_grps([ipv4,], {PaloAltoAddressGroup.OPEN,})
                                                for ipv6 in ipv6s:
                                                    if ipv6 not in fw_web_ipv6s:
                                                        fw.add_addr_objs_to_addr_grps([ipv6,], {PaloAltoAddressGroup.HTTP,})
                                                    if ipv6 not in fw_ssh_ipv6s:
                                                        fw.add_addr_objs_to_addr_grps([ipv6,], {PaloAltoAddressGroup.SSH,})
                                                    if ipv6 in fw_open_ipv6s:
                                                        fw.remove_addr_objs_from_addr_grps([ipv6,], {PaloAltoAddressGroup.OPEN,})
                                            case HostServiceContract.MULTIPURPOSE:
                                                if ipv4 in fw_web_ipv4s:
                                                    fw.remove_addr_objs_from_addr_grps([ipv4,], {PaloAltoAddressGroup.HTTP,})
                                                if ipv4 in fw_ssh_ipv4s:
                                                    fw.remove_addr_objs_from_addr_grps([ipv4,], {PaloAltoAddressGroup.SSH,})
                                                if ipv4 not in fw_open_ipv4s:
                                                    fw.add_addr_objs_to_addr_grps([ipv4,], {PaloAltoAddressGroup.OPEN,})
                                                for ipv6 in ipv6s:
                                                    if ipv6 in fw_web_ipv6s:
                                                        fw.remove_addr_objs_from_addr_grps([ipv6,], {PaloAltoAddressGroup.HTTP,})
                                                    if ipv6 in fw_ssh_ipv6s:
                                                        fw.remove_addr_objs_from_addr_grps([ipv6,], {PaloAltoAddressGroup.SSH,})
                                                    if ipv6 not in fw_open_ipv6s:
                                                        fw.add_addr_objs_to_addr_grps([ipv6,], {PaloAltoAddressGroup.OPEN,})
                                            case _:
                                                logger.warning(f"Invlaid service profile: {host.service_profile}")
                                                continue

                                        
                                        # consistency IPAM <-> Scanner
                                        # if ipv4 not in v_scanner_hosts:
                                        #     if not scanner.add_host_to_periodic_scans(ipv4, ''):
                                        #         logger.warning("Could not add %s to Scanner", str(ipv4))

                                    # RESTORE CONSISTENCY FOR HOSTS THAT ARE NOT ONLINE IN IPAM
                                    else:
                                        # consistency IPAM <-> FW
                                        if ipv4 in fw_ipv4s:
                                            if not fw.remove_addr_objs_from_addr_grps([ipv4,], {ag for ag in PaloAltoAddressGroup}):
                                                logger.warning("Could not remove %s from FW", str(ipv4))
                                        for ipv6 in ipv6s:
                                            if ipv6 in fw_ipv6s:
                                                if not fw.remove_addr_objs_from_addr_grps([ipv6,], {ag for ag in PaloAltoAddressGroup}):
                                                    logger.warning("Could not remove %s from FW", str(ipv6))

                                        # consistency IPAM <-> Scanner
                                        # if ipv4 in v_scanner_hosts:
                                        #     if not scanner.remove_host_from_periodic_scans(ipv4):
                                        #         logger.warning("Coudld not remove %s from Scanner", str(ipv4))

                                # RESTORE COSISTENCY FOR HOSTS THAT ARE NOT EVEN IPAM
                                # IPAM <-> Scanner
                                # for ipv4 in v_scanner_hosts:
                                #     if ipv4 not in ipam_hosts_total.keys():
                                #         if not scanner.remove_host_from_periodic_scans(ipv4):
                                #             logger.warning("Could not remove %s from scanner", str(ipv4))

                                # IPAM <-> FW
                                for ip in fw_ipv4s.union(fw_ipv6s):
                                    if ip not in ipam_ipv4s_online.union(ipam_ipv6s_online):
                                        if not fw.remove_addr_objs_from_addr_grps([ip,], {ag for ag in PaloAltoAddressGroup}):
                                            logger.warning("Could not remove %s from FW", str(ip))


                                return


if __name__ == "__main__":
    # set logger for manual executions
    logger.setLevel(logging.DEBUG)
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    Command().handle()
