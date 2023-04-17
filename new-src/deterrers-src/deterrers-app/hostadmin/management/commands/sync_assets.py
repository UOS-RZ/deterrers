from django.core.management.base import BaseCommand, CommandError
import os
import getpass
import ipaddress


from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.v_scanner_interface import GmpVScannerInterface
from hostadmin.core.fw_interface import PaloAltoInterface, PaloAltoAddressGroup
from hostadmin.core.contracts import HostStatusContract, HostServiceContract
from hostadmin.util import set_host_online

class Command(BaseCommand):
    help = 'Compares data in IPAM with data in V-Scanner and perimeter FW.'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        while True:
            ipam_username = os.environ.get('IPAM_USERNAME', input('IPAM username: '))
            ipam_password = os.environ.get('IPAM_SECRET_KEY', getpass.getpass('IPAM password: '))
            ipam_url = os.environ.get('IPAM_URL', input('IPAM URL: '))
            with ProteusIPAMInterface(ipam_username, ipam_password, ipam_url) as ipam:
                if not ipam.enter_ok:
                    continue
                while True:
                    v_scanner_username = os.environ.get('V_SCANNER_USERNAME', input('V-Scanner username: '))
                    v_scanner_password = os.environ.get('V_SCANNER_SECRET_KEY', getpass.getpass('V-Scanner password: '))
                    v_scanner_url = os.environ.get('V_SCANNER_URL', input('V-Scanner URL: '))
                    with GmpVScannerInterface(v_scanner_username, v_scanner_password, v_scanner_url) as scanner:
                        if not scanner.enter_ok:
                            continue
                        while True:
                            fw_username = os.environ.get('FIREWALL_USERNAME', input('FW username: '))
                            fw_password = os.environ.get('FIREWALL_SECRET_KEY', getpass.getpass('FW password: '))
                            fw_url = os.environ.get('FIREWALL_URL', input('FW URL: '))
                            with PaloAltoInterface(fw_username, fw_password, fw_url) as fw:
                                if not fw.enter_ok:
                                    continue
                                # get all hosts in IPAM
                                print("Get assets from IPAM!")
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
                                print('Get assets in periodic scan!')
                                v_scanner_hosts = set()
                                # get periodic task info, get target info, get hosts
                                filter_str = f'"{scanner.PERIODIC_TASK_NAME}" rows=-1 first=1'
                                response = scanner.gmp.get_tasks(filter_string=filter_str)
                                response_status = int(response.xpath('@status')[0])
                                if response_status != 200:
                                    raise RuntimeError(f"Couldn't get tasks! Status: {response_status}")
                                try:
                                    # get task uuid and uuid of the existing target
                                    target_uuid = response.xpath('//target/@id')[0]
                                    response = scanner.gmp.get_target(target_uuid)
                                    response_status = int(response.xpath('@status')[0])
                                    if response_status != 200:
                                        raise RuntimeError(f"Couldn't get target! Status: {response_status}")
                                    hosts_str = response.xpath('//hosts')[0].text
                                    v_scanner_hosts = {h.strip() for h in hosts_str.split(',')}
                                except IndexError as err:
                                    print(f"{err}")

                                # get all hosts that online in FW
                                print('Get assets unblocked by FW!')
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
                                        try:
                                            ip = ipaddress.ip_address(addr_obj.replace('-', '.'))
                                        except:
                                            continue
                                        if isinstance(ip, ipaddress.IPv4Address):
                                            fw_ipv4s.add(str(ip))
                                            match ag:
                                                case PaloAltoAddressGroup.HTTP:
                                                    fw_web_ipv4s.add(str(ip))
                                                case PaloAltoAddressGroup.SSH:
                                                    fw_ssh_ipv4s.add(str(ip))
                                                case PaloAltoAddressGroup.OPEN:
                                                    fw_open_ipv4s.add(str(ip))
                                        elif isinstance(ip, ipaddress.IPv6Address):
                                            fw_ipv6s.add(str(ip))
                                            match ag:
                                                case PaloAltoAddressGroup.HTTP:
                                                    fw_web_ipv6s.add(str(ip))
                                                case PaloAltoAddressGroup.SSH:
                                                    fw_ssh_ipv6s.add(str(ip))
                                                case PaloAltoAddressGroup.OPEN:
                                                    fw_open_ipv6s.add(str(ip))


                                print('---------------------------------------------------------------------')
                                print(f"IPAM IPs online: {len(ipam_ipv4s_online.union(ipam_ipv6s_online))}")
                                print(f"IPAM Hosts under review: {len(ipam_hosts_under_review)} ({ipam_hosts_under_review})")
                                print(f"Scanner hosts online: {len(v_scanner_hosts)}")
                                print(f"FW IPs online: {len(fw_ipv4s.union(fw_ipv6s))}")
                                print()
                                print('Diff:')
                                print(f"IPAM - Scanner: {ipam_ipv4s_online.difference(v_scanner_hosts)}")
                                print(f"Scanner - IPAM: {v_scanner_hosts.difference(ipam_ipv4s_online)}")
                                print()
                                print(f"IPAM - FW: {ipam_ipv4s_online.union(ipam_ipv6s_online).difference(fw_ipv4s.union(fw_ipv6s))}")
                                print(f"FW - IPAM: {fw_ipv4s.union(fw_ipv6s).difference(ipam_ipv4s_online.union(ipam_ipv6s_online))}")
                                print()
                                print(f"Scanner - FW: {v_scanner_hosts.difference(fw_ipv4s)}")
                                print(f"FW - Scanner: {fw_ipv4s.difference(v_scanner_hosts)}")
                                print()

                                # check if Service Profile is consistent in IPAM and FW
                                for ipv4 in ipam_ipv4s_online:
                                    host = ipam_hosts_total[ipv4]
                                    if host.status != HostStatusContract.ONLINE:
                                        continue
                                    inconsistent = False
                                    # check consistency of IPv4
                                    match host.service_profile:
                                        case HostServiceContract.HTTP:
                                            if ipv4 not in fw_web_ipv4s or \
                                                ipv4 in fw_ssh_ipv4s or \
                                                    ipv4 in fw_open_ipv4s:
                                                print(f"{ipv4} is in wrong fw profile")
                                                inconsistent = True
                                        case HostServiceContract.SSH:
                                            if ipv4 not in fw_ssh_ipv4s or \
                                                ipv4 in fw_web_ipv4s or \
                                                    ipv4 in fw_open_ipv4s:
                                                print(f"{ipv4} is in wrong fw profile")
                                                inconsistent = True
                                        case HostServiceContract.HTTP_SSH:
                                            if ipv4 not in fw_web_ipv4s or \
                                                ipv4 not in fw_ssh_ipv4s or \
                                                    ipv4 in fw_open_ipv4s:
                                                print(f"{ipv4} is in wrong fw profile")
                                                inconsistent = True
                                        case HostServiceContract.MULTIPURPOSE:
                                            if ipv4 not in fw_open_ipv4s or \
                                                ipv4 in fw_web_ipv4s or \
                                                    ipv4 in fw_ssh_ipv4s:
                                                print(f"{ipv4} is in wrong fw profile")
                                                inconsistent = True
                                        case _:
                                            print(f"Invlaid service profile: {host.service_profile}")
                                    # check consistency of IPv6
                                    ipv6s = ipam.get_IP6Addresses(ipam.get_id_of_addr(ipv4))
                                    if len(ipv6s) > 1:
                                        print("Length " + str(len(ipv6s)))
                                    for ipv6 in ipv6s:
                                        match host.service_profile:
                                            case HostServiceContract.HTTP:
                                                if ipv6 not in fw_web_ipv6s or \
                                                    ipv6 in fw_ssh_ipv6s or \
                                                        ipv6 in fw_open_ipv6s:
                                                    print(f"{ipv6} is in wrong fw profile")
                                                    inconsistent = True
                                            case HostServiceContract.SSH:
                                                if ipv6 not in fw_ssh_ipv6s or \
                                                    ipv6 in fw_web_ipv6s or \
                                                        ipv6 in fw_open_ipv6s:
                                                    print(f"{ipv6} is in wrong fw profile")
                                                    inconsistent = True
                                            case HostServiceContract.HTTP_SSH:
                                                if ipv6 not in fw_web_ipv6s or \
                                                    ipv6 not in fw_ssh_ipv6s or \
                                                        ipv6 in fw_open_ipv6s:
                                                    print(f"{ipv6} is in wrong fw profile")
                                                    inconsistent = True
                                            case HostServiceContract.MULTIPURPOSE:
                                                if ipv6 not in fw_open_ipv6s or \
                                                    ipv6 in fw_web_ipv6s or \
                                                        ipv6 in fw_ssh_ipv6s:
                                                    print(f"{ipv6} is in wrong fw profile")
                                                    inconsistent = True
                                            case _:
                                                print(f"Invlaid service profile: {host.service_profile}")

                                    if inconsistent and __name__ != "__main__":
                                        set_host_online(ipv4)

                                return


if __name__ == "__main__":
    Command().handle()
