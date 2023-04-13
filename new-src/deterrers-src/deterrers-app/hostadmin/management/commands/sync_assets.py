from django.core.management.base import BaseCommand, CommandError
import os
import getpass
import ipaddress


from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.v_scanner_interface import GmpVScannerInterface
from hostadmin.core.fw_interface import PaloAltoInterface, PaloAltoAddressGroup
from hostadmin.core.contracts import HostStatusContract, HostServiceContract

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
                            fw_username = os.environ.get('FW_USERNAME', input('FW username: '))
                            fw_password = os.environ.get('FW_SECRET_KEY', getpass.getpass('FW password: '))
                            fw_url = os.environ.get('FW_URL', input('FW URL: '))
                            with PaloAltoInterface(fw_username, fw_password, fw_url) as fw:
                                if not fw.enter_ok:
                                    continue
                                # get all hosts in IPAM
                                print("Get assets from IPAM!")
                                ipam_hosts_total = set()
                                ipam_hosts_online = []
                                ipam_hosts_under_review = set()
                                admin_tag_names = ipam.get_admin_tag_names()
                                for a_tag_name in admin_tag_names:
                                    hosts = ipam.get_hosts_of_admin(admin_rz_id=a_tag_name)
                                    for host in hosts:
                                        ipam_hosts_total.add(str(host.ipv4_addr))
                                        if host.status == HostStatusContract.ONLINE:
                                            ipam_hosts_online.append(host)
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
                                fw_hosts = set()
                                fw_web_hosts = set()
                                fw_ssh_hosts = set()
                                fw_open_hosts = set()
                                for ag in PaloAltoAddressGroup:
                                    addr_objs = fw.get_addr_objs_in_addr_grp(ag)
                                    for addr_obj in addr_objs:
                                        try:
                                            ip = ipaddress.IPv4Address(addr_obj.replace('-', '.'))
                                        except:
                                            continue
                                        if isinstance(ip, ipaddress.IPv4Address):
                                            fw_hosts.add(str(ip))
                                            match ag:
                                                case PaloAltoAddressGroup.HTTP:
                                                    fw_web_hosts.add(str(ip))
                                                case PaloAltoAddressGroup.SSH:
                                                    fw_ssh_hosts.add(str(ip))
                                                case PaloAltoAddressGroup.OPEN:
                                                    fw_open_hosts.add(str(ip))


                                print('---------------------------------------------------------------------')
                                print(f"IPAM Hosts online: {len(ipam_hosts_online)}")
                                print(f"IPAM Hosts under review: {len(ipam_hosts_under_review)} ({ipam_hosts_under_review})")
                                print(f"Scanner hosts online: {len(v_scanner_hosts)}")
                                print(f"FW hosts online: {len(fw_hosts)}")
                                print()
                                print('Diff:')
                                print(f"IPAM - Scanner: {ipam_hosts_online.difference(v_scanner_hosts)}")
                                print(f"Scanner - IPAM: {v_scanner_hosts.difference(ipam_hosts_online)}")
                                print()
                                print(f"IPAM - FW: {ipam_hosts_online.difference(fw_hosts)}")
                                print(f"FW - IPAM: {fw_hosts.difference(ipam_hosts_online)}")
                                print()
                                print(f"Scanner - FW: {v_scanner_hosts.difference(fw_hosts)}")
                                print(f"FW - Scanner: {fw_hosts.difference(v_scanner_hosts)}")
                                print()
                                for host in ipam_hosts_total:
                                    match fw:
                                        case HostServiceContract.HTTP:
                                            if not str(host.ipv4_addr) in fw_web_hosts:
                                                print(f"{str(host.ipv4_addr)} is not in {PaloAltoAddressGroup.HTTP}")
                                        case HostServiceContract.SSH:
                                            if not str(host.ipv4_addr) in fw_ssh_hosts:
                                                print(f"{str(host.ipv4_addr)} is not in {PaloAltoAddressGroup.SSH}")
                                        case HostServiceContract.HTTP_SSH:
                                            if not str(host.ipv4_addr) in fw_web_hosts:
                                                print(f"{str(host.ipv4_addr)} is not in {PaloAltoAddressGroup.HTTP}")
                                            if not str(host.ipv4_addr) in fw_ssh_hosts:
                                                print(f"{str(host.ipv4_addr)} is not in {PaloAltoAddressGroup.SSH}")
                                        case HostServiceContract.MULTIPURPOSE:
                                            if not str(host.ipv4_addr) in fw_open_hosts:
                                                print(f"{str(host.ipv4_addr)} is not in {PaloAltoAddressGroup.OPEN}")

                                return


if __name__ == "__main__":
    Command().handle()
