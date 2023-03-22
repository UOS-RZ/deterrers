from django.core.management.base import BaseCommand, CommandError
import os
import getpass

from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.v_scanner_interface import GmpVScannerInterface
from hostadmin.core.fw_interface import PaloAltoInterface
from hostadmin.core.contracts import HostStatusContract

class Command(BaseCommand):
    help = 'Compares data in IPAM with data in V-Scanner and perimeter FW.'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        ipam_username = os.environ.get('IPAM_USERNAME', input('IPAM username:'))
        ipam_password = os.environ.get('IPAM_SECRET_KEY', getpass.getpass('IPAM password:'))
        ipam_url = os.environ.get('IPAM_URL', input('IPAM URL:'))
        with ProteusIPAMInterface(ipam_username, ipam_password, ipam_url) as ipam:
            v_scanner_username = os.environ.get('V_SCANNER_USERNAME', input('V-Scanner username:'))
            v_scanner_password = os.environ.get('V_SCANNER_SECRET_KEY', getpass.getpass('V-Scanner password:'))
            v_scanner_url = os.environ.get('V_SCANNER_URL', input('V-Scanner URL:'))
            with GmpVScannerInterface(v_scanner_username, v_scanner_password, v_scanner_url) as scanner:
                fw_username = os.environ.get('FW_USERNAME', input('FW username:'))
                fw_password = os.environ.get('FW_SECRET_KEY', getpass.getpass('FW password:'))
                fw_url = os.environ.get('FW_URL', input('FW URL:'))
                with PaloAltoInterface(fw_username, fw_password, fw_url) as fw:
                    # get all hosts in IPAM
                    print("Get assets from IPAM!")
                    ipam_hosts_total = set()
                    ipam_hosts_online = set()
                    admin_tag_names = ipam.get_admin_tag_names()
                    for a_tag_name in admin_tag_names:
                        hosts = ipam.get_hosts_of_admin(admin_rz_id=a_tag_name)
                        for host in hosts:
                            ipam_hosts_total.add(str(host.ipv4_addr))
                            if host.status == HostStatusContract.ONLINE:
                                ipam_hosts_online.add(str(host.ipv4_addr))
                    
                    # get all hosts in periodic scan
                    print('Get assets in periodic scan!')
                    v_scanner_hosts = set()
                    # TODO: get periodic task info, get target info, get hosts

                    # get all hosts that online in FW
                    print('Get assets unblocked by FW!')
                    