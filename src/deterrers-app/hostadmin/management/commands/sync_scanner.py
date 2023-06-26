from django.core.management.base import BaseCommand
import os
import argparse
import logging

from django.conf import settings

from hostadmin.core.data_logic.ipam_wrapper import ProteusIPAMWrapper
from hostadmin.core.scanner.gmp_wrapper import GmpScannerWrapper
from hostadmin.core.contracts import HostStatusContract, HostServiceContract
from hostadmin.core.host import MyHost

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Compares data in IPAM with data in vulnerability scanner.'

    sync = False

    def add_arguments(self, parser):
        parser.add_argument(
            '-s',
            '--sync',
            action='store_true',
            help='Indicates whether to actually update the scanner config'
        )

    def __add_ip(self, scanner: GmpScannerWrapper, ipv4: str):
        logger.warning("IP %s is missing in scanner", str(ipv4))
        if self.sync:
            scanner.add_host_to_periodic_scans(ipv4, '')

    def __rmv_ip(self, scanner: GmpScannerWrapper, ipv4: str):
        logger.warning("IP %s is wrongfully present in scanner", str(ipv4))
        if self.sync:
            scanner.remove_host_from_periodic_scans(ipv4)

    def __sync_host_online(
        self,
        host:  MyHost,
        ipam: ProteusIPAMWrapper,
        scanner: GmpScannerWrapper,
        v_scanner_hosts: set
    ):
        ipv4 = str(host.ipv4_addr)
        if ipv4 not in v_scanner_hosts:
            self.__add_ip(scanner, ipv4)

    def __sync_host_blocked(
        self,
        host:  MyHost,
        ipam: ProteusIPAMWrapper,
        scanner: GmpScannerWrapper,
        v_scanner_hosts: set
    ):
        ipv4 = str(host.ipv4_addr)
        if ipv4 in v_scanner_hosts:
            self.__rmv_ip(scanner, ipv4)

    def __sync_host_under_review(self, host: MyHost):
        logger.info("Host under review: %s", str(host.ipv4_addr))

    def handle(self, *args, **options):
        logger.info("Start sync IPAM and scanner!")
        # quick sanity check if service profiles are still up-to-date
        if not (
            {sp for sp in HostServiceContract}
            ==
            {
                HostServiceContract.EMPTY,
                HostServiceContract.HTTP,
                HostServiceContract.SSH,
                HostServiceContract.HTTP_SSH,
                HostServiceContract.MULTIPURPOSE
            }
        ):
            logger.error("Service Profiles not up-to-date!")
            exit()

        self.sync = options.get('sync', None)

        while True:
            try:
                ipam_username = settings.IPAM_USERNAME
                ipam_password = settings.IPAM_SECRET_KEY
                ipam_url = settings.IPAM_URL
            except Exception:
                ipam_username = os.environ.get('IPAM_USERNAME')
                ipam_password = os.environ.get('IPAM_SECRET_KEY',)
                ipam_url = os.environ.get('IPAM_URL')
            with ProteusIPAMWrapper(
                ipam_username,
                ipam_password,
                ipam_url
            ) as ipam:
                if not ipam.enter_ok:
                    continue

                while True:
                    try:
                        v_scanner_username = settings.V_SCANNER_USERNAME
                        v_scanner_password = settings.V_SCANNER_SECRET_KEY
                        v_scanner_url = settings.V_SCANNER_URL
                    except Exception:
                        v_scanner_username = os.environ.get(
                            'V_SCANNER_USERNAME'
                        )
                        v_scanner_password = os.environ.get(
                            'V_SCANNER_SECRET_KEY'
                        )
                        v_scanner_url = os.environ.get(
                            'V_SCANNER_URL'
                        )
                    with GmpScannerWrapper(
                        v_scanner_username,
                        v_scanner_password,
                        v_scanner_url
                    ) as scanner:
                        if not scanner.enter_ok:
                            continue

                        """ GET DATA """

                        # get all hosts in IPAM
                        logger.info("Get assets from IPAM!")
                        ipam_hosts_total = {}
                        admin_tag_names = ipam.get_all_admin_names()
                        for a_tag_name in admin_tag_names:
                            hosts = ipam.get_hosts_of_admin(
                                admin_name=a_tag_name
                            )
                            for host in hosts:
                                ipam_hosts_total[str(host.ipv4_addr)] = host

                        logger.info('Get assets in periodic scan!')
                        try:
                            v_scanner_hosts = set()
                            # get periodic task info, get target info,
                            # get hosts
                            filter_str = (
                                f'"{scanner.PERIODIC_TASK_NAME}" '
                                + 'rows=-1 first=1'
                            )
                            response = scanner.gmp.get_tasks(
                                filter_string=filter_str
                            )
                            response_status = int(response.xpath('@status')[0])
                            if response_status != 200:
                                raise RuntimeError(
                                    ("Couldn't get tasks! "
                                     + f"Status: {response_status}")
                                )

                            # if stash target exists use it, else use
                            # default target
                            target_uuid = scanner._GmpVScannerInterface__get_target_id(
                                scanner.PERIODIC_TASK_STASH_TARGET_NAME
                            )
                            if not target_uuid:
                                target_uuid = response.xpath('//target/@id')[0]

                            response = scanner.gmp.get_target(target_uuid)
                            response_status = int(response.xpath('@status')[0])
                            if response_status != 200:
                                raise RuntimeError(
                                    ("Couldn't get target! "
                                     + f"Status: {response_status}")
                                )
                            hosts_str = response.xpath('//hosts')[0].text
                            v_scanner_hosts = {h.strip()
                                               for h in hosts_str.split(',')}
                        except Exception:
                            logger.exception("")

                        """ SYNC DATA """

                        for ipv4, host in ipam_hosts_total.items():

                            match host.status:
                                case HostStatusContract.ONLINE:
                                    self.__sync_host_online(
                                        host,
                                        ipam,
                                        scanner,
                                        v_scanner_hosts
                                    )
                                case HostStatusContract.UNDER_REVIEW:
                                    self.__sync_host_under_review(host)
                                case (HostStatusContract.BLOCKED
                                      | HostStatusContract.UNREGISTERED):
                                    self.__sync_host_blocked(
                                        host,
                                        ipam,
                                        scanner,
                                        v_scanner_hosts
                                    )
                                case _:
                                    logger.warning("Invalid host status: %s",
                                                   str(host.status))

                    logger.info("Sync IPAM and scanner finished.")
                    return


if __name__ == "__main__":
    # set logger for manual executions
    logger.setLevel(logging.DEBUG)
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-s',
        '--sync',
        action='store_true',
        help='Indicates whether to actually update the Scanner config'
    )
    args = parser.parse_args()

    c = Command()
    c.handle(sync=args.sync)
