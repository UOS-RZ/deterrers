from django.core.management.base import BaseCommand
import os
import argparse
import ipaddress
import logging

from django.conf import settings

from hostadmin.core.data_logic.ipam_wrapper import ProteusIPAMWrapper
from hostadmin.core.fw.pa_wrapper import PaloAltoWrapper
from hostadmin.core.contracts import HostStatus, HostServiceProfile
from hostadmin.core.host import MyHost

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Compares data in IPAM with data in perimeter FW.'

    sync = False

    def add_arguments(self, parser):
        parser.add_argument(
            '-s',
            '--sync',
            action='store_true',
            help='Indicates whether to actually update the FW configuration'
        )

    def __sync_host_online(
        self,
        host: MyHost,
        ipam: ProteusIPAMWrapper,
        fw: PaloAltoWrapper,
        fw_ip_addrs_allowed_sp: set
    ):

        ipv6s = {ipaddress.IPv6Address(ipv6)
                 for ipv6 in ipam.get_IP6Addresses(host)}
        if len(ipv6s) > 1:
            logger.info(f"---> {host.ipv4_addr} is linked to {ipv6s}")
        ips = ipv6s.union({host.ipv4_addr, })

        if ips.difference(fw_ip_addrs_allowed_sp):
            logger.warning(
                "IPs %s are not in service profile %s",
                str(ips.difference(fw_ip_addrs_allowed_sp)),
                str(host.service_profile)
            )
            if self.sync:
                fw.block_ips([str(ip) for ip in ips])
                fw.allow_service_profile_for_ips(
                    [str(ip) for ip in ips],
                    host.service_profile
                )

    def __sync_host_blocked(
        self,
        host:  MyHost,
        ipam: ProteusIPAMWrapper,
        fw: PaloAltoWrapper,
        fw_ip_addrs_allowed_total: set
    ):

        ipv6s = {ipaddress.IPv6Address(ipv6)
                 for ipv6 in ipam.get_IP6Addresses(host)}
        if len(ipv6s) > 1:
            logger.info(f"---> {host.ipv4_addr} is linked to {ipv6s}")
        ips = ipv6s.union({host.ipv4_addr, })

        if ips.intersection(fw_ip_addrs_allowed_total):
            logger.warning(
                "IPs %s are allowed but should be blocked",
                str(ips.intersection(fw_ip_addrs_allowed_total))
            )
            if self.sync:
                fw.block_ips([str(ip) for ip in ips])

    def __sync_host_under_review(self, host: MyHost):
        logger.info("Host under review: %s", str(host.ipv4_addr))

    def handle(self, *args, **options):
        logger.info("Start sync IPAM and FW.")
        # quick sanity check if service profiles and address groups are
        # still up-to-date
        if not (
            {
                sp for sp in HostServiceProfile
            } == {
                HostServiceProfile.EMPTY,
                HostServiceProfile.HTTP,
                HostServiceProfile.SSH,
                HostServiceProfile.HTTP_SSH,
                HostServiceProfile.MULTIPURPOSE
            }
        ):
            logger.error("Service Profiles not up-to-date!")
            exit()

        self.sync = options['sync']

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
                        fw_username = settings.FIREWALL_USERNAME
                        fw_password = settings.FIREWALL_SECRET_KEY
                        fw_url = settings.FIREWALL_URL
                    except Exception:
                        fw_username = os.environ.get('FIREWALL_USERNAME')
                        fw_password = os.environ.get('FIREWALL_SECRET_KEY')
                        fw_url = os.environ.get('FIREWALL_URL')
                    with PaloAltoWrapper(
                        fw_username,
                        fw_password,
                        fw_url
                    ) as fw:
                        if not fw.enter_ok:
                            continue

                        """ GET DATA """

                        # get all hosts in IPAM
                        logger.info("Get assets from IPAM!")
                        ipam_hosts_total = {
                            sp: set()
                            for sp in HostServiceProfile
                        }
                        admin_tag_names = ipam.get_all_admin_names()
                        for a_tag_name in admin_tag_names:
                            hosts = ipam.get_hosts_of_admin(
                                admin_name=a_tag_name
                            )
                            for host in hosts:
                                ipam_hosts_total[host.service_profile].add(
                                    host
                                )

                        """ SYNC DATA """

                        for service_profile, hosts in ipam_hosts_total.items():
                            # get addresses from firewall that are in the
                            # service profile
                            fw_ip_addrs_allowed_sp = fw.get_addrs_in_service_profile(
                                service_profile
                            )

                            # get addresses from firewall are in some allowing
                            # service profile
                            fw_ip_addrs_allowed_total = set()
                            for out_sp in set(HostServiceProfile).difference(
                                {HostServiceProfile.EMPTY, }
                            ):
                                fw_ip_addrs_allowed_total.update(
                                    fw.get_addrs_in_service_profile(out_sp)
                                )

                            # iterate through all hosts and sync them according
                            # to their status
                            for host in hosts:
                                match host.status:
                                    case HostStatus.ONLINE:
                                        self.__sync_host_online(
                                            host,
                                            ipam,
                                            fw,
                                            fw_ip_addrs_allowed_sp
                                        )
                                    case HostStatus.UNDER_REVIEW:
                                        self.__sync_host_under_review(host)
                                    case (HostStatus.BLOCKED
                                          | HostStatus.UNREGISTERED):
                                        self.__sync_host_blocked(
                                            host,
                                            ipam,
                                            fw,
                                            fw_ip_addrs_allowed_total
                                        )
                                    case _:
                                        logger.warning(
                                            "Invalid host status: %s",
                                            str(host.status)
                                        )

                    logger.info("Sync IPAM and FW finished.")
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
        help='Indicates whether to actually update the FW configuration'
    )
    args = parser.parse_args()

    c = Command()
    c.handle(sync=args.sync)
