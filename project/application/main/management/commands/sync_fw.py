from django.core.management.base import BaseCommand
import os
import argparse
import ipaddress
import logging

from django.conf import settings

from main.core.contracts import HostStatus, HostServiceProfile
from main.core.host import MyHost
if settings.IPAM_DUMMY:
    from main.core.data_logic.data_mock \
        import DataMockWrapper as IPAMWrapper
else:
    from main.core.data_logic.ipam_wrapper \
        import ProteusIPAMWrapper as IPAMWrapper
if settings.FIREWALL_DUMMY:
    from main.core.fw.fw_mock \
        import FWMock as FWWrapper
else:
    from main.core.fw.pa_wrapper \
        import PaloAltoWrapper as FWWrapper

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
        ipam: IPAMWrapper,
        fw: FWWrapper,
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
        ipam: IPAMWrapper,
        fw: FWWrapper,
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
            with IPAMWrapper(
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
                    with FWWrapper(
                        fw_username,
                        fw_password,
                        fw_url
                    ) as fw:
                        if not fw.enter_ok:
                            continue

                        # TODO: move logic to corresponding wrappers to
                        # generalize it

                        """ GET DATA """

                        # get all hosts in IPAM
                        logger.info("Get assets from IPAM!")
                        ipam_hosts_total = {
                            sp: set()
                            for sp in HostServiceProfile
                        }
                        ipam_ips_allowed_cnt = 0
                        ipam_ip_addrs_allowed_total = set()
                        admin_tag_names = ipam.get_all_admin_names()
                        for a_tag_name in admin_tag_names:
                            hosts = ipam.get_hosts_of_admin(
                                admin_name=a_tag_name
                            )
                            for host in hosts:
                                if (
                                    host.service_profile
                                    and host.service_profile != HostServiceProfile.EMPTY
                                    and host not in ipam_hosts_total[host.service_profile]
                                ):
                                    ipam_hosts_total[host.service_profile].add(
                                        host
                                    )
                                    if host.status in (
                                        HostStatus.ONLINE, HostStatus.UNDER_REVIEW
                                    ):
                                        ipam_ip_addrs_allowed_total.add(
                                            str(host.ipv4_addr)
                                        )
                                        ipv6s = ipam.get_IP6Addresses(host)
                                        ipam_ip_addrs_allowed_total.update(
                                            ipv6s
                                        )
                                        ipam_ips_allowed_cnt += (1 + len(ipv6s))
                        logger.info(
                            'Got %d IPs allowed or under review.',
                            ipam_ips_allowed_cnt
                        )

                        # get addresses from firewall that are in some
                        # allowing service profile
                        logger.info('Get assets from FW!')
                        fw_ip_addrs_allowed_total = set()
                        for out_sp in set(HostServiceProfile).difference(
                            {HostServiceProfile.EMPTY, }
                        ):
                            for ip in fw.get_addrs_in_service_profile(out_sp):
                                if type(ip) is ipaddress.IPv4Address:
                                    fw_ip_addrs_allowed_total.add(str(ip))
                                if type(ip) is ipaddress.IPv6Address:
                                    fw_ip_addrs_allowed_total.add(ip.exploded)
                        logger.info(
                            'Got %d IPs allowed at FW.',
                            len(fw_ip_addrs_allowed_total)
                        )

                        """ SYNC DATA """

                        # block IPs that are still allowed at FW even though
                        # they are not in IPAM
                        ips_to_block = fw_ip_addrs_allowed_total.difference(
                                    ipam_ip_addrs_allowed_total
                        )
                        if ips_to_block:
                            logger.warning(
                                ("IPs %s were still allowed at FW but not " +
                                 "defined in IPAM!"),
                                str(ips_to_block)
                            )
                            if self.sync:
                                fw.block_ips(
                                    list(
                                        fw_ip_addrs_allowed_total.difference(
                                            ipam_ip_addrs_allowed_total
                                        )
                                    )
                                )

                        # sync hosts that are defined in IPAM
                        for service_profile, hosts in ipam_hosts_total.items():
                            # get addresses from firewall that are in the
                            # service profile
                            fw_ip_addrs_allowed_sp = fw.get_addrs_in_service_profile(   # noqa: E501
                                service_profile
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
