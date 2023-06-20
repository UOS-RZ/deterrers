from django.core.management.base import BaseCommand
import os
import argparse
import ipaddress
import logging

from django.conf import settings

from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.fw_interface import PaloAltoInterface, PaloAltoAddressGroup
from hostadmin.core.contracts import HostStatusContract, HostServiceContract
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

    def __add_ips_to_addr_grps(
        self,
        fw: PaloAltoInterface,
        ips: list,
        grps: set
    ):
        logger.warning(
            "IPs %s are missing in AddressGroups %s",
            str(ips),
            str(grps)
        )
        if self.sync:
            fw.add_addr_objs_to_addr_grps(ips, grps)

    def __rmv_ips_from_addr_grps(
        self,
        fw: PaloAltoInterface,
        ips: list,
        grps: set
    ):
        logger.warning(
            "IPs %s are wrongfully present in AddressGroups %s",
            str(ips),
            str(grps)
        )
        if self.sync:
            fw.remove_addr_objs_from_addr_grps(ips, grps)

    def __sync_host_online(
        self,
        host: MyHost,
        ipam: ProteusIPAMInterface,
        fw: PaloAltoInterface,
        fw_web_ipv4s: set,
        fw_ssh_ipv4s: set,
        fw_open_ipv4s: set,
        fw_web_ipv6s: set,
        fw_ssh_ipv6s: set,
        fw_open_ipv6s: set
    ):

        ipv4 = str(host.ipv4_addr)
        ipv6s = ipam.get_IP6Addresses(ipam.get_id_of_addr(ipv4))
        if len(ipv6s) > 1:
            logger.info(f"---> {ipv4} is linked to {ipv6s}")

        match host.service_profile:
            case HostServiceContract.HTTP:
                if ipv4 not in fw_web_ipv4s:
                    self.__add_ips_to_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.HTTP, }
                    )
                if ipv4 in fw_ssh_ipv4s:
                    self.__rmv_ips_from_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.SSH, }
                    )
                if ipv4 in fw_open_ipv4s:
                    self.__rmv_ips_from_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.OPEN, }
                    )
                for ipv6 in ipv6s:
                    if ipv6 not in fw_web_ipv6s:
                        self.__add_ips_to_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.HTTP, }
                        )
                    if ipv6 in fw_ssh_ipv6s:
                        self.__rmv_ips_from_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.SSH, }
                        )
                    if ipv6 in fw_open_ipv6s:
                        self.__rmv_ips_from_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.OPEN, }
                            )

            case HostServiceContract.SSH:
                if ipv4 in fw_web_ipv4s:
                    self.__rmv_ips_from_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.HTTP, }
                    )
                if ipv4 not in fw_ssh_ipv4s:
                    self.__add_ips_to_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.SSH, }
                    )
                if ipv4 in fw_open_ipv4s:
                    self.__rmv_ips_from_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.OPEN, }
                    )
                for ipv6 in ipv6s:
                    if ipv6 in fw_web_ipv6s:
                        self.__rmv_ips_from_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.HTTP, }
                        )
                    if ipv6 not in fw_ssh_ipv6s:
                        self.__add_ips_to_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.SSH, }
                        )
                    if ipv6 in fw_open_ipv6s:
                        self.__rmv_ips_from_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.OPEN, }
                        )
            case HostServiceContract.HTTP_SSH:
                if ipv4 not in fw_web_ipv4s:
                    self.__add_ips_to_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.HTTP, }
                    )
                if ipv4 not in fw_ssh_ipv4s:
                    self.__add_ips_to_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.SSH, }
                    )
                if ipv4 in fw_open_ipv4s:
                    self.__rmv_ips_from_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.OPEN, }
                    )
                for ipv6 in ipv6s:
                    if ipv6 not in fw_web_ipv6s:
                        self.__add_ips_to_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.HTTP, }
                        )
                    if ipv6 not in fw_ssh_ipv6s:
                        self.__add_ips_to_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.SSH, }
                        )
                    if ipv6 in fw_open_ipv6s:
                        self.__rmv_ips_from_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.OPEN, }
                        )
            case HostServiceContract.MULTIPURPOSE:
                if ipv4 in fw_web_ipv4s:
                    self.__rmv_ips_from_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.HTTP, }
                    )
                if ipv4 in fw_ssh_ipv4s:
                    self.__rmv_ips_from_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.SSH, }
                    )
                if ipv4 not in fw_open_ipv4s:
                    self.__add_ips_to_addr_grps(
                        fw,
                        [ipv4, ],
                        {PaloAltoAddressGroup.OPEN, }
                    )
                for ipv6 in ipv6s:
                    if ipv6 in fw_web_ipv6s:
                        self.__rmv_ips_from_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.HTTP, }
                        )
                    if ipv6 in fw_ssh_ipv6s:
                        self.__rmv_ips_from_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.SSH, }
                        )
                    if ipv6 not in fw_open_ipv6s:
                        self.__add_ips_to_addr_grps(
                            fw,
                            [ipv6, ],
                            {PaloAltoAddressGroup.OPEN, }
                        )
            case HostServiceContract.EMPTY:
                if ipv4 in fw_web_ipv4s.union(
                    fw_ssh_ipv4s
                ).union(fw_open_ipv4s):
                    self.__rmv_ips_from_addr_grps(
                        fw,
                        [ipv4, ],
                        {addr_grp for addr_grp in PaloAltoAddressGroup}
                    )

                for ipv6 in ipv6s:
                    if ipv6 in fw_web_ipv6s.union(
                        fw_ssh_ipv6s
                    ).union(fw_open_ipv6s):
                        self.__rmv_ips_from_addr_grps(
                            fw,
                            [ipv6, ],
                            {addr_grp for addr_grp in PaloAltoAddressGroup}
                        )
            case _:
                logger.warning(
                    "Invalid service profile %s for %s",
                    str(host.service_profile),
                    str(ipv4)
                )
                # TODO: maybe make also sure that ips are not present in
                # any AddressGroup
                return

    def __sync_host_blocked(
        self,
        host:  MyHost,
        ipam: ProteusIPAMInterface,
        fw: PaloAltoInterface,
        fw_web_ipv4s: set,
        fw_ssh_ipv4s: set,
        fw_open_ipv4s: set,
        fw_web_ipv6s: set,
        fw_ssh_ipv6s: set,
        fw_open_ipv6s: set
    ):

        ipv4 = str(host.ipv4_addr)
        ipv6s = ipam.get_IP6Addresses(ipam.get_id_of_addr(ipv4))
        if len(ipv6s) > 1:
            logger.info(f"---> {ipv4} is linked to {ipv6s}")

        if ipv4 in fw_web_ipv4s.union(fw_ssh_ipv4s).union(fw_open_ipv4s):
            self.__rmv_ips_from_addr_grps(
                fw,
                [ipv4, ],
                {addr_grp for addr_grp in PaloAltoAddressGroup}
            )

        for ipv6 in ipv6s:
            if ipv6 in fw_web_ipv6s.union(fw_ssh_ipv6s).union(fw_open_ipv6s):
                self.__rmv_ips_from_addr_grps(
                    fw,
                    [ipv6, ],
                    {addr_grp for addr_grp in PaloAltoAddressGroup}
                )

    def __sync_host_under_review(self, host: MyHost):
        logger.info("Host under review: %s", str(host.ipv4_addr))

    def handle(self, *args, **options):
        # quick sanity check if service profiles and address groups are
        # still up-to-date
        if not (
            {
                sp for sp in HostServiceContract
            } == {
                HostServiceContract.EMPTY,
                HostServiceContract.HTTP,
                HostServiceContract.SSH,
                HostServiceContract.HTTP_SSH,
                HostServiceContract.MULTIPURPOSE
            }
        ):
            logger.error("Service Profiles not up-to-date!")
            exit()
        if not (
            {
                addrgrp for addrgrp in PaloAltoAddressGroup
            } == {
                PaloAltoAddressGroup.HTTP,
                PaloAltoAddressGroup.SSH,
                PaloAltoAddressGroup.OPEN
            }
        ):
            logger.error("Palo Alto AddressGroups are not up-to-date!")
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
            with ProteusIPAMInterface(
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
                    with PaloAltoInterface(
                        fw_username,
                        fw_password,
                        fw_url
                    ) as fw:
                        if not fw.enter_ok:
                            continue

                        """ GET DATA """

                        # get all hosts in IPAM
                        logger.info("Get assets from IPAM!")
                        ipam_hosts_total = {}
                        admin_tag_names = ipam.get_admin_tag_names()
                        for a_tag_name in admin_tag_names:
                            hosts = ipam.get_hosts_of_admin(
                                admin_rz_id=a_tag_name
                            )
                            for host in hosts:
                                ipam_hosts_total[str(host.ipv4_addr)] = host

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
                                    ipv4 = ipaddress.IPv4Address(
                                        addr_obj.replace('-', '.')
                                    )
                                    fw_ipv4s.add(str(ipv4))
                                    match ag:
                                        case PaloAltoAddressGroup.HTTP:
                                            fw_web_ipv4s.add(str(ipv4))
                                        case PaloAltoAddressGroup.SSH:
                                            fw_ssh_ipv4s.add(str(ipv4))
                                        case PaloAltoAddressGroup.OPEN:
                                            fw_open_ipv4s.add(str(ipv4))
                                    continue
                                except Exception:
                                    pass
                                # check if IPv6
                                try:
                                    ipv6 = ipaddress.IPv6Address(
                                        addr_obj.replace('-', ':')
                                    ).exploded
                                    fw_ipv6s.add(str(ipv6))
                                    match ag:
                                        case PaloAltoAddressGroup.HTTP:
                                            fw_web_ipv6s.add(str(ipv6))
                                        case PaloAltoAddressGroup.SSH:
                                            fw_ssh_ipv6s.add(str(ipv6))
                                        case PaloAltoAddressGroup.OPEN:
                                            fw_open_ipv6s.add(str(ipv6))
                                except Exception:
                                    logger.exception(
                                        f"Could not parse {addr_obj}"
                                    )

                        """ SYNC DATA """

                        for ipv4, host in ipam_hosts_total.items():
                            match host.status:
                                case HostStatusContract.ONLINE:
                                    self.__sync_host_online(
                                        host,
                                        ipam,
                                        fw,
                                        fw_web_ipv4s,
                                        fw_ssh_ipv4s,
                                        fw_open_ipv4s,
                                        fw_web_ipv6s,
                                        fw_ssh_ipv6s,
                                        fw_open_ipv6s
                                    )
                                case HostStatusContract.UNDER_REVIEW:
                                    self.__sync_host_under_review(host)
                                case (HostStatusContract.BLOCKED
                                      | HostStatusContract.UNREGISTERED):
                                    self.__sync_host_blocked(
                                        host,
                                        ipam,
                                        fw,
                                        fw_web_ipv4s,
                                        fw_ssh_ipv4s,
                                        fw_open_ipv4s,
                                        fw_web_ipv6s,
                                        fw_ssh_ipv6s,
                                        fw_open_ipv6s
                                    )
                                case _:
                                    logger.warning(
                                        "Invalid host status: %s",
                                        str(host.status)
                                    )

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
