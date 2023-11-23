from django.core.management.base import BaseCommand
import logging

from django.conf import settings

if settings.IPAM_DUMMY:
    from main.core.data_logic.data_mock \
        import DataMockWrapper as IPAMWrapper
else:
    from main.core.data_logic.ipam_wrapper \
        import ProteusIPAMWrapper as IPAMWrapper

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = ('Checks host validities.')

    def handle(self, *args, **options):
        logger.info("Start!")

        ipam_username = settings.IPAM_USERNAME
        ipam_password = settings.IPAM_SECRET_KEY
        ipam_url = settings.IPAM_URL
        with IPAMWrapper(
            ipam_username,
            ipam_password,
            ipam_url
        ) as ipam:
            if not ipam.enter_ok:
                return

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

            for ipv4, host in ipam_hosts_total.items():
                if not host.is_valid():
                    logger.error("Host %s not valid.", str(host))
