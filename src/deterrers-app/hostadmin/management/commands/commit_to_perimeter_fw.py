from django.core.management.base import BaseCommand
import logging


from django.conf import settings

from hostadmin.core.fw.pa_wrapper import PaloAltoWrapper

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Commits changes to perimeter FW if there are any.'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        fw_username = settings.FIREWALL_USERNAME
        fw_password = settings.FIREWALL_SECRET_KEY
        fw_url = settings.FIREWALL_URL
        with PaloAltoWrapper(fw_username, fw_password, fw_url) as fw:
            if not fw.enter_ok:
                logger.error("Couldn't start session with perimeter FW!")
                return

            if not fw.commit_changes():
                logger.error("Couldn't commit changes to perimeter FW!")
