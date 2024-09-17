from django.core.management.base import BaseCommand
import logging


from django.conf import settings

if settings.FIREWALL_TYPE == 'DUMMY':
    from main.core.fw.fw_mock \
        import FWMock as FWWrapper
elif settings.FIREWALL_TYPE == 'PaloAlto':
    from main.core.fw.pa_wrapper \
        import PaloAltoWrapper as FWWrapper
elif settings.FIREWALL_TYPE == 'FortiGate':
    from main.core.fw.fg_wrapper \
        import FortigateWrapper as FWWrapper
else:
    raise ImportError("Invalid firewall type!")

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Commits changes to perimeter FW if there are any.'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        fw_username = settings.FIREWALL_USERNAME
        fw_password = settings.FIREWALL_SECRET_KEY
        fw_url = settings.FIREWALL_URL
        with FWWrapper(fw_username, fw_password, fw_url) as fw:
            if not fw.enter_ok:
                logger.error("Couldn't start session with perimeter FW!")
                return

            if not fw.commit_changes():
                logger.error("Couldn't commit changes to perimeter FW!")
