from django.core.management.base import BaseCommand, CommandError
import os
import getpass
import logging
import datetime


from django.core.mail import EmailMessage
from django.conf import settings

from hostadmin.core.fw_interface import PaloAltoInterface

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Commits changes to perimter FW if there are any.'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        fw_username = settings.FIREWALL_USERNAME
        fw_password = settings.FIREWALL_SECRET_KEY
        fw_url = settings.FIREWALL_URL
        with PaloAltoInterface(fw_username, fw_password, fw_url) as fw:
            if not fw.enter_ok:
                logger.error("Couldn't start session with perimter FW!")
                return
                    
            if not fw.commit_changes():
                logger.error("Couldn't commit changes to perimeter FW!")
            else:
                logger.info("Requested commit successfully!")



if __name__ == "__main__":
    Command().handle()
