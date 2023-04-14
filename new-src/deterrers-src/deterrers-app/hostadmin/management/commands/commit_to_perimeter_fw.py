from django.core.management.base import BaseCommand, CommandError
import os
import getpass
import logging
import datetime


from django.core.mail import EmailMessage

from hostadmin.core.fw_interface import PaloAltoInterface

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Commits changes to perimter FW if there are any.'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        fw_username = os.environ.get('FIREWALL_USERNAME', input('FW username: '))
        fw_password = os.environ.get('FIREWALL_SECRET_KEY', getpass.getpass('FW password: '))
        fw_url = os.environ.get('FIREWALL_URL', input('FW URL: '))
        with PaloAltoInterface(fw_username, fw_password, fw_url) as fw:
            if not fw.enter_ok:
                logger.error("Couldn't start session with perimter FW!")
                return
            

            email = EmailMessage(
                subject="Test",
                body=f"Time: {datetime.datetime.now()}",
                from_email=None,
                to=["nwintering@uos.de"]
            )
            try:
                email.send()
            except Exception:
                logger.exception("Couldn't send e-mail!")
                    
            # if not fw.commit_changes():
            #     logger.error("Couldn't commit changes to perimeter FW!")
            
        logger.info("Commit successful!")



if __name__ == "__main__":
    Command().handle()
