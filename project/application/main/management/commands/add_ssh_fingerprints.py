from django.core.management.base import BaseCommand
import os


class Command(BaseCommand):
    help = ("Adds the SSH fingerprint of the vulnerability scanner server "
            + "to known_hosts.")

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        scanner_url = os.environ['SCANNER_HOSTNAME']
        port = 22
        known_hosts = f'{os.environ["MICRO_SERVICE"]}/known_hosts'
        # recreate known_hosts file every time
        os.system(f"ssh-keyscan -p {port} {scanner_url} > {known_hosts}")
