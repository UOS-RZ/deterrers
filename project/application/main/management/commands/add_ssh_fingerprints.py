from django.core.management.base import BaseCommand
import paramiko
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
        if not os.path.isfile(known_hosts):
            open(known_hosts, 'x').close()

        transport = paramiko.Transport(scanner_url + ':' + str(port))
        transport.connect()
        key = transport.get_remote_server_key()
        transport.close()

        hostfile = paramiko.HostKeys(filename=known_hosts)
        hostfile.add(hostname=scanner_url, key=key, keytype=key.get_name())

        hostfile.save(filename=known_hosts)
