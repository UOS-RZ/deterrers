"""
Management Command for filling the database with dummy data.
"""
import random

# from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand
from hostadmin.models import HostAdmin
from myuser.models import MyUser


class Command(BaseCommand):
    """
    Command class for the init_dummy_db-command.
    """
    help = "Creates dummy data for the database."

    def add_arguments(self, parser):
        parser.add_argument('--su_password', nargs='+', type=str)
        parser.add_argument('--u_password', nargs='+', type=str)

    def handle(self, *args, **options):
        # create dummy users
        try:
            MyUser.objects.get(username='nwintering')
        except MyUser.DoesNotExist:
            superuser = MyUser.objects.create_superuser("nwintering", "nwintering@uni-osnabrueck.de", options['su_password'][0])
            superuser.first_name = 'Nikolas'
            superuser.last_name = 'Wintering'
            superuser.save()
        try:
            MyUser.objects.get(username='mmusterman')
        except MyUser.DoesNotExist:
            user = MyUser.objects.create_user("mmustermann", "mmustermann@uos.de", options['u_password'][0])
            user.first_name = 'Max'
            user.last_name = 'Mustermann'
            user.save()

        # group = Group.objects.get(name="Host Administrator")
        # superuser.groups.add(group)
        # user.groups.add(group)

        admin1 = HostAdmin(user=superuser)
        admin1.save()
        admin2 = HostAdmin(user=user)
        admin2.save()
