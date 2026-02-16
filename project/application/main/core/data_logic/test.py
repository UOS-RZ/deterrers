#testing the blucatV2 wrapper
import sys
import os
import django

current_dir = os.path.dirname(os.path.abspath(__file__))
app_root = os.path.abspath(os.path.join(current_dir, '../../..'))
sys.path.insert(0, app_root)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'application.settings')
django.setup()

from main.core.data_logic.blueCatV2_wrapper import ProteusIPAMWrapper

def main():
    with ProteusIPAMWrapper("pmaskanakis", "u&oAPP3m", "https://proteus-clone.rz.uos.de") as ipam:
        # Adjust these three values to valid entries in your IPAM
        TEST_IP = "131.173.16.172"
        TEST_ADMIN = "andrmuel"
        TEST_DEPARTMENT = "RZ"

        print("user_exists:", ipam.user_exists("pmaskanakis"))
        print("departments:", ipam.get_department_names())
        print("admins:", ipam.get_all_admin_names())
        print("is_admin:", ipam.is_admin(TEST_ADMIN))
        print("department_of_admin:", ipam.get_department_to_admin(TEST_ADMIN))

        host = ipam.get_host_info_from_ip(TEST_IP)
        print("host:", bool(host))
        if host:
            print("ipv6:", ipam.get_IP6Addresses(host))
            print("add_admin:", ipam.add_admin_to_host(TEST_ADMIN, host))
            print("remove_admin:", ipam.remove_admin_from_host(TEST_ADMIN, host))
            host.comment = "test"
            print("update_host_info:", ipam.update_host_info(host))

        # Create admin (will return False if already exists)
        print("create_admin:", ipam.create_admin(TEST_ADMIN, TEST_DEPARTMENT))

if __name__ == "__main__":
    main()


