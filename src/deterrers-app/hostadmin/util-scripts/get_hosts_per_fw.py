import getpass

from hostadmin.core.data_logic.ipam_wrapper import ProteusIPAMWrapper
from hostadmin.core.contracts import HostFWContract


if __name__ == '__main__':
    username = 'nwintering'
    password = getpass.getpass(f"Password for {username}:")

    fw_host_mapping = {fw: set() for fw in HostFWContract}
    with ProteusIPAMWrapper(username, password, 'proteus.rz.uos.de') as ipam:
        admin_tag_names = ipam.get_all_admin_names()
        for a_tag_name in admin_tag_names:
            hosts = ipam.get_hosts_of_admin(admin_name=a_tag_name)
            for host in hosts:
                fw_host_mapping[host.fw].add(host.ipv4_addr)

        for host in fw_host_mapping.get(HostFWContract.FIREWALLD):
            print(
                f"  {host} {ipam.get_host_info_from_ip(str(host)).admin_ids}"
            )
