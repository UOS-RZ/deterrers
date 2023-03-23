import getpass
import ipaddress

from ..core.fw_interface import PaloAltoInterface
from ..core.ipam_api_interface import ProteusIPAMInterface
from ..core.contracts import PaloAltoAddressGroup



if __name__ == "__main__":
    fw_username = 'nwintering'
    fw_password = getpass.getpass(f'FW password for {fw_username}:')
    ipam_username = 'deterrers'
    ipam_password = getpass.getpass(f'IPAM password for {ipam_username}:')

    with PaloAltoInterface(fw_username, fw_password, 'pa-5220.rz.uni-osnabrueck.de') as fw:
        if not fw.enter_ok:
            exit(-1)
        with ProteusIPAMInterface(ipam_username, ipam_password, 'proteus.rz.uos.de') as ipam:
            if not ipam.enter_ok:
                exit(-1)
            # for each service profile address group
            for address_group in PaloAltoAddressGroup:
                addrs_to_add = list()
                # get all ip addresses in that group
                addr_obj_names = fw.get_addr_objs_in_addr_grp(address_group)
                # for each ip address
                for addr_obj_name in addr_obj_names:
                    ip_addr = addr_obj_name.replace('-', '.')
                    try:
                        if not isinstance(ipaddress.ip_address(ip_addr), ipaddress.IPv4Address):
                            continue
                    except ValueError:
                        continue
                    # get ipv6 address if exists
                    ip_id = ipam.get_id_of_addr(ip_addr)
                    ipv6_addrs = ipam.get_IP6Address_if_linked(ip_id)
                    if ipv6_addrs:
                        addrs_to_add.extend(ipv6_addrs)

                # add ipv6 address object to the same address group as ipv4 address
                print(fw.add_addr_objs_to_addr_grps(set(addrs_to_add), {address_group,}))
                print(address_group.value)
                print(addrs_to_add)
                print(len(addrs_to_add))
