import logging
import requests
import json
from enum import Enum
import ipaddress

from main.core.fw.fw_abstract import FWAbstract
from main.core.contracts import (HostStatus,
                                 HostServiceProfile)


logger = logging.getLogger(__name__)


class FortigateAPIError(Exception):
    """
    Custom exception that is raised when the Fortigate API does not respond
    as expected.
    """


class AddressGroup(Enum):
    """
    Enumeration of the different AddressGroup names which specify the service
    profiles in the Fortigate firewall configuration.
    """
    HTTP = "FWP1-WEB-DETERRERS"
    SSH = "FWP2-SSH-DETERRERS"
    OPEN = "FWP3-OPEN-DETERRERS"

    @classmethod
    def get_addr_grps(cla, servc_prof: HostServiceProfile) -> set:
        match servc_prof:
            case HostServiceProfile.HTTP:
                return {cla.HTTP, }
            case HostServiceProfile.SSH:
                return {cla.SSH, }
            case HostServiceProfile.HTTP_SSH:
                return {cla.HTTP, cla.SSH}
            case HostServiceProfile.MULTIPURPOSE:
                return {cla.OPEN, }
            case HostServiceProfile.EMPTY:
                return set()
            case _:
                raise NotImplementedError("Unknown service profile!")

    def get_ipv4_name(self):
        return self.value + '-v4'

    def get_ipv6_name(self):
        return self.value + '-v6'


class FortigateWrapper(FWAbstract):
    """
    Interface to Fortigate's ForitOS 7.4.3. Uses the REST API.
    """

    TIMEOUT = 60*5

    def __init__(
        self,
        username: str,
        password: str,
        url: str
    ) -> None:
        super().__init__(username, password, url)

        self.rest_url = f"{url}/api/v2/cmdb/"
        self.header = {
            "Accept": "application/json",
            "Authorization": f"Bearer {password}"
        }
        self.query_params = "?vdom=Uni"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    def __create_addr_obj(self, ip_addr: str) -> str:
        """
        Creates a new AddressObject in the firewall configuration.

        Args:
            ip_addr (str): IPv4 or v6 address of the new AddressObject.

        Returns:
            str: Returns the name of the new AddressObject (derived from
            IP address). Returns None otherwise.
        """
        try:
            ip = ipaddress.ip_address(ip_addr)
        except ValueError:
            logger.error(
                "Provided IP address is neither v4 nor v6: %s", ip_addr
            )
            return None

        payload = {
            'color': 0,
            'name': f"{ip.exploded.replace('.', '-').replace(':', '-')}",
            'comment': 'Auto-generated by DETERRERS',
            'associated-interface': {
                'q_origin_key': '',
            }
        }
        if type(ip) is ipaddress.IPv4Address:
            api_endpoint = "firewall/address"
            payload['subnet'] = f"{ip.exploded}/32"
        elif type(ip) is ipaddress.IPv6Address:
            api_endpoint = "firewall/address6"
            payload['ip6'] = f"{ip.exploded}/128"
        response = requests.post(
            self.rest_url+api_endpoint+self.query_params,
            headers=self.header,
            json=payload,
            verify=True
        )
        data = response.json()
        if not data.get('http_status') or int(data.get('http_status')) != 200:
            logger.warning(
                'Could not create address object. Status %s',
                str(data.get('http_status'))
            )
            return None
        name = data.get('mkey')

        return name

    def __get_addr_obj(self, ip_addr: str) -> str | None:
        """
        Queries a AddressObject from the firewall configuration.

        Args:
            ip_addr (str): IPv4 or v6 address of the AddressObject from which
            the name is derived.

        Returns:
            str|None: Returns the name of the AddressObject if it is found.
            Returns None otherwise.
        """
        try:
            ip = ipaddress.ip_address(ip_addr)
        except ValueError:
            logger.error(
                "Provided IP address is neither v4 nor v6: %s", ip_addr
            )
            return None

        if type(ip) is ipaddress.IPv4Address:
            api_endpoint = f"firewall/address/{ip.exploded.replace('.', '-')}"
        elif type(ip) is ipaddress.IPv6Address:
            api_endpoint = f"firewall/address6/{ip.exploded.replace(':', '-')}"
        query_params = f"{self.query_params}"
        response = requests.get(
            self.rest_url+api_endpoint+query_params,
            headers=self.header,
            verify=True
        )
        data = response.json()

        if not (data.get('status') == 'success'
                and int(data.get('http_status')) == 200):
            return None

        try:
            if len(data.get('results')) > 1:
                logger.error(
                    "There are to many address objects in the firewall with IP %s",
                    ip_addr
                )
                return None
            obj_name = data.get('results')[0].get('name')
        except TypeError:
            return None

        return obj_name

    def __get_all_addr_obj_names(self) -> set[str]:
        """
        Queries all addr obj names at the firewall.

        Returns:
            set[str]: Returns a set of strings.
        """
        obj_names = set()
        for ipv in [4, 6]:
            get_address_url = (
                self.rest_url
                + f"firewall/address{'' if ipv == 4 else '6'}"
                + self.query_params
            )
            response = requests.get(
                get_address_url,
                headers=self.header,
                timeout=self.TIMEOUT,
                verify=True
            )
            data = response.json()

            if (
                not data.get('status') == 'success'
                or int(response.status_code) != 200
            ):
                return []

            obj_names.update({obj['name'] for obj in data.get('results')})

        return obj_names

    def __get_addr_grp_properties(
        self,
        addr_grp: AddressGroup,
        ip_version: int
    ) -> dict:
        """
        Query the properties of an AddressGroup.

        Args:
            addr_grp (AddressGroup): Enum instance of the AddressGroup
            to query.
            ip_version (int): Either 4 or 6.

        Raises:
            FortigateAPIError: Raised if firewall responded unexpectedly.

        Returns:
            dict: Retruns a dictionary of properties.
        """
        if int(ip_version) == 4:
            addr_grp_name = AddressGroup.get_ipv4_name(addr_grp)
            api_endpoint = f'firewall/addrgrp/{addr_grp_name}'
        elif int(ip_version) == 6:
            addr_grp_name = AddressGroup.get_ipv6_name(addr_grp)
            api_endpoint = f'firewall/addrgrp6/{addr_grp_name}'
        else:
            raise FortigateAPIError(f'Invalid IP version: {ip_version}')

        get_addr_grp_params = f"{self.query_params}"
        get_addr_grp_url = (self.rest_url+api_endpoint+get_addr_grp_params)
        response = requests.get(
            get_addr_grp_url,
            headers=self.header,
            timeout=self.TIMEOUT,
            verify=True
        )
        data = response.json()

        if (response.status_code != 200
                or data.get('status') != 'success'
                or len(data.get('results', [])) != 1):

            raise FortigateAPIError(
                f"Could not query Address Group {addr_grp.value} from "
                + f"firewall! Status code: {response.status_code}. "
                + f"Status: {data.get('@status')}")

        addr_grp_props = data.get('results')[0]
        return addr_grp_props

    def commit_changes(self) -> None:
        """
        Not applicable to Fortigate. Does nothing.
        """
        pass

    def get_addrs_in_service_profile(
        self,
        serv_profile: HostServiceProfile
    ) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """
        Query a set of IP addresses for which given internet service profile
        is allowed at perimeter firewall.

        Args:
            serv_profile (HostServiceContract): Internet service profile for
            which IP addresses are queried.

        Returns:
            set[ipaddress.IPv4Address | ipaddress.IPv6Address]: Returns a set
            of IPv4 and IPv6 addresses.
        """
        try:
            ip_addrs = set()
            # get all IPv4 addresses
            api_endpoint = "firewall/addrgrp/"
            # map service profile to address groups
            srvc_prfl_addr_obj_names = self.__get_all_addr_obj_names()
            addr_grps = AddressGroup.get_addr_grps(serv_profile)
            for addr_grp in addr_grps:
                response = requests.get(
                    (
                        self.rest_url
                        + api_endpoint
                        + AddressGroup.get_ipv4_name(addr_grp)
                        + self.query_params
                    ),
                    headers=self.header,
                    verify=True
                )
                data = response.json()
                try:
                    data.get('results')[0].get('member')
                except TypeError:
                    logger.warning(
                        "Could not get members of AddressGroup '%s'",
                        str(addr_grp)
                    )
                    continue
                addr_grp_addr_obj_names = {
                    obj.get('name')
                    for obj in data.get('results')[0].get('member')
                }
                # remove all ip addrs that are not in the relevant addr grps
                srvc_prfl_addr_obj_names.intersection_update(
                    addr_grp_addr_obj_names
                )

            for addr_obj_name in srvc_prfl_addr_obj_names:
                try:
                    ipv4 = ipaddress.IPv4Address(
                        addr_obj_name.replace('-', '.')
                    )
                    ip_addrs.add(ipv4)
                except Exception:
                    pass

            # get all IPv6 addresses
            api_endpoint = "firewall/addrgrp6/"
            # map service profile to address groups
            srvc_prfl_addr_obj_names = self.__get_all_addr_obj_names()
            addr_grps = AddressGroup.get_addr_grps(serv_profile)
            for addr_grp in addr_grps:
                response = requests.get(
                    (
                        self.rest_url
                        + api_endpoint
                        + AddressGroup.get_ipv6_name(addr_grp)
                        + self.query_params
                    ),
                    headers=self.header,
                    verify=True
                )
                data = response.json()
                try:
                    data.get('results')[0].get('member')
                except TypeError:
                    logger.warning(
                        "Could not get members of AddressGroup '%s'",
                        str(addr_grp)
                    )
                    continue
                addr_grp_addr_obj_names = {
                    obj.get('name')
                    for obj in data.get('results')[0].get('member')
                }
                # remove all ip addrs that are not in the relevant addr grps
                srvc_prfl_addr_obj_names.intersection_update(
                    addr_grp_addr_obj_names
                )
            for addr_obj_name in srvc_prfl_addr_obj_names:
                try:
                    ipv4 = ipaddress.IPv6Address(
                        addr_obj_name.replace('-', ':')
                    )
                    ip_addrs.add(ipv4)
                except Exception:
                    pass

            return ip_addrs
        except (FortigateAPIError, json.decoder.JSONDecodeError):
            logger.exception("Couldn't get AddressObjects of AddressGroup %s",
                             addr_grp.value)
            return set()

    def allow_service_profile_for_ips(
        self,
        ip_addrs: list[str],
        service_profile: HostServiceProfile
    ) -> bool:
        """
        Allow internet service profile for multiple IPs.

        Args:
            ip_addrs (list[str]): IP addresses in string format.
            service_profile (HostServiceContract): Internet service profile.

        Returns:
            bool: Returns True on success and False otherwise.
        """
        try:
            addr4_obj_names = []
            addr6_obj_names = []
            for ip in ip_addrs:
                try:
                    ip = ipaddress.ip_address(ip)
                except:
                    continue
                name = self.__get_addr_obj(str(ip))
                if not name:
                    name = self.__create_addr_obj(str(ip))
                if type(ip) is ipaddress.IPv4Address:
                    addr4_obj_names.append(name)
                elif type(ip) is ipaddress.IPv6Address:
                    addr6_obj_names.append(name)

            for addr_grp in AddressGroup.get_addr_grps(service_profile):
                # do IPv4
                addr_grp_name = AddressGroup.get_ipv4_name(addr_grp)
                # get number of ip addrs in addr grp
                addr_grp_props = self.__get_addr_grp_properties(addr_grp, 4)   # noqa: E501
                # put the new addr obj into the addr grp
                api_endpoint = f'firewall/addrgrp/{addr_grp_name}'
                put_addr_grp_url = (
                    self.rest_url
                    + api_endpoint
                    + self.query_params
                )
                payload = {
                    "member": [
                        {'name': member.get('name')}
                        for member in addr_grp_props.get('member', [])
                    ] + [
                        {'name': addr_obj_name}
                        for addr_obj_name in addr4_obj_names
                    ]
                }

                response = requests.put(
                    put_addr_grp_url,
                    json=payload,
                    headers=self.header,
                    timeout=self.TIMEOUT,
                    verify=True
                )
                data = response.json()
                if (response.status_code != 200
                        or data.get('status') != 'success'):
                    raise FortigateAPIError(
                        f"Could not update Address Group {addr_grp_name}. "
                        + f"Status code: {response.status_code}. "
                        + f"Status: {data.get('status')}")
                
                # do IPv6
                addr_grp_name = AddressGroup.get_ipv6_name(addr_grp)
                # get number of ip addrs in addr grp
                addr_grp_props = self.__get_addr_grp_properties(addr_grp, 6)   # noqa: E501
                # put the new addr obj into the addr grp
                api_endpoint = f'firewall/addrgrp6/{addr_grp_name}'
                put_addr_grp_url = (
                    self.rest_url
                    + api_endpoint
                    + self.query_params
                )
                payload = {
                    "member": [
                        {'name': member.get('name')}
                        for member in addr_grp_props.get('member', [])
                    ] + [
                        {'name': addr_obj_name}
                        for addr_obj_name in addr6_obj_names
                    ]
                }

                response = requests.put(
                    put_addr_grp_url,
                    json=payload,
                    headers=self.header,
                    timeout=self.TIMEOUT,
                    verify=True
                )
                data = response.json()
                if (response.status_code != 200
                        or data.get('status') != 'success'):
                    raise FortigateAPIError(
                        f"Could not update Address Group {addr_grp_name}. "
                        + f"Status code: {response.status_code}. "
                        + f"Status: {data.get('status')}")

        except (FortigateAPIError, json.decoder.JSONDecodeError):
            logger.exception("Couldn't add AddressObjects to AddressGroups!")
            return False

        return True

    def block_ips(
        self,
        ip_addrs: list[str]
    ) -> bool:
        """
        Block multiple IPs at the perimeter firewall.

        Args:
            ip_addrs (list[str]): IP addresses in string format.

        Returns:
            bool: Returns True on success and False otherwise.
        """
        try:
            addr4_obj_names = []
            addr6_obj_names = []
            for ip in ip_addrs:
                try:
                    ip = ipaddress.ip_address(ip)
                except:
                    continue
                name = self.__get_addr_obj(str(ip))
                if name:
                    if type(ip) is ipaddress.IPv4Address:
                        addr4_obj_names.append(name)
                    elif type(ip) is ipaddress.IPv6Address:
                        addr6_obj_names.append(name)

            for addr_grp in [addr_grp for addr_grp in AddressGroup]:
                # do IPv4
                addr_grp_name = AddressGroup.get_ipv4_name(addr_grp)
                # get all properties of the address group
                addr_grp_props = self.__get_addr_grp_properties(addr_grp, 4)
                # remove addr obj from addr grp
                api_endpoint = f'firewall/addrgrp/{addr_grp_name}'
                put_addr_grp_url = (
                    self.rest_url
                    + api_endpoint
                    + self.query_params
                )
                payload = {'member': []}
                for member in addr_grp_props.get('member', []):
                    if member.get('name') not in addr4_obj_names:
                        payload['member'].append({'name': member.get('name')})
                response = requests.put(
                    put_addr_grp_url,
                    json=payload,
                    headers=self.header,
                    timeout=self.TIMEOUT,
                    verify=True
                )
                data = response.json()
                if (response.status_code != 200
                        or data.get('status') != 'success'):
                    raise FortigateAPIError(
                        f"Could not update Address Group {addr_grp_name}. "
                        + f"Status code: {response.status_code}. "
                        + f"Status: {data.get('status')}")
                
                # do IPv6
                addr_grp_name = AddressGroup.get_ipv6_name(addr_grp)
                # get all properties of the address group
                addr_grp_props = self.__get_addr_grp_properties(addr_grp, 6)
                # remove addr obj from addr grp
                api_endpoint = f'firewall/addrgrp6/{addr_grp_name}'
                put_addr_grp_url = (
                    self.rest_url
                    + api_endpoint
                    + self.query_params
                )
                payload = {'member': []}
                for member in addr_grp_props.get('member', []):
                    if member.get('name') not in addr6_obj_names:
                        payload['member'].append({'name': member.get('name')})
                response = requests.put(
                    put_addr_grp_url,
                    json=payload,
                    headers=self.header,
                    timeout=self.TIMEOUT,
                    verify=True
                )
                data = response.json()
                if (response.status_code != 200
                        or data.get('status') != 'success'):
                    raise FortigateAPIError(
                        f"Could not update Address Group {addr_grp_name}. "
                        + f"Status code: {response.status_code}. "
                        + f"Status: {data.get('status')}")

        except (FortigateAPIError, json.decoder.JSONDecodeError):
            logger.exception("Couldn't remove AddressObjects from "
                             + "AddressGroups!")
            return False

        return True

    def get_host_status(self, ip_addr: str) -> HostStatus:
        """
        Queries the host status for a given IP address.

        Args:
            ip_addr (str): IP address.

        Returns:
            HostStatusContract: Returns the host status.
        """
        try:
            addr_obj_name = self.__get_addr_obj(ip_addr)
            if not addr_obj_name:
                # if addr_obj does not exist yet, the host has not been
                # registered
                return HostStatus.UNREGISTERED

            for addr_grp in AddressGroup:
                # do IPv4 and IPv6
                for ipv in [4, 6]:
                    # get all properties of the address group
                    addr_grp_obj = self.__get_addr_grp_properties(addr_grp, ipv)
                    for addr_obj in addr_grp_obj.get('member'):
                        if addr_obj_name == addr_obj.get('name'):
                            # if addr_obj is member of any addr_grp than it is online
                            return HostStatus.ONLINE

            # if addr_obj is not member of any addr_grp than it is offline
            return HostStatus.BLOCKED

        except (FortigateAPIError, json.decoder.JSONDecodeError):
            logger.exception(
                "Couldn't remove AddressObject from AddressGroups!"
            )
            return None


# if __name__ == '__main__':
#     logging.basicConfig(level=logging.INFO)
#     import getpass
#     password = getpass.getpass()
#     with FortigateWrapper('deterrers', '<API_KEY>', 'https://fg-3201.net.uos.de') as fw:
#         fw.allow_service_profile_for_ips(['131.173.61.174', '2001:638:508:3d0::83ad:3dae'], HostServiceProfile.SSH)
#         fw.allow_service_profile_for_ips(['1.2.3.4'], HostServiceProfile.SSH)
#         fw.allow_service_profile_for_ips(['1.1.1.2'], HostServiceProfile.HTTP_SSH)
#         fw.allow_service_profile_for_ips(['1.2.3.5'], HostServiceProfile.MULTIPURPOSE)
#         logger.info('Test get_addrs_in_service_profile')
#         logger.info('HTTP')
#         logger.info(fw.get_addrs_in_service_profile(HostServiceProfile.HTTP))
#         logger.info('SSH')
#         logger.info(fw.get_addrs_in_service_profile(HostServiceProfile.SSH))
#         logger.info('HTTP_SSH')
#         logger.info(fw.get_addrs_in_service_profile(HostServiceProfile.HTTP_SSH))
#         logger.info('MULTIPURPOSE')
#         logger.info(fw.get_addrs_in_service_profile(HostServiceProfile.MULTIPURPOSE))

#         # fw.allow_service_profile_for_ips(['1.1.1.1', '1.2.3.4', '2001:638:508:f001:2f98:5e18:b19b:bb3a'], HostServiceProfile.HTTP)
#         # fw.allow_service_profile_for_ips(['1.1.1.2', '1.2.3.5', '2001:638:508:f001:2f98:5e18:b19b:bb3b'], HostServiceProfile.HTTP_SSH)

#         # fw.block_ips(['1.1.1.2', '1.1.1.1', '1.2.3.4', '2001:638:508:f001:2f98:5e18:b19b:bb3a', '1.2.3.5', '2001:638:508:f001:2f98:5e18:b19b:bb3b'])

#         # logger.info(fw.get_host_status('2001:638:508:f001:2f98:5e18:b19b:bb3a'))
#         # logger.info(fw.get_host_status('1.1.1.2'))
#         # logger.info(fw.get_host_status('1.1.1.3'))

#         # logger.info(fw._FortigateWrapper__get_all_addr_obj_names())


# test connection to FW: curl --insecure -H "Accept: application/json" -H "Authorization: Bearer <API_KEY>" https://fg-3201.net.uos.de/api/v2/cmdb/firewall/addrgrp/FWP2-SSH-DETERRERS-v4?vdom=Uni

