import logging
import requests
import time
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


class FortigateWrapper(FWAbstract):
    """
    Interface to Fortigate's ForitOS 7.4.3. Uses the REST API.
    """

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

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    def __create_addr_obj(self, ip_addr: str) -> str:
        """
        TODO: Creates a new AddressObject in the firewall configuration.

        Args:
            ip_addr (str): IPv4 or v6 address of the new AddressObject.

        Returns:
            str: Returns the name of the new AddressObject
            (is derived from IP address).
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
            'name': ip.exploded,
            'comment': 'Auto-generated by DETERRERS',
        }
        if type(ip) is ipaddress.IPv4Address:
            api_endpoint = "firewall/address"
            payload['subnet'] = f"{ip.exploded}/32"
        elif type(ip) is ipaddress.IPv6Address:
            api_endpoint = "firewall/address6"
            payload['ip6'] = f"{ip.exploded}/128"
        response = requests.post(
            self.rest_url+api_endpoint,
            headers=self.header,
            json=payload
        )
        data = response.json()

        # TODO: continue

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
            api_endpoint = "firewall/address"
        elif type(ip) is ipaddress.IPv6Address:
            api_endpoint = "firewall/address6"
        query_params = f"?filter=name=={ip.exploded}"
        response = requests.get(
            self.rest_url+api_endpoint+query_params,
            headers=self.header
        )
        data = response.json()

        if not (data.get('status') == 'success'
                and int(data.get('http_status')) == 200):
            return None

        if int(data.get('matched_count')) == 0:
            return None
        elif int(data.get('matched_count')) > 1:
            logger.error(
                "There are to many address objects in the firewall with IP %s",
                ip_addr
            )
            return None
        obj_name = data.get('results')[0].get('name')

        return obj_name

    def __get_all_addr_obj_names(self) -> set[str]:
        """
        TODO: Queries all addr obj names at the firewall.

        Returns:
            set[str]: Returns a set of strings.
        """
        pass

    def commit_changes(self) -> None:
        """
        Initiate commit if FW works with commits.
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
        pass

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
        pass

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
        pass

    def get_host_status(self, ip_addr: str) -> HostStatus:
        """
        Queries the host status for a given IP address.

        Args:
            ip_addr (str): IP address.

        Returns:
            HostStatusContract: Returns the host status.
        """
        pass
