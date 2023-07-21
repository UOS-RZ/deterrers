import logging
import requests
from lxml import etree
import time
from enum import Enum
import ipaddress

from hostadmin.core.fw.fw_abstract import FWAbstract
from hostadmin.core.contracts import (HostStatusContract,
                                      HostServiceContract)


logger = logging.getLogger(__name__)


class PaloAltoAPIError(Exception):
    """
    Custom exception that is raised when the Palo Alto API does not respond
    as expected.
    """


class AddressGroup(Enum):
    """
    Enumeration of the different AddressGroup names which specify the service
    profiles in the PaloAlto firewall configuration.
    """
    HTTP = "FWP1-WEB-DETERRERS"
    SSH = "FWP2-SSH-DETERRERS"
    OPEN = "FWP3-OPEN-DETERRERS"

    @classmethod
    def get_addr_grps(cla, servc_prof: HostServiceContract) -> set:
        match servc_prof:
            case HostServiceContract.HTTP:
                return {cla.HTTP, }
            case HostServiceContract.SSH:
                return {cla.SSH, }
            case HostServiceContract.HTTP_SSH:
                return {cla.HTTP, cla.SSH}
            case HostServiceContract.MULTIPURPOSE:
                return {cla.OPEN, }
            case HostServiceContract.EMPTY:
                return set()
            case _:
                raise NotImplementedError("Unknown service profile!")


class PaloAltoWrapper(FWAbstract):
    """
    Interface to the Palo Alto Firewall's PAN-OS v10.1.
    Uses the REST API for object manipulation and XML API for configuration
    and commiting changes.
    """

    TIMEOUT = 60*5
    VERSION = "v10.1"
    LOCATION = 'vsys&vsys=vsys1'

    def __init__(self, username: str, password: str, fw_url: str):
        self.username = username
        self.__password = password
        self.fw_url = fw_url
        self.rest_url = f"https://{fw_url}/restapi/{self.VERSION}/"
        self.xml_url = f"https://{fw_url}/api/"
        self.api_key = None
        self.header = {
            "Accept": "application/json",
        }
        self.enter_ok = True

    def __enter__(self):
        logger.debug("Start firewall interface session.")
        try:
            # get api key for this session
            req_url = (f"{self.xml_url}?type=keygen&user={self.username}"
                       + f"&password={self.__password}")
            response = requests.get(req_url, timeout=self.TIMEOUT)
            response_xml = etree.XML(response.content)
            status_code = response.status_code
            status = response_xml.xpath('//response/@status')[0]
            if status_code != 200 or status != "success":
                raise PaloAltoAPIError((
                    "Could not get API key from firewall!"
                    + f" Status: {status} Code: {status_code}")
                )

            self.api_key = response_xml.xpath('//key')[0].text

            self.header['X-PAN-KEY'] = self.api_key

            self.__acquire_config_lock()
        except (requests.ConnectionError, requests.ConnectTimeout):
            logger.exception("Connection to %s failed!", self.fw_url)
            self.enter_ok = False
        except (etree.XMLSyntaxError):
            logger.exception("Unexpected response!")
            self.enter_ok = False
        except Exception:
            logger.exception("Unknown error source!")
            self.enter_ok = False

        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        logger.debug("End firewall interface session.")
        try:
            self.__release_config_lock()
        except Exception:
            logger.exception("")

    def __acquire_config_lock(self):
        """
        Acquire configuration lock for this session.
        """
        while True:
            acquire_config_lock_url = (
                self.xml_url
                + "?type=op&cmd=<request><config-lock><add><comment>"
                + "DETERRERS config lock</comment></add>"
                + "</config-lock></request>")
            response = requests.get(
                acquire_config_lock_url,
                headers=self.header,
                timeout=self.TIMEOUT
            )
            try:
                response_xml = etree.XML(response.content)
                status = response_xml.xpath('//response/@status')[0]
            except etree.XMLSyntaxError:
                # some error occured on the other side
                time.sleep(0.5)
                continue
            if response.status_code == 200 and status == "success":
                return
            # try again if this did not work
            time.sleep(0.5)

    def __release_config_lock(self):
        """
        Release the configuration lock for this session.
        """
        # https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/pan-os-xml-api-request-types/run-operational-mode-commands-api
        while True:
            release_config_lock_url = (
                self.xml_url
                + "?type=op&cmd=<request><config-lock><remove></remove>"
                + "</config-lock></request>"
            )
            response = requests.get(release_config_lock_url,
                                    headers=self.header, timeout=self.TIMEOUT)
            if response.status_code == 200:
                # exit as soon as server responds with success
                return
            time.sleep(0.5)

    def __create_addr_obj(self, ip_addr: str) -> str:
        """
        Creates a new AddressObject in the firewall configuration.

        Args:
            ip_addr (str): IPv4 or v6 address of the new AddressObject.

        Raises:
            PaloAltoAPIError: Raised when AddressObject couldn't be created.

        Returns:
            str: Returns the name of the new AddressObject
            (is derived from IP address).
        """
        ip_addr_name = ip_addr.replace('.', '-')
        ip_addr_name = ip_addr_name.replace(':', '-')
        create_addr_params = (f"name={ip_addr_name}&location={self.LOCATION}"
                              + "&input-format=json")
        create_addr_url = (self.rest_url + "Objects/Addresses?"
                           + create_addr_params)
        create_addr_payload = {
            "entry": {
                "ip-netmask": ip_addr,
                "@name": ip_addr_name,
                "description": "Auto-generated by DETERRERS",
                # "tag": {
                #     "member": []
                # }
            }
        }
        response = requests.post(create_addr_url, json=create_addr_payload,
                                 headers=self.header, timeout=self.TIMEOUT)
        if response.status_code != 200:
            raise PaloAltoAPIError(
                f"Couldn't create AddressObject for host {ip_addr} in the "
                + "firewall configuration! Status Code: "
                + f"{response.status_code}"
            )

        return ip_addr_name

    def __get_addr_obj(self, ip_addr: str) -> str | None:
        """
        Queries a AddressObject from the firewall configuration.

        Args:
            ip_addr (str): IPv4 or v6 address of the AddressObject from which
            the name is derived.

        Raises:
            PaloAltoAPIError: Thrown when there are more than one
            AddressObjects with this name.

        Returns:
            str|None: Returns the name of the AddressObject if it is found.
            Returns None otherwise.
        """
        ip_addr_name = ip_addr.replace('.', '-')
        ip_addr_name = ip_addr_name.replace(':', '-')

        get_address_params = f"name={ip_addr_name}&location={self.LOCATION}"
        get_address_url = (self.rest_url
                           + "Objects/Addresses?"
                           + get_address_params)
        response = requests.get(get_address_url, headers=self.header,
                                timeout=self.TIMEOUT)
        data = response.json()

        if not (data.get('@status') == 'success'
                and data.get('@code') == '19'):
            return None

        if int(data.get('result').get('@total-count')) != 1:
            raise PaloAltoAPIError(
                "There are to many address objects in the firewall with IP "
                + f"{ip_addr}!"
            )
        obj_name = data.get('result').get('entry')[0].get('@name')

        return obj_name

    def __get_all_addr_obj_names(self) -> set[str]:
        """
        Queries all addr obj names at the firewall.

        Returns:
            set[str]: Returns a set of strings.
        """

        get_address_params = f"location={self.LOCATION}"
        get_address_url = (self.rest_url
                           + "Objects/Addresses?"
                           + get_address_params)
        response = requests.get(get_address_url, headers=self.header,
                                timeout=self.TIMEOUT)
        data = response.json()

        if not (data.get('@status') == 'success'
                and data.get('@code') == '19'):
            return None

        obj_names = {obj['@name'] for obj in data.get('result').get('entry')}

        return obj_names

    def __get_addr_grp_properties(self,
                                  addr_grp: AddressGroup) -> dict:
        """
        Query the properties of an AddressGroup.

        Args:
            addr_grp (AddressGroup): Enum instance of the AddressGroup
            to query.

        Raises:
            PaloAltoAPIError: Raised if firewall responded unexpectedly.

        Returns:
            dict: Retruns a dictionary of properties.
        """
        get_addr_grp_params = f"name={addr_grp.value}&location={self.LOCATION}"
        get_addr_grp_url = (self.rest_url + "Objects/AddressGroups?"
                            + get_addr_grp_params)
        response = requests.get(get_addr_grp_url, headers=self.header,
                                timeout=self.TIMEOUT)
        data = response.json()
        if (response.status_code != 200
                or data.get('@status') != 'success'
                or int(data.get('result').get('@total-count')) != 1):
            #
            raise PaloAltoAPIError(
                f"Could not query Address Group {addr_grp.value} from "
                + f"firewall! Status code: {response.status_code}. "
                + f"Status: {data.get('@status')}")

        addr_grp_props = data.get('result').get('entry')[0]
        return addr_grp_props

    def __changes_pending(self) -> bool:
        """
        Checks if changes are pending.

        Returns:
            bool: Retruns boolean.
        """
        pending_params = ("type=op&cmd=<check><pending-changes>"
                          + "</pending-changes></check>")
        pending_url = self.xml_url + "?" + pending_params
        response = requests.get(pending_url, headers=self.header,
                                timeout=self.TIMEOUT)
        response_xml = etree.XML(response.content)
        status_code = response.status_code
        status = response_xml.xpath("//response/@status")[0]
        if status_code != 200 or status != 'success':
            logger.error("Couldn't query pending changes. "
                         + "Status code: %d. Status: %s", status_code, status)
        pending = (response_xml.xpath("//response/result")[0].text == "yes")
        return pending

    def __cancle_commit(self):
        """
        Try to cancle scheduled commits.

        Raises:
            PaloAltoAPIError: Raised when commit couldn't be canceled.
        """
        cancle_commit_url = (self.xml_url
                             + "?type=op&cmd=<request><clear-commit-tasks>"
                             + "</clear-commit-tasks></request>")
        response = requests.get(cancle_commit_url, headers=self.header,
                                timeout=self.TIMEOUT)
        if response.status_code != 200:
            raise PaloAltoAPIError("Could not cancel commit!")

    def commit_changes(self) -> None:
        """
        Commit changes of current user.

        Returns:
            bool: Returns True on success and False on error.
        """
        if self.__changes_pending():
            commit_params = ("type=commit&cmd=<commit><partial><admin><member>"
                             + f"{self.username}</member></admin></partial>"
                             + "</commit>")
            commit_url = self.xml_url + "?" + commit_params
            response = requests.get(commit_url, headers=self.header,
                                    timeout=self.TIMEOUT)
            response_xml = etree.XML(response.content)
            status_code = response.status_code
            status = response_xml.xpath("//response/@status")[0]
            if status_code != 200 or status != 'success':
                logger.error("Queueing commit failed. Status code: %d. "
                             + "Status: %s", status_code, status)
                return False

            logger.info("Requested commit successfully!")

        else:
            logger.info("No changes pending at perimeter FW.")

        return True

    def get_addrs_in_service_profile(
        self,
        service_profile: HostServiceContract
    ) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """
        Queries all IP addresses that are in some internet service profile
        at the perimeter FW.

        Args:
            service_profile (HostServiceContract): Internet service profile

        Returns:
            set[ipaddress.IPv4Address | ipaddress.IPv6Address]: Returns set of
            ipaddress-objects that are deployed in the given internet service
            profile.
        """
        try:
            ip_addrs = set()
            # map service profile to address groups in Palo Altoaddr_grp
            srvc_prfl_addr_obj_names = self.__get_all_addr_obj_names()
            in_addr_grps = AddressGroup.get_addr_grps(service_profile)
            for addr_grp in in_addr_grps:
                # get all IP addresses in the address group
                addr_grp_addr_obj_names = set(self.__get_addr_grp_properties(
                    addr_grp
                )['static']['member'])
                # remove all ip addrs that are not in the relevant addr grps
                srvc_prfl_addr_obj_names.intersection_update(
                    addr_grp_addr_obj_names
                )

            for addr_grp in set(AddressGroup).difference(in_addr_grps):
                # get all IP addresses in the address group
                addr_grp_addr_obj_names = set(self.__get_addr_grp_properties(
                    addr_grp
                )['static']['member'])
                # remove all ip addrs that are in unrelevant addr grps
                srvc_prfl_addr_obj_names.difference_update(
                    addr_grp_addr_obj_names
                )

            # for all addr objs generate the IPv4/v6 address object if possible
            for addr_obj_name in srvc_prfl_addr_obj_names:
                try:
                    ipv4 = ipaddress.IPv4Address(
                        addr_obj_name.replace('-', '.')
                    )
                    ip_addrs.add(ipv4)
                except Exception:
                    try:
                        ipv6 = ipaddress.IPv6Address(
                            addr_obj_name.replace('-', ':')
                        )
                        ip_addrs.add(ipv6)
                    except Exception:
                        pass

            return ip_addrs
        except (PaloAltoAPIError, requests.exceptions.JSONDecodeError):
            logger.exception("Couldn't get AddressObjects of AddressGroup %s",
                             addr_grp.value)
            return set()

    def allow_service_profile_for_ips(
        self,
        ip_addrs: list[str],
        service_profile: HostServiceContract
    ) -> bool:
        """
        Creates AddressObjects for IP addresses if necessary and adds them
        to some AddressGroups.

        Args:
            ip_addr (list[str]): IP addresses of the AddressObjects.
            addr_grps (set[AddressGroups]): AddressGroups to which the
            AddressObject is added.

        Returns:
            bool: Returns True on success and False if something went wrong.
        """
        try:
            addr_obj_names = []
            for ip in ip_addrs:
                name = self.__get_addr_obj(ip)
                if not name:
                    name = self.__create_addr_obj(ip)
                addr_obj_names.append(name)

            for addr_grp_name in AddressGroup.get_addr_grps(service_profile):
                # get all properties of the address group
                addr_grp_obj = self.__get_addr_grp_properties(addr_grp_name)
                # put the new addr obj into the addr grp
                put_addr_grp_params = (f"name={addr_grp_name.value}&location="
                                       + f"{self.LOCATION}&input-format=json")
                put_addr_grp_url = (self.rest_url + "Objects/AddressGroups?"
                                    + put_addr_grp_params)
                put_addr_grp_payload = {
                    "entry": {
                        "static": {
                            "member": list(set(addr_grp_obj['static']['member']
                                               + addr_obj_names)),
                        },
                        "@name": addr_grp_obj['@name'],
                        "description": addr_grp_obj.get('description', '')
                    }
                }
                response = requests.put(
                    put_addr_grp_url, json=put_addr_grp_payload,
                    headers=self.header, timeout=self.TIMEOUT
                )
                data = response.json()
                if (response.status_code != 200
                        or data.get('@status') != 'success'):
                    raise PaloAltoAPIError(
                        f"Could not update Address Group {addr_grp_name.value}. "
                        + f"Status code: {response.status_code}. "
                        + f"Status: {data.get('@status')}")

        except (PaloAltoAPIError, requests.exceptions.JSONDecodeError):
            logger.exception("Couldn't add AddressObjects to AddressGroups!")
            return False

        return True

    def block_ips(
        self,
        ip_addrs: list[str]
    ) -> bool:
        """
        Removes AddressObjects from all AddressGroups.

        Args:
            ip_addr (list[str]): IP addresses of the AddressObjects.

        Returns:
            bool: Returns True on success and False if something went wrong.
        """
        try:
            addr_obj_names = []
            for ip in ip_addrs:
                name = self.__get_addr_obj(ip)
                if name:
                    addr_obj_names.append(name)
            for addr_grp_name in [addr_grp for addr_grp in AddressGroup]:
                # get all properties of the address group
                addr_grp_obj = self.__get_addr_grp_properties(addr_grp_name)
                # remove addr obj from addr grp
                put_addr_grp_params = (f"name={addr_grp_name.value}&location="
                                       + f"{self.LOCATION}&input-format=json")
                put_addr_grp_url = (self.rest_url + "Objects/AddressGroups?"
                                    + put_addr_grp_params)
                put_addr_grp_payload = {
                    "entry": {
                        "static": {
                            "member": list(
                                set(addr_grp_obj['static']['member'])
                                - set(addr_obj_names)
                            ),
                        },
                        "@name": addr_grp_obj['@name'],
                        "description": addr_grp_obj.get('description', '')
                    }
                }
                response = requests.put(
                    put_addr_grp_url, json=put_addr_grp_payload,
                    headers=self.header, timeout=self.TIMEOUT
                )
                data = response.json()
                if (response.status_code != 200
                        or data.get('@status') != 'success'):
                    raise PaloAltoAPIError(
                        f"Could not update Address Group {addr_grp_name.value}. "
                        + f"Status code: {response.status_code}. "
                        + f"Status: {data.get('@status')}")

        except (PaloAltoAPIError, requests.exceptions.JSONDecodeError):
            logger.exception("Couldn't remove AddressObjects from "
                             + "AddressGroups!")
            return False

        return True

    def get_host_status(self, ip_addr: str) -> HostStatusContract:
        """
        Query the status of a host at the perimeter firewall.

        Args:
            ip_addr (str): IP address of the host.

        Returns:
            HostStatusContract: Returns enum instance representing the
            host status.
        """
        try:
            addr_obj_name = self.__get_addr_obj(ip_addr)
            if not addr_obj_name:
                # if addr_obj does not exist yet, the host has not been
                # registered
                return HostStatusContract.UNREGISTERED

            for addr_grp in AddressGroup:
                # get all properties of the address group
                addr_grp_obj = self.__get_addr_grp_properties(addr_grp)
                if addr_obj_name in addr_grp_obj['static']['member']:
                    # if addr_obj is member of any addr_grp than it is online
                    return HostStatusContract.ONLINE
            # if addr_obj is not member of any addr_grp than it is offline
            return HostStatusContract.BLOCKED

        except (PaloAltoAPIError, requests.exceptions.JSONDecodeError):
            logger.exception("Couldn't remove AddressObject from AddressGroups!")
            return None
