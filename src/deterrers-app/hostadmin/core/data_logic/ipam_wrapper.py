import requests
import logging
import json
import socket
import threading
import ipaddress

from hostadmin.core.data_logic.data_abstract import DataAbstract
from hostadmin.core.host import MyHost
from hostadmin.core.contracts import (HostStatus,
                                      HostServiceProfile,
                                      HostFW)
from hostadmin.core.rule_generator import HostBasedPolicy

logger = logging.getLogger(__name__)

# TODO: check response codes of requests
# TODO: make functions not return bools but rather status codes like in
# add_tag_to_host()


class ProteusIPAMWrapper(DataAbstract):
    """
    Interface to BlueCat's Proteus IP Address Manager REST API
    """
    # settings
    TAG_GROUP_NAME = "Deterrers Host Admins"

    TIMEOUT = 3*180

    def __init__(self, username: str, password: str, url: str):
        super().__init__(username, password, url)

        self.main_url = url + "/Services/REST/v1/"
        self.header = ''
        self.__tag_group_id = None
        self.__department_tags = None

    def __enter__(self):
        login_url = (self.main_url
                     + "login?username="
                     + self.username
                     + "&password="
                     + self._password)
        try:
            # login to BlueCat
            response = requests.get(login_url, timeout=self.TIMEOUT)
            if response.status_code != 200:
                raise RuntimeError('Could not authenticate with IPAM!')
            # get token
            token = (response.json().split()[2]
                     + " "
                     + response.json().split()[3])
            # set http header
            self.header = {
                'Authorization': token,
                'Content-Type': 'application/json'
            }
        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', self.main_url)
            self.enter_ok = False
        except requests.exceptions.ConnectionError:
            logger.exception('Could not establish connection to "%s"!',
                             self.main_url)
            self.enter_ok = False
        except Exception:
            logger.exception('Unexpected error during login to %s!',
                             self.main_url)
            self.enter_ok = False

        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        logout_url = self.main_url + "logout?"
        try:
            # logout from BlueCat
            response = requests.get(logout_url, headers=self.header,
                                    timeout=self.TIMEOUT)
            if response.status_code != 200:
                logger.warning('Could not log out of IPAM!')
        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', logout_url)
        except requests.exceptions.ConnectionError:
            logger.exception('Could not establish connection to "%s"!',
                             logout_url)

    def __parse_ipam_host_entity(self, entity) -> tuple:
        """
        Parses the (user-defined) fields of a IP4Address object in the IPAM.

        Args:
            entity (_type_): Dict with the relevant fields as returned by the
            IPAM.

        Returns:
            tuple: Returns parsed fields as tuple.
        """
        try:
            host_id = entity['id']
        except (KeyError, TypeError):
            host_id = None
        try:
            name = entity['name']
        except (KeyError, TypeError):
            name = ''
        # parse the properties string
        try:
            prop_str = entity['properties'].split('|')
            props = dict([elem.split('=') for elem in prop_str
                          if len(elem.split('=')) == 2])
            try:
                ip = props['address']
            except KeyError:
                ip = ''
            try:
                mac = props['macAddress']
            except KeyError:
                mac = ''
            try:
                status = HostStatus(props['deterrers_status'])
            except KeyError:
                status = None
            try:
                service_profile = HostServiceProfile(
                    props['deterrers_service_profile']
                )
            except KeyError:
                service_profile = HostServiceProfile.EMPTY
            try:
                fw = HostFW(props['deterrers_fw'])
            except KeyError:
                fw = HostFW.EMPTY
            try:
                rules = [HostBasedPolicy.from_string(p_str)
                         for p_str in json.loads(props['deterrers_rules'])]
            except KeyError:
                rules = []
        except (KeyError, AttributeError, TypeError):
            ip = ''
            mac = ''
            status = None
            service_profile = HostServiceProfile.EMPTY
            fw = HostFW.EMPTY
            rules = []
        return host_id, name, ip, mac, status, service_profile, fw, rules

    def __escape_user_input(self, input_str: str) -> str:
        """
        Escape special characters for Proteus IPAM by replacement with their
        hexadecimal equivalent.
        List of special characters is given in
        https://docs.bluecatnetworks.com/r/Address-Manager-API-Guide/Escaping-characters/9.4.0

        Args:
            input_str (str): Input string.

        Returns:
            str: Escaped input.
        """
        input_str.replace('%', '%25')
        input_str.replace('|', '%7C')
        input_str.replace('#', '%23')
        input_str.replace('&', '%26')
        input_str.replace('+', '%2B')

        return input_str

    def __get_tag_grp_id(self) -> str:
        if not self.__tag_group_id:
            # get TagGroup_id with getEntitiesByName if it has not been
            # queried before
            entitybyname_parameters = (f"name={self.TAG_GROUP_NAME}"
                                       + "&parentId=0"
                                       + "&start=0"
                                       + "&type=TagGroup")
            get_entitiesbyname_url = (self.main_url
                                      + "getEntityByName?"
                                      + entitybyname_parameters)
            response = requests.get(get_entitiesbyname_url,
                                    headers=self.header,
                                    timeout=self.TIMEOUT)
            data = response.json()
            self.__tag_group_id = data["id"]
        return self.__tag_group_id

    def __get_tag_id(self, tag_name: str) -> str:
        for d_tag in self.__get_department_tags():
            if d_tag['name'] == tag_name:
                return d_tag['id']
            admin_tags = self.__get_child_tags(d_tag['id'])
            for a_tag in admin_tags:
                if a_tag.get('name') == tag_name:
                    return a_tag['id']

    def __get_child_tags(self, parent_id: str) -> list[dict]:
        get_entities_parameters = ("count=1000"
                                   + f"&parentId={parent_id}"
                                   + "&start=0"
                                   + "&type=Tag")
        get_entities_url = (self.main_url
                            + "getEntities?"
                            + get_entities_parameters)
        response = requests.get(get_entities_url,
                                headers=self.header,
                                timeout=self.TIMEOUT)
        data = response.json()
        return data

    def __get_parent_tag(self, tag_id: str) -> dict:
        get_parent_url = self.main_url + "getParent?" + f"entityId={tag_id}"
        response = requests.get(get_parent_url,
                                headers=self.header,
                                timeout=self.TIMEOUT)
        data = response.json()
        return data

    def __get_IP4Address(self, ip: str):
        # get configuration_id with getEntitiesByName
        entitybyname_parameters = ("count=1"
                                   + "&name=default"
                                   + "&parentId=0"
                                   + "&start=0"
                                   + "&type=Configuration")
        get_entitiesbyname_url = (self.main_url
                                  + "getEntitiesByName?"
                                  + entitybyname_parameters)
        response = requests.get(get_entitiesbyname_url,
                                headers=self.header,
                                timeout=self.TIMEOUT)
        data = response.json()
        configuration_id = data[0]["id"]

        # get range_id with IPRangedByIP
        iprangedbyip_parameters = (f"address={ip}"
                                   + f"&containerId={configuration_id}"
                                   + "&type=IP4Network")
        get_iprangedbyip_url = (self.main_url
                                + "getIPRangedByIP?"
                                + iprangedbyip_parameters)
        response = requests.get(get_iprangedbyip_url,
                                headers=self.header,
                                timeout=self.TIMEOUT)
        data = response.json()
        range_id = data["id"]

        # get properties of IP
        get_ip4address_url = (self.main_url
                              + "getIP4Address"
                              + f"?address={ip}"
                              + f"&containerId={range_id}")
        response = requests.get(get_ip4address_url,
                                headers=self.header,
                                timeout=self.TIMEOUT)
        data = response.json()
        return data

    def __get_linked_dns_records(self, host_ip: str) -> set[str]:
        dns_names = set()
        try:
            host_info = socket.gethostbyaddr(host_ip)
            dns_names.add(host_info[0])
            for alias in host_info[1]:
                dns_names.add(alias)
        except socket.herror:
            return set()
        except Exception:
            logger.exception("Error while querying host names of host %s",
                             host_ip)

        return dns_names

    def __get_id_of_addr(self, ipv4: str) -> int | None:
        """
        Get the entity ID of the IP4Address object in IPAM to a given IPv4
        address.

        Args:
            ipv4 (str): IPv4 address.

        Returns:
            int|None: Entity ID of IP4Address object in IPAM. None on error.
        """
        try:
            id = int(self.__get_IP4Address(ipv4)['id'])
            return id
        except Exception:
            return None

    def __get_admins_of_host(self, host_id: int) -> list:
        """
        Queries the Proteus IPAM system for all tagged admins of a host.

        Args:
            host_id (int): Entity ID of the host in the Proteus IPAM system.

        Returns:
            list: Returns a list of admin rz-ids.
        """
        tagged_admins = []
        try:
            tag_group_id = self.__get_tag_grp_id()
            # get all tags
            linkedentities_parameters = ("count=-1"
                                         + f"&entityId={host_id}"
                                         + "&start=0"
                                         + "&type=Tag")
            get_linkedentities_url = (self.main_url
                                      + "getLinkedEntities?"
                                      + linkedentities_parameters)
            response = requests.get(get_linkedentities_url,
                                    headers=self.header,
                                    timeout=self.TIMEOUT)
            data = response.json()
            # check for all tags whether they belong to the
            # "Deterrers Host Admins" Tag Group or a sub-tag
            for tag_entity in data:
                tag_id = tag_entity['id']
                tag_name = tag_entity['name']

                parent_tag = self.__get_parent_tag(tag_id)
                if parent_tag['id'] == tag_group_id:
                    # tag is a sub-tag of the "Deterrers Host Admins" Tag Group
                    # add department tag for completeness
                    tagged_admins.append(tag_name)
                    # get all admin tags that are children of this tag
                    data = self.__get_child_tags(tag_id)
                    for tag_entity in data:
                        tag_id = tag_entity['id']
                        tag_name = tag_entity['name']
                        tagged_admins.append(tag_name)
                else:
                    # check if parent-tag is a sub-tag of
                    # "Deterrers Host Admins" Tag Group
                    parent_parent_tag = self.__get_parent_tag(parent_tag['id'])
                    if parent_parent_tag['id'] == tag_group_id:
                        tagged_admins.append(tag_name)

        except Exception:
            logger.exception("Caught an unknown exception!")

        return tagged_admins

    def __get_department_tags(self) -> list[dict]:
        """
        Get all department tag entities.

        Returns:
            list[dict]: Returns a list of dicts holding the properties of the
            department tag entities.
        """
        try:
            # simple caching of department tag names
            if not self.__department_tags:
                tag_group_id = self.__get_tag_grp_id()
                self.__department_tags = self.__get_child_tags(tag_group_id)
        except Exception:
            logger.exception("Couldn't query department tags from IPAM!")
            return []

        return self.__department_tags

    def __host_is_tagged(self, host_id: str | int,  tag_id: str | int) -> bool:
        """
        Checks if tag is already linked to host.

        Args:
            host_id (str | int): Proteus entity ID of IPv4Address object.
            tag_id (str | int): Proteus entity ID of Tag object.

        Returns:
            bool: Returns True if tag is linked to host.
            False otherwise.
        """
        try:
            # query tags that are linked to host
            linkedentities_parameters = ("count=-1"
                                         + f"&entityId={host_id}"
                                         + "&start=0"
                                         + "&type=Tag")
            get_linkedentities_url = (self.main_url
                                      + "getLinkedEntities?"
                                      + linkedentities_parameters)
            response = requests.get(get_linkedentities_url,
                                    headers=self.header,
                                    timeout=self.TIMEOUT)
            data = response.json()

            # check for each tag of host if it is the given tag
            for t_entity in data:
                t_id = t_entity['id']
                if int(t_id) == int(tag_id):
                    return True
        except Exception:
            logger.exception("Couldn't query if host is already tagged!")

        return False

    def get_host_info_from_ip(self, ipv4: str) -> MyHost | None:
        """
        Queries the Proteus IPAM API for an entity with the given IP and
        returns an instance of MyHost.

        Args:
            ipv4 (str): IPv4 address of the host entity in the Proteus IPAM
            system.

        Returns:
            MyHost: Returns an instance of MyHost populated with the fields
            from the IPAM system and None on error.
        """
        # escape user input
        ipv4 = self.__escape_user_input(ipv4)

        # check if ip string has valid syntax
        try:
            ipaddress.ip_address(ipv4)
        except ValueError:
            logger.error('IPAM API Interface received invalid IP: %s', ipv4)
            return None

        try:
            data = self.__get_IP4Address(ipv4)
            (host_id,
             name,
             ipv4,
             mac,
             status,
             service,
             fw,
             rules) = self.__parse_ipam_host_entity(data)
            if type(host_id) is not int:
                logger.error("Couldn't get data for host %s", ipv4)
                return None
            # get all tagged admins
            tagged_admins = self.__get_admins_of_host(host_id)
            # get dns records
            dns_rcs = self.__get_linked_dns_records(ipv4)

            my_host = MyHost(
                ipv4_addr=ipv4,
                mac_addr=mac,
                admin_ids=tagged_admins,
                status=status,
                name=name,
                dns_rcs=dns_rcs,
                service_profile=service,
                fw=fw,
                host_based_policies=rules,
                entity_id=int(host_id)
            )
            if my_host.is_valid():
                return my_host
            else:
                logger.warning("Host '%s' is not valid!", str(my_host))
        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', self.main_url)
        except requests.exceptions.ConnectionError:
            logger.exception('Could not establish connection to "%s"!',
                             self.main_url)
        except Exception:
            logger.exception("Caught an unknown exception!")

        return None

    # def get_host_info_from_id(self, id: int) -> MyHost | None:
    #     """
    #     Queries the Proteus IPAM API for an entity with the given id and
    #     returns an instance of MyHost.

    #     Args:
    #         id (int): Identifier for the entity in the Proteus IPAM system.

    #     Returns:
    #         MyHost|None: Returns an instance of MyHost populated with the
    #         fields from the IPAM system and None on error.
    #     """
    #     try:
    #         # get entity with given id
    #         get_entitybyid_url = (self.main_url
    #                               + "getEntityById?"
    #                               + f"id={id}")
    #         response = requests.get(get_entitybyid_url,
    #                                 headers=self.header,
    #                                 timeout=self.TIMEOUT)
    #         data = response.json()
    #         (host_id,
    #          name,
    #          ip,
    #          mac,
    #          status,
    #          service,
    #          fw,
    #          rules) = self.__parse_ipam_host_entity(data)
    #         # get all tagged admins
    #         tagged_admins = self.__get_admins_of_host(host_id)
    #         # get dns records
    #         dns_rcs = self.__get_linked_dns_records(ip)

    #         my_host = MyHost(
    #             ipv4_addr=ip,
    #             mac_addr=mac,
    #             admin_ids=tagged_admins,
    #             status=status,
    #             name=name,
    #             dns_rcs=dns_rcs,
    #             service_profile=service,
    #             fw=fw,
    #             host_based_policies=rules,
    #             entity_id=int(host_id)
    #         )
    #         if my_host.is_valid():
    #             return my_host
    #         else:
    #             logger.warning("Host '%s' is not valid!", str(my_host))
    #     except requests.exceptions.ConnectTimeout:
    #         logger.exception('Connection to %s timed out!', self.main_url)
    #     except requests.exceptions.ConnectionError:
    #         logger.exception('Could not establish connection to "%s"!',
    #                          self.main_url)
    #     except Exception:
    #         logger.exception("Caught an unknown exception!")

    #     return None

    def get_hosts_of_admin(self, admin_name: str) -> list[MyHost]:
        """
        Queries all hosts that are tagged with an admin or their corresponding
        parent tag in the Proteus IPAM system.

        Args:
            admin_name (str): Identifier string for the admin tag in the
            Proteus IPAM system.

        Returns:
            list(): Returns a list of MyHost instances.
        """

        def __get_linked_hosts(tag_id: str | int):
            threads = []
            hosts = []

            def get_host_task(hosts: list, host_e):
                (host_id,
                 name,
                 ip,
                 mac,
                 status,
                 service,
                 fw,
                 rules) = self.__parse_ipam_host_entity(host_e)
                if type(host_id) is not int:
                    logger.error("Couldn't get data for host %s", str(ip))
                    return None
                # get all tagged admins
                tagged_admins = self.__get_admins_of_host(host_id)
                # get dns records
                dns_rcs = self.__get_linked_dns_records(ip)
                my_host = MyHost(
                    ipv4_addr=ip,
                    mac_addr=mac,
                    admin_ids=tagged_admins,
                    status=status,
                    name=name,
                    dns_rcs=dns_rcs,
                    service_profile=service,
                    fw=fw,
                    host_based_policies=rules,
                    entity_id=int(host_id)
                )
                if my_host.is_valid():
                    hosts.append(my_host)
                else:
                    logger.warning("Host '%s' is not valid!", str(my_host))

            # get tagged host's ids
            get_linked_entity_url = (self.main_url
                                     + "getLinkedEntities?"
                                     + "count=-1"
                                     + f"&entityId={tag_id}"
                                     + "&start=0"
                                     + "&type=IP4Address")
            response = requests.get(get_linked_entity_url,
                                    headers=self.header,
                                    timeout=self.TIMEOUT)
            data = response.json()
            # start a thread for each host that queries the relevant
            # information and appends host to hosts-list
            for host_e in data:
                t = threading.Thread(target=get_host_task,
                                     args=[hosts, host_e, ])
                threads.append(t)
                t.start()
            # wait until all threads have completed
            for t in threads:
                t.join(float(self.TIMEOUT))
            return hosts

        # escape user input
        admin_name = self.__escape_user_input(admin_name)

        hosts = []
        try:
            admin_tag_id = self.__get_tag_id(admin_name)
            department_tag_id = self.__get_parent_tag(admin_tag_id)['id']
            # get all linked hosts to this admin tag
            hosts += __get_linked_hosts(admin_tag_id)
            # get all linked hosts to the parent tag
            hosts += __get_linked_hosts(department_tag_id)

        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', self.main_url)
        except requests.exceptions.ConnectionError:
            logger.exception('Could not establish connection to "%s"!',
                             self.main_url)
        except Exception:
            logger.exception("Caught an unknown exception!")

        return hosts

    def get_IP6Addresses(self, host: MyHost) -> set[str]:
        """
        Queries the corresponding IPv6 addresses if they exist.

        Args:
            host (MyHost): Host instance for which IPv6 addresses are queried

        Returns:
            set[str]: Returns all unique public IPv6 addresses which are
            linked to IPv4 address by common Host Record. Otherwise returns
            None.
        """
        try:
            addrs = set()
            ipv4_id = host.entity_id
            linkedentities_parameters = ("count=10000"
                                         + f"&entityId={ipv4_id}"
                                         + "&start=0"
                                         + "&type=HostRecord")
            get_linkedentities_url = (self.main_url
                                      + "getLinkedEntities?"
                                      + linkedentities_parameters)
            response = requests.get(get_linkedentities_url,
                                    headers=self.header,
                                    timeout=self.TIMEOUT)
            host_records = response.json()
            for h_r in host_records:
                properties = h_r.get('properties')
                try:
                    properties = properties.split('|')
                except Exception:
                    continue
                for property in properties:
                    try:
                        key = property.split('=')[0]
                        value = property.split('=')[1]
                        if key == 'addresses':
                            addresses = value.split(',')
                            addrs.update(addresses)
                    except Exception:
                        continue

            # filter out all addresses which are not public IPv6 addresses
            ipv6_addrs = set()
            for ip in addrs:
                try:
                    ipv6 = ipaddress.IPv6Address(ip)
                    if not ipv6.is_private:
                        # NOTE: use exploded string repr of IPv6Address object
                        # to have coherent representations
                        ipv6_addrs.add(ipv6.exploded)
                except ipaddress.AddressValueError:
                    continue

            return ipv6_addrs

        except Exception:
            logger.exception(
                "Couldn't get IPv6 address for IP4Address with ID %s!",
                str(ipv4_id)
            )
            return set()

    def get_department_names(self) -> list:
        """
        Get all department tag names.

        Returns:
            list: Returns list of department tag names.
        """
        names = []
        for dep_tag in self.__get_department_tags():
            if dep_tag.get('name'):
                names.append(dep_tag.get('name'))
        return names

    def get_department_to_admin(self, admin_name: str) -> str | None:
        """
        Query the name of the department an admin belongs to.

        Args:
            admin_name (str): Name of the admin tag.

        Returns:
            str | None: Returns the name of a department or None if something
            went wrong.
        """
        try:
            for department_tag_entity in self.__get_department_tags():
                department_tag_id = department_tag_entity['id']
                # query whether admin tag exists under this department tag
                entitybyname_parameters = (f"name={admin_name}"
                                           + f"&parentId={department_tag_id}"
                                           + "&start=0"
                                           + "&type=Tag")
                get_entitiesbyname_url = (self.main_url
                                          + "getEntityByName?"
                                          + entitybyname_parameters)
                response = requests.get(get_entitiesbyname_url,
                                        headers=self.header,
                                        timeout=self.TIMEOUT)
                data = response.json()
                if data['name'] == admin_name:
                    return department_tag_entity['name']
        except Exception:
            logger.exception("Couldn't query parent tag from IPAM!")

        return None

    def get_all_admin_names(self) -> set[str]:
        """
        Query all admin tag names.

        Returns:
            set[str]: Returns a set of unique names.
        """
        admin_tag_names = []
        try:
            for d_tag in self.__get_department_tags():
                d_tag_id = d_tag['id']
                admin_tags = self.__get_child_tags(d_tag_id)
                for a_tag in admin_tags:
                    admin_tag_names.append(a_tag['name'])
            return set(admin_tag_names)
        except Exception:
            logger.exception("Couldn't query admin tag names from IPAM!")
        return set()

    def create_admin(
        self,
        admin_name: str,
        department_name: str
    ) -> bool:
        """
        Create an admin tag object under some existing department tag.

        Args:
            admin_name (str): Name of the admin tag to create.
            department_name (str): Name of the department tag that already
            exists.

        Returns:
            bool: Returns True on success and False if something goes wrong.
        """
        try:
            admin_name = self.__escape_user_input(admin_name)
            # get tag_id of department tag
            for department_tag in self.__get_department_tags():
                if department_tag.get('name') == department_name:
                    department_tag_id = department_tag.get('id')
                    break
            # create admin tag under given department tag
            addtag_params = (f"name={admin_name}"
                             + f"&parentId={department_tag_id}")
            addtag_url = (self.main_url
                          + "addTag?"
                          + addtag_params)
            response = requests.post(addtag_url,
                                     headers=self.header,
                                     timeout=self.TIMEOUT)
            if response.status_code != 200:
                raise RuntimeError(
                    f"Status code of {addtag_url}: {response.status_code}"
                )

            return True
        except Exception:
            logger.exception("Couldn't create a tag for admin %s!",
                             admin_name)

        return False

    def is_admin(self, admin_name: str) -> bool | None:
        """
        Check whether an admin tag exists.

        Args:
            admin_tag_name (str): Name of the admin tag.

        Returns:
            bool | None: Returns True if exists, False if not and None
            something goes wrong.
        """
        try:
            # get all department tags which themselves hold the actual
            # admin tags
            for department_tag_entity in self.__get_department_tags():
                department_tag_id = department_tag_entity['id']
                # query whether admin tag exists under this department tag
                entitybyname_parameters = (f"name={admin_name}"
                                           + f"&parentId={department_tag_id}"
                                           + "&start=0"
                                           + "&type=Tag")
                get_entitiesbyname_url = (self.main_url
                                          + "getEntityByName?"
                                          + entitybyname_parameters)
                response = requests.get(get_entitiesbyname_url,
                                        headers=self.header,
                                        timeout=self.TIMEOUT)
                data = response.json()
                if data['name'] == admin_name:
                    return True
            return False

        except Exception:
            logger.exception("Couldn't query IPAM whether tag exists!")

        return None

    def add_admin_to_host(self, admin_name: str, host: MyHost) -> int:
        """
        Link a tag to a IPv4Address object.

        Args:
            admin_name (str): Tag name corresponding to admin/department.
            host (MyHost): Host instance for which admin is added.

        Returns:
            int: Returns HTTP status code of the response.
        """
        try:
            host_id = host.entity_id

            # get tag object
            tag_id = self.__get_tag_id(admin_name)
            parent_tag = self.__get_parent_tag(tag_id)

            # check if admin or their department is already associated
            # with host
            if parent_tag.get('id') == self.__get_tag_grp_id():
                # tag is department tag
                if self.__host_is_tagged(host_id, tag_id):
                    # department is already tagged
                    return 200
                child_tags = self.__get_child_tags(tag_id)
                for child_tag in child_tags:
                    if child_tag.get('id') == tag_id:
                        # admin of this department is already tagged, so
                        # untag them and tag the department instead later
                        self.remove_admin_from_host(
                            child_tag.get('name'),
                            host
                        )
                        break
            else:
                # tag is admin tag
                if self.__host_is_tagged(host_id, tag_id):
                    # admin is already tagged
                    return 200
                if self.__host_is_tagged(host_id, parent_tag.get('id')):
                    # department is already tagged
                    return 200

            # link tag to host
            linkentities_params = (f"entity1Id={host_id}"
                                   + f"&entity2Id={tag_id}")
            linkentities_url = (self.main_url
                                + "linkEntities?"
                                + linkentities_params)
            response = requests.put(linkentities_url,
                                    headers=self.header,
                                    timeout=self.TIMEOUT)
            return response.status_code
        except Exception:
            logger.exception("Couldn't add tag to host!")

        return 500

    def remove_admin_from_host(self, admin_name: str, host: MyHost) -> int:
        """
        Unlink tag from an IPv4Address object.

        Args:
            admin_name (str): Tag name corresponding to admin/department.
            host (MyHost): Host instance.

        Returns:
            int: Returns HTTP status code of the response.
        """
        try:
            host_id = host.entity_id

            # get tag object
            tag_id = self.__get_tag_id(admin_name)

            # unlink tag from host
            linkentities_params = (f"entity1Id={host_id}"
                                   + f"&entity2Id={tag_id}")
            linkentities_url = (self.main_url
                                + "unlinkEntities?"
                                + linkentities_params)
            response = requests.put(linkentities_url,
                                    headers=self.header,
                                    timeout=self.TIMEOUT)

            # remove admin from admin set of host
            host.admin_ids.remove(admin_name)

            return response.status_code
        except Exception:
            logger.exception("Couldn't remove tag from host!")

        return 500

    def update_host_info(self, host: MyHost) -> bool:
        """
        Updates host information in the Proteus IPAM system.

        Args:
            host (MyHost): Host instance that holds all the latest information.

        Returns:
            bool: Returns True on success and False on error.
        """
        if host.is_valid():
            try:
                update_host_url = f"{self.main_url}update"
                props_str = (
                    f"macAddress={self.__escape_user_input(host.mac_addr)}"
                    + "|deterrers_service_profile="
                    + self.__escape_user_input(
                        host.get_service_profile_display()
                    )
                    + "|deterrers_fw="
                    + self.__escape_user_input(host.get_fw_display())
                    + "|deterrers_status="
                    + self.__escape_user_input(host.get_status_display())
                    + "|deterrers_rules="
                    + json.dumps([p.to_string()
                                  for p in host.host_based_policies])
                    + "|"
                )
                update_host_body = {
                    'id': host.entity_id,
                    # NOTE: Do not remove 'name' or else IP Address Name
                    # field is overwritten with empty string
                    'name': host.name,
                    'type': 'IP4Address',
                    'properties': props_str
                }

                response = requests.put(update_host_url,
                                        json=update_host_body,
                                        headers=self.header,
                                        timeout=self.TIMEOUT)

                if response.status_code == 200:
                    return True

            except requests.exceptions.ConnectTimeout:
                logger.exception('Connection to %s timed out!', self.main_url)
            except requests.exceptions.ConnectionError:
                logger.exception('Could not establish connection to "%s"!',
                                 self.main_url)
            except Exception:
                logger.exception("Caught an unknown exception!")
        else:
            logger.error("Host not valid: %s", str(host))

        return False

    def user_exists(self, username: str) -> bool | None:
        """
        Check whether a user of given name exists.

        Args:
            username (str): Name of the queried user.

        Returns:
            bool|None: Returns True if user exists, False if not and None if
            something went wrong.
        """
        try:
            # get username if exists
            entitybyname_parameters = (f"name={username}"
                                       + "&parentId=0"
                                       + "&start=0"
                                       + "&type=User")
            get_entitiesbyname_url = (self.main_url
                                      + "getEntityByName?"
                                      + entitybyname_parameters)
            response = requests.get(get_entitiesbyname_url,
                                    headers=self.header,
                                    timeout=self.TIMEOUT)
            data = response.json()
            if data['name'] == username:
                return True
            return False
        except Exception:
            logger.exception("Couldn't query IPAM whether user exists!")

        return None
