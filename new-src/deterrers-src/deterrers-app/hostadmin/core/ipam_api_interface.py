import requests
import logging
import json
import socket
import threading
import ipaddress

from .host import MyHost
from .contracts import HostStatusContract, HostServiceContract, HostFWContract
from .rule_generator import HostBasedPolicy

logger = logging.getLogger(__name__)

# TODO: check response codes of requests

class ProteusIPAMInterface():
    """
    Interface to BlueCat's Proteus IP Address Manager REST API
    """
    # settings
    TAG_GROUP_NAME = "Deterrers Host Admins"

    TIMEOUT = 3*180


    def __init__(self, username, password, ipam_url):
        self.username = username
        self.password = password
        self.ipam_url = ipam_url
        self.main_url = "https://" + ipam_url + "/Services/REST/v1/"
        self.header = ''
        self.__tag_group_id = None

        self.enter_ok = True

    def __enter__(self):
        login_url = self.main_url + "login?username=" + self.username + "&password=" + self.password
        try:
            # login to BlueCat
            response = requests.get(login_url, timeout=self.TIMEOUT)
            if response.status_code != 200:
                raise RuntimeError('Could not authenticate with IPAM!')
            # get token
            token = response.json().split()[2] + " " + response.json().split()[3]
            # set http header
            self.header = {'Authorization': token, 'Content-Type': 'application/json'}
        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', login_url)
            self.enter_ok = False
        except requests.exceptions.ConnectionError:
            logger.exception('Could not establish connection to "%s"!', login_url)
            self.enter_ok = False
        except:
            logger.exception('Unexpected error during login to %s!', login_url)
            self.enter_ok = False

        return self


    def __exit__(self, exc_type, exc_value, exc_tb):
        logout_url = self.main_url + "logout?"
        try:
            # logout from BlueCat
            response = requests.get(logout_url, headers = self.header, timeout=self.TIMEOUT)
        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', logout_url)
        except requests.exceptions.ConnectionError:
            logger.exception('Could not estaplish connection to "%s"!', logout_url)
    
    def __parse_ipam_host_entity(self, entity):
        
        try:
            host_id = entity['id']
        except KeyError:
            host_id = None
        try:
            name = entity['name']
        except KeyError:
            name = ''
        # parse the properties string
        try:
            prop_str = entity['properties'].split('|')
            props = dict([elem.split('=') for elem in prop_str if len(elem.split('='))==2])
            try:
                ip = props['address']
            except KeyError:
                ip = ''
            try:
                mac = props['macAddress']
            except KeyError:
                mac = ''
            try:
                status = HostStatusContract(props['deterrers_status'])
            except KeyError:
                status = None
            try:
                service_profile = HostServiceContract(props['deterrers_service_profile'])
            except KeyError:
                service_profile = HostServiceContract.EMPTY
            try:
                fw = HostFWContract(props['deterrers_fw'])
            except KeyError:
                fw = HostFWContract.EMPTY
            try:
                rules = [HostBasedPolicy.from_string(p_str) for p_str in json.loads(props['deterrers_rules'])]
            except KeyError:
                rules = []
        except (KeyError, AttributeError):
            ip = ''
            mac = ''
            status = None
            service_profile = HostServiceContract.EMPTY
            fw = HostFWContract.EMPTY
            rules = []
        return host_id, name, ip, mac, status, service_profile, fw, rules

    def __get_tagged_admins(self, host_id : int) -> list:
        """
        Queries the Proteus IPAM system for all tagged admins of a certain host.

        Args:
            host_id (int): Entity ID of the host in the Proteus IPAM system.

        Returns:
            list: Returns a list of admin rz-ids.
        """
        tagged_admins = []
        try:
            tag_group_id = self.__get_tag_grp_id()
            # get all tags
            linkedentities_parameters = f"count=-1&entityId={host_id}&start=0&type=Tag"
            get_linkedentities_url = self.main_url + "getLinkedEntities?" + linkedentities_parameters
            response = requests.get(get_linkedentities_url, headers=self.header, timeout=self.TIMEOUT)
            data = response.json()
            # check for all tags whether they belong to the Deterrers Host Admins Tag Group or a sub-tag
            for tag_entity in data:
                tag_id = tag_entity['id']
                tag_name = tag_entity['name']
                get_parent_url = self.main_url + "getParent?" + f"entityId={tag_id}"
                response =  requests.get(get_parent_url, headers=self.header, timeout=self.TIMEOUT)
                data = response.json()
                if data['id'] == tag_group_id:
                    # tag is a sub-tag of the Deterrers Host Admins Tag Group
                    tagged_admins.append(tag_name) # add department tag for completeness
                    # get all admin tags that are children of this tag
                    data = self.__get_child_tags(tag_id)
                    for tag_entity in data:
                        tag_id = tag_entity['id']
                        tag_name = tag_entity['name']
                        tagged_admins.append(tag_name)
                else:
                    # check if parent-tag is a sub-tag of Deterrers Host Admins Tag Group
                    get_parent_url = self.main_url + "getParent?" + f"entityId={data['id']}"
                    response =  requests.get(get_parent_url, headers=self.header, timeout=self.TIMEOUT)
                    data = response.json()
                    if data['id'] == tag_group_id:
                        tagged_admins.append(tag_name)

        except Exception:
            logger.exception("Caught an exception in ProteusIPAMInterface.__get_tagged_admins()!")

        return tagged_admins

    def __escape_user_input(self, input_str : str) -> str:
        """
        Escape special characters for Proteus IPAM by replacement with their hexadecimal equivalent.
        List of special characters is given in https://docs.bluecatnetworks.com/r/Address-Manager-API-Guide/Escaping-characters/9.4.0

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
            # get TagGroup_id with getEntitiesByName if it has not been queried before
            entitybyname_parameters = f"name={self.TAG_GROUP_NAME}&parentId=0&start=0&type=TagGroup"
            get_entitiesbyname_url = self.main_url + "getEntityByName?" + entitybyname_parameters
            response = requests.get(get_entitiesbyname_url, headers = self.header, timeout=self.TIMEOUT)
            data = response.json()
            self.__tag_group_id = data["id"]
        return self.__tag_group_id

    def __get_tag_id(self, tag_name : str) -> str:
        parent_id = self.__get_tag_grp_id()
        department_tags = self.__get_child_tags(parent_id)
        for d_tag in department_tags:
            if d_tag['name'] == tag_name:
                return d_tag['id']
            admin_tags = self.__get_child_tags(d_tag['id'])
            for a_tag in admin_tags:
                if a_tag.get('name') == tag_name:
                    return a_tag['id']


    def __get_child_tags(self, parent_id : str) -> list[dict]:
        get_entities_parameters = f"count=1000&parentId={parent_id}&start=0&type=Tag"
        get_entities_url = self.main_url + "getEntities?" + get_entities_parameters
        response = requests.get(get_entities_url, headers=self.header, timeout=self.TIMEOUT)
        data = response.json()
        return data


    def __get_IP4Address(self, ip : str):
        # get configuration_id with getEntitiesByName
        entitybyname_parameters = "count=1&name=default&parentId=0&start=0&type=Configuration"
        get_entitiesbyname_url = self.main_url + "getEntitiesByName?" + entitybyname_parameters
        response = requests.get(get_entitiesbyname_url, headers = self.header, timeout=self.TIMEOUT)
        data = response.json()
        configuration_id = data[0]["id"]

        # get range_id with IPRangedByIP
        iprangedbyip_parameters = f"address={ip}&containerId={configuration_id}&type=IP4Network"
        get_iprandedbyip_url = self.main_url + "getIPRangedByIP?" + iprangedbyip_parameters
        response = requests.get(get_iprandedbyip_url, headers = self.header, timeout=self.TIMEOUT)
        data = response.json()
        range_id = data["id"]

        # get properties of IP
        get_ip4adress_url = self.main_url + f"getIP4Address?address={ip}&containerId={range_id}"
        response = requests.get(get_ip4adress_url, headers = self.header, timeout=self.TIMEOUT)
        data = response.json()
        return data
    
    def __get_linked_dns_records(self, host_ip : str) -> set[str]:

        dns_names = set()
        try:
            host_info = socket.gethostbyaddr(host_ip)
            dns_names.add(host_info[0])
            for alias in host_info[1]:
                dns_names.add(alias)
        except socket.herror:
            return set()
        except Exception:
            logger.exception("Error while querying host names of host %s", host_ip)
                
        return dns_names
    
    def get_id_of_addr(self, ip : str) -> int:
        try:
            id = int(self.__get_IP4Address(ip)['id'])
            return id
        except:
            return None


    def get_host_info_from_ip(self, ip : str):
        """
        Queries the Proteus IPAM API for an entity with the given IP and returns an instance of MyHost.

        Args:
            ii (str): IP address of the host entity in the Proteus IPAM system.

        Returns:
            MyHost: Returns an instance of MyHost populated with the fields from the IPAM system 
            and None on error.
        """
        # escape user input
        ip = self.__escape_user_input(ip)

        # check if ip string has valid syntax
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error('IPAM API Interface received invalid IP: %s', ip)
            return None

        try:
            data = self.__get_IP4Address(ip)
            host_id, name, ip, mac, status, service, fw, rules = self.__parse_ipam_host_entity(data)
            # get all tagged admins
            tagged_admins = self.__get_tagged_admins(host_id)
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
                return my_host
            else:
                logger.warning("Host '%s' is not valid!", str(my_host))
        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', self.main_url)
        except requests.exceptions.ConnectionError:
            logger.exception('Could not estaplish connection to "%s"!', self.main_url)
        except Exception:
            logger.exception("Caught an exception in ProteusIPAMInterface.get_host_info_from_ip()!")
        
        return None

    def get_host_info_from_id(self, id : int):
        """
        Queries the Proteus IPAM API for an entity with the given id and returns an instance of MyHost.

        Args:
            id (int): Indentifier for the entity in the Proteus IPAM system.

        Returns:
            MyHost: Returns an instance of MyHost populated with the fields from the IPAM system and
            None on error.
        """
        try:
            # get entity with given id
            get_entitybyid_url = self.main_url + "getEntityById?" + f"id={id}"
            response =  requests.get(get_entitybyid_url, headers=self.header, timeout=self.TIMEOUT)
            data = response.json()
            host_id, name, ip, mac, status, service, fw, rules = self.__parse_ipam_host_entity(data)
            # get all tagged admins
            tagged_admins = self.__get_tagged_admins(host_id)
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
                return my_host
            else:
                logger.warning("Host '%s' is not valid!", str(my_host))
        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', self.main_url)
        except requests.exceptions.ConnectionError:
            logger.exception('Could not estaplish connection to "%s"!', self.main_url)
        except Exception:
            logger.exception("Caught an exception in ProteusIPAMInterface.get_host_info_from_id()!")

        return None
        

    def get_hosts_of_admin(self, admin_rz_id : str) -> list[MyHost]:
        """
        Queries all hosts that are tagged with an admin or their corresponding parent tag in the 
        Proteus IPAM system.

        Args:
            admin_rz_id (str): Identifier string for the admin tag in the Proteus IPAM system.

        Returns:
            list(): Returns a list of MyHost instances.
        """

        def __get_linked_hosts(tag_id):
            threads = []
            hosts = []

            def get_host_task(hosts : list, host_e):
                host_id, name, ip, mac, status, service, fw, rules = self.__parse_ipam_host_entity(host_e)
                # get all tagged admins
                tagged_admins = self.__get_tagged_admins(host_id)
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
            get_linked_entity_url= self.main_url + "getLinkedEntities?" + \
                f"count=-1&entityId={tag_id}&start=0&type=IP4Address"
            response = requests.get(get_linked_entity_url, headers = self.header, timeout=self.TIMEOUT)
            data = response.json()
            # start a thread for each host that queries the relevant information and appends host to hosts-list
            for host_e in data:
                t = threading.Thread(target=get_host_task, args=[hosts, host_e,])
                threads.append(t)
                t.start()
            # wait until all threads have completed
            for t in threads:
                t.join(float(self.TIMEOUT))
            return hosts

        # escape user input
        admin_rz_id = self.__escape_user_input(admin_rz_id)

        hosts  = []
        try:
            tag_group_id = self.__get_tag_grp_id()
            # get all parent tags (department tags) which themselves hold the actual admin tags
            data = self.__get_child_tags(tag_group_id)
            for tag_entity in data:
                parent_tag_id = tag_entity['id']
                # query whether the admin is a sub-tag of this tag
                entitybyname_parameters = f"name={admin_rz_id}&parentId={parent_tag_id}&start=0&type=Tag"
                get_entitiesbyname_url = self.main_url + "getEntityByName?" + entitybyname_parameters
                response = requests.get(get_entitiesbyname_url, headers = self.header, timeout=self.TIMEOUT)
                data = response.json()
                try:
                    admin_tag_id = data["id"]
                    if admin_tag_id == 0:
                        # admin is no sub-tag of this parent tag, therefore continue with next one
                        continue
                except KeyError:
                    continue
                # get all linked hosts to this admin tag
                hosts += __get_linked_hosts(admin_tag_id)
                # get all linked hosts to the parent tag
                hosts += __get_linked_hosts(parent_tag_id)
                # admins are only allowed to be sub-tag of one parent tag therefore break here
                break

        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', self.main_url)
        except requests.exceptions.ConnectionError:
            logger.exception('Could not estaplish connection to "%s"!', self.main_url)
        except Exception:
            logger.exception("Caught an exception in ProteusIPAMInterface.get_hosts_of_admin()!")

        return hosts

    def update_host_info(self, host : MyHost) -> bool:
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
                update_host_body = {
                    'id': host.entity_id,
                    'name': host.name, # NOTE: Do not remove this or else IP Address Name field is overwritten with empty string
                    'type': 'IP4Address',
                    'properties': f'macAddress={self.__escape_user_input(host.mac_addr)}|\
deterrers_service_profile={self.__escape_user_input(host.get_service_profile_display())}|\
deterrers_fw={self.__escape_user_input(host.get_fw_display())}|\
deterrers_status={self.__escape_user_input(host.get_status_display())}|\
deterrers_rules={json.dumps([p.to_string() for p in host.host_based_policies])}|'}

                response = requests.put(update_host_url, json=update_host_body, headers=self.header, timeout=self.TIMEOUT)

                if response.status_code == 200:
                    return True
                    
            except requests.exceptions.ConnectTimeout:
                logger.exception('Connection to %s timed out!', self.main_url)
            except requests.exceptions.ConnectionError:
                logger.exception('Could not estaplish connection to "%s"!', self.main_url)
            except Exception:
                logger.exception("Caught an exception in ProteusIPAMInterface.update_host_info()!")
        else:
            logger.error("Host not valid: %s", str(host))

        return False


    def get_department_tag_names(self) -> list:
        """
        Crawl all department tag names.

        Returns:
            list: Returns list of department tag names.
        """
        admin_tag_grps = []
        try:
            tag_group_id = self.__get_tag_grp_id()
            data = self.__get_child_tags(tag_group_id)
            for tag_entity in data:
                tag_name = tag_entity['name']
                admin_tag_grps.append(tag_name)
        except Exception:
            logger.exception("Couldn't query department tags from IPAM!")
            return []

        return admin_tag_grps

    def get_department_to_admin(self, admin_tag_name : str) -> str|None:
        """
        Query the name of the department an admin belongs to.

        Args:
            admin_tag_name (str): Name of the admin tag.

        Returns:
            str|None: Returns the name of a department or None if something went wrong.
        """
        try:
            tag_group_id = self.__get_tag_grp_id()
            # get all department tags which themselves hold the actual admin tags
            data = self.__get_child_tags(tag_group_id)
            for department_tag_entity in data:
                department_tag_id = department_tag_entity['id']
                # query whether admin tag exists under this department tag
                entitybyname_parameters = f"name={admin_tag_name}&parentId={department_tag_id}&start=0&type=Tag"
                get_entitiesbyname_url = self.main_url + "getEntityByName?" + entitybyname_parameters
                response = requests.get(get_entitiesbyname_url, headers = self.header, timeout=self.TIMEOUT)
                data = response.json()
                if data['name'] == admin_tag_name:
                    return department_tag_entity['name']
        except Exception:
            logger.exception("Couldn't query parent tag from IPAM!")

        return None
    
    def get_admin_tag_names(self) -> set[str]:
        """
        Query all admin tag names.

        Returns:
            set[str]: Returns a set of unique names.
        """
        admin_tag_names = []
        try:
            tag_grp_id = self.__get_tag_grp_id()
            department_tags = self.__get_child_tags(tag_grp_id)
            for d_tag in department_tags:
                d_tag_id = d_tag['id']
                admin_tags = self.__get_child_tags(d_tag_id)
                for a_tag in admin_tags:
                    admin_tag_names.append(a_tag['name'])
            return set(admin_tag_names)
        except Exception:
            logger.exception("Couldn't query admin tag names from IPAM!")
        return set()

    def create_admin_tag(self, admin_tag_name : str, department_tag_name : str) -> bool:
        """
        Create an admin tag object under some existing department tag.

        Args:
            admin_tag_name (str): Name of the admin tag to create.
            department_tag_name (str): Name of the department tag that already exists.

        Returns:
            bool: Returns True on success and False if something goes wrong.
        """
        try:
            admin_tag_name = self.__escape_user_input(admin_tag_name)
            tag_group_id = self.__get_tag_grp_id()
            # get tag_id of department tag
            entitybyname_parameters = f"name={department_tag_name}&parentId={tag_group_id}&start=0&type=Tag"
            get_entitiesbyname_url = self.main_url + "getEntityByName?" + entitybyname_parameters
            response = requests.get(get_entitiesbyname_url, headers = self.header, timeout=self.TIMEOUT)
            data = response.json()
            department_tag_id = data["id"]
            # create admin tag under given department tag
            addtag_params = f"name={admin_tag_name}&parentId={department_tag_id}"
            addtag_url = self.main_url + "addTag?" + addtag_params
            response = requests.post(addtag_url, headers=self.header, timeout=self.TIMEOUT)
            if response.status_code != 200:
                raise RuntimeError(f"Status code of {addtag_url}: {response.status_code}")

            return True
        except Exception:
            logger.exception("Couldn't create a tag for admin %s!", admin_tag_name)

        return False

    def admin_tag_exists(self, admin_tag_name : str) -> bool|None:
        """
        Check whether an admin tag exists.

        Args:
            admin_tag_name (str): Name of the admin tag.

        Returns:
            bool|None: Returns True if exists, False if not and None something goes wrong.
        """
        try:
            tag_group_id = self.__get_tag_grp_id()
            # get all department tags which themselves hold the actual admin tags
            data = self.__get_child_tags(tag_group_id)
            for department_tag_entity in data:
                department_tag_id = department_tag_entity['id']
                # query whether admin tag exists under this department tag
                entitybyname_parameters = f"name={admin_tag_name}&parentId={department_tag_id}&start=0&type=Tag"
                get_entitiesbyname_url = self.main_url + "getEntityByName?" + entitybyname_parameters
                response = requests.get(get_entitiesbyname_url, headers = self.header, timeout=self.TIMEOUT)
                data = response.json()
                if data['name'] == admin_tag_name:
                    return True
            return False

        except Exception:
            logger.exception("Couldn't query IPAM whether tag exists!")

        return None

    def add_tag_to_host(self, tag_name : str, host_ip : str) -> bool:
        """
        Link a tag to a IPv4Address object.

        Args:
            tag_name (str): Tag name.
            host_ip (str): IP address of the host.

        Returns:
            bool: Returns True on success and False if something goes wrong.
        """
        try:
            # get IPv4Address object
            data = self.__get_IP4Address(host_ip)
            host_id = data['id']

            # get tag object
            tag_id = self.__get_tag_id(tag_name)

            # link tag to host
            linkentities_params = f"entity1Id={host_id}&entity2Id={tag_id}"
            linkentities_url = self.main_url + "linkEntities?" + linkentities_params
            response = requests.put(linkentities_url, headers=self.header, timeout=self.TIMEOUT)
            if response.status_code == 200:
                return True
        except Exception:
            logger.exception("Couldn't add tag to host!")

        return False

    def user_exists(self, username : str) -> bool|None:
        """
        Check whether a user of given name exists.

        Args:
            username (str): Name of the queried user.

        Returns:
            bool|None: Returns True if user exists, False if not and None if something went wrong.
        """
        try:
            # get username if exists
            entitybyname_parameters = f"name={username}&parentId=0&start=0&type=User"
            get_entitiesbyname_url = self.main_url + "getEntityByName?" + entitybyname_parameters
            response = requests.get(get_entitiesbyname_url, headers = self.header, timeout=self.TIMEOUT)
            data = response.json()
            if data['name'] == username:
                return True
            return False
        except Exception:
            logger.exception("Couldn't query IPAM whether user exists!")

        return None
    
    def get_IP6Address_if_linked(self, ipv4_id : int) -> set[str]:
        """
        Queries the corresponding IPv6 address if it exists.

        Args:
            ipv4_id (int): ID of the IP4Address entitiy in IPAM.

        Returns:
            set[str]: Returns all unique public IPv6 addresses which are linked to IPv4 address by common Host Record. Otherwise returns None.
        """
        try:
            addrs = set()
            ipv4_id = int(ipv4_id)
            linkedentities_parameters = f"count=10000&entityId={ipv4_id}&start=0&type=HostRecord"
            get_linkedentities_url = self.main_url + "getLinkedEntities?" + linkedentities_parameters
            response = requests.get(get_linkedentities_url, headers=self.header, timeout=self.TIMEOUT)
            host_records = response.json()
            for h_r in host_records:
                properties = h_r.get('properties')
                try:
                    properties = properties.split('|')
                except:
                    continue
                for property in properties:
                    try:
                        key = property.split('=')[0]
                        value = property.split('=')[1]
                        if key == 'addresses':
                            addresses = value.split(',')
                            addrs.update(addresses)
                    except:
                        continue

            # filter out all addresses which are not public IPv6 addresses
            ipv6_addrs = set()
            for ip in addrs:
                try: 
                    if not ipaddress.IPv6Address(ip).is_private:
                        ipv6_addrs.add(ip)
                except ipaddress.AddressValueError:
                    continue

            return ipv6_addrs

        except Exception:
            logger.exception("Couldn't get IPv6 address for IP4Address with ID %d!", ipv4_id)
            return set()
