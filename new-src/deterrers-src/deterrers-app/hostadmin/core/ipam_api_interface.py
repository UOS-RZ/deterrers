import requests
from ipaddress import ip_address
import logging
import json

from .host import MyHost, HostStatusContract, HostServiceContract, HostFWContract

logger = logging.getLogger(__name__)

class ProteusIPAMInterface():
    """
    Interface to BlueCat's Proteus IP Address Manager REST API
    """
    # settings
    TAG_GROUP_NAME = "Deterrers Host Admins"

    TIMEOUT = 5


    def __init__(self, username, password, ipam_url):
        self.username = username
        self.password = password
        self.ipam_url = ipam_url
        self.main_url = "http://" + ipam_url + "/Services/REST/v1/" # TODO: change back to https when working with production system
        self.header = ''

    def __enter__(self):
        login_url = self.main_url + "login?username=" + self.username + "&password=" + self.password
        try:
            # login to BlueCat
            response = requests.get(login_url, timeout=self.TIMEOUT)
            # get token
            token = response.json().split()[2] + " " + response.json().split()[3]
            # set http header
            self.header = {'Authorization': token, 'Content-Type': 'application/json'}
        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', login_url)
        except requests.exceptions.ConnectionError:
            logger.exception('Could not establish connection to "%s"!', login_url)

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
                rules = json.loads(props['deterrers_rules'])
            except KeyError:
                rules = []
        except KeyError:
            ip = ''
            mac = ''
            status = None
            service_profile = HostServiceContract.EMPTY
            fw = HostFWContract.EMPTY
            rules = []
        return host_id, name, ip, mac, status, service_profile, fw, rules

    def __get_tagged_admins(self, host_id):
        """
        Queries the Proteus IPAM system for all tagged admins (max. 100) of a certain host.

        Args:
            host_id (int): Entity ID of the host in the Proteus IPAM system.

        Returns:
            list: Returns a list of admin rz-ids.
        """
        tagged_admins = []
        try:
            # get TagGroup_id with getEntitiesByName
            entitybyname_parameters = f"name={self.TAG_GROUP_NAME}&parentId=0&start=0&type=TagGroup"
            get_entitiesbyname_url = self.main_url + "getEntityByName?" + entitybyname_parameters
            response = requests.get(get_entitiesbyname_url, headers = self.header, timeout=self.TIMEOUT)
            data = response.json()
            tag_group_id = data["id"]
            # get all tags
            linkedentities_parameters = f"count=100&entityId={host_id}&start=0&type=Tag"
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
                    child_tags_parameters = f"count=1000&parentId={tag_id}&start=0&type=Tag"
                    get_child_tags_url = self.main_url + "getEntities?" + child_tags_parameters
                    response = requests.get(get_child_tags_url, headers=self.header, timeout=self.TIMEOUT)
                    data = response.json()
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
            ip_address(ip)
        except ValueError:
            logger.error('IPAM API Interface received invalid IP: %s', ip)
            return None

        try:
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

            host_id, name, ip, mac, status, service, fw, rules = self.__parse_ipam_host_entity(data)

            # get all tagged admins
            tagged_admins = self.__get_tagged_admins(host_id)


            my_host = MyHost(
                ip=ip,
                mac=mac,
                admin_ids=tagged_admins,
                status=status,
                name=name,
                service=service,
                fw=fw,
                rules=rules,
                entity_id=host_id
            )
            if my_host.is_valid():
                return my_host
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

            my_host = MyHost(
                ip=ip,
                mac=mac,
                admin_ids=tagged_admins,
                status=status,
                name=name,
                service=service,
                fw=fw,
                rules=rules,
                entity_id=host_id
            )
            if my_host.is_valid():
                return my_host

        except requests.exceptions.ConnectTimeout:
            logger.exception('Connection to %s timed out!', self.main_url)
        except requests.exceptions.ConnectionError:
            logger.exception('Could not estaplish connection to "%s"!', self.main_url)
        except Exception:
            logger.exception("Caught an exception in ProteusIPAMInterface.get_host_info_from_id()!")

        return None
        

    def get_hosts_of_admin(self, admin_rz_id : str):
        """
        Queries all hosts that are tagged with an admin or their corresponding parent tag in the 
        Proteus IPAM system.

        Args:
            admin_rz_id (str): Identifier string for the admin tag in the Proteus IPAM system.

        Returns:
            list(): Returns a list of MyHost instances.
        """

        def __get_linked_hosts(tag_id):
            hosts = []
            # get tagged host's ids
            scroll_i  = 0
            scroll_cnt = 50         # magic number for how many hosts to query at once
            ret_cnt = scroll_cnt    # set equally so that loop is traversed at least once
            while ret_cnt == scroll_cnt:
                get_linked_entity_url= self.main_url + "getLinkedEntities?" + \
                    f"count={scroll_cnt}&entityId={tag_id}&start={scroll_i*scroll_cnt}&type=IP4Address"
                response = requests.get(get_linked_entity_url, headers = self.header, timeout=self.TIMEOUT)
                data = response.json()
                for host_e in data:
                    host_id, name, ip, mac, status, service, fw, rules = self.__parse_ipam_host_entity(host_e)
                    # get all tagged admins
                    tagged_admins = self.__get_tagged_admins(host_id)
                    my_host = MyHost(
                        ip=ip,
                        mac=mac,
                        admin_ids=tagged_admins,
                        status=status,
                        name=name,
                        service=service,
                        fw=fw,
                        rules=rules,
                        entity_id=host_id
                    )
                    if my_host.is_valid():
                        hosts.append(my_host)
                ret_cnt = len(data)
            return hosts

        # escape user input
        admin_rz_id = self.__escape_user_input(admin_rz_id)

        hosts  = []
        try:
            # get TagGroup_id with getEntitiesByName
            entitybyname_parameters = f"name={self.TAG_GROUP_NAME}&parentId=0&start=0&type=TagGroup"
            get_entitiesbyname_url = self.main_url + "getEntityByName?" + entitybyname_parameters
            response = requests.get(get_entitiesbyname_url, headers = self.header, timeout=self.TIMEOUT)
            data = response.json()
            tag_group_id = data["id"]

            # get all parent tags (department tags) which themselves hold the actual admin tags
            child_tags_parameters = f"count=1000&parentId={tag_group_id}&start=0&type=Tag"
            get_child_tags_url = self.main_url + "getEntities?" + child_tags_parameters
            response = requests.get(get_child_tags_url, headers=self.header, timeout=self.TIMEOUT)
            data = response.json()
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
        Updates host information (only service profile and firewall fields) in the Proteus IPAM system.

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
                    'name': host.name,
                    'type': 'IP4Address',
                    'properties': f'macAddress={self.__escape_user_input(host.mac_addr)}|\
deterrers_service_profile={self.__escape_user_input(host.get_service_profile_display())}|\
deterrers_fw={self.__escape_user_input(host.get_fw_display())}|\
deterrers_status={self.__escape_user_input(host.get_status_display())}|\
deterrers_rules={json.dumps(host.custom_rules)}|'}

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
