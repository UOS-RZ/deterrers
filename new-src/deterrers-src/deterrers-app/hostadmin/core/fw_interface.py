import logging
import requests
from lxml import etree
from enum import Enum
import time


logger = logging.getLogger(__name__)


class AddressGroups(Enum):
    HTTP = "FWP1-WEB"
    SSH = "FWP2-SSH"
    OPEN = "FWP3-OPEN"

class PaloAltoInterface():
    """
    Interface to the Palo Alto Firewall's PAN-OS v10.1.
    Uses the REST API for object manipulation and XML API committing the changes.
    """
    # TODO: maybe specify API key lifetime in PA Webinterface

    TIMEOUT = 20
    VERSION = "v10.1"
    LOCATION = 'vsys&vsys=vsys4' # TODO: change location in production

    fw_url = None
    rest_url = None
    xml_url = None

    api_key = None

    username = None
    password = None

    header = {
        "Accept" : "application/json",
    }

    def __init__(self, username : str, password : str, fw_url : str):
        self.username = username
        self.password = password
        self.fw_url = fw_url
        self.rest_url = f"https://{fw_url}/restapi/{self.VERSION}/"
        self.xml_url = f"https://{fw_url}/api/"

    def __enter__(self):
        # get api key for this session
        req_url = f"https://{self.fw_url}/api/?type=keygen&user={self.username}&password={self.password}"
        response = requests.get(req_url, timeout=self.TIMEOUT)
        response_xml = etree.XML(response.content)
        status_code = response.status_code
        status = response_xml.xpath('//response/@status')[0]
        if status_code != 200 or status != "success":
            raise RuntimeError(f"Could not get API key from firewall! Status: {status} Code: {status_code}")
        
        self.api_key = response_xml.xpath('//key')[0].text

        self.header['X-PAN-KEY'] = self.api_key

        self.__acquire_config_lock()

        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        try:
            self.__release_config_lock()
        except Exception() as err:
            logger.error(repr(err))


    def __acquire_config_lock(self):
        # TODO: /api/?type=op&cmd=<request><config-lock><add><comment></comment></add></config-lock></request>
        pass

    def __release_config_lock(self):
        # TODO: /api/?type=op&cmd=<request><config-lock><remove></remove></config-lock></request>
        # https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/pan-os-xml-api-request-types/run-operational-mode-commands-api
        pass


    
    def __create_addr_obj(self, ip_addr : str):
        ip_addr_name =  ip_addr.replace('.', '-')
        create_addr_params = f"name={ip_addr_name}&location={self.LOCATION}&input-format=json"
        create_addr_url = self.rest_url + "Objects/Addresses?" +create_addr_params
        create_addr_payload = {
            "entry" : {
                "ip-netmask" : ip_addr,
                "@name" : ip_addr_name,
                "description" : "Auto-generated by DETERRERS",
                # "tag" : {
                #     "member" : []
                # }
            }
        }
        response = requests.post(
            create_addr_url, json=create_addr_payload, headers=self.header, timeout=self.TIMEOUT
        )
        if response.status_code != 200:
            return None

        return ip_addr_name

    def __get_addr_obj(self, ip_addr : str):
        ip_addr_name =  ip_addr.replace('.', '-')

        get_address_params = f"name={ip_addr_name}&location={self.LOCATION}"
        get_address_url = self.rest_url + "Objects/Addresses?" + get_address_params
        response = requests.get(get_address_url, headers=self.header, timeout=self.TIMEOUT)
        data = response.json()

        if not (data.get('@status') == 'success' and data.get('@code') == '19'):
            return None

        if int(data.get('result').get('@total-count')) != 1:
            raise RuntimeError(f"There are to many address objects in the firewall with IP {ip_addr}!")
        obj_name = data.get('result').get('entry')[0].get('@name')

        return obj_name


    def add_addr_obj_to_addr_grps(self, ip_addr : str, addr_grps : set[AddressGroups]):
        addr_obj_name = self.__get_addr_obj(ip_addr)
        if not addr_obj_name:
            addr_obj_name = self.__create_addr_obj(ip_addr)

        for addr_grp_name in addr_grps:
            # get all properties of the address group
            get_addr_grp_params =  f"name={addr_grp_name.value}&location={self.LOCATION}"
            get_addr_grp_url = self.rest_url + "Objects/AddressGroups?" + get_addr_grp_params
            response = requests.get(get_addr_grp_url, headers=self.header, timeout=self.TIMEOUT)
            data = response.json()
            if response.status_code != 200 or data.get('@status') != 'success' or int(data.get('result').get('@total-count')) != 1:
                raise RuntimeError(f"Could not query Address Group {addr_grp_name.value} from \
firewall! Status code: {response.status_code}. Status: {data.get('@status')}")

            addr_grp_obj = data.get('result').get('entry')[0]
            # put the new addr obj into the addr grp
            put_addr_grp_params = f"name={addr_grp_name.value}&location={self.LOCATION}&input-format=json"
            put_addr_grp_url = self.rest_url + "Objects/AddressGroups?" + put_addr_grp_params
            put_addr_grp_payload = {
                "entry" : {
                    "static" : {
                        "member" : list(set(addr_grp_obj['static']['member'] + [addr_obj_name,])),
                    },
                    "@name" : addr_grp_obj['@name'],
                    "description" : addr_grp_obj.get('description', '')
                }
            }
            response = requests.put(
                put_addr_grp_url, json=put_addr_grp_payload, headers=self.header, timeout=self.TIMEOUT
            )
            data = response.json()
            if response.status_code != 200 or data.get('@status') != 'success':
                raise RuntimeError(f"Could not update Address Group {addr_grp_name.value}. \
Status code: {response.status_code}. Status: {data.get('@status')}")
            # TODO: commit changes
            if not self.__commit_changes():
                raise RuntimeError("Could not commit changes!")


    def __commit_changes(self):
        commit_params = "type=commit&cmd=<commit></commit>"
        commit_url = self.xml_url + "?" + commit_params
        response = requests.get(commit_url, headers=self.header, timeout=self.TIMEOUT)
        response_xml = etree.XML(response.content)
        status_code = response.status_code
        status = response_xml.xpath("//response/@status")[0]
        if status_code != 200 or status != 'success':
            logger.error("Queueing commit failed. Status code: %d. Status: %s", status_code, status)
            return False

        job_id = response_xml.xpath("//result/job")[0].text
        if not job_id:
            return False
        # wait until commit has been submitted
        get_job_status_params = f"type=op&cmd=<show><jobs><id>{job_id}</id></jobs></show>"
        get_job_status_url = self.xml_url + "?" + get_job_status_params
        start = time.time()
        while True:
            if time.time() - start > 120:
                # TODO: cancle commit job
                logger.error("Commit took to long!")
                return False
            response = requests.get(get_job_status_url, headers=self.header, timeout=self.TIMEOUT)
            response_xml =  etree.XML(response.content)
            job_status = response_xml.xpath("//job/status")[0].text
            if job_status == "FIN":
                logger.debug("Commit finished!")
                break
            time.sleep(2)

        return True






if __name__ == '__main__':
    import getpass
    password = getpass.getpass()
    with PaloAltoInterface("nwintering", password, "pa-5220.rz.uni-osnabrueck.de") as fw:
        test_host_ip = "131.173.22.185"
        fw.add_addr_obj_to_addr_grps(test_host_ip, {AddressGroups.HTTP})
