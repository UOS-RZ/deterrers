import logging
import requests
from lxml import etree



logger = logging.getLogger(__name__)

class PaloAltoInterface():
    TIMEOUT = 20

    fw_url = None
    api_key = None

    username = None
    password = None

    header = {}

    def __init__(self, username, password, fw_url):
        self.username = username
        self.password = password
        self.fw_url = fw_url

    def __enter__(self):
        # get api key for this session
        req_url = f"https://{self.fw_url}/api/?type=keygen&user={self.username}&password={self.password}"
        response = requests.get(req_url, timeout=self.TIMEOUT)
        response_xml = etree.XML(response.content)
        status = int(response_xml.get('code'))
        if status != 200:
            raise RuntimeError("Could not get API key from firewall! Status Code: %d", status)
        print(response_xml.tag)


        self.header['X-PAN-KEY'] = self.api_key


        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        try:
            pass
        except Exception() as err:
            logger.error(repr(err))


if __name__ == '__main__':
    import getpass
    password = getpass.getpass()
    with PaloAltoInterface("nwintering", password, "pa-5220.rz.uni-osnabrueck.de") as fw:
        pass