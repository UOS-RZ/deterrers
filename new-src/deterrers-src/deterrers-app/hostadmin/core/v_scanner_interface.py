import logging
from enum import Enum
from datetime import datetime
import icalendar

from gvm.protocols.gmp import Gmp
from gvm.connections import SSHConnection
from gvm.transforms import EtreeCheckCommandTransform
from gvm.errors import GvmError
from gvm.xml import pretty_print
from gvm.protocols.gmpv224 import AlertCondition, AlertEvent, AlertMethod, AliveTest

logger = logging.getLogger(__name__)


""" Following enums hold UUIDs that are custom to the respective GSM system """

class ScanConfig(Enum):
    FULL_FAST_UUID = "daba56c8-73ec-11df-a475-002264764cea"
    FULL_FAST_ULTIMATE_UUID = "698f691e-7489-11df-9d8c-002264764cea"
    FULL_VERY_DEEP_UUID = "708f25c4-7489-11df-8094-002264764cea"

class Scanner(Enum):
    OPENVAS_DEFAULT_SCANNER_UUID = "08b69003-5fc2-4037-a479-93b440211c73"

class PortList(Enum):
    ALL_IANA_TCP_UUID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    ALL_IANA_TCP_UDP_UUID = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
    ALL_TCP_UUID = "fd591a34-56fd-11e1-9f27-406186ea4fc5"
    ALL_TCP_NMAP_1000_UDP_UUID = "9ddce1ae-57e7-11e1-b13c-406186ea4fc5"
    ALL_TCP_UDP_UUID = "fa135e67-5e57-40ca-bbad-06dd8e201443"

class Credentials(Enum):
    HULK_SSH_CRED_UUID = "22bdc0be-827c-4566-9b1d-2679cf85cb65"
    HULK_SMB_CRED_UUID = "13c917aa-e0cc-4027-b249-068ed0f6f4a0"


class GmpVScannerInterface():
    """
    Interface to the Greenbone Vulnerability Scanner via Greenbone Management Protocol (GMP) v22.4.
    Communication uses the python-gvm API package.
    """
    TIMEOUT = 20
    SCANNER_URL = "hulk.rz.uni-osnabrueck.de"
    PORT = 22 # default
    PERIODIC_TASK_NAME = "DETERRERS - Periodic task for registered hosts"

    username = ''
    password = ''

    
    def __init__(self, username, password):
        """
        Create a Gmp instance based on a TLS connection.
        """
        self.username = username
        self.password = password
        transform = EtreeCheckCommandTransform()

        connection = SSHConnection(
            hostname=self.SCANNER_URL,
            port=self.PORT,
            timeout=self.TIMEOUT)
        self.gmp = Gmp(connection=connection, transform=transform)

    def __enter__(self):
        """
        Context manager that wraps around the Gmp context manager.

        Raises:
            err: In case an exception occurs during initialization it will be forwarded.

        Returns:
            GreenboneVScannerInterface: Returns self.
        """
        self.gmp = self.gmp.__enter__()
        try:
            # further initialization need to be enclosed here
            self.gmp.authenticate(self.username, self.password)
            
            return self
        except Exception as err:
            self.gmp.__exit__(None, None, None)
            raise err


    def __exit__(self, exc_type, exc_value, traceback):
        self.gmp.__exit__(exc_type, exc_value, traceback)


    def get_gmp_version(self):
        response = self.gmp.get_version()
        pretty_print(response)


    def create_scan(self, host_ip : str, deterrers_url : str):
        """
        Creates and starts a scan for some host:
            1. Create a scan target.
            2. Create a scan task.
            3. Start the scan task.
            4. Create a scan alert.
            5. Add the alert to the task.

        Args:
            host_ip (str): Host IP address of the scanned host.
            deterrers_url (str): URL of the DETERRERS host.

        Returns:
            (str, str, str, str): Returns a tuple of (traget ID, task ID, report ID, alert ID).
                Returns (None, None, None, None) on error.
        """
        logger.debug("Create scan for %s", host_ip)
        target_uuid =None
        task_uuid = None
        report_uuid = None
        alert_uuid = None
        try:
            # create a target
            target_name = f"DETERRERS - Scan target {host_ip}"
            # TODO: which port list should be used (this is 'All IANA assigned TCP and UDP')
            target_uuid = self.__create_target(
                [host_ip,],
                target_name,
                Credentials.HULK_SSH_CRED_UUID.value,
                22,
                PortList.ALL_IANA_TCP_UDP_UUID.value
            )

            # create the task
            task_name = f"DETERRERS - Scan host {host_ip}"
            task_uuid = self.__create_task(
                target_uuid,
                task_name,
                ScanConfig.FULL_FAST_UUID.value,
                Scanner.OPENVAS_DEFAULT_SCANNER_UUID.value,
                False
            )
            # start task
            report_uuid = self.__start_task(task_uuid, task_name)

            # create/get an alert that sends the report back to the server
            # TODO: change back to HTTP GET method (see above)
            # alert_uuid = self.__create_http_alert(host_ip, deterrers_url, target_uuid, task_uuid, report_uuid)
            alert_uuid = self.__create_email_alert(host_ip, task_uuid, "hulk@rz.uos.de", "nwintering@uos.de")

            # modify task to set the alert
            self.gmp.modify_task(task_id=task_uuid, alert_ids=[alert_uuid])

            return target_uuid, task_uuid, report_uuid, alert_uuid

        except Exception as err:
            logger.error("Error while creating a scan for host %s. Error: %s", host_ip, repr(err))
            self.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
            
        return None, None, None, None


    def create_registration_scan(self, host_ip : str, deterrers_url : str):
        """
        TODO: in case registration scan should have special properties (e.g. be more thorough)

        Args:
            host_ip (str): _description_
            deterrers_url (str): _description_

        Returns:
            _type_: _description_
        """
        logger.debug("Create registration scan for %s", host_ip)
        target_uuid =None
        task_uuid = None
        report_uuid = None
        alert_uuid = None
        try:
            # create a target
            target_name = f"DETERRERS - Registration scan target {host_ip}"
            # TODO: which port list should be used (this is 'All IANA assigned TCP and UDP')
            target_uuid = self.__create_target(
                [host_ip,],
                target_name,
                Credentials.HULK_SSH_CRED_UUID.value,
                22,
                PortList.ALL_TCP_UDP_UUID.value
            )

            # create the task
            task_name = f"DETERRERS - Scan host {host_ip}"
            task_uuid = self.__create_task(
                target_uuid,
                task_name,
                ScanConfig.FULL_FAST_UUID.value,
                Scanner.OPENVAS_DEFAULT_SCANNER_UUID.value,
                False
            )
            # start task
            report_uuid = self.__start_task(task_uuid, task_name)

            # create/get an alert that sends the report back to the server
            # TODO: change back to HTTP GET method (see above)
            # alert_uuid = self.__create_http_alert(host_ip, deterrers_url, target_uuid, task_uuid, report_uuid)
            alert_uuid = self.__create_email_alert(host_ip, task_uuid, "hulk@rz.uos.de", "nwintering@uos.de")

            # modify task to set the alert
            self.gmp.modify_task(task_id=task_uuid, alert_ids=[alert_uuid])

            return target_uuid, task_uuid, report_uuid, alert_uuid

        except Exception as err:
            logger.error("Error while creating a registration scan for host %s. Error: %s", host_ip, repr(err))
            self.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
            
        return None, None, None, None


    def __start_task(self, task_uuid : str, task_name : str):
        response = self.gmp.start_task(task_uuid)
        response_status = int(response.xpath('@status')[0])
        if response_status != 202:
            raise RuntimeError(f"Scan task '{task_name}' could not be started! Status: {response_status}")
        if len(response.xpath('//report_id')) != 1:
            raise RuntimeError("start_task_response does not contain exactly one report id!")
        # get uuid which is an element value
        report_uuid = response.xpath('//report_id')[0].text
        return report_uuid

    def __create_task(self, target_uuid : str, task_name  : str, scan_config : str, scanner : str, alterable : bool = False, schedule : str  = None):
        response = self.gmp.create_task(
            name=task_name,
            comment=f"Auto-generated by DETERRERS - {datetime.now()}",
            config_id=scan_config,
            target_id=target_uuid,
            scanner_id=scanner,
            alterable=alterable,
            schedule_id=schedule
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 201:  # status code docu: https://hulk.rz.uos.de/manual/en/gmp.html#status-codes
            raise RuntimeError(f"Scan task '{task_name}' could not be created! Status: {response_status}")
        task_uuid = response.xpath('@id')[0]
        return task_uuid

    def __create_target(self, host_ip : list, target_name : str, ssh_cred : str, ssh_cred_port : int, port_list : str):
        response = self.gmp.create_target(
            name=target_name,
            comment=f"Auto-generated by DETERRERS - {datetime.now()}",
            hosts=host_ip,
            ssh_credential_id=ssh_cred,
            ssh_credential_port=ssh_cred_port,
            port_list_id=port_list,
            alive_test=AliveTest.CONSIDER_ALIVE
        )
        # parse target-id
        target_uuid = response.xpath('@id')[0]
        return target_uuid


    def __create_http_alert(self, host_ip : str, deterrers_url : str, target_uuid : str, task_uuid : str, report_uuid : str):
        """
        Creates an alert that issues a HTTP GET request to the DETERRERS server with all relevant0
        UUIDs as query parameters.

        Args:
            host_ip (str): Host IP address of the scanned host.
            deterrers_url (str): URL of the DETERRERS server.
            target_uuid (str): Target ID.
            task_uuid (str): Task ID.
            report_uuid (str): Report ID.

        Raises:
            RuntimeError: Exception is raised in case alert could not be created or modified.

        Returns:
            str: Returns the ID of th generated alert entity.
        """
        # set alert to issue a HTTP GET request with relevant Uuuids as query params
        name = f"DETERRERS - Alert for {host_ip}"
        comment = f"Auto-generated by DETERRERS for task {task_uuid} of {host_ip} - {datetime.now()}"
        method_data = {
            "URL" : f"{deterrers_url}?host_ip={host_ip}&target_uuid={target_uuid}&task_uuid={task_uuid}&report_uuid={report_uuid}"
        }
        response = self.gmp.create_alert(
            name=name,
            condition=AlertCondition.ALWAYS,
            event=AlertEvent.TASK_RUN_STATUS_CHANGED,
            event_data={'status' : 'Done'},
            method=AlertMethod.HTTP_GET,
            method_data=method_data,
            comment=comment
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 201:
            raise RuntimeError(f"Couldn't create HTTP GET alert. Status: {response_status}")
        alert_uuid = response.xpath('@id')[0]
        # modify the alert so that its id is present in the url parameters
        # only possible after creation because id is not known earlier
        method_data["URL"] = method_data["URL"] + f"&alert_uuid={alert_uuid}"
        response =  self.gmp.modify_alert(
            alert_id=alert_uuid,
            name=name,
            method_data=method_data,
            comment=comment
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 202:
            raise RuntimeError(f"Couldn't modify HTTP GET alert. Status: {response_status}")

        return alert_uuid


    def __create_email_alert(self, host_ip :str, task_uuid : str, from_addr : str, to_addr : str):
        """
        Creates an alert that sends report to given e-mail.

        Args:
            host_ip (str): Host IP address.
            task_uuid (str): Task ID.
            from_addr (str): E-Mail address of the GSM instance.
            to_addr (str): E-Mail address of the admin that is to be notified.

        Raises:
            RuntimeError: Exception is raised in case alert could not be created.

        Returns:
            str: Returns the ID of the generated alert entity.
        """
        method_data = {
            "from_address" : from_addr,
            "to_address" : to_addr,
            "subject" : f"Test Alert from GSM for task {task_uuid}",
            "notice" : "2" # attack report
        }
        response = self.gmp.create_alert(
            name=f"DETERRERS - E-Mail alert for {host_ip}",
            condition=AlertCondition.ALWAYS,
            event=AlertEvent.TASK_RUN_STATUS_CHANGED,
            event_data={'status' : 'Done'},
            method=AlertMethod.EMAIL,
            method_data=method_data,
            comment=f"Auto-generated by DETERRERS for task {task_uuid} of {host_ip} - {datetime.now()}"
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 201:
            raise RuntimeError(f"Couldn't create email alert. Status: {response_status}")
        alert_uuid = response.xpath('@id')[0]
        return alert_uuid

    def __create_schedule(self, schedule_name : str, freq : str):
        now = datetime.now()
        cal = icalendar.Calendar()
        # Some properties are required to be compliant
        cal.add('prodid', '-//DETERRERS//')
        cal.add('version', '2.0')

        event = icalendar.Event()
        event.add("dtstart", now)
        event.add('rrule', {'freq': freq})

        cal.add_component(event)

        response = self.gmp.create_schedule(
            name=schedule_name,
            icalendar=cal.to_ical(),
            timezone="UTC",
            comment=f"Auto-generated by DETERRERS - {now}"
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 201:
            raise RuntimeError(f"Couldn't create schedule. Status: {response_status}")
        schedule_uuid = response.xpath('@id')[0]
        return schedule_uuid

    
    def add_host_to_periodic_scan(self, host_ip : str):

        # check whether periodic task exists, if not create it
        filter_str = f'"{self.PERIODIC_TASK_NAME}" rows=-1 first=1'
        response = self.gmp.get_tasks(filter_string=filter_str)
        response_status = int(response.xpath('@status')[0])
        if response_status != 200:
            raise RuntimeError(f"Couldn't get tasks! Status: {response_status}")
        
        task_count = int(response.xpath('//task_count')[0].text)
        if task_count == 1: # for some reason the count starts at 1 when there is no task returned...
            # target for periodic task does not exist yet, therfore create it
            old_target_uuid = self.__create_target(
                [host_ip, ],
                f"Target for {self.PERIODIC_TASK_NAME} | {datetime.now()}",
                Credentials.HULK_SSH_CRED_UUID.value,
                22,
                PortList.ALL_IANA_TCP_UDP_UUID.value
            )
            schedule_uuid = self.__create_schedule(
                f"Schedule for {self.PERIODIC_TASK_NAME}",
                "weekly"
            )
            task_uuid = self.__create_task(
                old_target_uuid,
                self.PERIODIC_TASK_NAME,
                ScanConfig.FULL_FAST_UUID.value,
                Scanner.OPENVAS_DEFAULT_SCANNER_UUID.value,
                True,
                schedule_uuid
            )
            report_uuid = self.__start_task(task_uuid, self.PERIODIC_TASK_NAME)

        elif task_count == 2:
            task_xml = response.xpath('//task')[0]
            task_uuid = task_xml.attrib['id']
            old_target_uuid = task_xml.xpath('//target/@id')[0]

            # 1. clone target
            response = self.gmp.clone_target(old_target_uuid)
            new_target_uuid = response.xpath('@id')[0]
            # 2. modify new target with new host added to old host-list
            response = self.gmp.get_target(new_target_uuid)
            hosts = response.xpath('//hosts')[0].text.split(',')
            hosts = set(hosts + [host_ip])
            response = self.gmp.modify_target(
                new_target_uuid,
                hosts=hosts,
                name=f"Target for {self.PERIODIC_TASK_NAME} | {datetime.now()}"
            )
            response_status = int(response.xpath('@status')[0])
            if response_status != 200:
                raise RuntimeError(f"Couldn't modify host list of new target {new_target_uuid}! Status: {response_status}")
            # 3. modify task so that it uses new target
            response = self.gmp.modify_task(task_uuid, target_id=new_target_uuid)
            response_status = int(response.xpath('@status')[0])
            if response_status != 200:
                raise RuntimeError(f"Couldn't assign new target to task {task_uuid}! Status: {response_status}")
            # 4. delete old target
            response = self.gmp.delete_target(old_target_uuid, ultimate=True)
            response_status = int(response.xpath('@status')[0])
            if response_status != 200:
                raise RuntimeError(f"Couldn't delete target {old_target_uuid}! Status: {response_status}")

        else:
            raise RuntimeError(f"There are too many tasks matching the periodic task name. Couldn't add host {host_ip}.")




    def clean_up_scan_objects(self, target_uuid : str, task_uuid : str, report_uuid : str, alert_uuid : str):
        """
        Deletes all objects that are created during creation of a scan.

        Args:
            target_uuid (str): Tragte ID.
            task_uuid (str): Task ID.
            report_uuid (str): Report ID.
            alert_uuid (str): Alert ID.
        """
        logger.debug("Start clean up of scan!")
        if task_uuid:
            try:
                self.gmp.stop_task(task_id=task_uuid)
            except GvmError as err:
                logger.error("Couldn't stop task! Error: %s", repr(err))
        if report_uuid:
            try:
                self.gmp.delete_report(report_uuid)
            except GvmError as err:
                logger.error("Couldn't delete report! Error: %s", repr(err))
        if task_uuid:
            try:
                self.gmp.delete_task(task_uuid, ultimate=True)
            except GvmError as err:
                logger.error("Couldn't delete task! Error: %s", repr(err))
        if target_uuid:
            try:
                self.gmp.delete_target(target_id=target_uuid, ultimate=True)
            except GvmError as err:
                logger.error("Couldn't delete target! Error: %s", repr(err))
        if alert_uuid:
            try:
                self.gmp.delete_alert(alert_uuid, ultimate=True)
            except GvmError as err:
                logger.error("Couldn't delete alert! Error: %s", repr(err))


    def clean_up_all_history(self):
        """
        Delete all elements that were created by DETERRERS at some point in time.
        **ATTENTION**: Also stops and deletes running scan tasks.
        """
        filter_str = "DETERRERS"
        # delete all reports by DETERRERS
        logger.info("Deleting all reports by DETERRERS!")
        response = self.gmp.get_reports(filter_string=filter_str, ignore_pagination=True)
        to_del_set = set()
        for report in response.xpath('//report'):
            to_del_set.add( report.attrib['id'])
        for uuid in to_del_set:
            try:
                self.gmp.delete_report(uuid)
            except GvmError as err:
                logger.error("Couldn't delete report! Error: %s", repr(err))

        # delete all tasks by DETERRERS
        logger.info("Deleting all tasks by DETERRERS!")
        response = self.gmp.get_tasks(filter_string=filter_str)
        to_del_set = set()
        for task in response.xpath('//task'):
            to_del_set.add(task.attrib['id'])
        for uuid in to_del_set:
            try:
                self.gmp.stop_task(task_id=uuid)
                self.gmp.delete_task(uuid, ultimate=True)
            except GvmError as err:
                logger.error("Couldn't stop/delete task! Error: %s", repr(err))

        # delete all targets by DETERRERS
        logger.info("Deleting all targets by DETERRERS!")
        response = self.gmp.get_targets(filter_string=filter_str)
        to_del_set = set()
        for task in response.xpath('//target'):
            to_del_set.add(task.attrib['id'])
        for uuid in to_del_set:
            try:
                self.gmp.delete_target(uuid, ultimate=True)
            except GvmError as err:
                logger.error("Couldn't delete target! Error: %s", repr(err))

        # delete all alerts by DETERRERS
        logger.info("Deleting all alerts by DETERRERS!")
        response = self.gmp.get_alerts(filter_string=filter_str)
        to_del_set = set()
        for task in response.xpath('//alert'):
            to_del_set.add(task.attrib['id'])
        for uuid in to_del_set:
            try:
                self.gmp.delete_alert(uuid, ultimate=True)
            except GvmError as err:
                logger.error("Couldn't delete alert! Error: %s", repr(err))


    def get_report_xml(self, report_uuid : str):
        rep_filter = "status=Done apply_overrides=0 rows=-1 min_qod=70 first=1"
        try:
            response = self.gmp.get_report(report_uuid, filter_string=rep_filter, ignore_pagination=True)
            return response
        except GvmError as err:
            logger.error("Couldn't fetch report with ID '%s' from GSM! Error: %s", report_uuid, err)

        return None

    def extract_report_data(self, report):
        scan_start = report.xpath('//scan_start')[0].text

        results_xml = report.xpath('//results/result')
        results = []

        for result_xml in results_xml:
            result_uuid = result_xml.attrib['id']
            host_ip = result_xml.xpath('host')[0].text
            hostname = result_xml.xpath('host/hostname')[0].text
            nvt_name = result_xml.xpath('nvt/name')[0].text
            nvt_oid = result_xml.xpath('nvt')[0].attrib['oid']
            cvss_base = float(result_xml.xpath('nvt/cvss_base')[0].text)
            cvss_vector = result_xml.xpath('nvt/severities/severity/value')[0].text

            res = {
                'uuid' : result_uuid,
                'host_ip' : host_ip,
                'hostname' : hostname,
                'nvt_name' : nvt_name,
                'nvt_oid' : nvt_oid,
                'cvss_base' : cvss_base,
                'cvss_vector' : cvss_vector
            }
            results.append(res)

        return scan_start, results



# if __name__ == "__main__":
#     username = 'DETERRERS'
#     from getpass import getpass
#     password = getpass()

#     with GmpVScannerInterface(username, password) as interf:
#         test_host_ip = "131.173.22.184"

#         # target_uuid, task_uuid, report_uuid, alert_uuid = interf.create_scan(test_host_ip, test_host_ip)
#         # input("Enter anything to delete everything: ")
#         # try:
#         #     interf.clean_up_all_history()
#         # except Exception() as err:
#         #     logger.error("%s", repr(err))
#         # input("Enter anything to delete everything: ")
#         # interf.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)

#         # test_report_id = "c936b5cf-0e62-4c5b-af40-44ae18dee92c"
#         # report = interf.get_report_xml(test_report_id)
#         # with open('test_report_xml.txt', 'w') as f:
#         #     pretty_print(report, f)
#         # scan_start, results = interf.extract_report_data(report)

#         interf.add_host_to_periodic_task(test_host_ip)
#         interf.add_host_to_periodic_task("131.173.23.44")
