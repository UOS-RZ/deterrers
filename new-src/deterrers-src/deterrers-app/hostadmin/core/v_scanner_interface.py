import logging
from enum import Enum
from datetime import datetime, timedelta
import icalendar
from base64 import b64decode
import os
from time import sleep

from gvm.protocols.gmp import Gmp
from gvm.connections import SSHConnection
from gvm.transforms import EtreeCheckCommandTransform
from gvm.errors import GvmError
from gvm.xml import pretty_print
from gvm.protocols.gmpv224 import AlertCondition, AlertEvent, AlertMethod, AliveTest, HostsOrdering

from .risk_assessor import VulnerabilityScanResult

logger = logging.getLogger(__name__)


""" Following enums hold UUIDs that are custom to the respective GSM system """

class ScanConfig(Enum):
    FULL_FAST_UUID = "daba56c8-73ec-11df-a475-002264764cea"
    FULL_FAST_ULTIMATE_UUID = "698f691e-7489-11df-9d8c-002264764cea"
    FULL_VERY_DEEP_UUID = "708f25c4-7489-11df-8094-002264764cea"
    FULL_VERY_DEEP_ULTIMATE_UUID = "74db13d6-7489-11df-91b9-002264764cea"

class Scanner(Enum):
    OPENVAS_DEFAULT_SCANNER_UUID = "08b69003-5fc2-4037-a479-93b440211c73"

class PortList(Enum):
    ALL_IANA_TCP_UUID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    ALL_IANA_TCP_UDP_UUID = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
    ALL_TCP_UUID = "fd591a34-56fd-11e1-9f27-406186ea4fc5"
    ALL_TCP_NMAP_1000_UDP_UUID = "9ddce1ae-57e7-11e1-b13c-406186ea4fc5"
    ALL_TCP_UDP_UUID = "94c4fe31-c6e4-4e38-b876-fc00a0225021"

class Credentials(Enum):
    HULK_SSH_CRED_UUID = "22bdc0be-827c-4566-9b1d-2679cf85cb65"
    HULK_SMB_CRED_UUID = "13c917aa-e0cc-4027-b249-068ed0f6f4a0"

class ReportFormat(Enum):
    ANON_XML_UUID = "5057e5cc-b825-11e4-9d0e-28d24461215b"
    XML_UUID = "a994b278-1f62-11e1-96ac-406186ea4fc5"
    HTML_UUID = "ffa123c9-a2d2-409e-bbbb-a6c1385dbeaa"




class GmpAPIError(Exception):
    """ Custom exception that can be raised when the gmp does not respond as expected. """

class GmpVScannerInterface():
    """
    Interface to the Greenbone Vulnerability Scanner via Greenbone Management Protocol (GMP) v22.4.
    Communication uses the python-gvm API package.
    """
    TIMEOUT = 60*180

    PERIODIC_TASK_NAME = "DETERRERS - Periodic task for registered hosts"
    PERIODIC_CVE_TASK_NAME = "DETERRERS - Periodic task for registered hosts (CVE Scan only)"

    
    def __init__(self, username, password, scanner_url, scanner_port=22):
        """
        Create a Gmp instance based on a TLS connection.
        """
        self.username = username
        self.__password = password
        self.scanner_url = scanner_url
        self.scanner_port = scanner_port

        if os.environ.get('MICRO_SERVICE', None):
            known_hosts_path = os.environ.get('MICRO_SERVICE', '')+'/known_hosts'
        else:
            known_hosts_path = None

        transform = EtreeCheckCommandTransform()
        connection = SSHConnection(
            hostname=self.scanner_url,
            port=self.scanner_port,
            timeout=self.TIMEOUT,
            # vulnerability scanner must have been added to a known_hosts-file before application was started
            known_hosts_file=known_hosts_path
        )
        self.gmp = Gmp(connection=connection, transform=transform)
        self.enter_ok = True

    def __enter__(self):
        """
        Context manager that wraps around the Gmp context manager.

        Raises:
            err: In case an exception occurs during initialization it will be forwarded.

        Returns:
            GreenboneVScannerInterface: Returns self.
        """
        logger.debug("Start session with vulnerability scanner.")
        self.gmp = self.gmp.__enter__()
        try:
            # further initialization need to be enclosed here
            response = self.gmp.authenticate(self.username, self.__password)
            if int(response.xpath('@status')[0]) != 200:
                logger.error("Authentication with Scanner failed! Status: %s", response.xpath('@status')[0])
                self.enter_ok = False
        except:
            logger.exception("Authentication failed!")
            self.gmp.__exit__(None, None, None)
            self.enter_ok = False
            # raise err
            
        return self


    def __exit__(self, exc_type, exc_value, traceback):
        logger.debug("End session with vulnerability scanner.")
        self.gmp.__exit__(exc_type, exc_value, traceback)


    def __start_task(self, task_uuid : str, task_name : str) -> str:
        """
        Start a scan task in the vulnerability scanner.

        Args:
            task_uuid (str): UUID of the task.
            task_name (str): Name of the task

        Raises:
            GmpAPIError: If vulnerability scanner couldn't start task.
            GmpAPIError: If an invalid number of report UUIDs is returned by the scanner.

        Returns:
            str: UUID of the report.
        """
        response = self.gmp.start_task(task_uuid)
        response_status = int(response.xpath('@status')[0])
        if response_status != 202:
            raise GmpAPIError(f"Scan task '{task_name}' could not be started! Status: {response_status}")
        if len(response.xpath('//report_id')) != 1:
            raise GmpAPIError("start_task_response does not contain exactly one report id!")
        # get uuid which is an element value
        report_uuid = response.xpath('//report_id')[0].text
        return report_uuid

    def __create_task(
        self,
        target_uuid : str,
        task_name : str,
        scan_config_uuid : str,
        scanner_uuid : str,
        alert_uuids : list[str]|None = None,
        alterable : bool = False,
        schedule_uuid : str|None  = None,
        hosts_ordering : HostsOrdering = HostsOrdering.RANDOM,
        max_conc_nvts : int = 64,
        max_conc_hosts : int = 20) -> str:
        """
        Create a scan task with given configurations.

        Args:
            target_uuid (str): UUID of the target.
            task_name (str): Name to give the task.
            scan_config_uuid (str): UUID of the ScanConfiguration.
            scanner_uuid (str): UUID of the scanner.
            alert_uuidss (list[str]|None): List of UUIDs of alerts. Defaults to None.
            alterable (bool, optional): Whether to create the task as alterable. Defaults to False.
            schedule_uuid (str|None, optional): UUID of the schedule. Defaults to None.
            hosts_ordering (HostsOrdering): Enum instance for configuring the ordering of target hosts. Defaults to random.

        Raises:
            GmpAPIError: If vulnerability scanner could not create the task.

        Returns:
            str: UUID of the created task.
        """
        response = self.gmp.create_task(
            name=task_name,
            comment=f"Auto-generated by DETERRERS - {datetime.now()}",
            config_id=scan_config_uuid,
            target_id=target_uuid,
            scanner_id=scanner_uuid,
            alert_ids=alert_uuids,
            alterable=alterable,
            schedule_id=schedule_uuid,
            hosts_ordering=hosts_ordering,
            preferences={
                "max_checks" : max_conc_nvts,
                "max_hosts" : max_conc_hosts,
            }
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 201:  # status code docu: https://hulk.rz.uos.de/manual/en/gmp.html#status-codes
            raise GmpAPIError(f"Scan task '{task_name}' could not be created! Status: {response_status}")
        task_uuid = response.xpath('@id')[0]
        return task_uuid

    def __create_target(
        self,
        host_ip : list,
        target_name : str,
        ssh_cred_uuid : str,
        ssh_cred_port : int,
        smb_cred_uuid : str,
        port_list_uuid : str,
        alive_test : AliveTest = AliveTest.CONSIDER_ALIVE) -> str:
        """
        Create a scan target with given configurations.

        Args:
            host_ip (list): IP addresses of hosts to be targeted by this target.
            target_name (str): Name to give the target.
            ssh_cred_uuid (str): UUID of the SSH credential configuration.
            ssh_cred_port (int): Port to use for SSH.
            smb_cred_uuid (str): UUID of the SMB credential configuration.
            port_list_uuid (str): UUID of the PortList.
            alive_test (AliveTest): Enum instance for configuring the alive test. Defaults to 'Consider Alive'.

        Raises:
            GmpAPIError: If vulnerability scanner could not create the target.

        Returns:
            str: UUID of the created target.
        """
        response = self.gmp.create_target(
            name=target_name,
            comment=f"Auto-generated by DETERRERS - {datetime.now()}",
            hosts=host_ip,
            ssh_credential_id=ssh_cred_uuid,
            ssh_credential_port=ssh_cred_port,
            smb_credential_id=smb_cred_uuid,
            port_list_id=port_list_uuid,
            alive_test=alive_test
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 201:  # status code docu: https://hulk.rz.uos.de/manual/en/gmp.html#status-codes
            raise GmpAPIError(f"Scan target '{target_name}' could not be created! Status: {response_status}")
        # parse target-id
        target_uuid = response.xpath('@id')[0]
        return target_uuid


    def __create_http_alert(self, alert_name : str):
        """
        Creates an alert that issues a HTTP GET request to the DETERRERS server with all relevant0
        UUIDs as query parameters.

        Args:
            alert_name (str): Alert name.

        Raises:
            GmpAPIError: Exception is raised in case alert could not be created.

        Returns:
            str: Returns the ID of th generated alert entity.
        """
        # set alert to issue a HTTP GET request with relevant Uuuids as query params
        comment = f"Auto-generated by DETERRERS for {alert_name} - {datetime.now()}"
        method_data = {"URL" : ""}
        response = self.gmp.create_alert(
            name=alert_name,
            condition=AlertCondition.ALWAYS,
            event=AlertEvent.TASK_RUN_STATUS_CHANGED,
            event_data={'status' : 'Done'},
            method=AlertMethod.HTTP_GET,
            method_data=method_data,
            comment=comment
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 201:
            raise GmpAPIError(f"Couldn't create HTTP GET alert. Status: {response_status}")
        alert_uuid = response.xpath('@id')[0]

        return alert_uuid

    def __modify_http_alert_data(
        self,
        host_ip : str,
        deterrers_url : str,
        target_uuid : str,
        task_uuid : str,
        report_uuid : str,
        alert_uuid : str):
        """
        Set the necessary identifiers as query parameters in the HTTP alert.

        Args:
            host_ip (str): IP address of the host.
            deterrers_url (str): Server address to send alert to.
            target_uuid (str): UUID of scan target.
            task_uuid (str): UUID of scan task.
            report_uuid (str): UUID of scan report.
            alert_uuid (str): UUID of HTTP alert itself.

        Raises:
            GmpAPIError: Raised if couldn't query or modify alert.
        """
        response = self.gmp.get_alert(alert_uuid)
        response_status = int(response.xpath('@status')[0])
        if response_status != 200:
            raise GmpAPIError(f"Could not query alert '{alert_uuid}'. Status: {response_status}")
        name = response.xpath('//alert/name')[0].text
        condition = response.xpath('//alert/condition')[0].text
        event = response.xpath('//alert/event')[0].text
        event_data = {'status' : 'Done'} # {response.xpath('//alert/event/data/name')[0].text : response.xpath('//alert/event/data')[0].text} # TODO: Quick-fixed; find real error why 'response.xpath('//alert/event/data')[0].text' does not return 'Done'
        method = response.xpath('//alert/method')[0].text
        
        comment = response.xpath('//alert/comment')[0].text
        # modify the alert so that its id is present in the url parameters
        # only possible after creation because id is not known earlier
        # NOTE: all fields need to be reset because API is buggy
        response =  self.gmp.modify_alert(
            alert_id=alert_uuid,
            name=name,
            condition=AlertCondition(condition),
            event=AlertEvent(event),
            event_data=event_data,
            method=AlertMethod(method),
            method_data = {
                "URL" : f"{deterrers_url}?host_ip={host_ip}&target_uuid={target_uuid}&task_uuid={task_uuid}&report_uuid={report_uuid}&alert_uuid={alert_uuid}"
            },
            comment=comment
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 200:
            raise GmpAPIError(f"Couldn't modify HTTP GET alert '{alert_uuid}'. Status: {response_status}")
        

    def __create_email_alert(
        self,
        host_ip :str,
        task_uuid : str,
        target_uuid : str,
        report_uuid : str,
        from_addr : str,
        to_addr : str):
        """
        Creates an alert that sends report to given e-mail.

        Args:
            host_ip (str): Host IP address.
            task_uuid (str): Task ID.
            from_addr (str): E-Mail address of the GSM instance.
            to_addr (str): E-Mail address of the admin that is to be notified.

        Raises:
            GmpAPIError: Exception is raised in case alert could not be created.

        Returns:
            str: Returns the ID of the generated alert entity.
        """
        method_data = {
            "from_address" : from_addr,
            "to_address" : to_addr,
            "subject" : f"Test Alert from GSM for host_ip={host_ip}",
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
            raise GmpAPIError(f"Couldn't create email alert. Status: {response_status}")
        alert_uuid = response.xpath('@id')[0]
        return alert_uuid

    def __create_schedule(self, schedule_name : str, freq : str = 'weekly') -> str:
        """
        Create a schedule for scan tasks in the vulnerability scanner.
        First scheduled event will be 12 hours in future.

        Args:
            schedule_name (str): Name to give the schedule.
            freq (str): Frequency for the schedult, e.g. 'daily', 'weekly', 'monthly' etc.

        Raises:
            GmpAPIError: If vulnerability scanner could not create the schedule.

        Returns:
            str: UUID of the schedule.
        """
        now = datetime.utcnow()
        cal = self.__create_cal(timedelta(hours=12), freq=freq)

        response = self.gmp.create_schedule(
            name=schedule_name,
            icalendar=cal.to_ical(),
            timezone="UTC",
            comment=f"Auto-generated by DETERRERS - {now}"
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 201:
            raise GmpAPIError(f"Couldn't create schedule. Status: {response_status}")
        schedule_uuid = response.xpath('@id')[0]
        return schedule_uuid

    def __create_cal(self, start_delta : timedelta, freq : str = 'weekly') -> icalendar.Calendar:
        now = datetime.utcnow()
        cal = icalendar.Calendar()
        # Some properties are required to be compliant
        cal.add('prodid', '-//DETERRERS//')
        cal.add('version', '2.0')

        event = icalendar.Event()
        event.add("dtstart", now + start_delta)
        event.add('rrule', {'freq': freq})

        cal.add_component(event)
        return cal

    def __get_task_info(self, task_name : str):
        filter_str = f'"{task_name}" rows=-1 first=1'
        response = self.gmp.get_tasks(filter_string=filter_str)
        response_status = int(response.xpath('@status')[0])
        if response_status != 200:
            raise GmpAPIError(f"Couldn't get tasks! Status: {response_status}")
        try:
            # get task uuid and uuid of the existing target
            task_xml = response.xpath('//task')[0]
            task_uuid = task_xml.attrib['id']
            target_uuid = task_xml.xpath('//target/@id')[0]
        except IndexError:
            task_xml = None
            task_uuid = None
            target_uuid = None
        return task_xml, task_uuid, target_uuid

    def __stop_task_if_running(self, task_name : str):
        task_xml, task_uuid, target_uuid = self.__get_task_info(task_name)
        # wait if task is queued or requested, stop task in case it is running
        task_status = task_xml.xpath('//task/status')[0].text
        while task_status == "Queued" or task_status == "Requested" or task_status == "Stop Requested":
            sleep(1.0)
            task_xml, task_uuid, target_uuid = self.__get_task_info(task_name)
            task_status = task_xml.xpath('//task/status')[0].text
                
        running = (task_status == 'Running')
        if running:
            response = self.gmp.stop_task(task_uuid)
            response_status = int(response.xpath('@status')[0])
            if response_status >= 300:
                raise GmpAPIError(f"Couldn't stop periodic task. Status: {response_status}")
            stopped = True
        else:
            stopped = False
        return task_xml, task_uuid, target_uuid, stopped

    def __restart_scheduled_task(self, schedule_uuid : str):
        # reschedule task because scheduled tasks cannot be resumed
        new_cal = self.__create_cal(timedelta(minutes=1))
        response = self.gmp.modify_schedule(
                        schedule_uuid,
                        icalendar=new_cal.to_ical(),
                        timezone='UTC'
                    )
        response_status = int(response.xpath('@status')[0])
        if response_status not in (200, 201, 202, 203, 204):
            raise GmpAPIError(f"Couldn't modify schedule. Status: {response_status}")

    def __set_new_target(self, task_uuid, new_target_uuid):
        response = self.gmp.modify_task(task_uuid, target_id=new_target_uuid)
        response_status = int(response.xpath('@status')[0])
        if response_status != 200:
            raise GmpAPIError(f"Couldn't assign new target to task {task_uuid}! Status: {response_status}")


    def create_ordinary_scan(self, host_ip : str, deterrers_url : str):
        """
        Creates and starts a scan for some host:
            1. Create a scan target.
            2. Create a scan task.
            3. Start the scan task.
            4. Create a scan alert.
            5. Add the alert to the task.
        Scans all TCP and UDP ports standardized by IANA in 'Full and Fast Ultimate' mode.

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
            target_name = f"DETERRERS - Scan target for host {host_ip}"
            target_uuid = self.__create_target(
                [host_ip,],
                target_name,
                Credentials.HULK_SSH_CRED_UUID.value,
                22,
                Credentials.HULK_SMB_CRED_UUID.value,
                PortList.ALL_TCP_NMAP_1000_UDP_UUID.value
            )

            # create/get an alert that sends the report back to the server
            alert_name = f"DETERRERS - Scan alert for host {host_ip}"
            alert_uuid = self.__create_http_alert(alert_name)

            # create the task
            task_name = f"DETERRERS - Scan task for host {host_ip}"
            task_uuid = self.__create_task(
                target_uuid,
                task_name,
                ScanConfig.FULL_FAST_UUID.value,
                Scanner.OPENVAS_DEFAULT_SCANNER_UUID.value,
                [alert_uuid,],
                max_conc_nvts=32
            )

            # start task
            report_uuid = self.__start_task(task_uuid, task_name)

            self.__modify_http_alert_data(host_ip, deterrers_url, target_uuid, task_uuid, report_uuid, alert_uuid)

            return target_uuid, task_uuid, report_uuid, alert_uuid

        except:
            logger.exception("Error while creating a scan for host %s.", host_ip)
            self.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
            
        return None, None, None, None


    def create_registration_scan(self, host_ip : str, deterrers_url : str):
        """
        Creates and starts a scan for some host:
            1. Create a scan target.
            2. Create a scan task.
            3. Start the scan task.
            4. Create a scan alert.
            5. Add the alert to the task.
        Scans all IANA registered TCP and UDP ports in 'Full and Fast Ultimate' mode.

        Args:
            host_ip (str): Host IP address of the scanned host.
            deterrers_url (str): URL of the DETERRERS host.

        Returns:
            (str, str, str, str): Returns a tuple of (traget ID, task ID, report ID, alert ID).
                Returns (None, None, None, None) on error.
        """
        logger.debug("Create registration scan for %s", host_ip)
        target_uuid =None
        task_uuid = None
        report_uuid = None
        alert_uuid = None
        try:
            # create a target
            target_name = f"DETERRERS - Registration scan target for host {host_ip}"
            target_uuid = self.__create_target(
                [host_ip,],
                target_name,
                Credentials.HULK_SSH_CRED_UUID.value,
                22,
                Credentials.HULK_SMB_CRED_UUID.value,
                # Limit port scan to all tcp and udp ports registered with IANA.
                # This will also minimize probability that defense mechanisms against port scans
                # are triggered on the host.
                PortList.ALL_TCP_NMAP_1000_UDP_UUID.value,
            )

            # create/get an alert that sends the report back to the server
            alert_name = f"DETERRERS - Registration alert for host {host_ip}"
            alert_uuid = self.__create_http_alert(alert_name)

            # create the task
            task_name = f"DETERRERS - Registration scan task for host {host_ip}"
            task_uuid = self.__create_task(
                target_uuid,
                task_name,
                ScanConfig.FULL_FAST_ULTIMATE_UUID.value,
                Scanner.OPENVAS_DEFAULT_SCANNER_UUID.value,
                [alert_uuid,],
                max_conc_nvts=32
            )

            # start task
            report_uuid = self.__start_task(task_uuid, task_name)

            # modify alert to hold relevant uuids
            self.__modify_http_alert_data(host_ip, deterrers_url, target_uuid, task_uuid, report_uuid, alert_uuid)

            return target_uuid, task_uuid, report_uuid, alert_uuid

        except:
            logger.exception("Error while creating a registration scan for host %s.", host_ip)
            self.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
            
        return None, None, None, None


    def create_periodic_scan(self, host_ip : str, deterrers_url : str, schedule_freq : str = 'weekly'):
        """
        Creates and starts a periodic scan with some host:
            1. Create a scan target.
            2. Create a schedule.
            3. Create a scan alert.
            4. Create a scan task.
            5. Add the alert to the task.
        Scans all IANA registered TCP and UDP ports in 'Full and Fast Ultimate' mode.

        Args:
            host_ip (str): Host IP address of the first host.
            deterrers_url (str): URL of the DETERRERS host.
        """
        logger.debug("Create periodic scan")
        target_uuid = self.__create_target(
            [host_ip, ],
            f"Target for task '{self.PERIODIC_TASK_NAME}' | {datetime.now()}",
            Credentials.HULK_SSH_CRED_UUID.value,
            22,
            Credentials.HULK_SMB_CRED_UUID.value,
            PortList.ALL_TCP_NMAP_1000_UDP_UUID.value
        )
        schedule_uuid = self.__create_schedule(
            f"Schedule for task '{self.PERIODIC_TASK_NAME}' | {datetime.now()}",
            schedule_freq
        )
        alert_uuid = self.__create_http_alert(f"Alert for task '{self.PERIODIC_TASK_NAME}' | {datetime.now()}")
        task_uuid = self.__create_task(
            target_uuid,
            self.PERIODIC_TASK_NAME,
            ScanConfig.FULL_FAST_UUID.value,
            Scanner.OPENVAS_DEFAULT_SCANNER_UUID.value,
            [alert_uuid,],
            True,
            schedule_uuid,
            hosts_ordering=HostsOrdering.RANDOM,
            max_conc_nvts=32,
            max_conc_hosts=40
        )
        # report_uuid = self.__start_task(task_uuid, self.PERIODIC_TASK_NAME)
        report_uuid = ""
        self.__modify_http_alert_data('', deterrers_url, '', task_uuid, report_uuid, alert_uuid)

        
    def add_host_to_periodic_scans(self, host_ip : str, deterrers_url : str) -> bool:
        """
        Add a host to the periodic scan task which scans all hosts that are online once a week.
        Add also to the periodic CVE task.
        If the periodic scan task does not exist yet, it will be created.

        Args:
            host_ip (str): IP address to add to the periodic scan task.
            deterrers_url (str): URL to the DETERRERS server.

        Returns:
            bool: Returns True on success and False if something went wrong.
        """
        
        try:
            # check whether periodic task exists, if not, IndexError will be raised later
            task_xml, task_uuid, old_target_uuid = self.__get_task_info(self.PERIODIC_TASK_NAME)

            if not task_uuid:
                # periodic scan task does not exist yet
                self.create_periodic_scan(
                    host_ip=host_ip,
                    deterrers_url=deterrers_url
                )

                # TODO: Creation of CVE task
            else:
                # periodic scan task does exist
                task_xml, task_uuid, old_target_uuid, stopped = self.__stop_task_if_running(self.PERIODIC_TASK_NAME)
                cve_task_xml, cve_task_uuid, _, cve_stopped = self.__stop_task_if_running(self.PERIODIC_CVE_TASK_NAME)

                # 1. clone target
                response = self.gmp.clone_target(old_target_uuid)
                response_status = int(response.xpath('@status')[0])
                if response_status != 201:
                    raise GmpAPIError(f"Couldn't clone target {old_target_uuid}! Status: {response_status}")
                new_target_uuid = response.xpath('@id')[0]
                # 2. modify new target with new host added to old host-list
                response = self.gmp.get_target(new_target_uuid)
                response_status = int(response.xpath('@status')[0])
                if response_status != 200:
                    raise GmpAPIError(f"Couldn't get new target {new_target_uuid}! Status: {response_status}")
                hosts = response.xpath('//hosts')[0].text.split(',')
                hosts = set(hosts + [host_ip])
                response = self.gmp.modify_target(
                    new_target_uuid,
                    hosts=hosts,
                    name=f"Target for task periodic tasks | {datetime.now()}"
                )
                response_status = int(response.xpath('@status')[0])
                if response_status != 200:
                    raise GmpAPIError(f"Couldn't modify host list of new target {new_target_uuid}! Status: {response_status}")
                # 3. modify tasks so that they use new target
                self.__set_new_target(task_uuid, new_target_uuid)
                self.__set_new_target(cve_task_uuid, new_target_uuid)
                # 4. delete old target
                response = self.gmp.delete_target(old_target_uuid, ultimate=True)
                response_status = int(response.xpath('@status')[0])
                if response_status != 200:
                    raise GmpAPIError(f"Couldn't delete target {old_target_uuid}! Status: {response_status}")

                if stopped:
                    schedule_uuid = task_xml.xpath('//schedule/@id')[0]
                    self.__restart_scheduled_task(schedule_uuid)
                if cve_stopped:
                    cve_schedule_uuid = cve_task_xml.xpath('//schedule/@id')[0]
                    self.__restart_scheduled_task(cve_schedule_uuid)

        except GmpAPIError:
            logger.exception("Couldn't add host to periodic scan task.")
            return False
        return True


    def remove_host_from_periodic_scans(self, host_ip : str) -> bool:
        """
        Remove a host from the periodic scan tasks.

        Args:
            host_ip (str): IP address of the host that is to be removed.

        Returns:
            bool: Returns True on success and False on failure.
        """
        try:
            task_xml, task_uuid, old_target_uuid = self.__get_task_info(self.PERIODIC_TASK_NAME)
            if task_uuid:
                # periodic scan task does exist
                task_xml, task_uuid, old_target_uuid, stopped = self.__stop_task_if_running(self.PERIODIC_TASK_NAME)
                cve_task_xml, cve_task_uuid, _, cve_stopped = self.__stop_task_if_running(self.PERIODIC_CVE_TASK_NAME)

                # 1. clone target
                response = self.gmp.clone_target(old_target_uuid)
                response_status = int(response.xpath('@status')[0])
                if response_status != 201:
                    raise GmpAPIError(f"Couldn't clone target {old_target_uuid}! Status: {response_status}")
                new_target_uuid = response.xpath('@id')[0]
                # 2. modify new target with new host added to old host-list
                response = self.gmp.get_target(new_target_uuid)
                response_status = int(response.xpath('@status')[0])
                if response_status != 200:
                    raise GmpAPIError(f"Couldn't get new target {new_target_uuid}! Status: {response_status}")
                hosts = [h.strip() for h in response.xpath('//hosts')[0].text.split(',')]
                try:
                    hosts.remove(host_ip)
                except ValueError:
                    pass
                response = self.gmp.modify_target(
                    new_target_uuid,
                    hosts=hosts,
                    name=f"Target for task '{self.PERIODIC_TASK_NAME}' | {datetime.now()}"
                )
                response_status = int(response.xpath('@status')[0])
                if response_status != 200:
                    raise GmpAPIError(f"Couldn't modify host list of new target {new_target_uuid}! Status: {response_status}")
                # 3. modify task so that it uses new target
                self.__set_new_target(task_uuid, new_target_uuid)
                self.__set_new_target(cve_task_uuid, new_target_uuid)
                # 4. delete old target
                response = self.gmp.delete_target(old_target_uuid, ultimate=True)
                response_status = int(response.xpath('@status')[0])
                if response_status != 200:
                    raise GmpAPIError(f"Couldn't delete target {old_target_uuid}! Status: {response_status}")

                if stopped:
                    # reschedule task
                    schedule_uuid = task_xml.xpath('//schedule/@id')[0]
                    self.__restart_scheduled_task(schedule_uuid)
                if cve_stopped:
                    # reschedule task
                    cve_schedule_uuid = cve_task_xml.xpath('//schedule/@id')[0]
                    self.__restart_scheduled_task(cve_schedule_uuid)
        except GmpAPIError:
            logger.exception("Couldn't remove host from periodic scan task.")
            return False
        return True


    def clean_up_scan_objects(self, target_uuid : str, task_uuid : str, report_uuid : str, alert_uuid : str|list[str]):
        """
        Deletes all objects that are created during creation of a scan.

        Args:
            target_uuid (str): Tragte ID.
            task_uuid (str): Task ID.
            report_uuid (str): Report ID.
            alert_uuid (str|list[str]): Alert ID.
        """
        logger.debug("Start clean up of scan!")
        if task_uuid:
            try:
                self.gmp.stop_task(task_id=task_uuid)
            except GvmError as err:
                logger.warning("Couldn't stop task! Error: %s", str(err))
                self.gmp.authenticate(self.username, self.__password) # TODO: instead of reauthentication, we could check beforehand if the task is running
        if report_uuid:
            try:
                self.gmp.delete_report(report_uuid)
            except GvmError as err:
                logger.warning("Couldn't delete report! Error: %s", str(err))
                self.gmp.authenticate(self.username, self.__password)
        if task_uuid:
            try:
                self.gmp.delete_task(task_uuid, ultimate=True)
            except GvmError as err:
                logger.warning("Couldn't delete task! Error: %s", str(err))
                self.gmp.authenticate(self.username, self.__password)
        if target_uuid:
            try:
                self.gmp.delete_target(target_id=target_uuid, ultimate=True)
            except GvmError as err:
                logger.warning("Couldn't delete target! Error: %s", str(err))
                self.gmp.authenticate(self.username, self.__password)
        if alert_uuid:
            try:
                if type(alert_uuid) is str:
                    self.gmp.delete_alert(alert_uuid, ultimate=True)
                elif type(alert_uuid) is list:
                    for a_uuid in alert_uuid:
                        self.gmp.delete_alert(a_uuid, ultimate=True)
            except GvmError as err:
                logger.warning("Couldn't delete alert! Error: %s", str(err))
                self.gmp.authenticate(self.username, self.__password)


    # def __clean_up_all_history(self):
    #     """
    #     Delete all elements that were created by DETERRERS at some point in time.
    #     **ATTENTION**: Also stops and deletes running scan tasks.
    #     """
    #     filter_str = "DETERRERS"
    #     # delete all reports by DETERRERS
    #     logger.info("Deleting all reports by DETERRERS!")
    #     response = self.gmp.get_reports(filter_string=filter_str, ignore_pagination=True)
    #     to_del_set = set()
    #     for report in response.xpath('//report'):
    #         to_del_set.add( report.attrib['id'])
    #     for uuid in to_del_set:
    #         try:
    #             self.gmp.delete_report(uuid)
    #         except GvmError as err:
    #             logger.warning("Couldn't delete report! Error: %s", str(err))

    #     # delete all tasks by DETERRERS
    #     logger.info("Deleting all tasks by DETERRERS!")
    #     response = self.gmp.get_tasks(filter_string=filter_str)
    #     to_del_set = set()
    #     for task in response.xpath('//task'):
    #         to_del_set.add(task.attrib['id'])
    #     for uuid in to_del_set:
    #         try:
    #             self.gmp.stop_task(task_id=uuid)
    #             self.gmp.delete_task(uuid, ultimate=True)
    #         except GvmError as err:
    #             logger.warning("Couldn't stop/delete task! Error: %s", str(err))

    #     # delete all targets by DETERRERS
    #     logger.info("Deleting all targets by DETERRERS!")
    #     response = self.gmp.get_targets(filter_string=filter_str)
    #     to_del_set = set()
    #     for task in response.xpath('//target'):
    #         to_del_set.add(task.attrib['id'])
    #     for uuid in to_del_set:
    #         try:
    #             self.gmp.delete_target(uuid, ultimate=True)
    #         except GvmError as err:
    #             logger.warning("Couldn't delete target! Error: %s", str(err))

    #     # delete all alerts by DETERRERS
    #     logger.info("Deleting all alerts by DETERRERS!")
    #     response = self.gmp.get_alerts(filter_string=filter_str)
    #     to_del_set = set()
    #     for task in response.xpath('//alert'):
    #         to_del_set.add(task.attrib['id'])
    #     for uuid in to_del_set:
    #         try:
    #             self.gmp.delete_alert(uuid, ultimate=True)
    #         except GvmError as err:
    #             logger.warning("Couldn't delete alert! Error: %s", str(err))


    def get_latest_report_uuid(self, task_uuid : str) -> str|None:
        """
        Get the UUID of the latest report of some task!

        Args:
            task_uuid (str): UUID of the task

        Returns:
            str|None: Returns the UUID on success and None if something went wrong
        """
        try:
            response = self.gmp.get_task(task_uuid)
            response_status = int(response.xpath('@status')[0])
            if response_status != 200:
                raise GmpAPIError(f"Couldn't get task info for task {task_uuid}! Status: {response_status}")
            last_report_uuid = response.xpath('task/last_report/report')[0].attrib['id']
            return last_report_uuid
        except GmpAPIError:
            logger.exception("Couldn't get last report UUID for task %s!", task_uuid)
            return None


    def get_report_xml(self, report_uuid : str, min_qod : int = 70, report_format_id : str = ReportFormat.XML_UUID.value):
        """
        Query the XML report for some report UUID.

        Args:
            report_uuid (str): UUID of the report.

        Returns:
            _type_: XML etree object of the report.
        """
        rep_filter = f"status=Done apply_overrides=0 rows=-1 min_qod={min_qod} first=1 sort-reverse=severity"
        try:
            response = self.gmp.get_report(report_uuid, filter_string=rep_filter, report_format_id=report_format_id, ignore_pagination=True, details=True)
            response_status = int(response.xpath('@status')[0])
            if response_status != 200:
                raise GmpAPIError(f"Couldn't query report {report_uuid}!")
            return response
        except GvmError:
            logger.exception("Couldn't fetch report with ID '%s' from GSM!", report_uuid)
        except GmpAPIError:
            logger.exception("Get report as XML failed.")

        return None

    def get_report_html(self, report_uuid : str, min_qod : int = 70):
        """
        Query the HTML report for some report UUID.

        Args:
            report_uuid (str): UUID of the report.

        Returns:
            _type_: HTML string of the report.
        """
        rep_filter = f"status=Done apply_overrides=0 rows=-1 min_qod={min_qod} first=1 sort-reverse=severity"
        try:
            response = self.gmp.get_report(report_uuid, filter_string=rep_filter, report_format_id=ReportFormat.HTML_UUID.value, details=True, ignore_pagination=True)
            response = response.find("report")
            response = response.find("report_format").tail
            # HTML reports are send base64 encoded
            response = b64decode(response).decode('utf-8')
            return response
        except GvmError:
            logger.exception("Couldn't fetch report with ID '%s' from GSM!", report_uuid)
        except GmpAPIError:
            logger.exception("Get report as HTML failed.")
        return None

    def extract_report_data(self, report) -> tuple[str, str, dict]:
        """
        Extract relevant result data from a report.

        Args:
            report (_type_): XML etree report objcet.

        Returns:
            tuple[str, str, dict]: Tuple consisting of the scan start and end time, and a dictionary
                of vulnerabilities per IPv4 address. On error, (None, None, None) is returned.
        """
        try:
            scan_start = report.xpath('//scan_start')[0].text
            scan_end = report.xpath('report/report/scan_end')[0].text

            highest_severity_filtered = report.xpath('report/report/severity/filtered')[0].text

            results_xml = report.xpath('report/report/results/result')
            results = {}

            for result_xml in results_xml:
                result_uuid = result_xml.attrib['id']
                host_ip = result_xml.xpath('host')[0].text
                port_proto = result_xml.xpath('port')[0].text
                if port_proto and len(port_proto.split('/')) == 2:
                    port = port_proto.split('/')[0]
                    proto = port_proto.split('/')[1]
                else:
                    port = ''
                    proto = ''
                hostname = result_xml.xpath('host/hostname')[0].text
                nvt_name = result_xml.xpath('nvt/name')[0].text
                nvt_oid = result_xml.xpath('nvt')[0].attrib['oid']
                qod = result_xml.xpath('qod/value')[0].text
                severities = result_xml.xpath('nvt/severities/severity')
                cvss_severities = []
                for severity in severities:
                    cvss_severities.append(
                        {
                            'type' : severity.attrib['type'],
                            'base_score' : float(severity.xpath('score')[0].text),
                            'base_vector' : severity.xpath('value')[0].text,
                        }
                    )
                refs = [ref.attrib['id'] for ref in result_xml.xpath('nvt/refs/ref')]

                # get newest CVSS version
                cvss_version, cvss_base_score, cvss_base_vector = -1, -1, ''
                for version in range(2, 5, 1):
                    for sev in cvss_severities:
                        if sev.get('type') == f'cvss_base_v{version}':
                            cvss_version = version
                            cvss_base_score = float(sev.get('base_score', -1.0))
                            cvss_base_vector = sev.get('base_vector', '')
                            break

                res = VulnerabilityScanResult(
                    uuid=result_uuid,
                    host_ip=host_ip,
                    port=port,
                    proto=proto,
                    hostname=hostname,
                    nvt_name=nvt_name,
                    nvt_oid=nvt_oid,
                    qod=int(qod),
                    cvss_version=cvss_version,
                    cvss_base_score=cvss_base_score,
                    cvss_base_vector=cvss_base_vector,
                    refs=refs,
                )
                if results.get(host_ip):
                    results[host_ip].append(res)
                else:
                    results[host_ip] = [res,]

            return scan_start, scan_end, results
        except Exception:
            logger.exception("Couldn't extract data from report!")
        
        return None, None, None
