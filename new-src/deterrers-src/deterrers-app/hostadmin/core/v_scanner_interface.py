import logging

from .v_scanner_configurations import (
    Credentials,
    ScanConfig,
    Scanner,
    PortList
)

from gvm.protocols.gmp import Gmp
from gvm.connections import SSHConnection
from gvm.transforms import EtreeCheckCommandTransform
from gvm.errors import GvmError
from gvm.xml import pretty_print
from gvm.protocols.gmpv224 import AlertCondition, AlertEvent, AlertMethod

logger = logging.getLogger(__name__)

class GmpVScannerInterface():
    """
    Interface to the Greenbone Vulnerability Scanner via Greenbone Management Protocol (GMP) v22.4.
    Communication uses the python-gvm API package.
    """
    TIMEOUT = 20
    SCANNER_URL = "hulk.rz.uni-osnabrueck.de"
    PORT = 22 # default

    username = ''
    password = ''

    SSH_CRED_UUID = Credentials.HULK_SSH_CRED_UUID.value
    SMB_CRED_UUID = Credentials.HULK_SMB_CRED_UUID.value
    SCAN_CONFIG_UUID = ScanConfig.FULL_FAST_UUID.value
    SCANNER_UUID = Scanner.OPENVAS_DEFAULT_SCANNER_UUID.value
    # TODO: which port list should be used (this is 'All IANA assigned TCP and UDP')
    PORT_LIST_UUID = PortList.ALL_IANA_TCP_UUID.value
    
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
            response = self.gmp.create_target(
                name=target_name,
                hosts=[host_ip],
                ssh_credential_id=self.SSH_CRED_UUID,
                ssh_credential_port=22,
                port_list_id=self.PORT_LIST_UUID
            )
            # parse target-id
            target_uuid = response.xpath('@id')[0]

            # create the task
            task_name = f"DETERRERS - Scan host {host_ip}"
            response = self.gmp.create_task(
                name=task_name,
                config_id=self.SCAN_CONFIG_UUID,
                target_id=target_uuid,
                scanner_id=self.SCANNER_UUID
            )
            response_status = int(response.xpath('@status')[0])
            if response_status != 201:  # status code docu: https://hulk.rz.uos.de/manual/en/gmp.html#status-codes
                raise RuntimeError(f"Scan task '{task_name}' could not be created! Status: {response_status}")
            task_uuid = response.xpath('@id')[0]
            # start task
            response = self.gmp.start_task(task_uuid)
            response_status = int(response.xpath('@status')[0])
            if response_status != 202:
                raise RuntimeError(f"Scan task '{task_name}' could not be started! Status: {response_status}")
            if len(response.xpath('//report_id')) != 1:
                raise RuntimeError("start_task_response does not contain exactly one report id!")

            # get uuid which is an element value
            report_uuid = response.xpath('//report_id')[0].text

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
        return self.create_scan(host_ip, deterrers_url)


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
        comment = f"Auto-generated by DETERRERS for task {task_uuid} of {host_ip}."
        method_data = {
            "URL" : f"{deterrers_url}/greenbone-alert?target_uuid={target_uuid}&task_uuid={task_uuid}&report_uuid={report_uuid}"
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
            comment=f"Auto-generated by DETERRERS for task {task_uuid} of {host_ip}."
        )
        response_status = int(response.xpath('@status')[0])
        if response_status != 201:
            raise RuntimeError(f"Couldn't create email alert. Status: {response_status}")
        alert_uuid = response.xpath('@id')[0]
        return alert_uuid


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

#         test_report_id = "c936b5cf-0e62-4c5b-af40-44ae18dee92c"
#         report = interf.get_report_xml(test_report_id)
#         with open('test_report_xml.txt', 'w') as f:
#             pretty_print(report, f)
#         scan_start, results = interf.extract_report_data(report)
