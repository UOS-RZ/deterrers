import logging

from v_scanner_configurations import (
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


class GmpVScannerInterface():
    """
    Interface to the Greenbone Vulnerability Scanner via Greenbone Management Protocol (GMP).
    Communication uses the python-gvm API package.
    """
    TIMEOUT = 20
    SCANNER_HOSTNAME = "hulk.rz.uni-osnabrueck.de"
    PORT = 22 # default

    username = ''
    password = ''

    SSH_CRED_UUID = Credentials.HULK_SSH_CRED_UUID
    SMB_CRED_UUID = Credentials.HULK_SMB_CRED_UUID
    SCAN_CONFIG_UUID = ScanConfig.FULL_FAST_UUID
    SCANNER_UUID = Scanner.OPENVAS_DEFAULT_SCANNER_UUID
    # TODO: which port list should be used (this is 'All IANA assigned TCP and UDP')
    PORT_LIST_UUID = PortList.ALL_IANA_TCP_UDP_UUID
    
    def __init__(self, username, password):
        """
        Create a Gmp instance based on a TLS connection.
        """
        self.username = username
        self.password = password
        transform = EtreeCheckCommandTransform()

        connection = SSHConnection(
            hostname=self.SCANNER_HOSTNAME,
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

    def get_report(self, report_uuid):
        response = self.gmp.get_report(report_uuid)
        pretty_print(response)

    def create_scan(self, host_ip : str, deterrers_ip : str):
        # create a target
        target_name = f"DETERRERS - Scan target {host_ip}"
        response = self.gmp.create_target(
            name=target_name,
            hosts=[host_ip],
            ssh_credential_id=self.SSH_CRED_UUID,
            ssh_credential_port=22,
            smb_credential_id=self.SMB_CRED_UUID,
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
        response_status = response.xpath('@status')[0]
        if response_status != 201:
            logging.error("Scan task '%s' could not be created!", task_name)
        task_uuid = response.xpath('@id')[0]
        # start task
        response = self.gmp.start_task(task_uuid)
        response_status = response.xpath('@status')[0]
        if response_status != 202:
            logging.error("Scan task '%s' could not be started!", task_name)
        report_uuid = response.xpath('report_id')[0]

        # create/get an alert that sends the report back to the server
        alert_uuid = self.create_alert(host_ip, deterrers_ip, target_uuid, task_uuid, report_uuid)

        # modify task to set the alert
        self.gmp.modify_task(task_id=task_uuid, alert_ids=[alert_uuid])


    def create_alert(self, host_ip, deterrers_ip, target_uuid, task_uuid, report_uuid):
        # # set alert to issue a HTTP GET request with relevant Uuuids as query params
        # name = f"DETERRERS - Alert for {host_ip}"
        # comment = f"Auto-generated by DETERRERS for task {task_uuid} of {host_ip}."
        # method_data = {
        #     "URL" : f"{deterrers_ip}/greenbone-alert?target_uuid={target_uuid}&task_uuid={task_uuid}&report_uuid={report_uuid}"
        # }
        # response = self.gmp.create_alert(
        #     name=name,
        #     condition=AlertCondition.ALWAYS,
        #     event=AlertEvent.TASK_RUN_STATUS_CHANGED,
        #     event_data={'status' : 'Done'},
        #     method=AlertMethod.HTTP_GET,
        #     method_data=method_data,
        #     comment=comment
        # )
        # alert_uuid = response.xpath('@id')[0]
        # # modify the alert so that its id is present in the url parameters
        # # only possible after creation because id is not known earlier
        # method_data["URL"] = method_data["URL"] + f"&alert_uuid={alert_uuid}"
        # response =  self.gmp.modify_alert(
        #     alert_id=alert_uuid,
        #     name=name,
        #     method_data=method_data,
        #     comment=comment
        # )
        # return alert_uuid

        # TODO: change back to HTTP GET method (see above)
        method_data = {
            "from_address" : "hulk@rz.uos.de",
            "to_address" : "nwintering@uos.de",
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
        alert_uuid = response.xpath('@id')[0]
        return alert_uuid


    def clean_up_scan_objects(self, target_uuid, task_uuid, report_uuid, alert_uuid):
        try:
            self.gmp.delete_report(report_uuid)
        except GvmError as err:
            logging.error("Couldn't delete report! Error: %s", type(err))
        try:
            self.gmp.delete_task(task_uuid, ultimate=True)
        except GvmError as err:
            logging.error("Couldn't delete task! Error: %s", type(err))
        try:
            self.gmp.delete_target(target_id=target_uuid, ultimate=True)
        except GvmError as err:
            logging.error("Couldn't delete target! Error: %s", type(err))
        try:
            self.gmp.delete_alert(alert_uuid, ultimate=True)
        except GvmError as err:
            logging.error("Couldn't delete alert! Error: %s", type(err))


if __name__ == "__main__":
    import sys
    username = sys.argv[1]
    password = sys.argv[2]
    with GmpVScannerInterface(username, password) as interf:
        test_host_ip = "131.173.22.184"
        # interf.create_scan(test_host_ip)
        a_uuid = interf.create_alert(test_host_ip, test_host_ip, "test_target_uuid", "test_task_uuid", "test_report_uuid")
        
        input("Enter anything to delete everything: ")
        interf.clean_up_scan_objects("", "", "", a_uuid)