from abc import ABC, abstractmethod


class ScannerAbstract(ABC):
    """
    Abstract class for implementation of vulnerability scanner wrappers.
    """

    @abstractmethod
    def __init__(
        self,
        username: str,
        password: str,
        scanner_url: str,
        scanner_port: int
    ) -> None:
        pass

    @abstractmethod
    def __enter__(self):
        pass

    @abstractmethod
    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    @abstractmethod
    def create_ordinary_scan(
        self,
        host_ip: str,
        alert_dest_url: str
    ) -> tuple[str, str, str, str]:
        """
        Create and start a vulnerability scan for some host.

        Args:
            host_ip (str): IP address of the scanned host.
            alert_dest_url (str): URL to which an alert is send when scan
            is finished.

        Returns:
            tuple[str, str, str, str]: Tuple of
            (target_id, task_id, report_id, alert_id).
        """
        pass

    @abstractmethod
    def create_registration_scan(
        self,
        host_ip: str,
        alert_dest_url: str
    ) -> tuple[str, str, str, str]:
        """
        Creates and starts a registration process for some host.

        Args:
            host_ip (str): IP address of the host.
            alert_dest_url (str): URL to which an alert is send when scan
            is finished.

        Returns:
            tuple[str, str, str, str]: Tuple of
            (target_id, task_id, report_id, alert_id).
        """
        pass

    @abstractmethod
    def create_periodic_scan(
        self,
        host_ip: str,
        alert_dest_url: str,
        schedule_freq: str
    ) -> None:
        """
        Creates and schedules a periodic scan.

        Args:
            host_ip (str): IP address of the first host in periodic scan.
            alert_dest_url (str): URL to which an alert is send when scan
            is finished.
            schedule_freq (str): Frequency at which the periodic scan should
            be performed.
        """
        pass

    @abstractmethod
    def add_host_to_periodic_scans(
        self,
        host_ip: str,
        alert_dest_url: str
    ) -> bool:
        """
        Add host to the periodic scan task.

        Args:
            host_ip (str): IP address of the host that is added to scan.
            alert_dest_url (str): URL to which an alert is send when scan
            is finished.

        Returns:
            bool: True on success and False on error.
        """
        pass

    @abstractmethod
    def remove_host_from_periodic_scans(
        self,
        host_ip: str
    ) -> bool:
        """
        Remove host from periodic scan task.

        Args:
            host_ip (str): IP address of the host that is removed.

        Returns:
            bool: True on success and False on error.
        """
        pass

    @abstractmethod
    def update_periodic_scan_target(
        self
    ) -> bool:
        """
        Update the scan target of the periodic scan task.

        Returns:
            bool: True on success and False on error.
        """
        pass

    @abstractmethod
    def clean_up_scan_objects(
        self,
        target_uuid: str,
        task_uuid: str,
        report_uuid: str,
        alert_uuid: str | list[str]
    ):
        """
        Delete objects at the scanner.

        Args:
            target_uuid (str): Target ID.
            task_uuid (str): Task ID.
            report_uuid (str): Report ID.
            alert_uuid (str | list[str]): Alert ID(s).
        """
        pass

    @abstractmethod
    def get_latest_report_uuid(
        self,
        task_uuid: str
    ) -> str | None:
        """
        Get the ID of the latest scan report of some scan task.

        Args:
            task_uuid (str): Task ID.

        Returns:
            str | None: ID on success and None error.
        """
        pass

    @abstractmethod
    def extract_report_data(
        self,
        report_uuid: str,
        min_qod: int
    ) -> tuple[str, str, dict]:
        """
        Extract relevant result data from a scan report.

        Args:
            report_uuid (str): Report ID.
            min_qod (int): Minimum Quality of Detection value.

        Returns:
            tuple[str, str, dict]: Tuple consisting of (scan start, scan end,
            dict of vulnerabilities per IPv4).
        """
        pass

    @abstractmethod
    def get_report_html(
        self,
        report_uuid: str,
        min_qod: int
    ) -> str:
        """
        Query a HTML report by report ID.

        Args:
            report_uuid (str): Report ID.
            min_qod (int): Minimum Quality of Detection value.

        Returns:
            str: HTML string.
        """
        pass
