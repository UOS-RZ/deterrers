from abc import ABC, abstractmethod


class ScannerAbstract(ABC):
    """
    Abstract class for implementation of vulnerability scanner wrappers.
    """

    @abstractmethod
    def create_ordinary_scan(
        self,
        host_ip: str,
        alert_dest_url: str
    ) -> tuple[str, str, str, str]:
        pass

    @abstractmethod
    def create_registration_scan(
        self,
        host_ip: str,
        alert_dest_url: str
    ) -> tuple[str, str, str, str]:
        pass

    @abstractmethod
    def create_periodic_scan(
        self,
        host_ip: str,
        alert_dest_url: str,
        schedule_freq: str
    ) -> None:
        pass

    @abstractmethod
    def add_host_to_periodic_scans(
        self,
        host_ip: str,
        alert_dest_url: str
    ) -> bool:
        pass

    @abstractmethod
    def remove_host_from_periodic_scans(
        self,
        host_ip: str
    ) -> bool:
        pass

    @abstractmethod
    def update_periodic_scan_target(
        self
    ) -> bool:
        pass

    @abstractmethod
    def clean_up_scan_objects(
        self,
        target_uuid: str,
        task_uuid: str,
        report_uuid: str,
        alert_uuid: str | list[str]
    ):
        pass

    @abstractmethod
    def get_latest_report_uuid(
        self,
        task_uuid: str
    ) -> str | None:
        pass

    @abstractmethod
    def extract_report_data(
        self,
        report_uuid: str,
        min_qod: int
    ) -> tuple[str, str, dict]:
        pass

    @abstractmethod
    def get_report_html(
        self,
        report_uuid: str,
        min_qod: int
    ) -> str:
        pass
