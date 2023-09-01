import threading
import requests
import time
import datetime
import json
import logging
import os

from hostadmin.core.scanner.scanner_abstract import ScannerAbstract

logger = logging.getLogger(__name__)


class ScannerMock(ScannerAbstract):

    def __init__(
        self,
        username: str,
        password: str,
        scanner_url: str = "",
        scanner_port: int = -1
    ) -> None:
        super().__init__(username, password, scanner_url, scanner_port)
        self.f_path = "./mock_scanner_data.json"
        if not os.path.exists(self.f_path):
            with open(self.f_path, "x") as f:
                pass
        with open(self.f_path, "r+") as f:
            try:
                data = json.load(f)
            except json.decoder.JSONDecodeError:
                data = []
                json.dump(data, f)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    def create_ordinary_scan(
        self,
        host_ip: str,
        alert_dest_url: str
    ) -> tuple[str, str, str, str]:
        def dummy_task(url, host_ip, target_id, task_id, report_id, alert_id):
            time.sleep(5.0)
            response = requests.get(
                url=url,
                params={
                    "target_uuid": target_id,
                    "task_uuid": task_id,
                    "report_uuid": report_id,
                    "alert_uuid": alert_id,
                    "host_ip": host_ip
                }
            )
            logger.info("%s", str(response))

        t = threading.Thread(
            target=dummy_task,
            kwargs={
                "url": "http://127.0.0.1:89",
                "host_ip": host_ip,
                "target_id": "1",
                "task_id": "2",
                "report_id": "3",
                "alert_id": "4"
            }
        )
        t.start()

        return ("1", "2", "3", "4")

    def create_registration_scan(
        self,
        host_ip: str,
        alert_dest_url: str
    ) -> tuple[str, str, str, str]:
        def dummy_task(url, host_ip, target_id, task_id, report_id, alert_id):
            time.sleep(5.0)
            response = requests.get(
                url=url,
                params={
                    "target_uuid": target_id,
                    "task_uuid": task_id,
                    "report_uuid": report_id,
                    "alert_uuid": alert_id,
                    "host_ip": host_ip
                }
            )
            logger.info("%s", str(response))

        t = threading.Thread(
            target=dummy_task,
            kwargs={
                "url": "http://127.0.0.1:89",
                "host_ip": host_ip,
                "target_id": "1",
                "task_id": "2",
                "report_id": "3",
                "alert_id": "4"
            }
        )
        t.start()

        return ("1", "2", "3", "4")

    def create_periodic_scans(
        self,
        task_name: str,
        first_target_ip: str,
        alert_dest_url: str,
        schedule_freq: str
    ) -> None:
        with open(self.f_path, "r+") as f:
            data = set(json.load(f))
            f.seek(0)
            data.add(first_target_ip)
            json.dump(list(data), f)
            f.truncate()

    def add_host_to_periodic_scans(
        self,
        host_ip: str,
        alert_dest_url: str
    ) -> bool:
        with open(self.f_path, "r+") as f:
            data = set(json.load(f))
            f.seek(0)
            data.add(host_ip)
            json.dump(list(data), f)
            f.truncate()

    def remove_host_from_periodic_scans(
        self,
        host_ip: str
    ) -> bool:
        with open(self.f_path, "r+") as f:
            data = set(json.load(f))
            f.seek(0)
            data.remove(host_ip)
            json.dump(list(data), f)
            f.truncate()

    def update_periodic_scan_target(
        self
    ) -> bool:
        # NOTE: not mocked
        return True

    def clean_up_scan_objects(
        self,
        target_uuid: str,
        task_uuid: str,
        report_uuid: str,
        alert_uuid: str | list[str]
    ):
        # NOTE: not mocked
        pass

    def get_latest_report_uuid(
        self,
        task_uuid: str
    ) -> str | None:
        return ""

    def extract_report_data(
        self,
        report_uuid: str,
        min_qod: int
    ) -> tuple[str, str, dict]:
        start_t = str(datetime.datetime(1970, 1, 1, 0, 0, 0))
        end_t = str(datetime.datetime.now())

        return (start_t, end_t, {})

    def get_report_html(
        self,
        report_uuid: str,
        min_qod: int
    ) -> str:
        return "<html><body>Dummy HTML report</body></html>"

    def get_periodic_scanned_hosts(
        self
    ) -> set[str]:
        with open(self.f_path, "r") as f:
            return set(json.load(f))
