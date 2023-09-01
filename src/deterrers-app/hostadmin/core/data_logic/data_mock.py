import json
import ipaddress
import logging

from hostadmin.core.data_logic.data_abstract import DataAbstract
from hostadmin.core.host import MyHost
from hostadmin.core.contracts import (HostStatus,
                                      HostServiceProfile,
                                      HostFW)

logger = logging.getLogger(__name__)


class DataMockWrapper(DataAbstract):
    """
    Mock implementation of the data logic interface for dev and testing.
    Data is written to a local json file.
    """

    def __init__(
        self,
        username: str = "",
        password: str = "",
        url: str = ""
    ) -> None:
        super().__init__(username, password, url)
        self.f_path = "./mock_data.json"
        # fill in default data
        with open(self.f_path, "r+") as f:
            try:
                data = json.load(f)
            except json.decoder.JSONDecodeError:
                data = dict()
                data["departments"] = {
                    "Department 1": ["mmustermann", ],
                    "Department 2": []
                }
                data["hosts"] = {
                    int(ipaddress.IPv4Address("1.1.1.1")): {
                        "entity_id": int(ipaddress.IPv4Address("1.1.1.1")),
                        "ipv4_addr": "1.1.1.1",
                        "mac_addr": "",
                        "admin_ids": ["mmustermann", ],
                        "status": HostStatus.UNREGISTERED.name,
                        "name": "1.1.1.1 Name",
                        "dns_rcs": [],
                        "service_profile": HostServiceProfile.EMPTY.name,
                        "fw": HostFW.EMPTY.name,
                        "host_based_policies": []
                    }
                }
                json.dump(data, f)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    def get_host_info_from_ip(
        self,
        ipv4: str
    ) -> MyHost | None:
        with open(self.f_path, "r") as f:
            data = json.load(f)
            if not data["hosts"].get(int(ipaddress.IPv4Address(ipv4))):
                return None
            data = data["hosts"][int(ipaddress.IPv4Address(ipv4))]
            return MyHost(
                data["entity_id"],
                data["ipv4_addr"],
                data["mac_addr"],
                set(data["admin_ids"]),
                HostStatus[data["status"]],
                data["name"],
                set(data["dns_rcs"]),
                HostServiceProfile[data["service_profile"]],
                HostFW[data["fw"]],
                data["host_based_policies"]
            )

    def get_hosts_of_admin(
        self,
        admin_name: str
    ) -> list[MyHost]:
        hosts = []
        with open(self.f_path, "r") as f:
            data = json.load(f)
            for ipv4, host_data in data["hosts"].items():
                if admin_name in host_data["admin_ids"]:
                    hosts.append(MyHost(
                        host_data["entity_id"],
                        host_data["ipv4_addr"],
                        host_data["mac_addr"],
                        set(host_data["admin_ids"]),
                        HostStatus[host_data["status"]],
                        host_data["name"],
                        set(host_data["dns_rcs"]),
                        HostServiceProfile[host_data["service_profile"]],
                        HostFW[host_data["fw"]],
                        host_data["host_based_policies"]
                    ))
        return hosts

    def get_IP6Addresses(
        self,
        host: MyHost
    ) -> set[str]:
        return set()

    def get_department_names(self) -> list:
        with open(self.f_path, "r") as f:
            data = json.load(f)
            return list(data["departments"].keys())

    def get_department_to_admin(
        self,
        admin_name: str
    ) -> str | None:
        with open(self.f_path, "r") as f:
            data = json.load(f)
            for department, admins in data["departments"].items():
                if admin_name in admins:
                    return department
        return None

    def get_all_admin_names(self) -> set[str]:
        names = set()
        with open(self.f_path, "r") as f:
            data = json.load(f)
            for department, admins in data["departments"].items():
                names.update(admins)
        return names

    def create_admin(
        self,
        admin_name: str,
        department_name: str
    ) -> bool:
        with open(self.f_path, "r") as f:
            data = json.load(f)

        data["departments"][department_name] = list(
            set(
                data["departments"][department_name] + [admin_name]
            )
        )

        with open(self.f_path, "w") as f:
            json.dump(data, f)
        return True

    def is_admin(
        self,
        admin_name: str
    ) -> bool | None:
        if admin_name in self.get_all_admin_names():
            return True
        return False

    def add_admin_to_host(
        self,
        admin_name: str,
        host: MyHost
    ) -> int:
        host.admin_ids.add(admin_name)
        self.update_host_info(host)

    def remove_admin_from_host(
        self,
        admin_name: str,
        host: MyHost
    ) -> int:
        host.admin_ids.remove(admin_name)
        self.update_host_info(host)

    def update_host_info(
        self,
        host: MyHost
    ) -> bool:
        with open(self.f_path, "r") as f:
            data = json.load(f)

        data["hosts"][host.entity_id] = {
            "entity_id": host.entity_id,
            "ipv4_addr": str(host.ipv4_addr),
            "mac_addr": host.mac_addr,
            "admin_ids": list(host.admin_ids),
            "status": host.status.name,
            "name": host.name,
            "dns_rcs": list(host.dns_rcs),
            "service_profile": host.service_profile.name,
            "fw": host.fw.name,
            "host_based_policies": host.host_based_policies
        }

        with open(self.f_path, "w") as f:
            json.dump(data, f)
        return True

    def user_exists(
        self,
        username: str
    ) -> bool | None:
        return True
