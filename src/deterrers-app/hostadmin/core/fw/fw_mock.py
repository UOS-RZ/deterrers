import ipaddress
import json

from hostadmin.core.fw.fw_abstract import FWAbstract
from hostadmin.core.contracts import (HostStatus,
                                      HostServiceProfile)


class FWMock(FWAbstract):

    def __init__(
        self,
        username: str,
        password: str,
        url: str = "./fw_mock_data.json"
    ) -> None:
        self.f_path = url
        with open(self.f_path, "w+") as f:
            try:
                data = json.load(f)
            except json.decoder.JSONDecodeError:
                data = {
                    sp.value: [] for sp in HostServiceProfile
                    if sp is not HostServiceProfile.EMPTY
                }
                json.dump(data, f)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass

    def commit_changes(self) -> None:
        pass

    def get_addrs_in_service_profile(
        self,
        serv_profile: HostServiceProfile
    ) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        with open(self.f_path, "r") as f:
            data = json.load(f)
            addrs = set(
                [
                    ipaddress.ip_address(addr)
                    for addr in data[HostServiceProfile.value]
                ]
            )
        return addrs

    def allow_service_profile_for_ips(
        self,
        ip_addrs: list[str],
        service_profile: HostServiceProfile
    ) -> bool:
        with open(self.f_path, "w+") as f:
            data = json.load(f)
            data[service_profile.value] = list(set(
                data[service_profile.value].extend(ip_addrs)
            ))
            json.dump(data, f)
        return True

    def block_ips(
        self,
        ip_addrs: list[str]
    ) -> bool:
        with open(self.f_path, "w+") as f:
            data = json.load(f)
            for sp_value, addrs in data.items():
                for rv_ip in ip_addrs:
                    try:
                        addrs.remove(rv_ip)
                    except ValueError:
                        pass
            json.dump(data, f)
        return True

    def get_host_status(self, ip_addr: str) -> HostStatus:
        with open(self.f_path, "r") as f:
            data = json.load(f)
            for _, addrs in data.items():
                if ip_addr in addrs:
                    return HostStatus.ONLINE
        return HostStatus.BLOCKED
