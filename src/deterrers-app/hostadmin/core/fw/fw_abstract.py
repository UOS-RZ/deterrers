from abc import (ABC, abstractmethod)
import ipaddress

from hostadmin.core.contracts import (HostStatusContract,
                                      HostServiceContract)


class FWAbstract(ABC):
    """TODO"""

    @abstractmethod
    def commit_changes(self) -> None:
        pass

    @abstractmethod
    def get_addrs_in_service_profile(
        self,
        serv_profile: HostServiceContract
    ) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        pass

    @abstractmethod
    def allow_service_profile_for_ips(
        self,
        ip_addrs: list[str],
        service_profile: HostServiceContract
    ) -> bool:
        pass

    @abstractmethod
    def block_ips(
        self,
        ip_addrs: list[str]
    ) -> bool:
        pass

    @abstractmethod
    def get_host_status(self, ip_addr: str) -> HostStatusContract:
        pass
