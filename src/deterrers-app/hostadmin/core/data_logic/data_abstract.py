from abc import (ABC, abstractmethod)

from hostadmin.core.host import MyHost


class DataAbstract(ABC):
    """ Abstract class for implementation of DB/IPAM wrappers."""

    @abstractmethod
    def get_host_info_from_ip(self, ipv4: str) -> MyHost | None:
        pass

    @abstractmethod
    def get_hosts_of_admin(self, admin_name: str) -> list[MyHost]:
        pass

    @abstractmethod
    def get_IP6Addresses(self, host: MyHost) -> set[str]:
        pass

    @abstractmethod
    def get_department_names(self) -> list:
        pass

    @abstractmethod
    def get_department_to_admin(self, admin_name: str) -> str | None:
        pass

    @abstractmethod
    def get_all_admin_names(self) -> set[str]:
        pass

    @abstractmethod
    def create_admin(
        self,
        admin_name: str,
        department_name: str
    ) -> bool:
        pass

    @abstractmethod
    def is_admin(self, admin_name: str) -> bool | None:
        pass

    @abstractmethod
    def add_admin_to_host(self, admin_name: str, host: MyHost) -> int:
        pass

    @abstractmethod
    def remove_admin_from_host(self, admin_name: str, host: MyHost) -> int:
        pass

    @abstractmethod
    def update_host_info(self, host: MyHost) -> bool:
        pass

    @abstractmethod
    def user_exists(self, username: str) -> bool | None:
        pass
