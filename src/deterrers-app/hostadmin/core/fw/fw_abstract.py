from abc import (ABC, abstractmethod)
import ipaddress

from hostadmin.core.contracts import (HostStatus,
                                      HostServiceProfile)


class FWAbstract(ABC):
    """ Abstract class for implementation of perimeter firewall wrappers. """

    @abstractmethod
    def commit_changes(self) -> None:
        """
        Initiate commit if FW works with commits.
        """
        pass

    @abstractmethod
    def get_addrs_in_service_profile(
        self,
        serv_profile: HostServiceProfile
    ) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """
        Query a set of IP addresses for which given internet service profile
        is allowed at perimeter firewall.

        Args:
            serv_profile (HostServiceContract): Internet service profile for
            which IP addresses are queried.

        Returns:
            set[ipaddress.IPv4Address | ipaddress.IPv6Address]: Returns a set
            of IPv4 and IPv6 addresses.
        """
        pass

    @abstractmethod
    def allow_service_profile_for_ips(
        self,
        ip_addrs: list[str],
        service_profile: HostServiceProfile
    ) -> bool:
        """
        Allow internet service profile for multiple IPs.

        Args:
            ip_addrs (list[str]): IP addresses in string format.
            service_profile (HostServiceContract): Internet service profile.

        Returns:
            bool: Returns True on success and False otherwise.
        """
        pass

    @abstractmethod
    def block_ips(
        self,
        ip_addrs: list[str]
    ) -> bool:
        """
        Block multiple IPs at the perimeter firewall.

        Args:
            ip_addrs (list[str]): IP addresses in string format.

        Returns:
            bool: Returns True on success and False otherwise.
        """
        pass

    @abstractmethod
    def get_host_status(self, ip_addr: str) -> HostStatus:
        """
        Queries the host status for a given IP address.

        Args:
            ip_addr (str): IP address.

        Returns:
            HostStatusContract: Returns the host status.
        """
        pass
