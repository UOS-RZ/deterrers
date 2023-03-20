import ipaddress

from django.urls import reverse

from .rule_generator import HostBasedPolicy
from .contracts import HostFWContract, HostServiceContract, HostStatusContract


class MyHost():
    """
    Custom host class that holds all important information per host in DETERRERS.
    """

    def __init__(
        self,
        entity_id : int,
        ipv4 : str,
        mac : str,
        admin_ids : set,
        status : HostStatusContract,
        name : str = '',
        dns_rcs : set[str] = set(),
        service : HostServiceContract = HostServiceContract.EMPTY,
        fw : HostFWContract = HostFWContract.EMPTY,
        policies  : list[HostBasedPolicy] = []):

        # Mandatory
        self.entity_id = int(entity_id)
        try:
            self.ipv4_addr = ipaddress.IPv4Address(ipv4.replace('_', '.'))
        except ipaddress.AddressValueError:
            self.ipv4_addr = None
            return
        self.mac_addr = mac
        self.admin_ids = set(admin_ids)
        self.status = status
        # Optional
        self.name = name
        self.dns_rcs = set(dns_rcs)
        self.service_profile = service
        self.fw = fw
        self.host_based_policies = policies


    def __str__(self) -> str:
        return f"IPv4: {str(self.ipv4_addr)} ({self.get_dns_rcs_display()}) Status: {self.get_status_display()} Service Profile: {self.get_service_profile_display()} FW: {self.get_fw_display()}"
    
    def __eq__(self, other):
        return ipaddress.IPv4Address(self.ipv4_addr) == ipaddress.IPv4Address(other.ipv4_addr)
    
    def __lt__(self, other):
        return ipaddress.IPv4Address(self.ipv4_addr) < ipaddress.IPv4Address(other.ipv4_addr)

    def get_ip_escaped(self) -> str:
        return str(self.ipv4_addr).replace('.', '_')

    def get_absolute_url(self):
        """
        Returns the url of this host by using reverse()-function.
        """
        return reverse('host_detail', kwargs={'ip' : self.get_ip_escaped()})

    def get_service_profile_display(self) -> str:
        return self.service_profile.value

    def get_fw_display(self) -> str:
        return self.fw.value

    def get_status_display(self) -> str:
        return self.status.value
    
    def get_dns_rcs_display(self) -> str:
        return ", ".join(self.dns_rcs)

    def add_host_based_policy(self, subnets : dict, ports : list[str], proto : str) -> bool:
        new_policy = HostBasedPolicy(subnets, ports, proto)
        for policy in self.host_based_policies:
            if new_policy.is_subset_of(policy):
                return False

        self.host_based_policies.append(new_policy)
        return True

    def is_valid(self) -> bool:
        """
        Performs validity check of parameters.

        Returns:
            bool: True for valid and False for invalid.
        """
        if not isinstance(self.entity_id, int):
            return False
        
        if not isinstance(self.ipv4_addr, ipaddress.IPv4Address):
            return False

        # check for valid mac address format if mac is set
        if self.mac_addr != '':
            if len(self.mac_addr.split('-')) != 6:
                return False
            for hex in self.mac_addr.split('-'):
                try:
                    int(hex, 16)
                except ValueError:
                    return False
        
        if self.status not in HostStatusContract:
            return False

        if self.service_profile not in HostServiceContract:
            return False

        if self.fw not in HostFWContract:
            return False

        for policy in self.host_based_policies:
            if not policy.is_valid():
                return False
        
        return True
