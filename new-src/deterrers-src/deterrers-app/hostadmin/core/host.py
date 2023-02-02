import ipaddress
from enum import Enum
import uuid

from django.urls import reverse

from .rule_generator import HostBasedPolicy

class HostStatusContract(Enum):
    UNREGISTERED =  'Unscanned' # TODO: should rather be 'Unregistered' but must be changed everywhere
    UNDER_REVIEW =  'Under Review'
    BLOCKED =       'Blocked'
    ONLINE =        'Online'

class HostServiceContract(Enum):
    HTTP =          'HTTP'
    SSH =           'SSH'
    MULTIPURPOSE =  'Multipurpose'
    EMPTY =         ''

class HostFWContract(Enum):
    UFW =       'UFW'
    FIREWALLD = 'FirewallD'
    NFTABLES =  'nftables'
    EMPTY =     ''


class MyHost():
    """
    Custom host class that holds all important information per host in DETERRERS.
    """

    def __init__(
        self,
        ip : str,
        mac : str,
        admin_ids : list,
        status : HostStatusContract,
        name : str = '',
        service : HostServiceContract = HostServiceContract.EMPTY,
        fw : HostFWContract = HostFWContract.EMPTY,
        policies  : list[HostBasedPolicy] = [],
        entity_id=None ):

        # Mandatory
        self.ip_addr = ip.replace('_', '.')
        self.mac_addr = mac
        self.admin_ids = admin_ids
        self.status = status
        # Optional
        self.name = name
        self.service_profile = service
        self.fw = fw
        self.host_based_policies = policies
        self.entity_id = entity_id


    def __str__(self) -> str:
        return f"Host: {self.ip_addr} ({self.name}) Status: {self.get_status_display()} Service Profile: {self.get_service_profile_display()} FW: {self.get_fw_display()}"

    def get_ip_escaped(self) -> str:
        return str(self.ip_addr).replace('.', '_')

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

    def add_host_based_policy(self, subnets : list[str], ports : list[str], proto : str) -> bool:
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
        try:
            ipaddress.ip_address(self.ip_addr)
        except ValueError:
            return False

        # check for valid mac address format
        if self.mac_addr == '':
            return False
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

        # TODO: check validity of intranet_rules
        
        return True
