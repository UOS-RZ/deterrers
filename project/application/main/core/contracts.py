from enum import Enum

from django.conf import settings

class HostBasedPolicySrc(Enum):
    """
    Enumeration for grouping network segments into allow-sources in
    host-based FW policies.
    """
    ANY = {
        'name': 'Any',
        'range': ['0.0.0.0/0', '::/0']
    }
    RZ_INTERN = {
        'name': 'RZ Intern',
        'range': settings.RZ_INTERN_RANGES
    }
    VM_INTERN = {
        'name': 'Uni Intern',
        'range': settings.VM_INTERN_RANGES
    }
    IT_ADMIN_VPN = {
        'name': 'IT Admin VPN',
        'range': settings.IT_ADMIN_VPN_RANGES
    }

    def display(self):
        return f"{self.value['name']}"


class HostBasedPolicyProtocol(Enum):
    """
    Enumeration for supported protocols in host-based FW policies.
    """
    TCP = "tcp"
    UDP = "udp"


class HostStatus(Enum):
    """
    Definition of possible states of hosts.
    """
    UNREGISTERED = 'Unregistered'
    UNDER_REVIEW = 'Under Review'
    BLOCKED = 'Blocked'
    ONLINE = 'Online'


class HostServiceProfile(Enum):
    """
    Definition of possible service profiles of hosts.
    """
    HTTP = 'HTTP'
    SSH = 'SSH'
    HTTP_SSH = 'HTTP+SSH'
    MULTIPURPOSE = 'Multipurpose'
    EMPTY = ''


class HostFW(Enum):
    """
    Definition of possible host-based FW tools of hosts.
    """
    UFW = 'UFW'
    FIREWALLD = 'FirewallD'
    NFTABLES = 'nftables'
    EMPTY = ''
