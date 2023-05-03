from enum import Enum


class HostBasedPolicySrcContract(Enum):
    """
    Enumeration for grouping network segments into allow-sources in host-based FW policies.
    """
    ANY = {
        'name' : 'Any',
        'range' : ['0.0.0.0/0']
    }
    RZ_INTERN = {
        'name' : 'RZ Intern',
        'range' : ['131.173.61.0/24', '131.173.245.32/27']
    }
    VM_INTERN = {
        'name' : 'Uni Intern',
        'range' : [
            '131.173.0.0/19',
            '131.173.32.0/20',
            '131.173.56.0/22',
            '131.173.60.0/23',
            '131.173.63.0/24',
            '131.173.128.0/20',
            '131.173.144.0/21',
            '131.173.160.0/19',
            '131.173.192.0/20',
            '131.173.208.0/21',
            '131.173.224.0/21',
            '131.173.244.0/23',
            '131.173.248.0/23',
            '131.173.252.0/22',
            '193.175.2.48/28',
            '2001:638:508::/48',
            '172.16.0.0/12',
        ]
    }
    IT_ADMIN_VPN = {
        'name' : 'IT Admin VPN',
        'range' : [
            '131.173.16.48/32',
            '2001:638:508:FE30::/64',
            '2001:638:508:FE31::/64',
            '2001:638:508:FE32::/64',
            ]
    }

    def display(self):
        return f"{self.value['name']}"

class HostBasedPolicyProtocolContract(Enum):
    """
    Enumeration for supported protocols in host-based FW policies.
    """
    TCP = "tcp"
    UDP = "udp"
    # ANY = "any" # cannot be modelled with firewalld and nftables, so we do not support it in the meantime




class HostStatusContract(Enum):
    """
    Definition of possible states of hosts.
    """
    UNREGISTERED =  'Unregistered'
    UNDER_REVIEW =  'Under Review'
    BLOCKED =       'Blocked'
    ONLINE =        'Online'

class HostServiceContract(Enum):
    """
    Definition of possible service profiles of hosts.
    """
    HTTP =          'HTTP'
    SSH =           'SSH'
    HTTP_SSH =      'HTTP+SSH'
    MULTIPURPOSE =  'Multipurpose'
    EMPTY =         ''

class HostFWContract(Enum):
    """
    Definition of possible host-based FW tools of hosts.
    """
    UFW =       'UFW'
    FIREWALLD = 'FirewallD'
    NFTABLES =  'nftables'
    EMPTY =     ''




class PaloAltoAddressGroup(Enum):
    """
    Enumeration of the different AddressGroup names which specify the service profiles in the
    PaloAlto firewall configuration.
    """
    HTTP = "FWP1-WEB-DETERRERS"
    SSH = "FWP2-SSH-DETERRERS"
    OPEN = "FWP3-OPEN-DETERRERS"