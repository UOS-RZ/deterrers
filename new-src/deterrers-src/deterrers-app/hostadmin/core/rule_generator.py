from __future__ import annotations # enable type hinting to class in class itself; might be unneccessary from 3.11 on
import logging
import uuid
import json

from.contracts import HostFWContract


logger = logging.getLogger(__name__)

class HostBasedPolicy():
    """
    Class representing a host-based firewall policy.
    """ 
    SEPERATOR = '___'

    def __init__(self, allow_src : dict, allow_ports : set[str], allow_proto : str, id : str = str(uuid.uuid4())):
        self.id = id
        self.allow_src = allow_src
        self.allow_ports = set(allow_ports)
        self.allow_proto = allow_proto

    @classmethod
    def from_string(cls, string : str) -> HostBasedPolicy:
        elems = string.split(cls.SEPERATOR)
        if len(elems) == 4:
            id = elems[0]
            allow_src = json.loads(elems[1])
            allow_ports = json.loads(elems[2])
            allow_proto = elems[3]
        return cls(id=id, allow_src=allow_src, allow_ports=allow_ports, allow_proto=allow_proto)

    def is_subset_of(self, p : HostBasedPolicy) -> bool:
        """
        Checks if this policy (self) is made obsolete by policy p.

        Args:
            p (HostBasedPolicy): Policy which is checked to be a superset of self.

        Returns:
            bool: Returns True if self is made obsolete by p, False otherwise.
        """
        same_src = self.allow_src == p.allow_src
        same_proto = self.allow_proto == p.allow_proto
        ports_are_subset = self.allow_ports.issubset(p.allow_ports)
        if same_src and same_proto and ports_are_subset:
            return True
        return False

    def to_string(self) -> str:
        return self.id + self.SEPERATOR + json.dumps(self.allow_src) + self.SEPERATOR + json.dumps(self.allow_ports) + self.SEPERATOR + self.allow_proto





def __generate_ufw__script(custom_rules : list[HostBasedPolicy]) -> str|None:
    rule_config = ""
    # the preamble is the same for every service profile
    PREAMBLE = \
"""#!/bin/bash
# This script should be run with sudo permissions!

# disable the host-based firewall before making any changes
ufw disable

# delete all previous configurations so old settings can be overwritten
echo 'y' | ufw reset

# set default rules
ufw default deny incoming
ufw default allow outgoing
"""

    ## construct custom rules
    for n, c_rule in enumerate(custom_rules):
        allow_src = c_rule.allow_src
        allow_ports = c_rule.allow_ports
        allow_proto = c_rule.allow_proto
        rule_config += \
f"""
# set custom rule no. {n}"""
        rule_config += \
f"""
ufw allow proto {allow_proto} from {allow_src['range']} to any port {','.join(allow_ports)} comment 'Custom DETERRERS rule no. {n}' """

    # postamble is the same for every service profile
    POSTAMBLE = \
"""

# finally enable the host-based firewall again
ufw enable
"""
    return PREAMBLE + rule_config + POSTAMBLE



def __generate_firewalld__script(custom_rules : list[HostBasedPolicy]) -> str|None:
    rule_config = ""
    CUSTOM_ZONE = "zone-by-deterrers"
    PREAMBLE = \
f"""#!/bin/bash
# This script should be run with sudo permissions!

# make sure the firewalld service is running and will activated at system start
systemctl enable firewalld
systemctl start firewalld

# delete custum zone if it exists so previous configurations can be overwritten
firewall-cmd --permanent --delete-zone={CUSTOM_ZONE}

# create custom zone
firewall-cmd --permanent --new-zone={CUSTOM_ZONE}

# make custom zone available in runtime configuration
firewall-cmd --reload
"""

    ## construct custom rules
    for n, c_rule in enumerate(custom_rules):
        allow_src = c_rule.allow_src
        allow_ports = c_rule.allow_ports
        allow_proto = c_rule.allow_proto
        allow_family = "ipv4" # TODO: for IPv6 support this needs to be changed
        rule_config += \
f"""
# set custom rule no. {n}"""
        for port in allow_ports:
            port = port.replace(':', '-') # firewalld uses 'x-y'-notation for port ranges
            rule_config += \
f"""
firewall-cmd --add-rich-rule='rule familiy={allow_family} source address={allow_src['range']} port port={port} protocol={allow_proto}  accept' """


    POSTAMBLE = \
f"""

# set default zone to zone-by-deterrers
firewall-cmd --set-default-zone={CUSTOM_ZONE}

# make all changes permanent and reload firewall
firewall-cmd --runtime-to-permanent
firewall-cmd --reload
"""
    return PREAMBLE + rule_config + POSTAMBLE



def __generate_nftables__script(custom_rules : list[HostBasedPolicy]) -> str|None:
    rule_config = ""
    FILE_PATH = "/etc/nftables/deterrers_rules.nft"
    PREAMBLE = \
f"""#!/bin/bash
# This script should be run with sudo permissions!

# create the config file
mkdir -p /etc/nftables/
touch {FILE_PATH}

# create a config file that specifies the custom rule set
echo '
#!/usr/sbin/nft -f
flush ruleset

# table type inet stands for Iv4 and IPv6
table inet deterrers-ruleset {{
    # create a table named input-chain which will hold rules for incoming traffic
    chain input-chain {{
        # accept packets to localhost
        iif lo accept

        # accept packets of existing connections
        ct state {{ established, related }} accept
        # drop all packets that do not match a rule in this chain
        type deterrers-ruleset hook input priority 0; policy drop;
"""
    
    ## construct the custom rules
    for n, c_rule in enumerate(custom_rules):
        allow_src = c_rule.allow_src
        allow_ports = c_rule.allow_ports
        allow_proto = c_rule.allow_proto
        rule_config += \
f"""
        # set custom rule no. {n}"""
        for port in allow_ports:
            port = port.replace(':', '-') # nftables uses 'x-y'-notation for port ranges
            rule_config += \
f"""
        ip saddr {allow_src['range']} {allow_proto} dport {port} accept"""

    POST_AMBLE = \
f"""
    }}
}}
' > {FILE_PATH}

# load the custom rule set
nft -f {FILE_PATH}

# make nftables load the custom rule set at each system start
echo '

include "{FILE_PATH}"
' >> /etc/nftables.conf

# enable nftables at system start and restart
systemctl enable nftables.service
systemctl start nftables
"""
    return PREAMBLE + rule_config + POST_AMBLE


def generate_rule(fw : HostFWContract, custom_rules : list[HostBasedPolicy]) -> str|None:
    """
    Generate/Suggest a firewall configuration script for some combination of fw program and service profile.
    Additionally consider custom rules that might be specified.

    Args:
        fw (HostFWContract): Firewall program.
        custom_rules (list[dict]): List of host-based firewall policies.
    """
    match fw:
        case HostFWContract.UFW:
            script = __generate_ufw__script( custom_rules)
        case HostFWContract.FIREWALLD:
            script = __generate_firewalld__script( custom_rules)
        case HostFWContract.NFTABLES:
            script = __generate_nftables__script( custom_rules)
        case _:
            logger.error(f"Firewall '{fw}' is not supported by rule generator!")
            return None

    return script