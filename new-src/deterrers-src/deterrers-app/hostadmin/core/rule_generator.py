from __future__ import annotations # enable type hinting to class in class itself; might be unneccessary from 3.11 on
import logging
import uuid
import json
import ipaddress

from.contracts import HostFWContract


logger = logging.getLogger(__name__)

class HostBasedPolicy():
    """
    Class representing a host-based firewall policy.
    """ 
    SEPERATOR = '___'

    def __init__(self, allow_srcs : dict, allow_ports : set[str], allow_proto : str, id : str = str(uuid.uuid4())):
        self.id = id
        self.allow_srcs = allow_srcs
        self.allow_ports = set(allow_ports)
        self.allow_proto = allow_proto

    @classmethod
    def from_string(cls, string : str) -> HostBasedPolicy:
        elems = string.split(cls.SEPERATOR)
        if len(elems) == 4:
            p_id = elems[0]
            allow_srcs = json.loads(elems[1])
            allow_ports = set(json.loads(elems[2]))
            allow_proto = elems[3]
            return cls(id=p_id, allow_srcs=allow_srcs, allow_ports=allow_ports, allow_proto=allow_proto)
        logger.error("Invalid string input: %s", string)
        return None

    def to_string(self) -> str:
        return self.id + self.SEPERATOR + json.dumps(self.allow_srcs) + self.SEPERATOR + json.dumps(list(self.allow_ports)) + self.SEPERATOR + self.allow_proto

    def is_subset_of(self, p : HostBasedPolicy) -> bool:
        """
        Checks if this policy (self) is made obsolete by policy p.

        Args:
            p (HostBasedPolicy): Policy which is checked to be a superset of self.

        Returns:
            bool: Returns True if self is made obsolete by p, False otherwise.
        """
        same_src = self.allow_srcs == p.allow_srcs
        same_proto = self.allow_proto == p.allow_proto
        ports_are_subset = self.allow_ports.issubset(p.allow_ports)
        if same_src and same_proto and ports_are_subset:
            return True
        return False


FW_PROGRAM_CHECK = \
"""
# get OS in order to know which package manager to use below
while : ; do
    echo "Please choose the operating system this machine is running on:
    [1] Debian/Ubuntu
    [2] CentOS
    [3] other"

    read OS_I
    if [ $OS_I == 1 ] || [ $OS_I == 2 ] || [ $OS_I == 3 ]
    then
        break
    fi
    echo "Invalid input!"
done

# check if firewall progamm is installed
if [ $OS_I == 1 ]
then
    # Debian/Ubunut uses dpkg
    if dpkg -s ${fw_name} | grep -q "Status: install ok installed"
    then
        echo "Found ${fw_name} installed. Continue..."
    else
        echo "Did not find ${fw_name} installed on machine. Please make sure to install it first!"
        exit 0
    fi
elif [ $OS_I == 2 ]
then
    # CentOS uses rpm
    if rpm -qa | grep ${fw_name}
    then
        echo "Found ${fw_name} installed. Continue..."
    else
        echo "Did not find ${fw_name} installed on machine. Please make sure to install it first!"
        exit 0
    fi
elif [ $OS_I == 3 ]
then
    # other can't be handeled
    echo "Cannot check if ${fw_name} is installed without infos about OS. Please make sure that it is installed manually!
    Contiue anyways? [y/n]"

    read cont
    if [ ${{cont}} != y ]
    then
        exit 0
    fi
fi
"""


def __generate_ufw__script(custom_rules : list[HostBasedPolicy]) -> str|None:
    rule_config = ""
    # the preamble is the same for every service profile
    PREAMBLE = \
f"""#!/bin/bash
# This script should be run with sudo permissions!

{FW_PROGRAM_CHECK.format(fw_name='ufw')}

# confirm that user wants to overwrite existing rules
echo "Continuing will overwrite all present configurations to ufw! Do you agree to reset ufw? [y/n]"
read continue
if [ ${{continue}} =! y ]
then
    exit 0
fi

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
        allow_srcs = c_rule.allow_srcs
        allow_ports = c_rule.allow_ports
        allow_proto = c_rule.allow_proto
        rule_config += \
f"""
# set custom rule no. {n}"""
        for src in allow_srcs['range']:
            rule_config += \
f"""
ufw allow proto {allow_proto} from {src} to any port {','.join(allow_ports)} comment 'Custom DETERRERS rule no. {n}' """

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

{FW_PROGRAM_CHECK.format(fw_name='firewalld')}

# get consent to delete all present configurations
echo "This script will overwrite all custom configurations to firewalld you might have done in the past! Do you want to proceed? [y/n]"
read continue
if [ ${{continue}} =! y ]
then
    exit 0
fi
# fw configurations are saved in /etc/firewalld/zones; delete all files in the directory and do a complete reset
rm -f /etc/firewalld/zones/*
firewall-cmd --complete-reload

# make sure the firewalld service is running and will activated at system start
systemctl enable firewalld
systemctl start firewalld

# create custom zone
firewall-cmd --permanent --new-zone={CUSTOM_ZONE}

# make custom zone available in runtime configuration
firewall-cmd --reload
"""

    ## construct custom rules
    for n, c_rule in enumerate(custom_rules):
        allow_srcs = c_rule.allow_srcs
        allow_ports = c_rule.allow_ports
        allow_proto = c_rule.allow_proto
        rule_config += \
f"""
# set custom rule no. {n}"""
        for src in allow_srcs['range']:
            rule_config += \
f"""
firewall-cmd --zone={CUSTOM_ZONE} --add-source={src}"""

        for port in allow_ports:
            port = port.replace(':', '-') # firewalld uses 'x-y'-notation for port ranges
            rule_config += \
f"""
firewall-cmd --zone={CUSTOM_ZONE} --add-port={port}/{allow_proto}"""


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
    PREAMBLE = \
f"""#!/bin/bash
# This script should be run with sudo permissions!

{FW_PROGRAM_CHECK.format(fw_name='nftables')}

# get consent to delete all present configurations
echo "This script will overwrite all custom configurations to nftables you might have done in the past! Do you want to proceed? [y/n]"
read continue
if [ ${{continue}} =! y ]
then
    exit 0
fi

# nftables.conf may exist at different locations in filesystem, so check where it is
PATHS=("/etc/nftables.conf" "/etc/sysconfig/nftables.conf")
for path in ${{PATHS[@]}}
do
    if [ -f "$path" ]
    then
        CONF_LOC=$path
        break
    fi
done

# create a config file that specifies the custom rule set
echo '#!/usr/sbin/nft -f
flush ruleset

# table type inet stands for Iv4 and IPv6
table inet deterrers-ruleset {{
    # create two chains that give the default behavior for foreward and outgoing traffic
    chain forward {{
        # do not forward any traffic
        type filter hook forward priority 0; policy drop;
    }}

    chain output {{
        # allow all outgoing traffic
        type filter hook output priority 0; policy accept;
    }}
    
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
        allow_srcs = c_rule.allow_srcs['range']
        allow_ports = c_rule.allow_ports
        allow_proto = c_rule.allow_proto
        rule_config += \
f"""
        # set custom rule no. {n}"""
        allow_ports = [p.replace(':', '-') for p in allow_ports] # nftables uses 'x-y'-notation for port ranges
        allow_srcs_ipv4 = [src for src in allow_srcs if isinstance(ipaddress.ip_network(src), ipaddress.IPv4Network)]
        allow_srcs_ipv6 = [src for src in allow_srcs if isinstance(ipaddress.ip_network(src), ipaddress.IPv6Network)]
        rule_config += \
f"""
        ip saddr {{ {','.join(allow_srcs_ipv4)} }} {allow_proto} dport {{ {','.join(allow_ports)} }} accept"""
        rule_config += \
f"""
        ip6 saddr {{ {','.join(allow_srcs_ipv6)} }} {allow_proto} dport {{ {','.join(allow_ports)} }} accept"""

    POST_AMBLE = \
"""
    }
}
' > $CONF_LOC

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
            script = __generate_ufw__script(custom_rules)
        case HostFWContract.FIREWALLD:
            script = __generate_firewalld__script(custom_rules)
        case HostFWContract.NFTABLES:
            script = __generate_nftables__script(custom_rules)
        case _:
            logger.error(f"Firewall '{fw}' is not supported by rule generator!")
            return None

    return script