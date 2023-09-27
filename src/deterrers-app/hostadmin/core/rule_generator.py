# enable type hinting to class in class itself; might be unnecessary from
# python 3.11 on
from __future__ import annotations
import logging
import uuid
import json
import ipaddress

from .contracts import HostFW


logger = logging.getLogger(__name__)


class HostBasedPolicy():
    """
    Class representing a host-based firewall policy.
    """
    SEPERATOR = '___'

    def __init__(
        self,
        allow_srcs: dict,
        allow_ports: set[str],
        allow_proto: str,
        id: str | None = None
    ):
        if not id:
            self.id = str(uuid.uuid4())
        else:
            self.id = id
        self.allow_srcs = allow_srcs
        self.allow_ports = set([allow_port.strip()
                                for allow_port in allow_ports])
        self.allow_proto = allow_proto

    @classmethod
    def from_string(cls, string: str) -> HostBasedPolicy | None:
        """
        Construct an instance of HostBasedPolicy from its string
        representation.

        Args:
            string (str): String representation of a HostBasedPolicy object.

        Returns:
            HostBasedPolicy|None: Returns the constructed object or None if
            something goes wrong.
        """
        elems = string.split(cls.SEPERATOR)
        if len(elems) == 4:
            p_id = elems[0]
            allow_srcs = json.loads(elems[1])
            allow_ports = set(json.loads(elems[2]))
            allow_proto = elems[3]
            return cls(id=p_id,
                       allow_srcs=allow_srcs,
                       allow_ports=allow_ports,
                       allow_proto=allow_proto)
        logger.error("Invalid string input: %s", string)
        return None

    def to_string(self) -> str:
        """
        Transform an instance of HostBasedPolicy into its string
        representation.

        Returns:
            str: Returns the string representation.
        """
        return (self.id
                + self.SEPERATOR
                + json.dumps(self.allow_srcs)
                + self.SEPERATOR
                + json.dumps(list(self.allow_ports))
                + self.SEPERATOR
                + self.allow_proto)

    def is_subset_of(self, p: HostBasedPolicy) -> bool:
        """
        Checks if this policy (self) is made obsolete by policy p.

        Args:
            p (HostBasedPolicy): Policy which is checked to be a superset
            of self.

        Returns:
            bool: Returns True if self is made obsolete by p, False otherwise.
        """
        same_src = self.allow_srcs == p.allow_srcs
        same_proto = self.allow_proto == p.allow_proto
        ports_are_subset = self.allow_ports.issubset(p.allow_ports)
        if same_src and same_proto and ports_are_subset:
            return True
        return False

    def is_valid(self) -> bool:
        """
        Check if this policy has valid values.

        Returns:
            bool: Returns True if valid and False if not valid.
        """
        # check types
        if not (isinstance(self.id, str)
                and isinstance(self.allow_srcs, dict)
                and isinstance(self.allow_ports, set)
                and isinstance(self.allow_proto, str)):
            logger.warning(
                ("Property of HostBasedPolicy has wrong type! "
                 + "id: %s allow_srcs: %s allow_ports: %s allow_proto: %s"),
                str(type(self.id)),
                str(type(self.allow_srcs)),
                str(type(self.allow_ports)),
                str(type(self.allow_proto))
            )
            return False

        # check value sanity
        try:
            uuid.UUID(self.id)
        except ValueError:
            logger.warning("UUID of policy is invalid: '%s", self.id)
            return False

        if not self.allow_srcs.get('name') or not self.allow_srcs.get('range'):
            logger.warning(
                "Policy's allow_srcs has no field 'name' or 'range'!"
            )
            return False
        for src_range in self.allow_srcs.get('range'):
            try:
                ipaddress.ip_network(src_range)
            except ValueError:
                logger.warning("Policy's allow_srcs range '%s' is invalid!",
                               src_range)
                return False

        for p in self.allow_ports:
            try:
                if ':' in p:
                    ps = p.split(':')
                    int(ps[0])
                    int(ps[1])
                else:
                    int(p)
            except ValueError:
                logger.warning("Policy's allow_port is invalid: '%s'", p)
                return False

        if self.allow_proto.lower() not in ('tcp', 'udp'):
            logger.warning("Policy's allow_proto is invalid: '%s'",
                           self.allow_proto)
            return False

        return True


FW_PROGRAM_CHECK = """
# check if firewall program is installed
if command -v {fw_name} | grep {fw_name}
then
    echo "{fw_name} is installed."
else
    echo "{fw_name} command was not found on system! Please make sure to install it first."
    exit 0
fi

# get consent to delete all present configurations
echo "This script will overwrite all custom configurations to {fw_name} you might have done in the past! Do you want to proceed? [y/n]"
read continue
if [ ${{continue}} != y ]
then
    exit 0
fi
"""  # noqa: E501


def __generate_ufw__script(custom_policies: list[HostBasedPolicy]) -> str:
    """
    Generates a configuration script for ufw.

    Args:
        custom_policies (list[HostBasedPolicy]): List of allow-policies.

    Returns:
        str: Configuration script as string.
    """
    policy_config = ""
    # the preamble is the same for every service profile
    PREAMBLE = f"""#!/bin/bash
# This script should be run with sudo permissions!

{FW_PROGRAM_CHECK.format(fw_name='ufw')}

# enable service at system start and start the services
systemctl enable ufw
systemctl start ufw

# disable the host-based firewall before making any changes
ufw disable

# delete all previous configurations so old settings can be overwritten
echo 'y' | ufw reset

# set default rules
ufw default deny incoming
ufw default allow outgoing
"""

    # construct custom rules
    for n, c_policy in enumerate(custom_policies):
        allow_srcs = c_policy.allow_srcs
        allow_ports = c_policy.allow_ports
        allow_proto = c_policy.allow_proto
        policy_config += f"""
# set custom rule no. {n}"""

        for src in allow_srcs['range']:
            policy_config += f"""
ufw allow proto {allow_proto} from {src} to any port {','.join(allow_ports)} comment 'Custom DETERRERS rule no. {n}' """  # noqa: E501

    # postamble is the same for every service profile
    POSTAMBLE = """

# finally enable the host-based firewall again
ufw enable
"""
    return PREAMBLE + policy_config + POSTAMBLE


def __generate_firewalld__script(
    custom_policies: list[HostBasedPolicy]
) -> str:
    """
    Generates a configuration script for firewalld.

    Args:
        custom_policies (list[HostBasedPolicy]): List of allow-policies.

    Returns:
        str: Configuration script as string.
    """
    policy_config = ""
    CUSTOM_ZONE = "deterrers-zone"
    PREAMBLE = f"""#!/bin/bash
# This script should be run with sudo permissions!

{FW_PROGRAM_CHECK.format(fw_name='firewall-cmd')}

# make sure the firewalld service is running and will be activated at system start
systemctl enable firewalld
systemctl start firewalld

# fw configurations are saved in /etc/firewalld/zones; delete all files in the directory and do a complete reset
su - root -c "rm -rf /etc/firewalld/zones/*"
firewall-cmd --complete-reload"""  # noqa: E501

    # create new zone and make it default
    policy_config += f"""
# create custom zone
firewall-cmd --permanent --new-zone={CUSTOM_ZONE}

# make custom zone available in runtime configuration
firewall-cmd --reload

"""

    # construct custom rules as rich rules because abstraction to zone does
    # not work as long as sources cannot overlap
    for n, c_policy in enumerate(custom_policies):
        allow_srcs = c_policy.allow_srcs['range']
        allow_ports = c_policy.allow_ports
        allow_proto = c_policy.allow_proto
        policy_config += f"""
# set custom rule no. {n}"""
        for src in allow_srcs:
            if isinstance(ipaddress.ip_network(src), ipaddress.IPv4Network):
                allow_family = "ipv4"
            elif isinstance(ipaddress.ip_network(src), ipaddress.IPv6Network):
                allow_family = "ipv6"
            else:
                logger.error("Not a valid source: %s", src)
                continue
            for port in allow_ports:
                # firewalld uses 'x-y'-notation for port ranges
                port = port.replace(':', '-')
                policy_config += f"""
firewall-cmd --zone={CUSTOM_ZONE} --add-rich-rule='rule family={allow_family} source address={src} port port={port} protocol={allow_proto}  accept' """  # noqa: E501

    POSTAMBLE = f"""

# set the target of custom zone to REJECT in order to make it default behavior
firewall-cmd --permanent --zone={CUSTOM_ZONE} --set-target=REJECT

# make custom zone default
firewall-cmd --set-default-zone={CUSTOM_ZONE}

# make changes permanent
firewall-cmd --runtime-to-permanent

firewall-cmd --reload
"""
    return PREAMBLE + policy_config + POSTAMBLE


def __generate_nftables__script(custom_policy: list[HostBasedPolicy]) -> str:
    """
    Generates a configuration script for nftables.

    Args:
        custom_policies (list[HostBasedPolicy]): List of allow-policies.

    Returns:
        str: Configuration script as string.
    """
    policy_config = ""
    PREAMBLE = f"""#!/bin/bash
# This script should be run with sudo permissions!

{FW_PROGRAM_CHECK.format(fw_name='nft')}

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
table inet filter {{
    # create two chains that give the default behavior for forward and outgoing traffic
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
        type filter hook input priority 0; policy drop;
"""  # noqa: E501

    # construct the custom rules
    for n, c_policy in enumerate(custom_policy):
        allow_srcs = c_policy.allow_srcs['range']
        allow_ports = c_policy.allow_ports
        allow_proto = c_policy.allow_proto
        policy_config += f"""
        # set custom rule no. {n}"""

        # nftables uses 'x-y'-notation for port ranges
        allow_ports = [p.replace(':', '-') for p in allow_ports]
        allow_srcs_ipv4 = [src for src in allow_srcs
                           if isinstance(ipaddress.ip_network(src),
                                         ipaddress.IPv4Network)]
        if len(allow_srcs_ipv4) > 0:
            policy_config += f"""
        ip saddr {{ {','.join(allow_srcs_ipv4)} }} {allow_proto} dport {{ {','.join(allow_ports)} }} accept"""  # noqa: E501
        allow_srcs_ipv6 = [src for src in allow_srcs
                           if isinstance(ipaddress.ip_network(src),
                                         ipaddress.IPv6Network)]
        if len(allow_srcs_ipv6) > 0:
            policy_config += f"""
        ip6 saddr {{ {','.join(allow_srcs_ipv6)} }} {allow_proto} dport {{ {','.join(allow_ports)} }} accept"""  # noqa: E501

    POST_AMBLE = """
    }
}
' > $CONF_LOC

# enable nftables at system start and restart
systemctl enable nftables.service
systemctl restart nftables
"""
    return PREAMBLE + policy_config + POST_AMBLE


def generate_fw_config(fw: HostFW,
                       custom_policies: list[HostBasedPolicy]) -> str | None:
    """
    Generate/Suggest a firewall configuration script for some combination of
    fw program and service profile.
    Additionally consider custom rules that might be specified.

    Args:
        fw (HostFWContract): Firewall program.
        custom_rules (list[dict]): List of host-based firewall policies.

    Returns:
        str|None: Configuration script as string. None on error.
    """
    match fw:
        case HostFW.UFW:
            script = __generate_ufw__script(custom_policies)
        case HostFW.FIREWALLD:
            script = __generate_firewalld__script(custom_policies)
        case HostFW.NFTABLES:
            script = __generate_nftables__script(custom_policies)
        case _:
            logger.error(
                f"Firewall '{fw}' is not supported by rule generator!"
            )
            return None

    return script
