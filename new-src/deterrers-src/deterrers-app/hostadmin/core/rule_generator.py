import os
import logging

from .host import HostFWContract, HostServiceContract, CustomRuleSubnetContract

from django.conf import settings


logger = logging.getLogger(__name__)



def __generate_ufw__script(service_profile : HostServiceContract, custom_rules : list[dict]) -> str|None:

    # the preamble is the same for every service profile
    PREAMBLE = \
"""#!/bin/bash
# This script should be run with sudo permissions!

# disable the host-based firewall before making any changes
ufw disable

# delete all previous configurations so old settings can be overwritten
echo 'y' | ufw reset

"""

    # first configure the rules derived from the service profile
    rule_config = ""
    match service_profile:
        case HostServiceContract.HTTP:
            rule_config += \
"""
# set default rules
ufw default deny incoming
ufw default allow outgoing

# always allow SSH
ufw allow ssh

# allow HTTP/S
ufw allow http
ufw allow https
"""
        case HostServiceContract.SSH:
            rule_config += \
"""
# set default rules
ufw default deny incoming
ufw default allow outgoing

# allow SSH
ufw allow ssh
"""
        case HostServiceContract.MULTIPURPOSE:
            rule_config += \
"""
# set default rules
ufw default allow incoming
ufw default allow outgoing
"""
        case _:
            logger.error("Service profile %s not supported by rule generator!", str(service_profile))
            return None

    ## construct custom rules; they may overwrite the service profile rules
    for n, c_rule in enumerate(custom_rules):
        allow_src = c_rule['allow_src']
        allow_ports = c_rule['allow_ports']
        allow_proto = c_rule['allow_proto']
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



def __generate_firewalld__script(service_profile : HostServiceContract, custom_rules : list[dict]) -> str|None:
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

    # first configure the rules derived from the service profile
    rule_config = ""
    match service_profile:
        case HostServiceContract.HTTP:
            rule_config += \
f"""
# always allow SSH
firewall-cmd --zone={CUSTOM_ZONE} --add-service=ssh

# allow HTTP/S
firewall-cmd --zone={CUSTOM_ZONE} --add-service=http
firewall-cmd --zone={CUSTOM_ZONE} --add-service=https
"""
        case HostServiceContract.SSH:
            rule_config += \
f"""
# allow SSH
firewall-cmd --zone={CUSTOM_ZONE} --add-service=ssh
"""
        case HostServiceContract.MULTIPURPOSE:
            rule_config += \
f"""
#set the target of custom zone to ALLOW in order to make it default behaviour
firewall-cmd --zone={CUSTOM_ZONE} --set-target=ACCEPT
"""
        case _:
            logger.error("Service profile %s not supported by rule generator!", str(service_profile))
            return None

    ## construct custom rules; they may overwrite the service profile rules
    for n, c_rule in enumerate(custom_rules):
        allow_src = c_rule['allow_src']
        allow_ports = c_rule['allow_ports']
        allow_proto = c_rule['allow_proto']
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



def __generate_nftables__script(service_profile : HostServiceContract, custom_rules : list[dict]) -> str|None:
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
"""

    # first configure the rules derived from the service profile
    rule_config = ""
    match service_profile:
        case HostServiceContract.HTTP:
            rule_config += \
"""
        # drop all packets that do not match a rule in this chain
        type deterrers-ruleset hook input priority 0; policy drop;
        # accept SSH
        tcp dport ssh accept
        # accept HTTP and HTTPS
        tcp dport { http, https } accept
"""
        case HostServiceContract.SSH:
            rule_config += \
"""
        # drop all packets that do not match a rule in this chain
        type deterrers-ruleset hook input priority 0; policy drop;
        # accept SSH
        tcp dport ssh accept
"""
        case HostServiceContract.MULTIPURPOSE:
            rule_config += \
"""
        # allow all packets that do not match a rule in this chain
        type filter hook input priority 0; policy allow;
"""
        case _:
            logger.error("Service profile %s not supported by rule generator!", str(service_profile))
            return None
    
    ## construct the custom rules
    for n, c_rule in enumerate(custom_rules):
        allow_src = c_rule['allow_src']
        allow_ports = c_rule['allow_ports']
        allow_proto = c_rule['allow_proto']
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


def generate_rule(fw : HostFWContract, service_profile : HostServiceContract, custom_rules : list[dict]) -> str|None:
    """
    Generate/Suggest a firewall configuration script for some combination of fw program and service profile.
    Additionally consider custom rules that might be specified.

    Args:
        fw (HostFWContract): Firewall program.
        service_profile (HostServiceContract): Service profile.
        custom_rules (list[dict]): List of dicts specifying custom rules in following form:
        {
            'allow_src' : <CustomRuleSubnetContract.value>,
            'allow_ports' : <list[str]>,
            'allow_proto' : CustomRuleProtocolContract.value
            'id' : <UUID>
        }
    """
    match fw:
        case HostFWContract.UFW:
            script = __generate_ufw__script(service_profile, custom_rules)
        case HostFWContract.FIREWALLD:
            script = __generate_firewalld__script(service_profile, custom_rules)
        case HostFWContract.NFTABLES:
            script = __generate_nftables__script(service_profile, custom_rules)
        case _:
            logger.error(f"Firewall '{fw}' is not supported by rule generator!")
            return None

    return script