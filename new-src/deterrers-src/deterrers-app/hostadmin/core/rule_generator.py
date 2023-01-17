import os


from .host import HostFWContract, HostServiceContract, IntraSubnetContract

from django.conf import settings



def __generate_ufw__script(service_profile : HostServiceContract, custom_rules : list[dict]) -> str|None:

    # the preamble is the same for every service profile
    PREAMBLE = """
#!/bin/bash
# This script should be run with sudo permissions!

# disable the host-based firewall before making any changes
ufw disable

"""

    # the configuration of the actual fw rules depends on the service profile and custom rules
    rule_config = ""
    match service_profile:
        case HostServiceContract.HTTP:
            rule_config += """
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
            rule_config += """
# set default rules
ufw default deny incoming
ufw default allow outgoing

# always allow SSH
ufw allow ssh
"""
        case HostServiceContract.MULTIPURPOSE:
            rule_config += """
# set default rules
ufw default allow incoming
ufw default allow outgoing
"""
        case _:
            return None
    
    ## construct custom rules; they may overwrite the service profile rules
    for n, c_rule in enumerate(custom_rules):
        allow_srcs = c_rule['allow_srcs']
        allow_ports = c_rule['allow_ports']
        rule_config += f"""
# set custom rule no. {n}"""
        for src in allow_srcs:
            rule_config += f"""
ufw allow from {src['range']} to any port {','.join(allow_ports)} comment 'Custom DETERRERS rule no. {n}' """

    # postamble is the same for every service profile
    POSTAMBLE = """

# finally enable the host-based firewall again
ufw enable
"""

    return PREAMBLE + rule_config + POSTAMBLE


def __generate_firewalld__script(service_profile : HostServiceContract, custom_rules : list[dict]) -> str|None:
    pass

def __generate_nftables__script(service_profile : HostServiceContract, custom_rules : list[dict]) -> str|None:
    pass


def generate_rule(fw : HostFWContract, service_profile : HostServiceContract, custom_rules : list[dict]) -> str|None:
    """
    Generate/Suggest a firewall configuration script for some combination of fw program and service profile.
    Additionally consider custom rules that might be specified.

    Args:
        fw (HostFWContract): Firewall program.
        service_profile (HostServiceContract): Service profile.
        custom_rules (list[dict]): List of dicts specifying custom rules in following form:
        {
            'allow_srcs' : <list[IntraSubnetContract.value]>,
            'allow_ports' : <list[str]>,
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
            return None

    return script