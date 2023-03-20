import logging
import datetime
import ipaddress

from .core.host import MyHost
from .core.contracts import HostStatusContract, HostServiceContract, HostFWContract

logger = logging.getLogger(__name__)

def add_changelog(history : int = 10) -> list[str]:
    changes = [
        ("2023-02-21", "New: Internet service profile 'HTTP+SSH' was added for hosts which should provide both HTTP and SSH to the internet."),
        ("2023-02-21", "New: DNS names are now displayed per host."),
        ("2023-03-07", "New: 'My Hosts' page loads faster."),
        ("2023-03-12", "New: IPv6 will also be de-/blocked at the perimeter firewall in case an IPv6 address is linked to the same host record as the corresponding IPv4 address in Proteus IPAM."),
        ("2023-03-13", "Security Fix: Firewalld script generation was faulty. If a configuration script was deployed in the past, a new script should be downloaded and deployed!")
    ]

    today = datetime.datetime.today().date()
    return [f"{change[0]}: {change[1]}" for change in changes if (today - datetime.date.fromisoformat(change[0])) < datetime.timedelta(days=history)]

def is_public_ip(ip : str|ipaddress.IPv4Address|ipaddress.IPv6Address) -> bool:
    """
    Check whether ip address is public.

    Args:
        ip (str): IPv4 or IPv6 address

    Returns:
        bool: Returns True if IP is not private and False if private or string is no IP address at all.
    """
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        logger.exception("Expected string to be ip address. Instead got %s", str(ip))
    return False


def available_actions(host : MyHost) -> dict:
    """
    Compute which actions can be perfomed on a host.

    Args:
        host (MyHost): Host instance.

    Returns:
        dict: Returns a dictionary of boolean flags indicating available actions.
    """
    flags = {}
    match host.status:
        case HostStatusContract.UNREGISTERED:
            flags['can_update'] = True
            flags['can_register'] = host.service_profile != HostServiceContract.EMPTY and is_public_ip(host.ipv4_addr)
            flags['can_scan'] = True
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = False
        case HostStatusContract.UNDER_REVIEW:
            flags['can_update'] = False
            flags['can_register'] = False
            flags['can_scan'] = False
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = False
        case HostStatusContract.BLOCKED:
            flags['can_update'] = True
            flags['can_register'] = host.service_profile != HostServiceContract.EMPTY and is_public_ip(host.ipv4_addr)
            flags['can_scan'] = True
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = False
        case HostStatusContract.ONLINE:
            flags['can_update'] = True
            flags['can_register'] = False
            flags['can_scan'] = True
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = True
        case _:
            flags['can_update'] = False
            flags['can_register'] = False
            flags['can_scan'] = False
            flags['can_download_config'] = False
            flags['can_block'] = False
    return flags


def registration_mail_body(ipv4 : str, passed : bool, severity_str : str, admins : list[str], service_profile : HostServiceContract, fqdns : list[str], scan_ts):
    return f"""
The registration was {'passed' if passed else 'not passed because severity was higher than 5.0'}.

Severity of host {ipv4} is {severity_str}!


***System Information***

IPv4 Address: {ipv4}
Admins: {', '.join(admins)}
Internet Service Profile: {service_profile.value}
FQDN: {', '.join(fqdns)}


Scan completed: {scan_ts}

Scan report can be found attached to this e-mail."""


def scan_mail_body(ipv4 : str, passed : bool, severity_str : str, admins : list[str], service_profile : HostServiceContract, fqdns : list[str], scan_ts):
    return f"""
The scan was {'passed' if passed else 'not passed because severity was higher than 5.0'}.

Severity of host {ipv4} is {severity_str}!


***System Information***

IPv4 Address: {ipv4}
Admins: {', '.join(admins)}
Internet Service Profile: {service_profile.value}
FQDN: {', '.join(fqdns)}


Scan completed: {scan_ts}

Scan report can be found attached to this e-mail."""
