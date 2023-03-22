import logging
import datetime
import ipaddress

from django.conf import settings
from django.urls import reverse

from .core.host import MyHost
from .core.contracts import HostStatusContract, HostServiceContract, HostFWContract
from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.v_scanner_interface import GmpVScannerInterface
from hostadmin.core.fw_interface import PaloAltoInterface, PaloAltoAddressGroup


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




def set_host_offline(host_ipv4 : str) -> bool:
    """
    Block a host at the perimeter firewall and update the status in the IPAM.
    Removes host also from periodic scan.

    Args:
        host_ipv4 (str): IPv4 address of the host.

    Returns:
        bool: Returns True on success and False if something went wrong.
    """
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(host_ipv4)
        ips_to_block = ipam.get_IP6Address_if_linked(host.entity_id)
        ips_to_block.add(str(host.ipv4_addr))
        # change the perimeter firewall configuration so that host is blocked (IPv4 and IPv6 if available)
        with PaloAltoInterface(settings.FIREWALL_USERNAME, settings.FIREWALL_SECRET_KEY, settings.FIREWALL_URL) as fw:
            if not fw.enter_ok:
                return False
            if not fw.remove_addr_objs_from_addr_grps(ips_to_block, {ag for ag in PaloAltoAddressGroup}):
                return False
        host.status = HostStatusContract.BLOCKED
        if not ipam.update_host_info(host):
            return False
    
    # remove from periodic scan
    with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
        if not scanner.remove_host_from_periodic_scan(str(host.ipv4_addr)):
            return False
        
    return True

def set_host_bulk_offline(host_ipv4s : set[str]) -> bool:
    # TODO: optimize for better performance by querying many ips to FW
    for ipv4 in host_ipv4s:
        set_host_offline(ipv4)
        logger.error("Couldn't block host: %s", ipv4)
        continue
    return True


def set_host_online(host_ipv4 : str) -> bool:
    """
    Change the perimeter firewall configuration so that only host's service profile is allowed.
    Update the status in the IPAM.
    Add host to the periodic scan.

    Args:
        host_ipv4 (str): IPv4 address of the host.
    
    Returns:
        bool: Returns True on success and False if something goes wrong.
    """
    logger.info("Set host %s online.", host_ipv4)

    # add only the IPv4 address to periodic vulnerability scan
    with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
        response_url = settings.DOMAIN_NAME + reverse('v_scanner_periodic_alert')
        if not scanner.add_host_to_periodic_scan(host_ip=host_ipv4, deterrers_url=response_url):
            logger.error("Couldn't add host %s to periodic scan!", host_ipv4)
            return False
    
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # get IPv6 address to all IPv4 address
        host = ipam.get_host_info_from_ip(host_ipv4)
        ips_to_update = ipam.get_IP6Address_if_linked(host.entity_id)
        ips_to_update.add(str(host.ipv4_addr))

        with PaloAltoInterface(settings.FIREWALL_USERNAME, settings.FIREWALL_SECRET_KEY, settings.FIREWALL_URL) as fw:
            if not fw.enter_ok:
                logger.error("Connection to FW failed!")
                return False
            # first make sure ip is not already in any AddressGroups
            suc = fw.remove_addr_objs_from_addr_grps(ips_to_update, {ag for ag in PaloAltoAddressGroup})
            if not suc:
                logger.error("Couldn't update firewall configuration!")
                return False
            match host.service_profile:
                case HostServiceContract.HTTP:
                    suc = fw.add_addr_objs_to_addr_grps(ips_to_update, {PaloAltoAddressGroup.HTTP,})
                case HostServiceContract.SSH:
                    suc = fw.add_addr_objs_to_addr_grps(ips_to_update, {PaloAltoAddressGroup.SSH,})
                case HostServiceContract.MULTIPURPOSE:
                    suc = fw.add_addr_objs_to_addr_grps(ips_to_update, {PaloAltoAddressGroup.OPEN,})
                case HostServiceContract.HTTP_SSH:
                    suc = fw.add_addr_objs_to_addr_grps(ips_to_update, {PaloAltoAddressGroup.HTTP, PaloAltoAddressGroup.SSH})
                case HostServiceContract.EMPTY:
                    # if the service profile is set to empty, the host should be blocked
                    set_host_offline(host_ipv4)
                    return True
                case _:
                    logger.error("Unknown service profile: %s", str(host.service_profile))
                    return False
            if not suc:
                logger.error("Couldn't update firewall configuration!")
                return False
            
            # update host info in IPAM
            host.status = HostStatusContract.ONLINE
            if not ipam.update_host_info(host):
                logger.error("Couldn't update host information!")
                return False
    return True