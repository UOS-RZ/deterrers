import logging
import datetime
import ipaddress

from django.conf import settings
from django.urls import reverse

from hostadmin.core.host import MyHost
from hostadmin.core.contracts import (HostStatus,
                                      HostServiceProfile,
                                      HostFW)
from hostadmin.core.risk_assessor import VulnerabilityScanResult
if settings.IPAM_DUMMY:
    from hostadmin.core.data_logic.data_mock \
        import DataMockWrapper as IPAMWrapper
else:
    from hostadmin.core.data_logic.ipam_wrapper \
        import ProteusIPAMWrapper as IPAMWrapper
if settings.SCANNER_DUMMY:
    from hostadmin.core.scanner.scanner_mock \
        import ScannerMock as ScannerWrapper
else:
    from hostadmin.core.scanner.gmp_wrapper \
        import GmpScannerWrapper as ScannerWrapper
if settings.FIREWALL_DUMMY:
    from hostadmin.core.fw.fw_mock \
        import FWMock as FWWrapper
else:
    from hostadmin.core.fw.pa_wrapper \
        import PaloAltoWrapper as FWWrapper


logger = logging.getLogger(__name__)


def add_changelog(history: int = 10) -> list[str]:
    # form: ("<date>", "<description>")
    changes = [

    ]

    today = datetime.datetime.today().date()
    return [
        f"{change[0]}: {change[1]}"
        for change in changes
        if ((today - datetime.date.fromisoformat(change[0]))
            < datetime.timedelta(days=history))
    ]


def is_public_ip(
    ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address
) -> bool:
    """
    Check whether ip address is public.

    Args:
        ip (str): IPv4 or IPv6 address

    Returns:
        bool: Returns True if IP is not private and False if private or
        string is no IP address at all.
    """
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        logger.exception("Expected string to be ip address. Instead got %s",
                         str(ip))
    return False


def available_actions(host: MyHost) -> dict:
    """
    Compute which actions can be performed on a host.

    Args:
        host (MyHost): Host instance.

    Returns:
        dict: Returns a dictionary of boolean flags indicating available
        actions.
    """
    flags = {}
    match host.status:
        case HostStatus.UNREGISTERED:
            flags['can_update'] = True
            flags['can_register'] = (
                host.service_profile != HostServiceProfile.EMPTY
                and is_public_ip(host.ipv4_addr)
            )
            flags['can_scan'] = True
            flags['can_download_config'] = (
                host.service_profile != HostServiceProfile.EMPTY
                and host.fw != HostFW.EMPTY
            )
            flags['can_block'] = False
            flags['can_remove'] = True
        case HostStatus.UNDER_REVIEW:
            flags['can_update'] = False
            flags['can_register'] = False
            flags['can_scan'] = False
            flags['can_download_config'] = (
                host.service_profile != HostServiceProfile.EMPTY
                and host.fw != HostFW.EMPTY
            )
            flags['can_block'] = False
            flags['can_remove'] = False
        case HostStatus.BLOCKED:
            flags['can_update'] = True
            flags['can_register'] = (
                host.service_profile != HostServiceProfile.EMPTY
                and is_public_ip(host.ipv4_addr)
            )
            flags['can_scan'] = True
            flags['can_download_config'] = (
                host.service_profile != HostServiceProfile.EMPTY
                and host.fw != HostFW.EMPTY
            )
            flags['can_block'] = False
            flags['can_remove'] = True
        case HostStatus.ONLINE:
            flags['can_update'] = True
            flags['can_register'] = False
            flags['can_scan'] = True
            flags['can_download_config'] = (
                host.service_profile != HostServiceProfile.EMPTY
                and host.fw != HostFW.EMPTY
            )
            flags['can_block'] = True
            flags['can_remove'] = True
        case _:
            flags['can_update'] = False
            flags['can_register'] = False
            flags['can_scan'] = False
            flags['can_download_config'] = False
            flags['can_block'] = False
            flags['can_remove'] = False
    return flags


def set_host_offline(host_ipv4: str) -> bool:
    """
    Block a host at the perimeter firewall and update the status in the IPAM.
    Removes host also from periodic scan.

    Args:
        host_ipv4 (str): IPv4 address of the host.

    Returns:
        bool: Returns True on success and False if something went wrong.
    """
    with IPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return False
        with ScannerWrapper(
            settings.SCANNER_USERNAME,
            settings.SCANNER_SECRET_KEY,
            settings.SCANNER_HOSTNAME
        ) as scanner:
            if not scanner.enter_ok:
                return False
            with FWWrapper(
                settings.FIREWALL_USERNAME,
                settings.FIREWALL_SECRET_KEY,
                settings.FIREWALL_URL
            ) as fw:
                if not fw.enter_ok:
                    return False

                host = ipam.get_host_info_from_ip(host_ipv4)
                ips_to_block = ipam.get_IP6Addresses(host)
                ips_to_block.add(str(host.ipv4_addr))
                # change the perimeter firewall configuration so that host
                # is blocked (IPv4 and IPv6 if available)
                if not fw.block_ips(ips_to_block):
                    return False

                # remove from periodic scan
                if not scanner.remove_host_from_periodic_scans(
                    str(host.ipv4_addr)
                ):
                    return False

                # update status in IPAM
                host.status = HostStatus.BLOCKED
                if not ipam.update_host_info(host):
                    return False
    return True


def set_host_bulk_offline(host_ipv4s: set[str]) -> bool:
    # TODO: optimize for better performance by querying many ips to FW
    for ipv4 in host_ipv4s:
        if not set_host_offline(ipv4):
            logger.error("Couldn't block host: %s", ipv4)
        continue
    return True


def set_host_online(host_ipv4: str) -> bool:
    """
    Change the perimeter firewall configuration so that only host's
    service profile is allowed.
    Update the status in the IPAM.
    Add host to the periodic scan.

    Args:
        host_ipv4 (str): IPv4 address of the host.

    Returns:
        bool: Returns True on success and False if something goes wrong.
    """
    logger.info("Set host %s online.", host_ipv4)

    with IPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return False
        with ScannerWrapper(
            settings.SCANNER_USERNAME,
            settings.SCANNER_SECRET_KEY,
            settings.SCANNER_HOSTNAME
        ) as scanner:
            if not scanner.enter_ok:
                return False
            with FWWrapper(
                settings.FIREWALL_USERNAME,
                settings.FIREWALL_SECRET_KEY,
                settings.FIREWALL_URL
            ) as fw:
                if not fw.enter_ok:
                    return False

                host = ipam.get_host_info_from_ip(host_ipv4)
                if (
                    not host.is_valid()
                    or host.service_profile is HostServiceProfile.EMPTY
                ):
                    logger.error("Can not set host '%s' online.", str(host))
                    return False

                # add only the IPv4 address to periodic vulnerability scan
                response_url = (settings.DOMAIN_NAME
                                + reverse('scanner_periodic_alert'))
                if not scanner.add_host_to_periodic_scans(
                    host_ip=host_ipv4,
                    alert_dest_url=response_url
                ):
                    logger.error("Couldn't add host %s to periodic scan!",
                                 host_ipv4)
                    return False

                # get IPv6 address to all IPv4 address
                ips_to_update = ipam.get_IP6Addresses(host)
                ips_to_update.add(str(host.ipv4_addr))

                # first make sure ip is not already in any AddressGroups
                suc = fw.block_ips(ips_to_update)
                if not suc:
                    logger.error("Couldn't update firewall configuration!")
                    return False
                suc = fw.allow_service_profile_for_ips(
                    ips_to_update,
                    host.service_profile
                )
                if not suc:
                    logger.error("Couldn't update firewall configuration!")
                    return False

                # update host info in IPAM
                host.status = HostStatus.ONLINE
                if not ipam.update_host_info(host):
                    logger.error("Couldn't update host information!")
                    return False
    return True


def registration_mail_body(
    host: MyHost,
    passed: bool,
    scan_ts: str,
    block_reasons: list[VulnerabilityScanResult]
) -> str:
    email_body = f"""
The registration was {'successful' if passed else 'NOT successful'}.


*************** System Information ***************

IPv4 Address:             {str(host.ipv4_addr)}
FQDN:                     {', '.join(host.dns_rcs)}
Admins:                   {', '.join(host.admin_ids)}
Internet Service Profile: {host.service_profile.value}

**************************************************

Scan completed: {scan_ts}

Complete scan report can be found attached to this e-mail.

--------------------------------------------------
"""
    if not passed:
        email_body += """
Following vulnerabilities resulted in the blocking:
"""
        for vul in block_reasons:
            email_body += f"""
    Network Vulnerability Test Name:    {vul.nvt_name}
    Network Vulnerability Test ID:      {vul.nvt_oid}
    CVSS Base Score:                    {vul.cvss_base_score} ({vul.cvss_base_vector})
    Quality of Detection:               {vul.qod}
    Hostname:                           {vul.hostname}
    Port:                               {vul.port}/{vul.proto}
    Vulnerability References:           {", ".join(vul.refs)}

"""

    return email_body


def scan_mail_body(host: MyHost, scan_ts):
    return f"""
*************** System Information ***************

IPv4 Address:             {str(host.ipv4_addr)}
FQDN:                     {', '.join(host.dns_rcs)}
Admins:                   {', '.join(host.admin_ids)}
Internet Service Profile: {host.service_profile.value}

**************************************************


Scan completed: {scan_ts}

Scan report can be found attached to this e-mail."""


def periodic_mail_body(
    host: MyHost,
    block_reasons: list[VulnerabilityScanResult],
    notify_reasons: list[VulnerabilityScanResult]
):
    if len(block_reasons) != 0:
        email_body = f"""
DETERRERS found a high risk for host {str(host.ipv4_addr)} during a periodic scan and will block it at the perimeter firewall.

*************** System Information ***************

IPv4 Address:             {str(host.ipv4_addr)}
FQDN:                     {', '.join(host.dns_rcs)}
Admins:                   {', '.join(host.admin_ids)}
Internet Service Profile: {host.service_profile.value}

**************************************************

Following vulnerabilities resulted in the blocking:
"""
        for vul in block_reasons:
            email_body += f"""
    Network Vulnerability Test Name:    {vul.nvt_name}
    Network Vulnerability Test ID:      {vul.nvt_oid}
    CVSS Base Score:                    {vul.cvss_base_score} ({vul.cvss_base_vector})
    Quality of Detection:               {vul.qod}
    Hostname:                           {vul.hostname}
    Port:                               {vul.port}/{vul.proto}
    Vulnerability References:           {", ".join(vul.refs)}

"""
        # if block reasons and notify reasons
        if len(notify_reasons) != 0:
            email_body += """
Additionally, following vulnerabilities were found but do not result in blocking.
They are either not exposed to the internet, affect only the availability or are not severe enough to legitimize blocking the host:
"""
            for vul in notify_reasons:
                email_body += f"""
    Network Vulnerability Test Name:    {vul.nvt_name}
    Network Vulnerability Test ID:      {vul.nvt_oid}
    CVSS Base Score:                    {vul.cvss_base_score} ({vul.cvss_base_vector})
    Quality of Detection:               {vul.qod}
    Hostname:                           {vul.hostname}
    Port:                               {vul.port}/{vul.proto}
    Vulnerability References:           {", ".join(vul.refs)}

"""

        email_body += """
Please remediate the security risks and re-register the host in DETERRERS!"""

    # no block reasons only notify reasons
    elif len(notify_reasons) != 0:
        email_body = f"""
DETERRERS found vulnerabilities for host {str(host.ipv4_addr)} during a periodic scan but will NOT block it at the perimeter firewall.

*************** System Information ***************

IPv4 Address:             {str(host.ipv4_addr)}
FQDN:                     {', '.join(host.dns_rcs)}
Admins:                   {', '.join(host.admin_ids)}
Internet Service Profile: {host.service_profile.value}

**************************************************

Following vulnerabilities were found but do not result in blocking.
They are either not exposed to the internet, affect only the availability or are not severe enough to legitimize blocking the host:
"""
        for vul in notify_reasons:
            email_body += f"""
    Network Vulnerability Test Name:    {vul.nvt_name}
    Network Vulnerability Test ID:      {vul.nvt_oid}
    CVSS Base Score:                    {vul.cvss_base_score} ({vul.cvss_base_vector})
    Quality of Detection:               {vul.qod}
    Hostname:                           {vul.hostname}
    Port:                               {vul.port}/{vul.proto}
    Vulnerability References:           {", ".join(vul.refs)}

"""
        email_body += """
Remediation of these vulnerabilities will still increase the security level of the whole campus network.
"""

    # if no block reasons and no notify reasons
    else:
        email_body = ""

    return email_body
