import logging

from django.conf import settings

from hostadmin.core.ipam_api_interface import ProteusIPAMInterface

logger = logging.getLogger(__name__)

class VulnerabilityScanResult():

    def __init__(self, uuid : str, host_ip : str, port : str, proto : str, hostname : str, nvt_name : str, nvt_oid : str, qod : int, cvss_version : int, cvss_base_score : float, cvss_base_vector : str, refs : list[str]) -> None:
        self.uuid = str(uuid)
        self.host_ip = str(host_ip)
        self.port = str(port)
        self.proto = str(proto)
        self.hostname = str(hostname)
        self.nvt_name = str(nvt_name)
        self.nvt_oid = str(nvt_oid)
        self.qod = int(qod)
        self.cvss_version = int(cvss_version)
        self.cvss_base_score = float(cvss_base_score)
        self.cvss_base_vector = str(cvss_base_vector)
        self.refs = list(refs)




def compute_risk_of_network_exposure(vuls : list[VulnerabilityScanResult], qod_threshold : int = 70) -> tuple[set[str]|None, dict|None]:
    """
    Compute which hosts should be blocked because scan results pose a too high risk.

    Possibly important meta data:
        - cvss vectors
        - Quality of Detection values
        - overall severity of the network

    Args:
        vuls (list[VulnerabilityScanResult]): List of vulnerabilities.

    Returns:
        (tuple): Returns a set of IP addresses to block and a dict with the vulnerabilities that lead to the decision.
    """
    hosts_to_block = set()
    risky_vuls = dict()
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        if not ipam.enter_ok:
            return None, None
        
        for vul in vuls:
            # only consider results with a Quality of Detection value higher than given threshold
            if vul.qod >= qod_threshold:
                host = ipam.get_host_info_from_ip(vul.host_ip)
                if not host or not host.is_valid():
                    logger.error("Invalid host during risk assessment: %s", str(host))
                    continue
                # TODO: implement smart logic

                # if still no severity matched CVSS v2 or v3 skip to avoid error
                if vul.cvss_version not in (2, 3):
                    logger.warning("Vulnerability results severity entries did not match CVSS v2 or v3: %s", str(vul.cvss_severities))
                    continue
                
                # naive approach: block all hosts with a vulnerability CVSS base score higher than 5.0
                if vul.cvss_base_score > 5.0:
                    hosts_to_block.add(vul.host_ip)
                    if risky_vuls.get(vul.host_ip, None) is None:
                        risky_vuls[vul.host_ip] = [vul,]
                    else:
                        risky_vuls[vul.host_ip].append(vul)

    return hosts_to_block, risky_vuls
