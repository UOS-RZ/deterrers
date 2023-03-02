import logging

logger = logging.getLogger(__name__)

class VulnerabilityScanResult():

    def __init__(self, uuid : str, host_ip : str, hostname : str, nvt_name : str, nvt_oid : str, qod : int, cvss_severities : list[dict], refs : list[str]) -> None:
        self.uuid = str(uuid)
        self.host_ip = str(host_ip)
        self.hostname = str(hostname)
        self.nvt_name = str(nvt_name)
        self.nvt_oid = str(nvt_oid)
        self.qod = int(qod)
        self.cvss_severities = list(cvss_severities) # should be a list of dicts with fields 'type', 'base_score' and 'base_vector'
        self.refs = list(refs)

def compute_risk_of_network_exposure(vuls : list[VulnerabilityScanResult], qod_threshold : int = 70):
    """
    Compute which hosts should be blocked because scan results pose a too high risk.

    Possibly important meta data:
        - cvss vectors
        - Quality of Detection values
        - overall severity of the network

    Args:
        vuls (list[VulnerabilityScanResult]): List of vulnerabilities.

    Returns:
        (tuple): Returns a set of IP address to block and a dict with the vulnerabilities that lead to the decision.
    """
    all_hosts = set()
    hosts_to_block = set()
    risky_vuls = dict()
    for vul in vuls:
        all_hosts.add(vul.host_ip)
        # TODO: implement smart logic
        # only consider results with a Quality of Detection value higher than given threshold
        if vul.qod >= qod_threshold:
            # get severity in newest CVSS version
            cvss_base_score = None
            cvss_base_vector = None
            for sev in vul.cvss_severities:
                if sev.get('type') == 'cvss_base_v3':
                    cvss_base_score = float(sev.get('base_score', -1.0))
                    cvss_base_vector = sev.get('base_vector', '')
            # if no CVSSv3 entry was found, fall back to v2
            if cvss_base_score is None or cvss_base_score == -1.0:
                for sev in vul.cvss_severities:
                    if sev.get('type') == 'cvss_base_v2':
                        cvss_base_score = float(sev.get('base_score', -1.0))
                        cvss_base_vector = sev.get('base_vector', '')
            # if still no severity matched CVSS v2 or v3 skip to avoid error
            if cvss_base_score is None or cvss_base_score < 0.0:
                logger.warning("Vulnerability results severity entries did not match CVSS v2 or v3: %s", str(vul.cvss_severities))
                continue
            
            # naive approach: block all hosts with a vulnerability CVSS base score higher than 5.0
            if cvss_base_score > 5.0:
                hosts_to_block.add(vul.host_ip)
                if risky_vuls.get(vul.host_ip, None) is None:
                    risky_vuls[vul.host_ip] = [vul,]
                else:
                    risky_vuls[vul.host_ip].append(vul)

    return hosts_to_block, risky_vuls
