import logging
from enum import Enum
from cvss import CVSS2, CVSS3

from django.conf import settings

from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.host import MyHost
from hostadmin.core.contracts import HostServiceContract

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

class RiskLevel(Enum):
    BLOCK = 0
    NOTIFY = 1
    NONE = 2


def __is_remote_exploitable(version : int, cvss_vector : str) -> bool:
    if version == 2:
        score = CVSS2(cvss_vector)
    elif version == 3:
        score = CVSS3(cvss_vector)
    else:
        return False

    if score.get_value_description('AV') == 'Network':
        return True
    return False


def assess_vulnerability_risk(host : MyHost, vul : VulnerabilityScanResult, qod_threshold : int = 70) -> RiskLevel:
    """
    Assess the risk of a vulnerability based on context information from the host.

    Args:
        host (MyHost): Host the vulnerability was found on.
        vul (VulnerabilityScanResult): Vulnerability to assess.
        qod_threshold (int, optional): Quality of Detection threshold used to reduce false positives. Defaults to 70.

    Returns:
        RiskLevel: Returns the risk level of the vulnerability.
    """
    try:
        # only consider results with a Quality of Detection value higher than given threshold
        if vul.qod >= qod_threshold:
            # if still no severity matched CVSS v2 or v3 skip to avoid error
            if vul.cvss_version not in (2, 3):
                return RiskLevel.NONE
            
            if not __is_remote_exploitable(vul.cvss_version, vul.cvss_base_vector):
                return RiskLevel.NONE

            # vulnerability can be ignored if it affects ports outside of internet service profile
            # NOTE: reducing service profiles to default ports may be inaccurate since hosts might be 
            # configured differently and perimeter FW probably ist NGFW and does not block based on 
            # ports but based on deep packet inspection
            match host.service_profile:
                case HostServiceContract.HTTP:
                    relevant_ports = ['general', '80', '443']
                    if vul.port not in relevant_ports:
                        return RiskLevel.NONE
                case HostServiceContract.SSH:
                    relevant_ports = ['general', '22']
                    if vul.port not in relevant_ports:
                        return RiskLevel.NONE
                case HostServiceContract.HTTP_SSH:
                    relevant_ports = ['general', '80', '443', '22']
                    if vul.port not in relevant_ports:
                        return RiskLevel.NONE
                case HostServiceContract.MULTIPURPOSE:
                    pass
                case _:
                    logger.error("Invalid service profile: %s", host.service_profile.value)
            
            # naive approach: block all hosts with a vulnerability CVSS base score higher than 5.0
            if vul.cvss_base_score > 5.0:
                return RiskLevel.BLOCK
    except:
        pass
    
    return RiskLevel.NONE

def assess_host_risk(host : MyHost, vuls : list[VulnerabilityScanResult]) -> list[VulnerabilityScanResult]:
    """
    TODO: docu

    Args:
        host (MyHost): _description_
        vuls (list[VulnerabilityScanResult]): _description_

    Returns:
        list[VulnerabilityScanResult]: _description_
    """
    block_reasons = []
    for vul in vuls:
        if assess_vulnerability_risk(host, vul) is RiskLevel.BLOCK:
            block_reasons.append(vul)
    return block_reasons

