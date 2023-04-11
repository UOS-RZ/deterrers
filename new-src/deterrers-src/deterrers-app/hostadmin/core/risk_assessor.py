import logging
from enum import Flag, auto
from cvss import CVSS2, CVSS3

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

class RiskFlag(Flag):
    NONE = 0
    HIGH_QOD = auto()
    REMOTE = auto()
    PORT_MATCH = auto()
    PROTO_MATCH = auto()
    MEDIUM_CVSS = auto()
    HIGH_CVSS = auto()
    MEDIUM_CVSS_NO_AVAILABILITY = auto()
    HIGH_CVSS_NO_AVAILABILITY = auto()


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

def __cvss_score_without_availability_impact(vul : VulnerabilityScanResult) -> float:
    # set the Availability Impact metric to None because reaction to this risk is blocking (i.e. making it unavailable)
    # NOTE: using Availability Requirement metric from environmental metrics is not fitting because
    # possible values are 'Low' and 'High' which both won't cancle out Availability Impact completely
    if vul.cvss_version == 2:
        score = CVSS2(vul.cvss_base_vector)
        score.metrics['A'] = 'N'
        score.compute_base_score()
        return float(score.base_score)
    elif vul.cvss_version == 3:
        score = CVSS3(vul.cvss_base_vector)
        score.metrics['A'] = 'N'
        score.compute_base_score()
        return float(score.base_score)

    return vul.cvss_base_score

def __block_worthy(risk_flags : RiskFlag) -> bool:
    block_flags = (RiskFlag.HIGH_QOD | RiskFlag.REMOTE | RiskFlag.PORT_MATCH | RiskFlag.PROTO_MATCH | RiskFlag.HIGH_CVSS_NO_AVAILABILITY)
    if block_flags in risk_flags:
        return True
    return False

def __notify_worthy(risk_falgs : RiskFlag) -> bool:
    # 1st condition is same as block-condition but CVSS score is not context-aware (still considers availability impact)
    notify_flags = (RiskFlag.HIGH_QOD | RiskFlag.REMOTE | RiskFlag.PORT_MATCH | RiskFlag.PROTO_MATCH | RiskFlag.MEDIUM_CVSS_NO_AVAILABILITY)
    if notify_flags in risk_falgs:
        return True
    notify_flags = (RiskFlag.HIGH_QOD | RiskFlag.HIGH_CVSS)
    if notify_flags in risk_falgs:
        return True
    
    return False


def assess_vulnerability_risk(
        host : MyHost,
        vul : VulnerabilityScanResult,
        qod_threshold : int = 70,
        medium_cvss_threshold : float = 4.0,
        high_cvss_threshold : float = 7.0
    ) -> RiskFlag:
    """
    Assess the risk of a vulnerability based on context information from the host.

    Args:
        host (MyHost): Host the vulnerability was found on.
        vul (VulnerabilityScanResult): Vulnerability to assess.
        qod_threshold (int, optional): Quality of Detection threshold used to reduce false positives. Defaults to 70.
        medium_cvss_threshold (float, optional): Threshold at which CVSS scores are interpreted as medium severe. Defaults to 4.0.
        high_cvss_threshold (float, optional): Threshold at which CVSS scores are interpreted as highly severe. Defaults to 7.0.

    Returns:
        RiskFlag: Returns flags on the risk conditions of the vulnerability.
    """
    risk = RiskFlag.NONE
    try:
        # if still no severity matched CVSS v2 or v3 skip to avoid error
        if vul.cvss_version not in (2, 3):
            return RiskFlag.NONE

        # only consider results with a Quality of Detection value higher than given threshold
        if vul.qod >= qod_threshold:
            risk = risk | RiskFlag.HIGH_QOD
        
        # set flag if the vulnerability is remotly exploitable
        if __is_remote_exploitable(vul.cvss_version, vul.cvss_base_vector):
            risk = risk | RiskFlag.REMOTE

        # vulnerability can be ignored if it affects port and protocol are outside of internet service profile
        # NOTE: reducing service profiles to default ports may be inaccurate since hosts might be 
        # configured differently and perimeter FW probably ist NGFW and does not block based on 
        # ports but based on deep packet inspection
        match host.service_profile:
            case HostServiceContract.HTTP:
                relevant_ports = ['general', '80', '443']
                relevant_protocols = ['ip', 'tcp']

                if vul.port in relevant_ports:
                    risk = risk | RiskFlag.PORT_MATCH
                if vul.proto.lower() in relevant_protocols:
                    risk = risk | RiskFlag.PROTO_MATCH
            case HostServiceContract.SSH:
                relevant_ports = ['general', '22']
                relevant_protocols = ['ip', 'tcp']
                
                if vul.port in relevant_ports:
                    risk = risk | RiskFlag.PORT_MATCH
                if vul.proto.lower() in relevant_protocols:
                    risk = risk | RiskFlag.PROTO_MATCH
            case HostServiceContract.HTTP_SSH:
                relevant_ports = ['general', '80', '443', '22']
                relevant_protocols = ['ip', 'tcp']
                
                if vul.port in relevant_ports:
                    risk = risk | RiskFlag.PORT_MATCH
                if vul.proto.lower() in relevant_protocols:
                    risk = risk | RiskFlag.PROTO_MATCH
            case HostServiceContract.MULTIPURPOSE:
                risk = risk | RiskFlag.PORT_MATCH | RiskFlag.PROTO_MATCH
            case _:
                logger.error("Invalid service profile: %s", host.service_profile.value)
        
        # set flags for CVSS base score severity
        if vul.cvss_base_score >= medium_cvss_threshold:
            risk = risk | RiskFlag.MEDIUM_CVSS
        if vul.cvss_base_score >= high_cvss_threshold:
            risk = risk | RiskFlag.HIGH_CVSS
        
        # set flags for customized CVSS base score severity
        if __cvss_score_without_availability_impact(vul) >= medium_cvss_threshold:
            risk = risk | RiskFlag.MEDIUM_CVSS_NO_AVAILABILITY
        if __cvss_score_without_availability_impact(vul) >= high_cvss_threshold:
            risk = risk | RiskFlag.HIGH_CVSS_NO_AVAILABILITY
    except:
        pass
    
    return risk

def assess_host_risk(
        host : MyHost,
        vuls : list[VulnerabilityScanResult],
        qod_threshold : int = 70,
        medium_cvss_threshold : float = 4.0,
        high_cvss_threshold : float = 7.0
    ) -> tuple[list[VulnerabilityScanResult], list[VulnerabilityScanResult]]:
    """
    TODO: docu

    Args:
        host (MyHost): _description_
        vuls (list[VulnerabilityScanResult]): _description_
        qod_threshold (int, optional): _description_. Defaults to 70.
        medium_cvss_threshold (float, optional): _description_. Defaults to 4.0.
        high_cvss_threshold (float, optional): _description_. Defaults to 7.0.

    Returns:
        tuple[list[VulnerabilityScanResult], list[VulnerabilityScanResult]]: _description_
    """
    block_reasons = []
    notify_reasons = []
    for vul in vuls:
        risk_flags = assess_vulnerability_risk(host, vul, qod_threshold, medium_cvss_threshold, high_cvss_threshold)
        if __block_worthy(risk_flags):
            block_reasons.append(vul)
        elif __notify_worthy(risk_flags):
            # add vulnerability to notify reasosns only when it is not severe enough for blocking
            notify_reasons.append(vul)
    return block_reasons, notify_reasons
