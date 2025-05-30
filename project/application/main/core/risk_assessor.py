import logging
from enum import Flag, auto
from cvss import CVSS2, CVSS3

from main.core.host import MyHost
from main.core.contracts import HostServiceProfile

logger = logging.getLogger(__name__)


class VulnerabilityScanResult():
    """
    Representation of a scan result with all important features.
    """
    def __init__(
        self,
        uuid: str,
        vulnerability_name: str,
        time_of_detection: str,
        host_ip: str,
        port: str,
        proto: str,
        hostname: str,
        nvt_name: str,
        nvt_oid: str,
        qod: int,
        cvss_version: int,
        cvss_base_score: float,
        cvss_base_vector: str,
        refs: list[str],
        description: str,
        overrides: list[dict]
    ) -> None:
        self.uuid = str(uuid)
        self.vulnerability_name = str(vulnerability_name)
        self.host_ip = str(host_ip)
        self.time_of_detection = str(time_of_detection)
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
        self.description = description
        self.overrides = list(overrides)

    def to_dict(self) -> dict:
        return self.__dict__


class RiskFlag(Flag):
    """
    Flagging system which enables risk assessment decisions by comparing flags.
    """
    NONE = 0
    HIGH_QOD = auto()
    REMOTE = auto()
    PORT_MATCH = auto()
    PROTO_MATCH = auto()
    MEDIUM_CVSS = auto()
    HIGH_CVSS = auto()
    MEDIUM_CVSS_NO_AVAILABILITY = auto()
    HIGH_CVSS_NO_AVAILABILITY = auto()


def __is_remote_exploitable(version: int, cvss_vector: str) -> bool:
    """
    Check if a given CVSS vector has the Attack Vector metric set to 'Network'.

    Args:
        version (int): CVSS version of the vector.
        cvss_vector (str): CVSS vector.

    Returns:
        bool: Returns True if CVSS vector has 'AV'-metric set to 'Network'.
    """
    if version == 2:
        score = CVSS2(cvss_vector)
    elif version == 3:
        score = CVSS3(cvss_vector)
    else:
        return False

    if score.get_value_description('AV') == 'Network':
        return True
    return False


def adapt_cvss_score(vul: VulnerabilityScanResult) -> float:
    """
    Adapts the CVSS base score of a given scan result to the context
    of DETERRERS.
    Sets the Availability Impact metric to None because reaction to high
    risks is blocking (i.e. making it unavailable)
    NOTE: using Availability Requirement metric from environmental metrics
    is not fitting because possible values are 'Low' and 'High' which both
    won't cancel out Availability Impact completely

    Args:
        vul (VulnerabilityScanResult): Vulnerability scan result which holds
        a CVSS base score.

    Returns:
        float: Returns the adapted CVSS base score.
    """

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


def __block_worthy(risk_flags: RiskFlag) -> bool:
    """
    Decide if risk flags trigger blocking.

    Args:
        risk_flags (RiskFlag): Risk flags of a vulnerability.

    Returns:
        bool: Returns True if relevant flags are set.
    """
    # only condition triggers if QoD is higher than threshold, if
    # remotely exploitable, if port and protocol matches service profile
    # and if adapted CVSS is high
    block_flags = (RiskFlag.HIGH_QOD
                   | RiskFlag.REMOTE
                   | RiskFlag.PORT_MATCH
                   | RiskFlag.PROTO_MATCH
                   | RiskFlag.HIGH_CVSS_NO_AVAILABILITY)
    if block_flags in risk_flags:
        return True
    return False


def __notify_worthy(risk_flags: RiskFlag) -> bool:
    """
    Decide if risk flags trigger notification.

    Args:
        risk_flags (RiskFlag): Risk flags of a vulnerability.

    Returns:
        bool: Returns True if relevant flags are set.
    """
    # 1st condition is same as block-condition except that it already triggers
    # for medium adapted CVSS scores
    notify_flags = (RiskFlag.HIGH_QOD
                    | RiskFlag.REMOTE
                    | RiskFlag.PORT_MATCH
                    | RiskFlag.PROTO_MATCH
                    | RiskFlag.MEDIUM_CVSS_NO_AVAILABILITY)
    if notify_flags in risk_flags:
        return True
    # 2nd condition triggers for all high CVSS scores with sufficient QoD
    notify_flags = (RiskFlag.HIGH_QOD | RiskFlag.HIGH_CVSS)
    if notify_flags in risk_flags:
        return True

    return False


def assess_vulnerability_risk(
    host: MyHost,
    vul: VulnerabilityScanResult,
    qod_threshold: int = 70,
    medium_cvss_threshold: float = 4.0,
    high_cvss_threshold: float = 7.0
) -> RiskFlag:
    """
    Assess the risk of a vulnerability based on context information from
    the host.

    Args:
        host (MyHost): Host the vulnerability was found on.
        vul (VulnerabilityScanResult): Vulnerability to assess.
        qod_threshold (int, optional): Quality of Detection threshold used to
        reduce false positives. Defaults to 70.
        medium_cvss_threshold (float, optional): Threshold at which CVSS scores
        are interpreted as medium severe. Defaults to 4.0.
        high_cvss_threshold (float, optional): Threshold at which CVSS scores
        are interpreted as highly severe. Defaults to 7.0.

    Returns:
        RiskFlag: Returns flags on the risk conditions of the vulnerability.
    """
    risk = RiskFlag.NONE
    try:
        # if there is an override for this vulnerability which sets its
        # threat-level to False Positive, there is no risk assumed
        for override in vul.overrides:
            if override['new_threat'] == 'False Positive':
                return RiskFlag.NONE

        # if still no severity matched CVSS v2 or v3 skip to avoid error
        if vul.cvss_version not in (2, 3):
            return RiskFlag.NONE

        # only consider results with a Quality of Detection value higher
        # than given threshold
        if vul.qod >= qod_threshold:
            risk = risk | RiskFlag.HIGH_QOD

        # set flag if the vulnerability is remotely exploitable
        if __is_remote_exploitable(vul.cvss_version, vul.cvss_base_vector):
            risk = risk | RiskFlag.REMOTE

        # vulnerability can be ignored if it affects port and protocol
        # outside of internet service profile
        match host.service_profile:
            case HostServiceProfile.HTTP:
                unblocked_locations = [
                    ('general', 'ip'),
                    ('general', 'tcp'),
                    ('80',      'tcp'),
                    ('443',     'tcp'),
                ]
                if (vul.port, vul.proto.lower()) in unblocked_locations:
                    risk = risk | RiskFlag.PORT_MATCH | RiskFlag.PROTO_MATCH

            case HostServiceProfile.SSH:
                unblocked_locations = [
                    ('general', 'ip'),
                    ('general', 'tcp'),
                    ('22',      'tcp'),
                ]
                if (vul.port, vul.proto.lower()) in unblocked_locations:
                    risk = risk | RiskFlag.PORT_MATCH | RiskFlag.PROTO_MATCH

            case HostServiceProfile.HTTP_SSH:
                unblocked_locations = [
                    ('general', 'ip'),
                    ('general', 'tcp'),
                    ('80',      'tcp'),
                    ('443',     'tcp'),
                    ('22',      'tcp'),
                ]
                if (vul.port, vul.proto.lower()) in unblocked_locations:
                    risk = risk | RiskFlag.PORT_MATCH | RiskFlag.PROTO_MATCH

            case HostServiceProfile.MULTIPURPOSE:
                # these services are always blocked at perimeter FW, so if
                # vulnerability matches service there is no risk of exposure
                # NOTE: depends on FW configuration
                blocked_locations = [
                    # Services in 'in-deny-srv-grp'
                    ('270217', 'tcp'),  # 27017-tcp
                    ('67', 'tcp'),  # bootps-tcp
                    ('67', 'udp'),  # bootps-udp
                    ('19', 'tcp'),  # chargen-tcp
                    ('19', 'udp'),  # chargen-udp
                    ('53', 'tcp'),  # domain-tcp
                    ('53', 'udp'),  # domain-udp
                    ('23', 'tcp'),  # port-23-tcp
                    ('111', 'tcp'),  # port-111-tcp
                    ('111', 'udp'),  # port-111-udp
                    ('139', 'tcp'),  # port-139-tcp
                    ('139', 'udp'),  # port-139-udp
                    ('389', 'tcp'),  # port-389-tcp-ldap
                    ('445', 'tcp'),  # port-445-tcp
                    ('445', 'udp'),  # port-445-udp
                    ('515', 'tcp'),  # port-515-tcp
                    ('631', 'tcp'),  # port-631-tcp
                    ('636', 'tcp'),  # port-636-tcp-ldap
                    ('1801', 'tcp'),  # port-1801-tcp-msmq
                    ('9100', 'tcp'),  # printer-pdl-data-stream-tcp
                    ('9101', 'tcp'),
                    ('9102', 'tcp'),
                    ('9103', 'tcp'),
                    ('9104', 'tcp'),
                    ('9105', 'tcp'),
                    ('9106', 'tcp'),
                    ('9107', 'tcp'),
                    ('9108', 'tcp'),
                    ('9109', 'tcp'),
                    ('9100', 'udp'),  # printer-pdl-data-stream-udp
                    ('9101', 'udp'),
                    ('9102', 'udp'),
                    ('9103', 'udp'),
                    ('9104', 'udp'),
                    ('9105', 'udp'),
                    ('9106', 'udp'),
                    ('9107', 'udp'),
                    ('9108', 'udp'),
                    ('9109', 'udp'),
                    ('25', 'tcp'),  # smtp-tcp
                    ('25', 'udp'),  # smtp-udp
                    ('135', 'tcp'),  # tcp-135
                    ('3389', 'tcp'),  # tcp-3389
                    ('3389', 'udp'),  # udp-3389
                    ('5000', 'tcp'),  # upnp-tcp
                    ('5000', 'udp'),  # upnp-udp
                    # Applications in 'in-deny-app-grp'
                    ('138', 'udp'),  # netbios-dg
                    ('137', 'udp'),  # netbios-ns
                    ('137', 'tcp'),
                    ('139', 'tcp'),  # netbios-ss
                    ('19', 'tcp'),  # chargen
                    ('19', 'udp'),
                    ('67', 'tcp'),  # dhcp
                    ('67', 'udp'),
                    ('68', 'tcp'),
                    ('68', 'udp'),
                    ('53', 'udp'),  # dns
                    ('53', 'tcp'),
                    ('631', 'tcp'),  # ipp
                    ('515', 'tcp'),  # lpd
                    ('1433', 'tcp'),  # mssql-db
                    ('1433', 'udp'),
                    ('1434', 'udp'),  # mssql-mon
                    ('123', 'udp'),  # ntp
                    ('25', 'tcp'),  # smtp
                    ('161', 'udp'),  # snmp
                    ('162', 'udp'),  # snmp-trap
                    ('9100', 'tcp'),  # hp-jetdirect
                    ('1900', 'udp'),  # ssdp
                    ('9200', 'tcp'),  # elastic-search
                    ('6379', 'tcp'),  # redis
                    ('27017', 'tcp'),  # mongodb
                    ('445', 'tcp'),  # ms-ds-smb
                    ('139', 'tcp'),
                    ('23', 'tcp'),  # telnet
                    ('3389', 'tcp'),  # ms-rdp
                    ('3389', 'udp'),
                    ('1503', 'tcp'),  # t.120
                    ('389', 'tcp'),  # ldap
                    ('636', 'tcp'),
                    # exclude other locations
                    ('package', ''),
                ]

                if (vul.port, vul.proto.lower()) not in blocked_locations:
                    risk = risk | RiskFlag.PORT_MATCH | RiskFlag.PROTO_MATCH

            case HostServiceProfile.EMPTY:
                pass

            case _:
                logger.error("Invalid service profile: %s",
                             host.service_profile.value)

        # set flags for CVSS base score severity
        if vul.cvss_base_score >= medium_cvss_threshold:
            risk = risk | RiskFlag.MEDIUM_CVSS
        if vul.cvss_base_score >= high_cvss_threshold:
            risk = risk | RiskFlag.HIGH_CVSS

        # set flags for customized CVSS base score severity
        if adapt_cvss_score(vul) >= medium_cvss_threshold:
            risk = risk | RiskFlag.MEDIUM_CVSS_NO_AVAILABILITY
        if adapt_cvss_score(vul) >= high_cvss_threshold:
            risk = risk | RiskFlag.HIGH_CVSS_NO_AVAILABILITY
    except Exception:
        pass

    return risk


def assess_host_risk(
    host: MyHost,
    vuls: list[VulnerabilityScanResult],
    qod_threshold: int = 70,
    medium_cvss_threshold: float = 4.0,
    high_cvss_threshold: float = 7.0
) -> tuple[list[VulnerabilityScanResult], list[VulnerabilityScanResult]]:
    """
    Assess the risk for a host on basis of given list of vulnerability
    scan results.

    Args:
        host (MyHost): Host instance.
        vuls (list[VulnerabilityScanResult]): List of vulnerability
        scan results.
        qod_threshold (int, optional): Quality of Detection threshold used
        to reduce false positives. Defaults to 70.
        medium_cvss_threshold (float, optional): Threshold at which CVSS
        scores are interpreted as medium severe. Defaults to 4.0.
        high_cvss_threshold (float, optional): Threshold at which CVSS scores
        are interpreted as highly severe. Defaults to 7.0.

    Returns:
        tuple[list[VulnerabilityScanResult], list[VulnerabilityScanResult]]:
        Returns one list with vulnerabilities that triggered a blocking
        and one list with vulnerabilities that triggered a notification.
    """
    block_reasons = []
    notify_reasons = []
    for vul in vuls:
        risk_flags = assess_vulnerability_risk(host, vul, qod_threshold,
                                               medium_cvss_threshold,
                                               high_cvss_threshold)
        if __block_worthy(risk_flags):
            block_reasons.append(vul)
        elif __notify_worthy(risk_flags):
            # add vulnerability to notify reasons only when it is not severe
            # enough for blocking
            notify_reasons.append(vul)
    return block_reasons, notify_reasons
