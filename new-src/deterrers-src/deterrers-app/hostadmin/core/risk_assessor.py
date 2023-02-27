


def compute_risk_of_network_exposure(vuls : list[dict]):
    """
    Compute the combined risk of network exposure for a list of vulnerabilities.

    Important meta data:
        - cvss vectors
        - Quality of Detection values
        - overall severity of the network

    Args:
        vuls (list[dict]): List of vulnerabilities on one host.
            Vulnerabilities come as dicts of form:
                res = {
                    'uuid' : result_uuid,
                    'host_ip' : host_ip,
                    'hostname' : hostname,
                    'nvt_name' : nvt_name,
                    'nvt_oid' : nvt_oid,
                    'cvss_base' : cvss_base,
                    'cvss_vector' : cvss_vector
                }
    """
    # TODO: implement
    return None
