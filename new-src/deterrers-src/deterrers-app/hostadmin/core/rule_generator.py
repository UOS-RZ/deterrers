import os

from .host import HostFWContract, HostServiceContract

from django.conf import settings

STATIC_PATH = os.path.join(settings.STATIC_ROOT, 'fw-config-samples')


def __get_fw_folder(fw : HostFWContract) -> str:
    """
    Get the folder name corresponding to the firewall programm.

    Args:
        fw (HostFWContract): Firewall program
    
    Raises:
        RuntimeError: Raised if fw is not supported by HostFWContract.
    """
    match fw:
        case HostFWContract.UFW:
            return "/ufw/"
        case HostFWContract.FIREWALLD:
            return "/firewalld/"
        case HostFWContract.NFTABLES:
            return "/nftables/"
        case _:
            raise RuntimeError(f"Invalid firewall program: {fw}")

def __get_profile_folder(service_profile : HostServiceContract) -> str:
    """
    Get the folder name corresponding to the service profile.

    Args:
        service_profile (HostServiceContract): Service profile.
    
    Raises:
        RuntimeError: Raised if service_profile is not supported by HostServiceContract.
    """
    match service_profile:
        case HostServiceContract.HTTP:
            return "/http/"
        case HostServiceContract.SSH:
            return "/ssh/"
        case HostServiceContract.MULTIPURPOSE:
            return "/open/"
        case _:
            raise RuntimeError(f"Invalid service profile: {service_profile}")


def generate_rule(fw : HostFWContract, service_profile : HostServiceContract) -> str:
    """
    Generate/Suggest a firewall rule for some combination of fw program and service profile.

    Args:
        fw (HostFWContract): Firewall program.
        service_profile (HostServiceContract): Service profile.
    """
    fw_folder = __get_fw_folder(fw)
    service_profile_folder = __get_profile_folder(service_profile)

    conf_path = os.path.join(STATIC_PATH, fw_folder, service_profile_folder)

    with open(conf_path, "r") as f:
        conf = f.read()
        return conf