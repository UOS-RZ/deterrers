import logging

from rest_framework.response import Response
from rest_framework.decorators import (api_view,
                                       authentication_classes,
                                       permission_classes)
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from django.conf import settings
from django.shortcuts import get_object_or_404
from django.http import Http404
from django.urls import reverse

from myuser.models import MyUser
from hostadmin.util import (available_actions,
                            set_host_bulk_offline,
                            set_host_online,
                            set_host_offline)
from hostadmin.core.data_logic.ipam_wrapper import ProteusIPAMWrapper
from hostadmin.core.scanner.gmp_wrapper import GmpScannerWrapper
from hostadmin.core.host import MyHost
from hostadmin.core.contracts import (HostStatusContract,
                                      HostServiceContract,
                                      HostBasedPolicySrcContract,
                                      HostBasedPolicyProtocolContract,
                                      HostFWContract)
from .serializers import MyHostSerializer, HostActionSerializer

logger = logging.getLogger(__name__)


class Http400(Exception):
    """ Bad Request """


class Http409(Exception):
    """ Conflict """


class Http500(Exception):
    """ Internal Error """


def __get_host(request) -> Response:
    """
    Get information of a host.

    Args:
        request (_type_): Request object.

    Returns:
        Response: Returns Response object.
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            raise Http500("No connection to IPAM")

        # check if user has IPAM permission and an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404(f"{hostadmin.username} is not admin")

        # get host from IPAM
        ipv4 = request.GET.get('ipv4_addr')
        if not ipv4:
            raise Http400("No IP provided")
        host = ipam.get_host_info_from_ip(ipv4)
        if not host:
            raise Http404("Host not found")
        if not host.is_valid():
            raise Http409("Host not valid")

        # check if user is admin of this host
        if hostadmin.username not in host.admin_ids:
            raise Http404("Host not found")

        host_serializer = MyHostSerializer(host)
        return Response(data=host_serializer.data)


def __add_host(request) -> Response:
    """
    Add a host to DETERRERS.

    Args:
        request (_type_): Request object which holds data.

    Returns:
        Response: Returns Response object.
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            raise Http500("No connection to IPAM")

        # check if user has IPAM permission and an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404(f"{hostadmin.username} is not admin")

        # get ipv4 address and admin_ids (i.e. tag names) by deserializing
        host_serializer = MyHostSerializer(data=request.data)
        if not host_serializer.is_valid():
            raise Http400("Invalid data given")
        host_update_data = host_serializer.validated_data
        host_ipv4 = host_update_data['ipv4_addr']
        host = ipam.get_host_info_from_ip(host_ipv4)
        if not host:
            raise Http404("Host not found")
        if not host.is_valid():
            raise Http409("Host not valid")
        try:
            tag_names = set(host_update_data['admin_ids'])
        except KeyError:
            raise Http400("No admin IDs provided")
        # check if tag names are either department or admin tag
        for tag_name in tag_names:
            if (tag_name in ipam.get_department_names()
                    or ipam.is_admin(tag_name)):
                # add tag to host
                code = ipam.add_admin_to_host(tag_name, host)
                if code not in range(200,  205, 1):
                    return Response(status=code)

        # update host if there are changes
        if (host_update_data.get('service_profile', None)
                or host_update_data.get('fw', None)):
            __update_host_logic(ipam, host, host_update_data)

    return Response()


def __remove_host(request) -> Response:
    """
    Remove a host from DETERRERS.
    Sets all custom fields to blank in IPAM, removes all admins, blocks host,
    removes it from periodic scan.

    Args:
        request (_type_): Request object.

    Returns:
        Response: Returns Response object.
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            raise Http500("No connection to IPAM")
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404(f"{hostadmin.username} is not admin")

        # get host by deserializing and then querying IPAM
        host_serializer = MyHostSerializer(data=request.data)
        if not host_serializer.is_valid():
            raise Http400("Invalid data provided")
        host_update_data = host_serializer.validated_data
        host = ipam.get_host_info_from_ip(host_update_data['ipv4_addr'])
        if not host:
            raise Http404("Host not found")

        # check if user is admin of this host
        if hostadmin.username not in host.admin_ids:
            raise Http404("Host not found")

        # check if this host can be removed at the moment or whether there
        # are processes running for it
        if not available_actions(host).get('can_remove'):
            raise Http409("Removing host currently not available")

        # block
        if host.status == HostStatusContract.ONLINE:
            if not set_host_offline(str(host.ipv4_addr)):
                raise Http500("Host could not be set offline")

        # set all DETERRERS fields to blank
        host.status = HostStatusContract.UNREGISTERED
        host.service_profile = HostServiceContract.EMPTY
        host.fw = HostFWContract.EMPTY
        host.host_based_policies = []
        ipam.update_host_info(host)

        # remove all admin tags
        for admin_tag_name in host.admin_ids:
            ipam.remove_admin_from_host(admin_tag_name, host)
        # check that no admins are left for this host
        if len(host.entity_id) > 0:
            logger.error(
                "Couldn't remove all tags from host '%s'",
                str(host.ipv4_addr)
            )
            raise Http500("Not all admins could be removed from host")

    return Response()


def __update_host_logic(ipam: ProteusIPAMWrapper,
                        host: MyHost,
                        host_update_data: dict):
    """
    Utility function that does the actual update logic.

    Args:
        ipam (ProteusIPAMInterface): Instantiated IPAMInterface object
        for communication.
        host (MyHost): Host to update.
        host_update_data (dict): Dict holding the update data.
    """
    # check if this host can be changed at the moment or whether there are
    # already processes running for it
    if not available_actions(host).get('can_update'):
        raise Http400("Updating host currently not available")

    # update the actual host instance
    service_profile_change = (
        host.service_profile != host_update_data.get('service_profile',
                                                     host.service_profile)
    )
    if host_update_data.get('service_profile', None):
        host.service_profile = host_update_data['service_profile']
    fw_change = host.fw != host_update_data.get('fw', host.fw)
    if host_update_data.get('fw', None):
        host.fw = host_update_data['fw']
    if not ipam.update_host_info(host):
        raise Http500("Host information could not be updated in IPAM")

    # if nothing changes return immediatly
    if not service_profile_change and not fw_change:
        return
    elif service_profile_change:
        # if host is already online, update the perimeter FW
        if host.status == HostStatusContract.ONLINE:
            if host.service_profile == HostServiceContract.EMPTY:
                if not set_host_offline(str(host.ipv4_addr)):
                    raise Http500("Could not set host offline")
            else:
                if not set_host_online(str(host.ipv4_addr)):
                    raise Http500("Could not set new service profile for host")

        # auto-add some host-based policies
        match host.service_profile:
            case HostServiceContract.EMPTY:
                pass
            case (HostServiceContract.SSH
                  | HostServiceContract.HTTP
                  | HostServiceContract.HTTP_SSH) as s_p:
                # allow SSH standard port 22 over TCP if a service profile
                # is specified
                host.add_host_based_policy(
                    HostBasedPolicySrcContract.ANY.value, ['22'],
                    HostBasedPolicyProtocolContract.TCP.value
                )
                match s_p:
                    case HostServiceContract.SSH:
                        # since SSH rules have already been added do
                        # nothing else
                        pass
                    case (HostServiceContract.HTTP
                          | HostServiceContract.HTTP_SSH):
                        # allow HTTP and HTTPS standard ports 80 and 443
                        # over TCP
                        host.add_host_based_policy(
                            HostBasedPolicySrcContract.ANY.value,
                            ['80'],
                            HostBasedPolicyProtocolContract.TCP.value
                        )
                        host.add_host_based_policy(
                            HostBasedPolicySrcContract.ANY.value,
                            ['443'],
                            HostBasedPolicyProtocolContract.TCP.value
                        )
            case HostServiceContract.MULTIPURPOSE:
                # allow nothing else; users are expected to configure their
                # own rules
                pass
            case _:
                logger.error("Service profile '%s' is not supported.",
                             host.service_profile)
        if not ipam.update_host_info(host):
            raise Http500("Host information could not be updated in IPAM")


def __update_host(request) -> Response:
    """
    Modify details of a host. List of admins can also be modified

    Args:
        request (_type_): Request object which holds new data.

    Returns:
        Response: Returns Response object.
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            raise Http500("No connection to IPAM")

        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404(f"{hostadmin.username} is not admin")
        # get host by deserializing and then querying IPAM
        host_serializer = MyHostSerializer(data=request.data)
        if not host_serializer.is_valid():
            raise Http400("Provided data is invalid")
        host_update_data = host_serializer.validated_data
        ipv4_addr = host_update_data['ipv4_addr']
        host = ipam.get_host_info_from_ip(ipv4_addr)
        if not host:
            raise Http404("Host not found")
        if not host.is_valid():
            raise Http409("Host not valid")

        # check if user is admin of this host
        if hostadmin.username not in host.admin_ids:
            raise Http404("Host not found")

        # Update list of admins if requested
        new_admins = host_update_data.get('admin_ids')
        if new_admins is not None:
            new_admins = set(new_admins)
            if not new_admins:
                raise Http400("Cannot remove all admins")
            admins_to_delete = set(host.admin_ids) - new_admins
            admins_to_add = new_admins - set(host.admin_ids)

            # add new admins
            for admin_tag_name in admins_to_add:
                if (
                    admin_tag_name in ipam.get_department_names()
                    or ipam.is_admin(admin_tag_name)
                ):
                    code = ipam.add_admin_to_host(admin_tag_name, host)
                    if code not in range(200,  205, 1):
                        return Response(status=code)

            # remove old admins
            for admin_tag_name in admins_to_delete:
                ipam.remove_admin_from_host(admin_tag_name, host)

        # Update host properties
        __update_host_logic(ipam, host, host_update_data)

    return Response()


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def hosts(request):
    """
    API method for interaction with multiple hosts.
    Supports GET.

    Args:
        request (_type_): Request object.

    Returns:
        Response: Response object.
    """
    logger.info("API Request: Get all hosts for user %s",
                request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return Response(status=500)

        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            return Response(status=404)
        # get hosts
        hosts_list = ipam.get_hosts_of_admin(hostadmin.username)
        hosts_list = sorted(hosts_list)
    data = []
    for host in hosts_list:
        host_serializer = MyHostSerializer(host)
        data.append(host_serializer.data)
    return Response(data=data)


@api_view(['GET', 'POST', 'PATCH', 'DELETE'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def host(request):
    """
    API method for interaction with a host.
    Supports GET, POST, PATCH, DELETE.

    Args:
        request (_type_): Request object.

    Returns:
        Response: Response object.
    """
    try:
        match request.method:
            case 'GET':
                logger.info("API Request: Get host for user %s",
                            request.user.username)
                return __get_host(request)
            case 'POST':
                logger.info("API Request: Add host for user %s",
                            request.user.username)
                return __add_host(request)
            case 'PATCH':
                logger.info("API Request: Update host for user %s",
                            request.user.username)
                return __update_host(request)
            case 'DELETE':
                logger.info("API Request: Remove host for user %s",
                            request.user.username)
                return __remove_host(request)
            case _:
                logger.error('Unsupported host action!')
                return Response(status=405)
    except Http400:
        return Response(status=400)
    except Http404:
        return Response(status=404)
    except Http409:
        return Response(status=409)
    except Http500:
        return Response(status=500)


def register_bulk(hostadmin: MyUser, ipv4_addrs: set[str]):
    """
    Perform bulk registration by creating a registration scan and updating
    the status for each IP.
    If registration can not be started for some IP, it is skipped.

    Args:
        hostadmin (MyUser): User that performs the bulk request.
        ipv4_addrs (set[str]): Set of unique IPv4 addresses.
    """
    ipv4_addrs = set(ipv4_addrs)
    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            raise Http500()
        with GmpScannerWrapper(
            settings.V_SCANNER_USERNAME,
            settings.V_SCANNER_SECRET_KEY,
            settings.V_SCANNER_URL
        ) as scanner:
            if not scanner.enter_ok:
                raise Http500()

            # check if user has IPAM permission or an admin tag for them exists
            if not ipam.is_admin(hostadmin.username):
                raise Http404()

            # check if all requested hosts are permitted for this hostadmin
            hosts = []
            for ip in ipv4_addrs:
                # get host
                host = ipam.get_host_info_from_ip(ip)
                if not host:
                    raise Http404()
                # check if user is admin of this host
                if hostadmin.username not in host.admin_ids:
                    raise Http404()
                # check if action is available for this host
                if not available_actions(host).get('can_register'):
                    raise Http409()
                # check if host is actually valid
                if not host.is_valid():
                    raise Http409()
                hosts.append(host)

            # perform actual registration of hosts
            response_url = (settings.DOMAIN_NAME
                            + reverse('v_scanner_registration_alert'))
            for host in hosts:
                target_uuid, task_uuid, report_uuid, alert_uuid = \
                    scanner.create_registration_scan(str(host.ipv4_addr),
                                                     response_url)
                if target_uuid and task_uuid and report_uuid and alert_uuid:
                    # update state in IPAM
                    host.status = HostStatusContract.UNDER_REVIEW
                    if not ipam.update_host_info(host):
                        scanner.clean_up_scan_objects(target_uuid, task_uuid,
                                                      report_uuid, alert_uuid)
                        logger.error("Couldn't update status of host %s",
                                     str(host.ipv4_addr))
                        continue
                else:
                    logger.error(
                        "Registration for host %s couldn't be started!",
                        str(host.ipv4_addr)
                    )
                    continue


def block_bulk(hostadmin: MyUser, ipv4_addrs: set[str]):
    """
    Blocks a bulk of hosts.

    Args:
        hostadmin (MyUser): Hostadmin that issued bulk-block.
        ipv4_addrs (set[str]): Set of IPv4 addresses of hosts to block.
    """
    ipv4_addrs = set(ipv4_addrs)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            raise Http500

        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404()

        # check if all requested hosts are permitted for this hostadmin
        for ipv4 in ipv4_addrs:
            # get host
            host = ipam.get_host_info_from_ip(ipv4)
            if not host:
                raise Http404()
            # check if user is admin of this host
            if hostadmin.username not in host.admin_ids:
                raise Http404()
            # check if action is available for this host
            if not available_actions(host).get('can_block'):
                raise Http409()
            # check if host is actually valid
            if not host.is_valid():
                raise Http409()

    # set all hosts offline
    set_host_bulk_offline(ipv4_addrs)


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def action(request):
    """
    API method for performing an action on hosts.
    Not really RESTful but necessary.
    Supports POST.

    Args:
        request (_type_): Request object.

    Returns:
        Response: Response object.
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    bulk_action = HostActionSerializer(data=request.data)
    if not bulk_action.is_valid():
        return Response(status=400)
    action = bulk_action.validated_data['action']
    ipv4_addrs = set(bulk_action.validated_data.get('ipv4_addrs', []))
    logger.info("API Request: Action %s by user %s on hosts %s", str(action),
                request.user.username, str(ipv4_addrs))

    try:
        match action:
            case 'register':
                register_bulk(hostadmin=hostadmin, ipv4_addrs=ipv4_addrs)
            case 'block':
                block_bulk(hostadmin=hostadmin, ipv4_addrs=ipv4_addrs)
            case _:
                return Response(status=400)
    except Http404:
        return Response(status=404)
    except Http409:
        return Response(status=409)
    except Http500:
        return Response(status=500)

    return Response()
