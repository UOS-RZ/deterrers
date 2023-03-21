import logging

from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from django.conf import settings
from django.shortcuts import get_object_or_404
from django.http import Http404
from django.urls import reverse

from myuser.models import MyUser
from hostadmin.util import available_actions, set_host_offline
from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.v_scanner_interface import GmpVScannerInterface
from hostadmin.core.contracts import HostStatusContract
from .serializers import MyHostSerializer, HostActionSerializer

logger = logging.getLogger(__name__)



def __add_host(request):
    logger.info('Not implemented yet!')
    return Response()

def __get_host(request):
    logger.info('Not implemented yet.')
    return Response()

def __update_host(request):
    logger.info('Not implemented yet.')
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
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        user_exists = ipam.user_exists(hostadmin.username)
        admin_tag_exists = ipam.admin_tag_exists(hostadmin.username)
        if not user_exists or not admin_tag_exists:
            return Response(status=404)
        # get hosts
        hosts_list = ipam.get_hosts_of_admin(hostadmin.username)
        hosts_list = sorted(hosts_list)
    data = []
    for host in hosts_list:
        host_serializer = MyHostSerializer(host)
        data.append(host_serializer.data)
    return Response(data=data)


@api_view(['GET', 'POST', 'PATCH'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def host(request):
    """
    API method for interaction with a host.
    Supports GET, POST, PATCH.

    Args:
        request (_type_): Request object.

    Returns:
        Response: Response object.
    """
    match request.method:
        case 'GET':
            return __get_host(request)
        case 'POST':
            return __add_host(request)
        case 'PATCH':
            return __update_host(request)
        case _:
            logger.error('Unsupported host action!')
            return Response(status=405)

def register_bulk(hostadmin : MyUser, ipv4_addrs : set[str]):
    """
    Perform bulk registration by creating a registration scan and updating the status for each IP.
    If registration can not be started for some IP, it is skipped.

    Args:
        hostadmin (MyUser): User that performs the bulk request.
        ipv4_addrs (set[str]): Set of unique IPv4 addresses.
    """
    ipv4_addrs = set(ipv4_addrs)
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        user_exists = ipam.user_exists(hostadmin.username)
        admin_tag_exists = ipam.admin_tag_exists(hostadmin.username)
        if not user_exists and not admin_tag_exists:
            raise Http404()
        
        # check if all requested hosts are permitted for this hostadmin
        for ip in ipv4_addrs:
            # get host
            host = ipam.get_host_info_from_ip(ip)
            if not host:
                raise Http404()
            # check if user is admin of this host
            if not hostadmin.username in host.admin_ids:
                raise Http404()
            # check if action is available for this host
            if not available_actions(host).get('can_register'):
                raise Http404()
            # check if host is actually valid
            if not host.is_valid():
                raise Http404()
            
        # perform actual registration of hosts
        with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
            response_url = settings.DOMAIN_NAME + reverse('v_scanner_registration_alert')
            for ip in ipv4_addrs:
                target_uuid, task_uuid, report_uuid, alert_uuid = scanner.create_registration_scan(ip, response_url)
                if target_uuid and task_uuid and report_uuid and alert_uuid:
                    # update state in IPAM
                    host.status = HostStatusContract.UNDER_REVIEW
                    if not ipam.update_host_info(host):
                        scanner.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
                        logger.error("Couldn't update status of host %s", ip)
                        continue
                else:
                    logger.error("Registration for host %s couldn't be started!", ip)
                    continue

def block_bulk(hostadmin : MyUser, ipv4_addrs : set[str]):
    ipv4_addrs = set(ipv4_addrs)
    
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.user_exists(hostadmin.username) and not ipam.admin_tag_exists(hostadmin.username):
            raise Http404()
        
        # check if all requested hosts are permitted for this hostadmin
        for ipv4 in ipv4_addrs:
            # get host
            host = ipam.get_host_info_from_ip(ipv4)
            if not host:
                raise Http404()
            # check if user is admin of this host
            if not hostadmin.username in host.admin_ids:
                raise Http404()
            # check if action is available for this host
            if not available_actions(host).get('can_block'):
                raise Http404()
            # check if host is actually valid
            if not host.is_valid():
                raise Http404()

    # set all hosts offline
    for ipv4 in ipv4_addrs:
        if not set_host_offline(ipv4):
            logger.error("Couldn't block host: %s", ipv4)
            continue

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def action(request):
    """
    API method for performing an action on hosts. Not really RESTful but necessary.
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

    try:
        match  action:
            case 'register':
                register_bulk(hostadmin=hostadmin, ipv4_addrs=ipv4_addrs)
            case 'block':
                block_bulk(hostadmin=hostadmin, ipv4_addrs=ipv4_addrs)
            case _:
                return Response(status=400)
    except Http404:
        return Response(status=404)
    
        
    return Response()


