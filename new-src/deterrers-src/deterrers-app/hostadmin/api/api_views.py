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
from hostadmin.util import available_actions, set_host_bulk_offline, set_host_online
from hostadmin.core.ipam_api_interface import ProteusIPAMInterface
from hostadmin.core.v_scanner_interface import GmpVScannerInterface
from hostadmin.core.contracts import HostStatusContract, HostServiceContract, HostBasedRuleSubnetContract, HostBasedRuleProtocolContract
from .serializers import MyHostSerializer, HostActionSerializer

logger = logging.getLogger(__name__)

class Http409(Exception):
    # Conflict
    pass

def __add_host(request):
    # TODO: implement
    logger.info('Not implemented yet!')
    return Response(status=501)

def __get_host(request):
    # TODO: implement
    logger.info('Not implemented yet.')
    return Response(status=501)

def __update_host(request):
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.user_exists(hostadmin.username) and not ipam.admin_tag_exists(hostadmin.username):
            raise Http404()
        # get host by deserializing and then querying IPAM
        host_serializer = MyHostSerializer(data=request.data)
        if not host_serializer.is_valid():
            return Response(status=400)
        host_update_data = host_serializer.validated_data
        host = ipam.get_host_info_from_ip(host_update_data['ipv4_addr'])
        if not host:
            raise Http404()

        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()

        # check if this host can be changed at the moment or whether there are already processes running for it
        if not available_actions(host).get('can_update'):
            raise Http409()

        # update the actual host instance
        if host_update_data.get('service_profile', None):
            host.service_profile = host_update_data['service_profile']
        if host_update_data.get('fw', None):
            host.fw = host_update_data['fw']

        # if host is already online, update the perimeter FW
        if host.status == HostStatusContract.ONLINE:
            if not set_host_online(str(host.ipv4_addr)):
                return Response(status=500)

        # auto-add some host-based policies
        match host.service_profile:
            case HostServiceContract.EMPTY:
                pass
            case (HostServiceContract.SSH | HostServiceContract.HTTP | HostServiceContract.HTTP_SSH) as s_p:
                # allow SSH standard port 22 over TCP if a service profile is specified
                host.add_host_based_policy(HostBasedRuleSubnetContract.ANY.value, ['22'], HostBasedRuleProtocolContract.TCP.value)
                match s_p:
                    case HostServiceContract.SSH:
                        # since SSH rules have already been added do nothing else
                        pass
                    case (HostServiceContract.HTTP | HostServiceContract.HTTP_SSH):
                        # allow HTTP and HTTPS standard ports 80 and 443 over TCP
                        host.add_host_based_policy(HostBasedRuleSubnetContract.ANY.value, ['80'], HostBasedRuleProtocolContract.TCP.value)
                        host.add_host_based_policy(HostBasedRuleSubnetContract.ANY.value, ['443'], HostBasedRuleProtocolContract.TCP.value)
            case HostServiceContract.MULTIPURPOSE:
                # allow nothing else; users are expected to configure their own rules
                pass
            case _:
                logger.error("Service profile '%s' is not supported.", host.service_profile)
        
        if not ipam.update_host_info(host):
            return Response(status=500)
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
    try:
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
    except Http404:
        return Response(status=404)
    except Http409:
        return Response(status=409)

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
                raise Http409()
            # check if host is actually valid
            if not host.is_valid():
                raise Http409()
            
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
    except Http409:
        return Response(status=409)
    
        
    return Response()


