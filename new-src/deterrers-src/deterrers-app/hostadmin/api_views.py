import logging

from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

from django.conf import settings
from django.shortcuts import get_object_or_404
from django.http import Http404

from .core.ipam_api_interface import ProteusIPAMInterface
from .core.host import MyHostSerializer
from myuser.models import MyUser

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

    Raises:
        Http404: Raised if user does not exist in IPAM and has no admin tag in IPAM-

    Returns:
        Response: Response object.
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        user_exists = ipam.user_exists(hostadmin.username)
        admin_tag_exists = ipam.admin_tag_exists(hostadmin.username)
        if not user_exists or not admin_tag_exists:
            raise Http404()
        # get hosts
        hosts_list = ipam.get_hosts_of_admin(hostadmin.username)
        hosts_list = sorted(hosts_list)
    data = []
    for host in hosts_list:
        host_serializer = MyHostSerializer(data=host)
        if host_serializer.is_valid():
            data.append(host_serializer.validated_data)
        else:
            logger.warning("Validation error: %s", str(host_serializer.errors))
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
    logger.info('Not implemented yet.')
    return Response()


