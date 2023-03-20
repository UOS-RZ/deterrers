import logging

from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

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
    logger.info('Not implemented yet.')
    return Response()

@api_view(['GET', 'POST', 'PATCH'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def host(request):
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
    logger.info('Not implemented yet.')
    return Response()


