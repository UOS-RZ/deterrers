import logging

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseRedirect, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.conf import settings

from .forms import ChangeHostDetailForm
from .core.ipam_api_interface import ProteusIPAMInterface
from .core.v_scanner_interface import GmpVScannerInterface

from myuser.models import MyUser

logger = logging.getLogger(__name__)

# Create your views here.

@require_http_methods(['GET',])
def about_view(request):
    context = {}
    return render(request, 'about.html', context)

@login_required
@require_http_methods(['GET',])
def hostadmin_overview_view(request):
    """
    TODO: Implement overview page for host admins to view general information
    """
    hostadmin_inst = get_object_or_404(MyUser, username=request.user.username)
    context = {
        'hostadmin' : hostadmin_inst
    }
    return render(request, 'overview.html', context)

@login_required
@require_http_methods(['GET',])
def host_detail_view(request, ip):
    """
    Function-based view for showing host details. Only available to logged in users.

    Args:
        request (): Request object.
        ip (str): IP string from the URL parameter.

    Raises:
        Http404: When object is not available or user has no permission.

    Returns:
        HTTPResponse: Rendered HTML page.
    """
    ip = ip.replace('_', '.')

    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.PROTEUS_IPAM_USERNAME, settings.PROTEUS_IPAM_SECRET_KEY, settings.PROTEUS_IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip) # TODO: could be changed to get_host_info_from_id() for better performance
    # check if host is valid
    if not host or not host.is_valid():
        raise Http404()
    # check if user is admin of this host

    if not hostadmin.username in host.admin_ids:
        raise Http404()

    context = {
        'hostadmin' : hostadmin,
        'host_detail' : host,
    }

    # pass flags for available actions into context
    match host.status:
        case 'U':
            context['can_update'] = True
            if host.service_profile != '' and host.fw != '':
                context['can_register'] = True
                context['can_scan'] = True
            else:
                context['can_register'] = False
                context['can_scan'] = False
        case 'R':
            context['can_update'] = False
            context['can_register'] = False
            context['can_scan'] = False
        case 'B':
            context['can_update'] = True
            context['can_register'] = False
            if host.service_profile != '' and host.fw != '':
                context['can_scan'] = True
            else:
                context['can_scan'] = False
        case 'O':
            context['can_update'] = True
            context['can_register'] = False
            if host.service_profile != '' and host.fw != '':
                context['can_scan'] = True
            else:
                context['can_scan'] = False
        case _:
            context['can_update'] = False
            context['can_register'] = False
            context['can_scan'] = False

    return render(request, 'host_detail.html', context)


@login_required
@require_http_methods(['GET',])
def hosts_list_view(request):
    """
    Function view for showing all hosts that are administrated by the current hostadmin.
    Paginated to 20 entries per page.
    """
    PAGINATE = 20
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.PROTEUS_IPAM_USERNAME, settings.PROTEUS_IPAM_SECRET_KEY, settings.PROTEUS_IPAM_URL) as ipam:
        hosts_list = ipam.get_hosts_of_admin(hostadmin.username)

    paginator = Paginator(hosts_list, PAGINATE)
    page = request.GET.get('page', 1)

    try:
        hosts_list = paginator.page(page)
    except PageNotAnInteger:
        hosts_list = paginator.page(1)
    except EmptyPage:
        hosts_list = paginator.page(paginator.num_pages)

    context = {
        'hostadmin' : hostadmin,
        'hosts_list' : hosts_list,
        'is_paginated' : True,
        'page_obj' : hosts_list
    }
    return render(request, 'hosts_list.html', context)


@login_required
@require_http_methods(['GET', 'POST'])
def update_host_detail(request, ip):
    """
    View function for processing of the form for updating host information.
    Only available to logged in users.

    Args:
        request (): Request object.
        ip (str): IP string from the URL parameter.

    Raises:
        Http404: When object is not available or user has no permission.

    Returns:
        HTTPResponse: Rendered HTML page.
    """
    ip = ip.replace('_', '.')
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.PROTEUS_IPAM_USERNAME, settings.PROTEUS_IPAM_SECRET_KEY, settings.PROTEUS_IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip)
        if not host:
            raise Http404()

        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()

        # check if this host can be changed at the moment or whether there are already processes running for it
        if host.status not in ('U', 'B', 'O'):
            raise Http404()

        # do processing based on whether this is GET or POST request
        if request.method == 'POST':
            form = ChangeHostDetailForm(request.POST)

            if form.is_valid():
                # update the actual model instance
                # host_inst.name = form.cleaned_data['name']
                host.service_profile = form.cleaned_data['service_profile']
                host.fw = form.cleaned_data['fw']
                
                ret = ipam.update_host_info(host)
                if ret:
                    # TODO: compute new FW rules if data has changed

                    # redirect to a new URL:
                    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))
                
                form.add_error(None, "Host information could not be updated! Try again later...")
        else:
            form = ChangeHostDetailForm(
                initial={
                    'name' : host.name,
                    'service_profile' : host.service_profile,
                    'fw' : host.fw
                }
            )

    context = {
        'form' : form,
        'host_instance' : host
    }
    return render(request, 'update_host_detail.html', context=context)


@login_required
@require_http_methods(['POST', ])
def register_host(request, ip):
    ip = ip.replace('_', '.')
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    
    with ProteusIPAMInterface(settings.PROTEUS_IPAM_USERNAME, settings.PROTEUS_IPAM_SECRET_KEY, settings.PROTEUS_IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip)
        if not host:
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()
        # check if this host can be registered
        if host.status != 'U':
            raise Http404()

        # create an initial scan of the host
        with GmpVScannerInterface(settings.GREENBONE_USERNAME, settings.GREENBONE_SECRET_KEY, settings.GREENBONE_URL) as scanner:
            own_url = request.get_host()
            target_uuid, task_uuid, report_uuid, alert_uuid = scanner.create_registration_scan(ip, own_url)
            if target_uuid and task_uuid and report_uuid and alert_uuid:
                # update state in IPAM
                host.status = 'R'
                if not ipam.update_host_info(host):
                    # TODO: Handle error
                    pass

        # TODO: implement further registration

    # redirect to a new URL:
    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))


@login_required
@require_http_methods(['POST', ])
def scan_host(request, ip):
    ip = ip.replace('_', '.')
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    
    with ProteusIPAMInterface(settings.PROTEUS_IPAM_USERNAME, settings.PROTEUS_IPAM_SECRET_KEY, settings.PROTEUS_IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip)
        if not host:
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()
        # check if this host can be scanned at the moment or whether there are already processes running for it
        if host.status not in ('U', 'B', 'O'):
            raise Http404()

        # create an initial scan of the host
        with GmpVScannerInterface(settings.GREENBONE_USERNAME, settings.GREENBONE_SECRET_KEY, settings.GREENBONE_URL) as scanner:
            own_url = request.get_host()
            target_uuid, task_uuid, report_uuid, alert_uuid = scanner.create_scan(ip, own_url)
            if target_uuid and task_uuid and report_uuid and alert_uuid:
                # update state in IPAM
                host.status = 'R'
                if not ipam.update_host_info(host):
                    # TODO: Handle error
                    pass

    # redirect to a new URL:
    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))


@require_http_methods(['GET', ])
def greenbone_alert(request):
    logger.info("Received notification from Greenbone Securtiy Manager that a scan completed.")

    try:
        report_uuid = request.GET.get('report_uuid')
        task_uuid = request.GET.get('task_uuid')
        target_uuid = request.GET.get('target_uuid')
        alert_uuid = request.GET.get('alert_uuid')
        with GmpVScannerInterface(settings.GREENBONE_USERNAME, settings.GREENBONE_SECRET_KEY, settings.GREENBONE_URL) as scanner:
            report_xml = scanner.get_report_xml(report_uuid)
            scan_start, results = scanner.extract_report_data(report_xml)

            # TODO: Risk assessment

            scanner.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)

    except Exception() as err:
        logger.error(repr(err))
        return HttpResponse("Error!", status=500)

    return HttpResponse("Success!", status=200)
