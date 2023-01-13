import logging
import uuid

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseRedirect, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.conf import settings
from django.contrib import messages

from .forms import ChangeHostDetailForm, AddHostRulesForm
from .core.ipam_api_interface import ProteusIPAMInterface
from .core.v_scanner_interface import GmpVScannerInterface
from .core.fw_interface import PaloAltoInterface, AddressGroups
from .core.risk_assessor import compute_risk_of_network_exposure
from .core.host import HostStatusContract, HostServiceContract, HostFWContract, IntraSubnetContract

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
@require_http_methods(['GET', 'POST'])
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

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip) # TODO: could be changed to get_host_info_from_id() for better performance
        # check if host is valid
        if not host or not host.is_valid():
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()

        # parse form data and update host on POST
        if request.method == 'POST':
            form = AddHostRulesForm(request.POST)
            if form.is_valid():
                subnets = [IntraSubnetContract[subnet_enum_name].value for subnet_enum_name in form.cleaned_data['subnets']]
                ports = form.cleaned_data['ports']
                # update the actual model instance
                host.custom_rules.append(
                    {
                        'allow_srcs' : subnets,
                        'allow_ports' : list(ports),
                        'id' : str(uuid.uuid4())
                    }
                )
                
                ret = ipam.update_host_info(host)
                if not ret:
                    # TODO: make visible (not shown at the moment)
                    form.add_error(None, "Host rules could not be updated! Try again later...")
                else:
                    form = AddHostRulesForm()
        else:
            # create new empty form
            form = AddHostRulesForm()

    context = {
        'hostadmin' : hostadmin,
        'host_detail' : host,
        'host_rules' : [
                {'allow_srcs': [IntraSubnetContract(s_v).display() for s_v in rule['allow_srcs']],
                'allow_ports' : rule['allow_ports'],
                'id' : rule['id']}
            for rule in host.custom_rules],
    }

    # create new empty form
    form = AddHostRulesForm()

    context['form'] = form
    # pass flags for available actions into context
    match host.status:
        case HostStatusContract.UNREGISTERED:
            context['can_update'] = True
            if host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY:
                context['can_register'] = True
                context['can_scan'] = True
            else:
                context['can_register'] = False
                context['can_scan'] = False
        case HostStatusContract.UNDER_REVIEW:
            context['can_update'] = False
            context['can_register'] = False
            context['can_scan'] = False
        case HostStatusContract.BLOCKED:
            context['can_update'] = True
            context['can_register'] = False
            if host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY:
                context['can_scan'] = True
            else:
                context['can_scan'] = False
        case HostStatusContract.ONLINE:
            context['can_update'] = True
            context['can_register'] = False
            if host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY:
                context['can_scan'] = True
            else:
                context['can_scan'] = False
        case _:
            context['can_update'] = False
            context['can_register'] = False
            context['can_scan'] = False

    return render(request, 'host_detail.html', context)

@login_required
@require_http_methods(['POST',])
def delete_host_rule(request, ip : str, rule_id : uuid.UUID):
    ip = ip.replace('_', '.')

    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip) # TODO: could be changed to get_host_info_from_id() for better performance
        # check if host is valid
        if not host or not host.is_valid():
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()

        # delete rule from host
        for rule in host.custom_rules:
            if uuid.UUID(rule['id']) == rule_id:
                host.custom_rules.remove(rule)
                break
        ret = ipam.update_host_info(host)
        if not ret:
            logger.error("Host could not be updated! Try again later...")

    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))
    


@login_required
@require_http_methods(['GET',])
def hosts_list_view(request):
    """
    Function view for showing all hosts that are administrated by the current hostadmin.
    Paginated to 20 entries per page.
    """
    PAGINATE = 20
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
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

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip)
        if not host:
            raise Http404()

        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()

        # check if this host can be changed at the moment or whether there are already processes running for it
        if host.status not in (HostStatusContract.UNREGISTERED, HostStatusContract.BLOCKED, HostStatusContract.ONLINE):
            raise Http404()

        # do processing based on whether this is GET or POST request
        if request.method == 'POST':
            form = ChangeHostDetailForm(request.POST)

            if form.is_valid():
                # update the actual model instance
                host.service_profile = HostServiceContract(form.cleaned_data['service_profile'])
                host.fw = HostFWContract(form.cleaned_data['fw'])
                
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
                    'service_profile' : host.service_profile.value,
                    'fw' : host.fw.value
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
    
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip)
        if not host:
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()
        # check if this host can be registered
        if host.status != HostStatusContract.UNREGISTERED:
            raise Http404()

        # create an initial scan of the host
        with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
            own_url = request.get_host() + reverse('v_scanner_registration_alert')
            target_uuid, task_uuid, report_uuid, alert_uuid = scanner.create_registration_scan(ip, own_url)
            if target_uuid and task_uuid and report_uuid and alert_uuid:
                # update state in IPAM
                host.status = HostStatusContract.UNDER_REVIEW
                if not ipam.update_host_info(host):
                    scanner.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
                    messages.error(request, "Registration was aborted due to unknown reasons. Please notify the DETERRERS admin.")
                    logger.error("register_host() could not update the state of host %s", host.ip_addr)

    # redirect to a new URL:
    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))


@login_required
@require_http_methods(['POST', ])
def scan_host(request, ip):
    ip = ip.replace('_', '.')
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip)
        if not host:
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()
        # check if this host can be scanned at the moment or whether there are already processes running for it
        if host.status not in (HostStatusContract.UNREGISTERED, HostStatusContract.BLOCKED, HostStatusContract.ONLINE):
            raise Http404()

        # create an initial scan of the host
        with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
            own_url = request.get_host() + reverse('v_scanner_scan_alert')
            target_uuid, task_uuid, report_uuid, alert_uuid = scanner.create_scan(ip, own_url)
            if target_uuid and task_uuid and report_uuid and alert_uuid:
                # update state in IPAM
                host.status = HostStatusContract.UNDER_REVIEW
                if not ipam.update_host_info(host):
                    scanner.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
                    messages.error(request, "Scan was aborted due to unknown reasons. Please notify the DETERRERS admin.")
                    logger.error("scan_host() could not update the state of host %s", host.ip_addr)

    # redirect to a new URL:
    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))


@require_http_methods(['GET', ])
def v_scanner_registration_alert(request):
    logger.info("Received notification from Greenbone Securtiy Manager that a scan completed.")

    try:
        host_ip = request.GET['host_ip']
        report_uuid = request.GET['report_uuid']
        task_uuid = request.GET['task_uuid']
        target_uuid = request.GET['target_uuid']
        alert_uuid = request.GET['alert_uuid']
        with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
            report_xml = scanner.get_report_xml(report_uuid)
            scan_start, results = scanner.extract_report_data(report_xml)

            # TODO: get HTML report and send via e-mail to admin

            # TODO: Risk assessment
            risk = compute_risk_of_network_exposure(results)
            passed_scan = True

            if passed_scan:
                own_url = request.get_host() + reverse('v_scanner_periodic_alert')
                logger.debug("HTTP Alert URL is %s", own_url)
                scanner.add_host_to_periodic_scan(host_ip=host_ip, deterrers_url=own_url)
                # get the service profile of this host
                with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
                    host = ipam.get_host_info_from_ip(host_ip)
                    # change the perimeter firewall configuration so that only hosts service profile is allowed
                    with PaloAltoInterface(settings.FIREWALL_USERNAME, settings.FIREWALL_SECRET_KEY, settings.FIREWALL_URL) as fw:
                        match host.service_profile:
                            case HostServiceContract.HTTP:
                                fw.add_addr_obj_to_addr_grps(host_ip, {AddressGroups.HTTP,})
                            case HostServiceContract.SSH:
                                fw.add_addr_obj_to_addr_grps(host_ip, {AddressGroups.SSH,})
                            case HostServiceContract.MULTIPURPOSE:
                                fw.add_addr_obj_to_addr_grps(host_ip, {AddressGroups.OPEN,})
                            case _:
                                raise RuntimeError(f"Unknown service profile: {host.service_profile}")
                    host.status = HostStatusContract.ONLINE
                    if not ipam.update_host_info(host):
                        logger.error("v_scanner_registration_alert() could not update host status to 'O'!")
            else:
                with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
                    host = ipam.get_host_info_from_ip(host_ip)
                    # change the perimeter firewall configuration so that host is blocked
                    with PaloAltoInterface(settings.FIREWALL_USERNAME, settings.FIREWALL_SECRET_KEY, settings.FIREWALL_URL) as fw:
                        fw.remove_addr_obj_from_addr_grps(host_ip, {AddressGroups.HTTP, AddressGroups.SSH, AddressGroups.OPEN})
                    host.status = HostStatusContract.BLOCKED
                    if not ipam.update_host_info(host):
                        logger.error("v_scanner_registration_alert() could not update host status to 'B'!")

            scanner.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)

    except Exception as err:
        logger.error(repr(err))
        return HttpResponse("Error!", status=500)

    return HttpResponse("Success!", status=200)

@require_http_methods(['GET', ])
def v_scanner_scan_alert(request):
    # TODO
    pass

@require_http_methods(['GET',])
def v_scanner_periodic_alert(request):
    # TODO
    pass
