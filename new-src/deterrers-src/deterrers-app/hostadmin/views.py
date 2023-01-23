import logging
import uuid
import io
from threading import Thread

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseRedirect, HttpResponse, FileResponse
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
from .core.rule_generator import generate_rule
from .core.host import MyHost, HostStatusContract, HostServiceContract, HostFWContract, CustomRuleSubnetContract

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
                subnet = CustomRuleSubnetContract[form.cleaned_data['subnet']].value
                ports = form.cleaned_data['ports']
                proto = form.cleaned_data['protocol']
                # update the actual model instance
                host.custom_rules.append(
                    {
                        'allow_src' : subnet,
                        'allow_ports' : list(ports),
                        'allow_proto' : proto,
                        'id' : str(uuid.uuid4())
                    }
                )
                
                ret = ipam.update_host_info(host)
                if not ret:
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
                {'allow_src': CustomRuleSubnetContract(rule['allow_src']).display(),
                'allow_ports' : rule['allow_ports'],
                'allow_proto' : rule['allow_proto'],
                'id' : rule['id']}
            for rule in host.custom_rules],
        'form' : form,
    }

    # pass flags for available actions into context
    action_flags = __get_available_actions(host)
    for k, f in action_flags.items():
        context[k] = f

    return render(request, 'host_detail.html', context)

def __get_available_actions(host : MyHost) -> dict:
    """
    Compute which actions can be perfomed on a host.

    Args:
        host (MyHost): Host instance.

    Returns:
        dict: Returns a dictionary of boolean flags indicating available actions.
    """
    flags = {}
    match host.status:
        case HostStatusContract.UNREGISTERED:
            flags['can_update'] = True
            flags['can_register'] = True
            flags['can_scan'] = True
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = False
        case HostStatusContract.UNDER_REVIEW:
            flags['can_update'] = True
            flags['can_register'] = False
            flags['can_scan'] = False
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = False
        case HostStatusContract.BLOCKED:
            flags['can_update'] = True
            flags['can_register'] = True
            flags['can_scan'] = True
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = False
        case HostStatusContract.ONLINE:
            flags['can_update'] = True
            flags['can_register'] = False
            flags['can_scan'] = True
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = True
        case _:
            flags['can_update'] = False
            flags['can_register'] = False
            flags['can_scan'] = False
            flags['can_download_config'] = False
            flags['can_block'] = False
    return flags


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
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip)
        if not host:
            raise Http404()

        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()

        # check if this host can be changed at the moment or whether there are already processes running for it
        if not __get_available_actions(host).get('can_update'):
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


############################################ Host Actions ########################################

@login_required
@require_http_methods(['POST', ])
def register_host(request, ip):
    """
    TODO: docu

    Args:
        request (_type_): _description_
        ip (_type_): _description_

    Raises:
        Http404: _description_
        Http404: _description_
        Http404: _description_

    Returns:
        _type_: _description_
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip)
        if not host:
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()
        # check if this host can be registered
        if not __get_available_actions(host).get('can_register'):
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
    """
    TODO: docu

    Args:
        request (_type_): _description_
        ip (_type_): _description_

    Raises:
        Http404: _description_
        Http404: _description_
        Http404: _description_

    Returns:
        _type_: _description_
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip)
        if not host:
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()
        # check if this host can be scanned at the moment or whether there are already processes running for it
        if not __get_available_actions(host).get('can_scan'):
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


def __block_host(host_ip : str):
    """
    TODO: docu

    Args:
        host_ip (str): _description_
    """
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(host_ip)
        # change the perimeter firewall configuration so that host is blocked
        with PaloAltoInterface(settings.FIREWALL_USERNAME, settings.FIREWALL_SECRET_KEY, settings.FIREWALL_URL) as fw:
            fw.remove_addr_obj_from_addr_grps(host_ip, {AddressGroups.HTTP, AddressGroups.SSH, AddressGroups.OPEN})
        host.status = HostStatusContract.BLOCKED
        if not ipam.update_host_info(host):
            logger.error("__block_host() could not update host status to 'Blocked'!")

@login_required
@require_http_methods(['POST', ])
def block_host(request, ip : str):
    """
    TODO: docu

    Args:
        request (_type_): _description_
        ip (str): _description_

    Raises:
        Http404: _description_
        Http404: _description_
        Http404: _description_

    Returns:
        _type_: _description_
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip)
    if not host:
        raise Http404()
    # check if user is admin of this host
    if not hostadmin.username in host.admin_ids:
        raise Http404()
    # check if this host can be blocked at the moment or whether there are already processes running for it
    if not __get_available_actions(host).get('can_block'):
        raise Http404()

    __block_host(ip)

    # redirect to a new URL:
    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))


@login_required
@require_http_methods(['POST',])
def delete_host_rule(request, ip : str, rule_id : uuid.UUID):
    """
    TODO: docu

    Args:
        request (_type_): _description_
        ip (str): _description_
        rule_id (uuid.UUID): _description_

    Raises:
        Http404: _description_
        Http404: _description_

    Returns:
        _type_: _description_
    """
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
def get_fw_config(request, ip : str):
    """
    TODO: docu

    Args:
        request (_type_): _description_
        ip (str): _description_

    Raises:
        Http404: _description_
        Http404: _description_

    Returns:
        _type_: _description_
    """
    logger.info(f"Generate fw config script for host {ip}")
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip) # TODO: could be changed to get_host_info_from_id() for better performance
        # check if host is valid
        if not host or not host.is_valid():
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()

    script = generate_rule(host.fw, host.service_profile, host.custom_rules)
    if script:
        f_temp = io.BytesIO(bytes(script, 'utf-8'))
        f_response = FileResponse(f_temp, as_attachment=True, filename='fw_config.sh')
        # f_temp.close() # not closing io.BytesIO is probably fine because it is only an objet in RAM and will be released by GC
        return f_response
    
    return Http404()


############################## Vulnerability Scanner alerts ######################################

@require_http_methods(['GET', ])
def v_scanner_registration_alert(request):
    logger.info("Received notification from Greenbone Securtiy Manager that a registration completed.")

    def proc_registration_alert(request):
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
                    logger.info("Host %s passed the registration scan and will be set online!", host_ip)
                    own_url = request.get_host() + reverse('v_scanner_periodic_alert')
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
                            logger.error("v_scanner_registration_alert() could not update host status to 'Online'!")
                else:
                    logger.info("Host %s did not pass the registration and will be blocked.", host_ip)
                    __block_host(host_ip)

                scanner.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
        except Exception as err:
            logger.error(str(err))

    t = Thread(target=proc_registration_alert, args=[request], daemon=True)
    t.start()

    return HttpResponse("Success!", status=200)

@require_http_methods(['GET', ])
def v_scanner_scan_alert(request):
    # TODO
    logger.warn("Not implemented yet!")

@require_http_methods(['GET',])
def v_scanner_periodic_alert(request):
    # TODO
    logger.warn("Not implemented yet!")