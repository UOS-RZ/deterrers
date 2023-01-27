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
from django.core.mail import EmailMultiAlternatives

from .forms import ChangeHostDetailForm, AddHostRulesForm
from .core.ipam_api_interface import ProteusIPAMInterface
from .core.v_scanner_interface import GmpVScannerInterface
from .core.fw_interface import PaloAltoInterface, AddressGroup
from .core.risk_assessor import compute_risk_of_network_exposure
from .core.rule_generator import generate_rule
from .core.host import MyHost, HostStatusContract, HostServiceContract, HostFWContract, CustomRuleSubnetContract

from myuser.models import MyUser

logger = logging.getLogger(__name__)




def __block_host(host_ip : str) -> bool:
    """
    TODO: docu

    Args:
        host_ip (str): _description_
    """
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(host_ip)
        # change the perimeter firewall configuration so that host is blocked
        with PaloAltoInterface(settings.FIREWALL_USERNAME, settings.FIREWALL_SECRET_KEY, settings.FIREWALL_URL) as fw:
            if not fw.remove_addr_obj_from_addr_grps(host_ip, {AddressGroup.HTTP, AddressGroup.SSH, AddressGroup.OPEN}):
                return False
        host.status = HostStatusContract.BLOCKED
        if not ipam.update_host_info(host):
            return False
    
    # TODO: remove from periodic scan
        
    return True


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

def __send_report_email(report_html : bytes, subject : str, str_body : str, to : list):
    # TODO: docu
    email = EmailMultiAlternatives(
                subject=subject,
                body=str_body,
                to=to,
            )
    email.attach_alternative(report_html, 'text/html')
    try:
        email.send()
    except Exception:
        logger.exception("Couldn't send e-mail!")


# Create your views here.

@require_http_methods(['GET',])
def about_view(request):
    context = {}
    return render(request, 'about.html', context)


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


@login_required
@require_http_methods(['GET',])
def hosts_list_view(request):
    """
    Function view for showing all hosts that are administrated by the current hostadmin.
    Paginated to 20 entries per page.

    Args:
        request (_type_): Request object.

    Returns:
        HttpResponse: Rendered HTML page.
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
def update_host_detail(request, ip : str):
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
    Processes requests for performing a registration on a host.

    Args:
        request (_type_): Request object.
        ip (str): IP address of the host.

    Raises:
        Http404: Raised if host or hostadmin do not exist or if some permission is denied.

    Returns:
        HttpResponseRedirect: Redirect to the detail page of the host.
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
        if not host.is_valid():
            messages.error(request, "Host is not valid!")
        else:
            # create an initial scan of the host
            with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
                own_url = request.get_host() + reverse('v_scanner_registration_alert')
                target_uuid, task_uuid, report_uuid, alert_uuid = scanner.create_registration_scan(ip, own_url)
                if target_uuid and task_uuid and report_uuid and alert_uuid:
                    # update state in IPAM
                    host.status = HostStatusContract.UNDER_REVIEW
                    if not ipam.update_host_info(host):
                        scanner.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
                        messages.error(request, "Registration was aborted due to unknown reasons. Try again later...")
                else:
                    messages.error(request, "Not possible to start registration at the moment! Try again later...")

    # redirect to a new URL:
    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))


@login_required
@require_http_methods(['POST', ])
def scan_host(request, ip : str):
    """
    Processes requests for performing an ordinary scan on a host.

    Args:
        request (_type_): Request object.
        ip (str): IP address of the host.

    Raises:
        Http404: Raised if host or hostadmin do not exist or if some permission is denied.

    Returns:
        HttpResponseRedirect: Redirect to the detail page of the host.
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
        if not host.is_valid():
            messages.error(request, "Host is not valid!")
        else:
            # create an initial scan of the host
            with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
                own_url = request.get_host() + reverse('v_scanner_scan_alert')
                target_uuid, task_uuid, report_uuid, alert_uuid = scanner.create_scan(ip, own_url)
                if target_uuid and task_uuid and report_uuid and alert_uuid:
                    # update state in IPAM
                    host.status = HostStatusContract.UNDER_REVIEW
                    if not ipam.update_host_info(host):
                        scanner.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
                        messages.error(request, "Scan was aborted due to unknown reasons. Try again later...")
                else:
                    messages.error(request, "Not possible to start scan at the moment! Try again later...")

    # redirect to a new URL:
    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))

@login_required
@require_http_methods(['POST', ])
def block_host(request, ip : str):
    """
    Processes requests for blocking a certain host.

    Args:
        request (_type_): Request object.
        ip (str): IP address of the host.

    Raises:
        Http404: Raised if host or hostadmin do not exist or if some permission is denied.

    Returns:
        HttpResponseRedirect: Redirect to the detail page of the host.
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

    if not __block_host(ip):
        messages.error(request, "Couldn't block host!")

    # redirect to a new URL:
    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))


@login_required
@require_http_methods(['POST',])
def delete_host_rule(request, ip : str, rule_id : uuid.UUID):
    """
    Processes requests for deleting a custom firewall rule.

    Args:
        request (_type_): Request object.
        ip (str): IP address of the host.
        rule_id (uuid.UUID): UUID of the rule that is to be deleted.

    Raises:
        Http404: Raised if host or hostadmin do not exist or if some permission is denied.

    Returns:
        HttpResponseRedirect: Redirect to the detail page of the host.
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip) # TODO: could be changed to get_host_info_from_id() for better performance
        # check if host is valid
        if not host:
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()

        # delete rule from host
        for rule in host.custom_rules:
            if uuid.UUID(rule['id']) == rule_id:
                host.custom_rules.remove(rule)
                break
        if not ipam.update_host_info(host):
            messages.error(request, "Host could not be updated! Try again later...")

    return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))


@login_required
@require_http_methods(['GET',])
def get_fw_config(request, ip : str):
    """
    Processes requests of configuration scripts for host-based firewalls.

    Args:
        request (_type_): Request objects.
        ip (str): IP address of a host.

    Raises:
        Http404: Raised if host or hostadmin do not exist or if some permission is denied.

    Returns:
        FileResponse: Returns the firewall configuration script for the queried host as file.
    """
    logger.info("Generate fw config script for host %s", ip)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(ip) # TODO: could be changed to get_host_info_from_id() for better performance
        # check if host is valid
        if not host:
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()
        if not host.is_valid():
            messages.error(request, "Host is not valid!")
            return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))


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
    """
    Processes the alert send by the v-scanner when a registration scan has completed.
    The scan report will be assessed and an HTML report will be send to the admin.
    In case the risk assessment finds no high risks, the host is added to the target list of
    the periodic scan in the v-scanner and it is set online in the perimeter firewall.
    Otherwise, the host will be blocked (even though it probably is already in blocked state).

    Args:
        request (_type_): Request object.

    Returns:
        HTTPResponse: Always returns response with status 200 because processing of the alert
            happens independently in daemon thread.
    """
    logger.info("Received notification from v-scanner that a registration completed.")

    def proc_registration_alert(request):
        """
        Inner function for processing the registration alert in a daemon thread.

        Args:
            request (_type_): Request object.
        """
        try:
            host_ip = request.GET['host_ip']
            report_uuid = request.GET['report_uuid']
            task_uuid = request.GET['task_uuid']
            target_uuid = request.GET['target_uuid']
            alert_uuid = request.GET['alert_uuid']
            with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
                report_xml = scanner.get_report_xml(report_uuid)
                scan_start, results = scanner.extract_report_data(report_xml)
                if results is None:
                    return

                # get HTML report and send via e-mail to admin
                report_html = scanner.get_report_html(report_uuid)
                __send_report_email(
                    report_html,
                    "DETERRERS - Vulnerability Scanner report",
                    "String body in case e-mail server does not support HTML", # TODO
                    ["nwintering@uos.de"], # TODO
                )

                # TODO: Risk assessment
                risk = compute_risk_of_network_exposure(results)
                passed_scan = True

                if passed_scan:
                    logger.info("Host %s passed the registration scan and will be set online!", host_ip)
                    own_url = request.get_host() + reverse('v_scanner_periodic_alert')
                    if not scanner.add_host_to_periodic_scan(host_ip=host_ip, deterrers_url=own_url):
                        raise RuntimeError(f"Couldn't add host {host_ip} to periodic scan!")
                    # get the service profile of this host
                    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
                        host = ipam.get_host_info_from_ip(host_ip)
                        # change the perimeter firewall configuration so that only hosts service profile is allowed
                        with PaloAltoInterface(settings.FIREWALL_USERNAME, settings.FIREWALL_SECRET_KEY, settings.FIREWALL_URL) as fw:
                            match host.service_profile:
                                case HostServiceContract.HTTP:
                                    suc = fw.add_addr_obj_to_addr_grps(host_ip, {AddressGroup.HTTP,})
                                case HostServiceContract.SSH:
                                    suc = fw.add_addr_obj_to_addr_grps(host_ip, {AddressGroup.SSH,})
                                case HostServiceContract.MULTIPURPOSE:
                                    suc = fw.add_addr_obj_to_addr_grps(host_ip, {AddressGroup.OPEN,})
                                case _:
                                    raise RuntimeError(f"Unknown service profile: {host.service_profile}")
                            if not suc:
                                raise RuntimeError(f"Couldn't update firewall configuration!")
                        host.status = HostStatusContract.ONLINE
                        if not ipam.update_host_info(host):
                            raise RuntimeError("Couldn't update host information!")
                else:
                    logger.info("Host %s did not pass the registration and will be blocked.", host_ip)
                    if not __block_host(host_ip):
                        raise RuntimeError("Couldn't block host")

                scanner.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
        except Exception:
            logger.exception("Processing registration alert failed!")

    # run as daemon because v_scanner needs a response before scan objects can be cleaned up
    t = Thread(target=proc_registration_alert, args=[request], daemon=True)
    t.start()

    return HttpResponse("Success!", status=200)

@require_http_methods(['GET', ])
def v_scanner_scan_alert(request):
    """
    Processes the alert send by the v-scanner when an ordinary scan has completed.
    The scan report will be assessed and an HTML report will be send to the admin.

    Args:
        request (_type_): Request object.

    Returns:
        HTTPResponse: Always returns response with status 200 because processing of the alert
            happens independently in daemon thread.
    """
    logger.info("Received notification from v-scanner that an ordinary scan completed.")

    def proc_scan_alert(request):
        """
        Inner function for processing the scan alert in a daemon thread.

        Args:
            request (_type_): Request object.
        """
        try:
            host_ip = request.GET['host_ip']
            report_uuid = request.GET['report_uuid']
            task_uuid = request.GET['task_uuid']
            target_uuid = request.GET['target_uuid']
            alert_uuid = request.GET['alert_uuid']
            with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
                report_xml = scanner.get_report_xml(report_uuid)
                scan_start, results = scanner.extract_report_data(report_xml)
                if results is None:
                    return

                # get HTML report and send via e-mail to admin
                report_html = scanner.get_report_html(report_uuid)
                __send_report_email(
                    report_html,
                    "DETERRERS - Vulnerability Scanner report",
                    "String body in case e-mail server does not support HTML", # TODO
                    ["nwintering@uos.de"], # TODO
                )

                # TODO: Risk assessment
                risk = compute_risk_of_network_exposure(results)
                passed_scan = True

                if passed_scan:
                    logger.info("Host %s passed the scan!", host_ip)
                else:
                    logger.info("Host %s did not pass the scan.", host_ip)

                # reset hosts status
                with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
                    host = ipam.get_host_info_from_ip(host_ip)
                    with PaloAltoInterface(settings.FIREWALL_USERNAME, settings.FIREWALL_SECRET_KEY, settings.FIREWALL_URL) as fw:
                        host.status = fw.get_host_status(host.ip_addr)
                    if not ipam.update_host_info(host):
                        raise RuntimeError("Couldn't update host information!")

                scanner.clean_up_scan_objects(target_uuid, task_uuid, report_uuid, alert_uuid)
                
        except Exception:
            logger.exception("Processing scan alert failed!")

    # run as daemon because v_scanner needs a response before scan objects can be cleaned up
    t = Thread(target=proc_scan_alert, args=[request], daemon=True)
    t.start()

    return HttpResponse("Success!", status=200)

@require_http_methods(['GET',])
def v_scanner_periodic_alert(request):
    # TODO
    logger.warn("Not implemented yet!")
    raise Http404()