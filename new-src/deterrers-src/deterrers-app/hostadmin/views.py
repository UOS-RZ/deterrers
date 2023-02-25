import logging
import uuid
import io
from threading import Thread
import os

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseRedirect, HttpResponse, FileResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.conf import settings
from django.contrib import messages
from django.core.mail import EmailMessage

from .forms import ChangeHostDetailForm, AddHostRulesForm, HostadminForm, AddHostForm
from .core.ipam_api_interface import ProteusIPAMInterface
from .core.v_scanner_interface import GmpVScannerInterface
from .core.fw_interface import PaloAltoInterface
from .core.risk_assessor import compute_risk_of_network_exposure
from .core.rule_generator import generate_rule
from .core.host import MyHost
from .core.contracts import HostBasedRuleSubnetContract, HostBasedRuleProtocolContract, HostStatusContract, HostServiceContract, HostFWContract, PaloAltoAddressGroup


from myuser.models import MyUser

logger = logging.getLogger(__name__)




def __add_notifications(request):
    notifications = [
        "New: Internet service profile 'HTTP+SSH' was added for hosts which should provide both HTTP and SSH to the internet.", # TODO: added 2023-02-21
        "New: DNS names are now displayed per host.", # TODO: added 2023-02-21
    ]
    for msg in notifications:
        messages.info(request, msg)


def __block_host(host_ip : str) -> bool:
    """
    Block a host at the perimeter firewall and update the status in the IPAM.
    Removes host also from periodic scan.

    Args:
        host_ip (str): IP address of the host.

    Returns:
        bool: Returns True on success and False if something went wrong.
    """
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        host = ipam.get_host_info_from_ip(host_ip)
        # change the perimeter firewall configuration so that host is blocked
        with PaloAltoInterface(settings.FIREWALL_USERNAME, settings.FIREWALL_SECRET_KEY, settings.FIREWALL_URL) as fw:
            if not fw.remove_addr_obj_from_addr_grps(host_ip, {ag for ag in PaloAltoAddressGroup}):
                return False
        host.status = HostStatusContract.BLOCKED
        if not ipam.update_host_info(host):
            return False
    
    # remove from periodic scan
    with GmpVScannerInterface(settings.V_SCANNER_USERNAME, settings.V_SCANNER_SECRET_KEY, settings.V_SCANNER_URL) as scanner:
        if not scanner.remove_host_from_periodic_scan(host_ip):
            return False
        
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
            flags['can_register'] = host.service_profile != HostServiceContract.EMPTY
            flags['can_scan'] = True
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = False
        case HostStatusContract.UNDER_REVIEW:
            flags['can_update'] = False
            flags['can_register'] = False
            flags['can_scan'] = False
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = False
        case HostStatusContract.BLOCKED:
            flags['can_update'] = True
            flags['can_register'] = host.service_profile != HostServiceContract.EMPTY
            flags['can_scan'] = True
            flags['can_download_config'] = host.service_profile != HostServiceContract.EMPTY and host.fw != HostFWContract.EMPTY
            flags['can_block'] = False
        case HostStatusContract.ONLINE:
            flags['can_update'] = False
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

def __send_report_email(report_html : str, subject : str, str_body : str, to : list):
    """
    Utility method for sending e-mail.

    Args:
        report_html (str): HTML string that is attached to email.
        subject (str): Subject of email.
        str_body (str): String content of the email.
        to (list): List of addresses to send email to.
    """
    email = EmailMessage(
        subject,
        str_body,
        None,
        to
    )
    email.attach("report.html", report_html, "text/html")
    try:
        email.send()
    except Exception:
        logger.exception("Couldn't send e-mail!")


# Create your views here.

@require_http_methods(['GET',])
def about_view(request):
    context = {}
    __add_notifications(request)
    return render(request, 'about.html', context)


@login_required
@require_http_methods(['GET', 'POST'])
def host_detail_view(request, ip : str):
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
    logger.info("Request: Get details for host %s for user %s", ip, request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.user_exists(hostadmin.username) and not ipam.admin_tag_exists(hostadmin.username):
            raise Http404()
        host = ipam.get_host_info_from_ip(ip) # TODO: could be changed to get_host_info_from_id() for better performance
        # check if host is valid
        if not host or not host.is_valid():
            logger.warning("Host '%s' is not valid!", str(host))
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()

        # parse form data and update host on POST
        if request.method == 'POST':
            form = AddHostRulesForm(request.POST)
            if form.is_valid():
                subnet = HostBasedRuleSubnetContract[form.cleaned_data['subnet']].value
                ports = form.cleaned_data['ports']
                proto = form.cleaned_data['protocol']
                # update the actual model instance
                if not host.add_host_based_policy(subnet, ports, proto):
                    form.add_error(None, "Rule is redundant!")
                else:
                    if not ipam.update_host_info(host):
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
                {'allow_src': HostBasedRuleSubnetContract(p.allow_srcs).display(),
                'allow_ports' : p.allow_ports,
                'allow_proto' : p.allow_proto,
                'id' : p.id}
            for p in host.host_based_policies],
        'form' : form,
        'scanner_key_url' : f"https://{settings.DOMAIN_NAME}" + os.path.join(settings.STATIC_URL, "files/greenbone-scanner.pub")
    }

    # pass flags for available actions into context
    action_flags = __get_available_actions(host)
    for k, f in action_flags.items():
        context[k] = f

    return render(request, 'host_detail.html', context)


@login_required
@require_http_methods(['GET', 'POST'])
def hosts_list_view(request):
    """
    Function view for adding new hosts and showing all hosts that are administrated by the current
    hostadmin. Paginated to 20 entries per page.

    Args:
        request (_type_): Request object.

    Returns:
        HttpResponse: Rendered HTML page.
    """
    logger.info("Request: List hosts for user %s", request.user.username)

    __add_notifications(request)

    PAGINATE = 20
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        user_exists = ipam.user_exists(hostadmin.username)
        admin_tag_exists = ipam.admin_tag_exists(hostadmin.username)
        if not user_exists and not admin_tag_exists:
            raise Http404()
        # if for this admin no tag exists yet, they should be redirected to the init page
        if not admin_tag_exists:
            return HttpResponseRedirect(reverse('hostadmin_init'))

        tag_choices = [hostadmin.username, ipam.get_department_to_admin(hostadmin.username)]
        if request.method == 'POST':
            form = AddHostForm(request.POST, choices=tag_choices)
            if form.is_valid():
                tag_name = form.cleaned_data['admin_tag']
                host_ip = form.cleaned_data['ip_addr']
                if ipam.add_tag_to_host(tag_name, host_ip):
                    return HttpResponseRedirect(reverse('hosts_list'))
            form.add_error(None, "Couldn't add host! Try again later...")
        else:
            form = AddHostForm(choices=tag_choices)
        
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
        'page_obj' : hosts_list,
        'form' : form,
    }
    return render(request, 'hosts_list.html', context)


@login_required
@require_http_methods(['GET', 'POST'])
def hostadmin_init_view(request):
    """
    Function view for initialization of hostadmins. On GET the form is displayed, on POST the
    form is read and the hostadmin is initialized.

    Args:
        request (_type_): Request object.

    Returns:
        HttpResponse: Rendered HTML page or redirect.
    """
    logger.info("Request: Initialize hostadmin %s", request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # hostadmin can only initialize if they are a user in IPAM
        if not ipam.user_exists(hostadmin.username):
            raise Http404()
        # check if hostadmin already has a tag
        if ipam.admin_tag_exists(hostadmin.username):
            return HttpResponseRedirect(reverse('hosts_list'))

        department_choices = ipam.get_department_tag_names()
        # do processing based on whether this is GET or POST request
        if request.method == 'POST':
            form = HostadminForm(request.POST, choices=department_choices)
            if form.is_valid():
                if ipam.create_admin_tag(hostadmin.username, form.cleaned_data['department']):
                    return HttpResponseRedirect(reverse('hosts_list'))
            else:
                logger.error("Invalid form!")

        else:
            form = HostadminForm(choices=department_choices)
    context = {
        'form' : form,
    }
    return render(request, 'hostadmin_init.html', context)



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
    logger.info("Request: Update host %s with method %s by user %s", ip, str(request.method), request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.user_exists(hostadmin.username) and not ipam.admin_tag_exists(hostadmin.username):
            raise Http404()
        # get host
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
                        messages.warning(request, f"Please make sure to configure custom rules for your desired services when choosing the {HostServiceContract.MULTIPURPOSE.value} profile!")
                    case _:
                        logger.error("%s is not supported yet.", host.service_profile)
                
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
def register_host(request, ip : str):
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
    logger.info("Request: Register host %s by user %s", ip, request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.user_exists(hostadmin.username) and not ipam.admin_tag_exists(hostadmin.username):
            raise Http404()
        # get host
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
            logger.warning("Host '%s' is not valid!", str(host))
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
    logger.info("Request: Ordinary scan for host %s by user %s", ip, request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.user_exists(hostadmin.username) and not ipam.admin_tag_exists(hostadmin.username):
            raise Http404()
        # get host
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
            logger.warning("Host '%s' is not valid!", str(host))
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
    logger.info("Request: Block host %s by user %s", ip, request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.user_exists(hostadmin.username) and not ipam.admin_tag_exists(hostadmin.username):
            raise Http404()
        # get host
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
    logger.info("Request: Delete rule %s for host %s by user %s", str(rule_id), ip, request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.user_exists(hostadmin.username) and not ipam.admin_tag_exists(hostadmin.username):
            raise Http404()
        # get host
        host = ipam.get_host_info_from_ip(ip) # TODO: could be changed to get_host_info_from_id() for better performance
        # check if host is valid
        if not host:
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()

        # delete rule from host
        for rule in host.host_based_policies:
            if uuid.UUID(rule.id) == rule_id:
                host.host_based_policies.remove(rule)
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
    logger.info("Request: Generate fw config script for host %s by user %s", ip, request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.user_exists(hostadmin.username) and not ipam.admin_tag_exists(hostadmin.username):
            raise Http404()
        # get host
        host = ipam.get_host_info_from_ip(ip) # TODO: could be changed to get_host_info_from_id() for better performance
        # check if host is valid
        if not host:
            raise Http404()
        # check if user is admin of this host
        if not hostadmin.username in host.admin_ids:
            raise Http404()
        if not host.is_valid():
            logger.warning("Host '%s' is not valid!", str(host))
            messages.error(request, "Host is not valid!")
            return HttpResponseRedirect(reverse('host_detail', kwargs={'ip': host.get_ip_escaped()}))


    script = generate_rule(host.fw, host.host_based_policies)
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

    # TODO: check request origin to be scanner

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
                scan_start, highest_cvss, results = scanner.extract_report_data(report_xml)
                if highest_cvss < 0.1:
                    severity = 'None'
                elif highest_cvss >= 0.1 and highest_cvss < 4.0:
                    severity = 'Low'
                elif highest_cvss >= 4.0 and highest_cvss < 7.0:
                    severity = 'Medium'
                elif highest_cvss >=7.0 and highest_cvss < 9.0:
                    severity = 'High'
                elif highest_cvss >= 9.0:
                    severity = 'Critical'
                else:
                    severity = 'Unknown'

                if results is None:
                    return

                # TODO: Risk assessment
                risk = compute_risk_of_network_exposure(results)
                if highest_cvss <= 5.0:
                    passed_scan = True
                else:
                    passed_scan = False

                with ProteusIPAMInterface(settings.IPAM_USERNAME, settings.IPAM_SECRET_KEY, settings.IPAM_URL) as ipam:
                    host = ipam.get_host_info_from_ip(host_ip)
                    if passed_scan:
                        passed_str_rep = 'passed'
                        logger.info("Host %s passed the registration scan and will be set online!", host_ip)
                        own_url = request.get_host() + reverse('v_scanner_periodic_alert')
                        if not scanner.add_host_to_periodic_scan(host_ip=host_ip, deterrers_url=own_url):
                            raise RuntimeError(f"Couldn't add host {host_ip} to periodic scan!")
                        # change the perimeter firewall configuration so that only hosts service profile is allowed
                        with PaloAltoInterface(settings.FIREWALL_USERNAME, settings.FIREWALL_SECRET_KEY, settings.FIREWALL_URL) as fw:
                            # first make sure ip is not already in any AddressGroups
                            suc = fw.remove_addr_obj_from_addr_grps(host_ip, {ag for ag in PaloAltoAddressGroup})
                            if not suc:
                                raise RuntimeError("Couldn't update firewall configuration!")
                            match host.service_profile:
                                case HostServiceContract.HTTP:
                                    suc = fw.add_addr_obj_to_addr_grps(host_ip, {PaloAltoAddressGroup.HTTP,})
                                case HostServiceContract.SSH:
                                    suc = fw.add_addr_obj_to_addr_grps(host_ip, {PaloAltoAddressGroup.SSH,})
                                case HostServiceContract.MULTIPURPOSE:
                                    suc = fw.add_addr_obj_to_addr_grps(host_ip, {PaloAltoAddressGroup.OPEN,})
                                case HostServiceContract.HTTP_SSH:
                                    suc = fw.add_addr_obj_to_addr_grps(host_ip, {PaloAltoAddressGroup.HTTP, PaloAltoAddressGroup.SSH})
                                case _:
                                    raise RuntimeError(f"Unknown service profile: {host.service_profile}")
                            if not suc:
                                raise RuntimeError("Couldn't update firewall configuration!")
                        host.status = HostStatusContract.ONLINE
                        if not ipam.update_host_info(host):
                            raise RuntimeError("Couldn't update host information!")
                    else:
                        passed_str_rep = 'not passed because severity is higher than 5.0'
                        logger.info("Host %s did not pass the registration and will be blocked.", host_ip)
                        if not __block_host(host_ip):
                            raise RuntimeError("Couldn't block host")

                    # get HTML report and send via e-mail to admin
                    report_html = scanner.get_report_html(report_uuid)
                    # get all department names for use below
                    departments = ipam.get_department_tag_names()
                    # deduce admin email addr and filter out departments
                    admin_addresses = [admin_id + "@uos.de" for admin_id in host.admin_ids if admin_id not in departments]
                    logger.debug("Admin addresses: %s", str(admin_addresses))
                    __send_report_email(
                        report_html,
                        f"DETERRERS - Vulnerability scan report of host {host_ip}",
                        f"The scan was {passed_str_rep}.Severity of host {host_ip} is {severity}! You find the report of the vulnerability scan attached to this e-mail.", # TODO
                        admin_addresses,
                    )

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

    # TODO: check request origin to be scanner

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
                scan_start, highest_cvss, results = scanner.extract_report_data(report_xml)
                if highest_cvss < 0.1:
                    severity = 'None'
                elif highest_cvss >= 0.1 and highest_cvss < 4.0:
                    severity = 'Low'
                elif highest_cvss >= 4.0 and highest_cvss < 7.0:
                    severity = 'Medium'
                elif highest_cvss >=7.0 and highest_cvss < 9.0:
                    severity = 'High'
                elif highest_cvss >= 9.0:
                    severity = 'Critical'
                else:
                    severity = 'Unknown'

                if results is None:
                    return

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
                    # get all department names for use below
                    departments = ipam.get_department_tag_names()

                # get HTML report and send via e-mail to admin
                report_html = scanner.get_report_html(report_uuid)
                # deduce admin email addr and filter out departments
                admin_addresses = [admin_id + "@uos.de" for admin_id in host.admin_ids if admin_id not in departments]
                logger.debug("Admin addresses: %s", str(admin_addresses))
                __send_report_email(
                    report_html,
                    f"DETERRERS - Vulnerability scan report of host {host_ip}",
                    f"Severity of host {host_ip} is {severity}! You find the report of the vulnerability scan attached to this e-mail.", # TODO
                    admin_addresses,
                )

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
    logger.warning("Not implemented yet!")
    raise Http404()