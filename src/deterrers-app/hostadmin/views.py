import logging
import uuid
import io
from threading import Thread
import os
import markdown
import pathlib
import pickle
import time

from django.contrib.auth.decorators import login_required
from django.http import (Http404,
                         HttpResponseRedirect,
                         HttpResponse,
                         FileResponse)
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.conf import settings
from django.contrib import messages
from django.core.mail import EmailMessage

from hostadmin.util import (add_changelog,
                            available_actions,
                            registration_mail_body,
                            scan_mail_body,
                            periodic_mail_body,
                            set_host_offline,
                            set_host_online)

from hostadmin.forms import (ChangeHostDetailForm,
                             AddHostRulesForm,
                             HostadminForm,
                             AddHostForm)
from hostadmin.core.data_logic.ipam_wrapper import ProteusIPAMWrapper
from hostadmin.core.scanner.gmp_wrapper import GmpScannerWrapper
from hostadmin.core.fw.pa_wrapper import PaloAltoWrapper
from hostadmin.core.risk_assessor import assess_host_risk
from hostadmin.core.rule_generator import generate_fw_config
from hostadmin.core.contracts import (HostBasedPolicySrc,
                                      HostBasedPolicyProtocol,
                                      HostStatus,
                                      HostServiceProfile,
                                      HostFW,)


from myuser.models import MyUser

logger = logging.getLogger(__name__)


def __send_report_email(
    report_html: str | None,
    subject: str,
    str_body: str,
    to: list
):
    """
    Utility method for sending e-mail.

    Args:
        report_html (str): HTML string that is attached to email.
        subject (str): Subject of email.
        str_body (str): String content of the email.
        to (list): List of addresses to send email to.
    """
    headers = {
        "Reply-To": settings.DEFAULT_FROM_EMAIL
    }
    email = EmailMessage(
        subject=subject,
        body=str_body,
        from_email=None,
        to=to,
        headers=headers
    )
    if report_html:
        email.attach("report.html", report_html, "text/html")
    try:
        logger.info("Send e-mail '%s' to %s.", subject, str(to))
        email.send()
    except Exception:
        logger.exception("Couldn't send e-mail!")


# Create your views here.

@require_http_methods(['GET', ])
def about_view(request):
    """
    Function-based view serving the landing page.

    Args:
        request (): Request object

    Returns:
        HTTPResponse: Rendered HTML page.
    """
    context = {
        'changelog': add_changelog()
    }
    return render(request, 'about.html', context)


@require_http_methods(['GET', ])
def api_schema(request):
    """
    Function-based view serving the API schema.

    Args:
        request (): Request object

    Returns:
        HTTPResponse: Rendered HTML page.
    """
    with open(
        pathlib.Path(
            settings.BASE_DIR / 'hostadmin'
        ).joinpath('api/schema.md'),
        'r',
        encoding='utf-8'
    ) as f:
        context = {
            'schema_html': markdown.markdown(f.read()),
        }
    return render(request, 'api_schema.html', context)


@login_required
@require_http_methods(['GET', 'POST'])
def host_detail_view(request, ipv4: str):
    """
    Function-based view for showing host details. Only available to logged
    in users.

    Args:
        request (): Request object.
        ipv4 (str): IP string from the URL parameter.

    Raises:
        Http404: When object is not available or user has no permission.

    Returns:
        HTTPResponse: Rendered HTML page.
    """
    logger.info("Request: Get details for host %s for user %s",
                ipv4, request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return HttpResponse(status=500)

        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404()
        # TODO: could be changed to get_host_info_from_id() for better
        # performance
        host = ipam.get_host_info_from_ip(ipv4)
        # check if host is valid
        if not host or not host.is_valid():
            logger.warning("Host '%s' is not valid!", str(host))
            raise Http404()
        # check if user is admin of this host
        if hostadmin.username not in host.admin_ids:
            raise Http404()

        # parse form data and update host on POST
        if request.method == 'POST':
            form = AddHostRulesForm(request.POST)
            if form.is_valid():
                subnet = HostBasedPolicySrc[
                    form.cleaned_data['subnet']
                ].value
                ports = form.cleaned_data['ports']
                proto = form.cleaned_data['protocol']
                # update the actual model instance
                if not host.add_host_based_policy(subnet, ports, proto):
                    form.add_error(None, "Rule is redundant!")
                else:
                    if not ipam.update_host_info(host):
                        form.add_error(
                            None,
                            "Host rules could not be updated! Try again later."
                        )
                    else:
                        form = AddHostRulesForm()
        else:
            # create new empty form
            form = AddHostRulesForm()

    context = {
        'hostadmin': hostadmin,
        'host_detail': host,
        'host_rules': [
            {
                'allow_src': HostBasedPolicySrc(
                    p.allow_srcs
                ).display(),
                'allow_ports': p.allow_ports,
                'allow_proto': p.allow_proto,
                'id': p.id
            }
            for p in host.host_based_policies],
        'form': form,
        'scanner_key_url': (
            f"https://{settings.DOMAIN_NAME}"
            + os.path.join(settings.STATIC_URL,
                           "files/greenbone-scanner.pub")
        )
    }

    # pass flags for available actions into context
    action_flags = available_actions(host)
    for k, f in action_flags.items():
        context[k] = f

    return render(request, 'host_detail.html', context)


@login_required
@require_http_methods(['GET', 'POST'])
def hosts_list_view(request):
    """
    Function view for adding new hosts and showing all hosts that are
    administrated by the current hostadmin. Paginated to 200 entries per page.

    Args:
        request (_type_): Request object.

    Returns:
        HttpResponse: Rendered HTML page.
    """
    logger.info("Request: List hosts for user %s", request.user.username)

    PAGINATE = 200
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return HttpResponse(status=500)

        # if for this admin no tag exists yet, they should be redirected
        # to the init page
        if not ipam.is_admin(hostadmin.username):
            if ipam.user_exists(hostadmin.username):
                return HttpResponseRedirect(reverse('hostadmin_init'))
            else:
                raise Http404()

        tag_choices = [
            hostadmin.username,
            ipam.get_department_to_admin(hostadmin.username)
        ]
        if request.method == 'POST':
            form = AddHostForm(request.POST, choices=tag_choices)
            if form.is_valid():
                tag_name = form.cleaned_data['admin_tag']
                host_ipv4 = form.cleaned_data['ipv4_addr']
                host = ipam.get_host_info_from_ip(host_ipv4)
                if not host:
                    form.add_error(
                        None,
                        "Host not found!"
                    )
                elif not host.is_valid():
                    form.add_error(
                        None,
                        "Host not valid!"
                    )
                else:
                    code = ipam.add_admin_to_host(tag_name, host)
                    # NOTE: return codes are not well defined by Proteus
                    # but any 2xx is fine
                    if code in range(200, 205, 1):
                        return HttpResponseRedirect(reverse('hosts_list'))
                    elif code == 409:
                        form.add_error(
                            None,
                            "Conflict while adding host!"
                        )
                    else:
                        form.add_error(
                            None,
                            f"Couldn't add host! Code: {code}"
                        )
        else:
            form = AddHostForm(choices=tag_choices)

        hosts_list = ipam.get_hosts_of_admin(hostadmin.username)

        hosts_list = sorted(hosts_list)

    paginator = Paginator(hosts_list, PAGINATE)
    page = request.GET.get('page', 1)
    try:
        hosts_list = paginator.page(page)
    except PageNotAnInteger:
        hosts_list = paginator.page(1)
    except EmptyPage:
        hosts_list = paginator.page(paginator.num_pages)

    context = {
        'hostadmin': hostadmin,
        'hosts_list': hosts_list,
        'is_paginated': True,
        'page_obj': hosts_list,
        'form': form,
    }
    return render(request, 'hosts_list.html', context)


@login_required
@require_http_methods(['GET', 'POST'])
def hostadmin_init_view(request):
    """
    Function view for initialization of hostadmins. On GET the form is
    displayed, on POST the form is read and the hostadmin is initialized.

    Args:
        request (_type_): Request object.

    Returns:
        HttpResponse: Rendered HTML page or redirect.
    """
    logger.info("Request: Initialize hostadmin %s", request.user.username)
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return HttpResponse(status=500)

        # hostadmin can only initialize if they are a user in IPAM
        if not ipam.user_exists(hostadmin.username):
            raise Http404()
        # check if hostadmin already has a tag
        if ipam.is_admin(hostadmin.username):
            return HttpResponseRedirect(reverse('hosts_list'))

        department_choices = ipam.get_department_names()
        # do processing based on whether this is GET or POST request
        if request.method == 'POST':
            form = HostadminForm(request.POST, choices=department_choices)
            if form.is_valid():
                if ipam.create_admin(
                    hostadmin.username,
                    form.cleaned_data['department']
                ):
                    return HttpResponseRedirect(reverse('hosts_list'))
            else:
                logger.error("Invalid form!")

        else:
            form = HostadminForm(choices=department_choices)
    context = {
        'form': form,
    }
    return render(request, 'hostadmin_init.html', context)


@login_required
@require_http_methods(['GET', 'POST'])
def update_host_detail(request, ipv4: str):
    """
    View function for processing of the form for updating host information.
    Only available to logged in users.

    Args:
        request (): Request object.
        ipv4 (str): IP string from the URL parameter.

    Raises:
        Http404: When object is not available or user has no permission.

    Returns:
        HTTPResponse: Rendered HTML page.
    """
    logger.info(
        "Request: Update host %s with method %s by user %s",
        ipv4,
        str(request.method),
        request.user.username
    )
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return HttpResponse(status=500)

        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404()
        # get host
        host = ipam.get_host_info_from_ip(ipv4)
        if not host:
            raise Http404()

        # check if user is admin of this host
        if hostadmin.username not in host.admin_ids:
            raise Http404()

        # check if this host can be changed at the moment or whether there
        # are already processes running for it
        if not available_actions(host).get('can_update'):
            raise Http404()

        # do processing based on whether this is GET or POST request
        if request.method == 'POST':
            form = ChangeHostDetailForm(request.POST)

            if form.is_valid():
                # update the actual model instance
                service_profile_change = (
                    host.service_profile
                    != HostServiceProfile(
                        form.cleaned_data['service_profile']
                    )
                )
                host.service_profile = HostServiceProfile(
                    form.cleaned_data['service_profile']
                )
                fw_change = host.fw != HostFW(form.cleaned_data['fw'])
                host.fw = HostFW(form.cleaned_data['fw'])
                if not ipam.update_host_info(host):
                    form.add_error(
                        None,
                        ("Host information could not be updated! "
                         + "Try again later...")
                    )
                    # redirect to a new URL:
                    return HttpResponseRedirect(
                        reverse(
                            'host_detail',
                            kwargs={'ipv4': host.get_ipv4_escaped()}
                        )
                    )

                if not service_profile_change and not fw_change:
                    # return immediately if nothing was changed
                    return HttpResponseRedirect(
                        reverse(
                            'host_detail',
                            kwargs={'ipv4': host.get_ipv4_escaped()}
                        )
                    )
                elif service_profile_change:
                    # if host is already online, update the perimeter FW
                    if host.status == HostStatus.ONLINE:
                        if host.service_profile == HostServiceProfile.EMPTY:
                            form.add_error(
                                None,
                                "Please make sure to choose a service profile."
                            )
                            context = {
                                'form': form,
                                'host_instance': host
                            }
                            return render(
                                request,
                                'update_host_detail.html',
                                context=context
                            )
                        if not set_host_online(str(host.ipv4_addr)):
                            form.add_error(
                                None,
                                "Perimeter firewall could not be updated."
                            )
                            context = {
                                'form': form,
                                'host_instance': host
                            }
                            return render(
                                request,
                                'update_host_detail.html',
                                context=context
                            )

                    # auto-add some host-based policies
                    match host.service_profile:
                        case HostServiceProfile.EMPTY:
                            pass
                        case (HostServiceProfile.SSH
                              | HostServiceProfile.HTTP
                              | HostServiceProfile.HTTP_SSH) as s_p:
                            # allow SSH standard port 22 over TCP if a service
                            # profile is specified
                            host.add_host_based_policy(
                                HostBasedPolicySrc.ANY.value,
                                ['22'],
                                HostBasedPolicyProtocol.TCP.value
                            )
                            match s_p:
                                case HostServiceProfile.SSH:
                                    # since SSH rules have already been added
                                    # do nothing else
                                    pass
                                case (HostServiceProfile.HTTP
                                      | HostServiceProfile.HTTP_SSH):
                                    # allow HTTP and HTTPS standard ports
                                    # 80 and 443 over TCP
                                    host.add_host_based_policy(
                                        HostBasedPolicySrc.ANY.value,
                                        ['80'],
                                        HostBasedPolicyProtocol.TCP.value
                                    )
                                    host.add_host_based_policy(
                                        HostBasedPolicySrc.ANY.value,
                                        ['443'],
                                        HostBasedPolicyProtocol.TCP.value
                                    )
                        case HostServiceProfile.MULTIPURPOSE:
                            # allow nothing else; users are expected to
                            # configure their own rules
                            messages.warning(
                                request,
                                ("Please make sure to configure custom rules "
                                 + "for your desired services when choosing "
                                 + f"the {HostServiceProfile.MULTIPURPOSE.value} "
                                 + "profile!")
                            )
                        case _:
                            logger.error(
                                "%s is not supported yet.",
                                host.service_profile
                            )
                    if not ipam.update_host_info(host):
                        messages.error(
                            request,
                            ("Failed to update information!")
                        )

                # redirect to a new URL:
                return HttpResponseRedirect(
                    reverse(
                        'host_detail',
                        kwargs={'ipv4': host.get_ipv4_escaped()}
                    )
                )

        else:
            form = ChangeHostDetailForm(
                initial={
                    'name': host.name,
                    'service_profile': host.service_profile.value,
                    'fw': host.fw.value
                }
            )

    context = {
        'form': form,
        'host_instance': host
    }
    return render(request, 'update_host_detail.html', context=context)


""" Host Actions """


@login_required
@require_http_methods(['POST', ])
def register_host(request, ipv4: str):
    """
    Processes requests for performing a registration on a host.

    Args:
        request (_type_): Request object.
        ipv4 (str): IP address of the host.

    Raises:
        Http404: Raised if host or hostadmin do not exist or if some
        permission is denied.

    Returns:
        HttpResponseRedirect: Redirect to the detail page of the host.
    """
    logger.info(
        "Request: Register host %s by user %s",
        ipv4,
        request.user.username
    )
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return HttpResponse(status=500)
        with GmpScannerWrapper(
            settings.V_SCANNER_USERNAME,
            settings.V_SCANNER_SECRET_KEY,
            settings.V_SCANNER_URL
        ) as scanner:
            if not scanner.enter_ok:
                return HttpResponse(status=500)

            # check if user has IPAM permission or an admin tag for them exists
            if not ipam.is_admin(hostadmin.username):
                raise Http404()
            # get host
            host = ipam.get_host_info_from_ip(ipv4)
            if not host:
                raise Http404()
            # check if user is admin of this host
            if hostadmin.username not in host.admin_ids:
                raise Http404()
            # check if this host can be registered
            if not available_actions(host).get('can_register'):
                raise Http404()
            if not host.is_valid():
                logger.warning("Host '%s' is not valid!", str(host))
                messages.error(request, "Host is not valid!")
            else:
                # create an initial scan of the host
                own_url = (request.get_host()
                           + reverse('v_scanner_registration_alert'))
                (target_uuid,
                 task_uuid,
                 report_uuid,
                 alert_uuid) = scanner.create_registration_scan(ipv4, own_url)
                if target_uuid and task_uuid and report_uuid and alert_uuid:
                    # update state in IPAM
                    host.status = HostStatus.UNDER_REVIEW
                    if not ipam.update_host_info(host):
                        scanner.clean_up_scan_objects(
                            target_uuid, task_uuid,
                            report_uuid,
                            alert_uuid
                        )
                        messages.error(
                            request,
                            ("Registration was aborted due to unknown reasons."
                             + " Try again later...")
                        )
                else:
                    messages.error(
                        request,
                        ("Not possible to start registration at the moment! "
                         + "Try again later...")
                    )

    # redirect to a new URL:
    return HttpResponseRedirect(
        reverse(
            'host_detail',
            kwargs={'ipv4': host.get_ipv4_escaped()}
        )
    )


@login_required
@require_http_methods(['POST', ])
def scan_host(request, ipv4: str):
    """
    Processes requests for performing an ordinary scan on a host.

    Args:
        request (_type_): Request object.
        ipv4 (str): IP address of the host.

    Raises:
        Http404: Raised if host or hostadmin do not exist or if some
        permission is denied.

    Returns:
        HttpResponseRedirect: Redirect to the detail page of the host.
    """
    logger.info(
        "Request: Ordinary scan for host %s by user %s",
        ipv4,
        request.user.username
    )
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return HttpResponse(status=500)
        with GmpScannerWrapper(
            settings.V_SCANNER_USERNAME,
            settings.V_SCANNER_SECRET_KEY,
            settings.V_SCANNER_URL
        ) as scanner:
            if not scanner.enter_ok:
                return HttpResponse(status=500)

            # check if user has IPAM permission or an admin tag for them exists
            if not ipam.is_admin(hostadmin.username):
                raise Http404()
            # get host
            host = ipam.get_host_info_from_ip(ipv4)
            if not host:
                raise Http404()
            # check if user is admin of this host
            if hostadmin.username not in host.admin_ids:
                raise Http404()
            # check if this host can be scanned at the moment or whether
            # there are already processes running for it
            if not available_actions(host).get('can_scan'):
                raise Http404()
            if not host.is_valid():
                logger.warning("Host '%s' is not valid!", str(host))
                messages.error(request, "Host is not valid!")
            else:
                # create an initial scan of the host
                own_url = request.get_host() + reverse('v_scanner_scan_alert')
                (target_uuid,
                 task_uuid,
                 report_uuid,
                 alert_uuid) = scanner.create_ordinary_scan(ipv4, own_url)
                if target_uuid and task_uuid and report_uuid and alert_uuid:
                    # update state in IPAM
                    host.status = HostStatus.UNDER_REVIEW
                    if not ipam.update_host_info(host):
                        scanner.clean_up_scan_objects(
                            target_uuid,
                            task_uuid,
                            report_uuid,
                            alert_uuid
                        )
                        messages.error(
                            request,
                            ("Scan was aborted due to unknown reasons. "
                             + "Try again later...")
                        )
                else:
                    messages.error(
                        request,
                        ("Not possible to start scan at the moment! "
                         + "Try again later...")
                    )

    # redirect to a new URL:
    return HttpResponseRedirect(
        reverse(
            'host_detail',
            kwargs={'ipv4': host.get_ipv4_escaped()}
        )
    )


@login_required
@require_http_methods(['POST', ])
def block_host(request, ipv4: str):
    """
    Processes requests for blocking a certain host.

    Args:
        request (_type_): Request object.
        ipv4 (str): IP address of the host.

    Raises:
        Http404: Raised if host or hostadmin do not exist or if some
        permission is denied.

    Returns:
        HttpResponseRedirect: Redirect to the detail page of the host.
    """
    logger.info(
        "Request: Block host %s by user %s",
        ipv4,
        request.user.username
    )
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return HttpResponse(status=500)

        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404()
        # get host
        host = ipam.get_host_info_from_ip(ipv4)
    if not host:
        raise Http404()
    # check if user is admin of this host
    if hostadmin.username not in host.admin_ids:
        raise Http404()
    # check if this host can be blocked at the moment or whether there
    # are already processes running for it
    if not available_actions(host).get('can_block'):
        raise Http404()

    if not set_host_offline(ipv4):
        messages.error(request, "Couldn't block host!")

    # redirect to a new URL:
    return HttpResponseRedirect(
        reverse(
            'host_detail',
            kwargs={'ipv4': host.get_ipv4_escaped()}
        )
    )


@login_required
@require_http_methods(['POST', ])
def delete_host_rule(request, ipv4: str, rule_id: uuid.UUID):
    """
    Processes requests for deleting a custom firewall rule.

    Args:
        request (_type_): Request object.
        ipv4 (str): IP address of the host.
        rule_id (uuid.UUID): UUID of the rule that is to be deleted.

    Raises:
        Http404: Raised if host or hostadmin do not exist or if some
        permission is denied.

    Returns:
        HttpResponseRedirect: Redirect to the detail page of the host.
    """
    logger.info(
        "Request: Delete rule %s for host %s by user %s",
        str(rule_id),
        ipv4,
        request.user.username
    )
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return HttpResponse(status=500)

        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404()
        # get host
        # TODO: could be changed to get_host_info_from_id() for better
        # performance
        host = ipam.get_host_info_from_ip(ipv4)
        # check if host is valid
        if not host:
            raise Http404()
        # check if user is admin of this host
        if hostadmin.username not in host.admin_ids:
            raise Http404()

        # delete rule from host
        for rule in host.host_based_policies:
            if uuid.UUID(rule.id) == rule_id:
                host.host_based_policies.remove(rule)
                break
        if not ipam.update_host_info(host):
            messages.error(
                request,
                "Host could not be updated! Try again later..."
            )

    return HttpResponseRedirect(
        reverse(
            'host_detail',
            kwargs={'ipv4': host.get_ipv4_escaped()}
        )
    )


@login_required
@require_http_methods(['GET', ])
def get_fw_config(request, ipv4: str):
    """
    Processes requests of configuration scripts for host-based firewalls.

    Args:
        request (_type_): Request objects.
        ipv4 (str): IP address of a host.

    Raises:
        Http404: Raised if host or hostadmin do not exist or if some
        permission is denied.

    Returns:
        FileResponse: Returns the firewall configuration script for the
        queried host as file.
    """
    logger.info(
        "Request: Generate fw config script for host %s by user %s",
        ipv4,
        request.user.username
    )
    hostadmin = get_object_or_404(MyUser, username=request.user.username)
    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return HttpResponse(status=500)

        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404()
        # get host
        # TODO: could be changed to get_host_info_from_id() for better
        # performance
        host = ipam.get_host_info_from_ip(ipv4)
        # check if host is valid
        if not host:
            raise Http404()
        # check if user is admin of this host
        if hostadmin.username not in host.admin_ids:
            raise Http404()
        if not host.is_valid():
            logger.warning("Host '%s' is not valid!", str(host))
            messages.error(request, "Host is not valid!")
            return HttpResponseRedirect(
                reverse(
                    'host_detail',
                    kwargs={'ipv4': host.get_ipv4_escaped()}
                )
            )

    script = generate_fw_config(host.fw, host.host_based_policies)
    if script:
        f_temp = io.BytesIO(bytes(script, 'utf-8'))
        f_response = FileResponse(f_temp,
                                  as_attachment=True,
                                  filename='fw_config.sh')
        # not closing io.BytesIO is probably fine because it is only an
        # objet in RAM and will be released by GC
        # f_temp.close()
        return f_response

    return Http404()


@login_required
@require_http_methods(['POST', ])
def remove_host(request, ipv4: str):
    """
    Remove a host from DETERRERS.
    Sets all fields to blank, removes all admins, blocks at perimeter,
    removes IP from periodic scan.

    Args:
        request (_type_): Request object.
        ipv4 (str): IPv4 address of host to remove

    Returns:
        _type_: Returns a redirect to host-list page on success.
    """
    hostadmin = get_object_or_404(MyUser, username=request.user.username)

    with ProteusIPAMWrapper(
        settings.IPAM_USERNAME,
        settings.IPAM_SECRET_KEY,
        settings.IPAM_URL
    ) as ipam:
        if not ipam.enter_ok:
            return HttpResponse(status=500)
        # check if user has IPAM permission or an admin tag for them exists
        if not ipam.is_admin(hostadmin.username):
            raise Http404()

        # get host
        # TODO: could be changed to get_host_info_from_id() for better
        # performance
        host = ipam.get_host_info_from_ip(ipv4)
        # check if host is valid
        if not host:
            raise Http404()
        # check if user is admin of this host
        if hostadmin.username not in host.admin_ids:
            raise Http404()

        # check if this host can be removed at the moment or whether there
        # are processes running for it
        if not available_actions(host).get('can_remove'):
            return HttpResponse(status=409)

        # block
        if host.status == HostStatus.ONLINE:
            if not set_host_offline(str(host.ipv4_addr)):
                return HttpResponse(status=500)

        # set all DETERRERS fields to blank
        host.status = HostStatus.UNREGISTERED
        host.service_profile = HostServiceProfile.EMPTY
        host.fw = HostFW.EMPTY
        host.host_based_policies = []
        if not ipam.update_host_info(host):
            return HttpResponse(status=500)

        # remove all admin tags
        for admin_tag_name in host.admin_ids.copy():
            ipam.remove_admin_from_host(admin_tag_name, host)
        # check that no admins are left for this host
        if len(host.admin_ids) > 0:
            logger.error(
                "Couldn't remove all tags from host '%s'",
                str(host.ipv4_addr)
            )
            return HttpResponse(status=500)

    return HttpResponseRedirect(reverse('hosts_list'))


""" Vulnerability Scanner alerts """


@require_http_methods(['GET', ])
def v_scanner_registration_alert(request):
    """
    Processes the alert send by the v-scanner when a registration scan has
    completed. The scan report will be assessed and an HTML report will be
    send to the admin. In case the risk assessment finds no high risks, the
    host is added to the target list of the periodic scan in the v-scanner
    and it is set online in the perimeter firewall. Otherwise, the host will
    be blocked (even though it probably is already in blocked state).

    Args:
        request (_type_): Request object.

    Returns:
        HTTPResponse: Always returns response with status 200 because
        processing of the alert happens independently in daemon thread.
    """
    logger.info(
        "Received notification from v-scanner that a registration completed."
    )

    # TODO: check request origin to be scanner

    def proc_registration_alert(request):
        """
        Inner function for processing the registration alert in a
        daemon thread.

        Args:
            request (_type_): Request object.
        """
        try:
            with GmpScannerWrapper(
                settings.V_SCANNER_USERNAME,
                settings.V_SCANNER_SECRET_KEY,
                settings.V_SCANNER_URL
            ) as scanner:
                if not scanner.enter_ok:
                    return
                with ProteusIPAMWrapper(
                    settings.IPAM_USERNAME,
                    settings.IPAM_SECRET_KEY,
                    settings.IPAM_URL
                ) as ipam:
                    if not ipam.enter_ok:
                        return

                    host_ipv4 = request.GET['host_ip']
                    task_uuid = request.GET['task_uuid']
                    report_uuid = scanner.get_latest_report_uuid(task_uuid)
                    target_uuid = request.GET['target_uuid']
                    alert_uuid = request.GET['alert_uuid']

                    _, scan_end, scan_results = scanner.extract_report_data(
                        report_uuid
                    )
                    if scan_results is None:
                        return
                    # Risk assessment
                    for host_ipv4, vulnerabilities in scan_results.items():
                        host = ipam.get_host_info_from_ip(host_ipv4)
                        if not host or not host.is_valid():
                            logger.error(
                                "Invalid host during risk assessment: %s",
                                str(host)
                            )
                            continue
                        if len(host.admin_ids) == 0:
                            continue
                        block_reasons, notify_reasons = assess_host_risk(
                            host,
                            vulnerabilities,
                            medium_cvss_threshold=settings.REGI_MEDIUM_CVSS_T,
                            high_cvss_threshold=settings.REGI_HIGH_CVSS_T
                        )

                        # block if there were reasons found
                        if len(block_reasons) == 0:
                            passed = True
                            logger.info(
                                ("Host %s passed the registration scan and "
                                 + "will be set online!"),
                                host_ipv4
                            )
                            # change the perimeter firewall configuration so
                            # that only hosts service profile is allowed
                            if not set_host_online(host_ipv4):
                                raise RuntimeError("Couldn't set host online!")
                        else:
                            passed = False
                            logger.info(
                                ("Host %s did not pass the registration and "
                                 + "will be blocked."),
                                host_ipv4
                            )
                            if not set_host_offline(host_ipv4):
                                raise RuntimeError("Couldn't block host")

                        # get HTML report and send via e-mail to admin
                        report_html = scanner.get_report_html(report_uuid)
                        # get all department names for use below
                        departments = ipam.get_department_names()
                        # deduce admin email addr and filter out departments
                        admin_addresses = [admin_id + "@uos.de"
                                           for admin_id in host.admin_ids
                                           if admin_id not in departments]
                        if passed:
                            email_subject = (
                                f"DETERRERS - {str(host.ipv4_addr)} "
                                + "- Registration finished - PASSED"
                            )
                        else:
                            email_subject = (
                                f"DETERRERS - {str(host.ipv4_addr)} "
                                + "- Registration finished - BLOCKED"
                            )
                        __send_report_email(
                            report_html,
                            email_subject,
                            registration_mail_body(
                                host,
                                passed,
                                scan_end, block_reasons
                            ),
                            list(set(admin_addresses)),
                        )

                scanner.clean_up_scan_objects(
                    target_uuid,
                    task_uuid,
                    report_uuid,
                    alert_uuid
                )
        except Exception:
            logger.exception("Processing registration alert failed!")

    # run as daemon because v_scanner needs a response before scan objects
    # can be cleaned up
    t = Thread(target=proc_registration_alert, args=[request], daemon=True)
    t.start()

    return HttpResponse("Success!", status=200)


@require_http_methods(['GET', ])
def v_scanner_scan_alert(request):
    """
    Processes the alert send by the v-scanner when an ordinary scan
    has completed. The scan report will be assessed and an HTML report
    will be send to the admin.

    Args:
        request (_type_): Request object.

    Returns:
        HTTPResponse: Always returns response with status 200 because
        processing of the alert happens independently in daemon thread.
    """
    logger.info(
        ("Received notification from v-scanner that "
         + "an ordinary scan completed.")
    )

    # TODO: check request origin to be scanner

    def proc_scan_alert(request):
        """
        Inner function for processing the scan alert in a daemon thread.

        Args:
            request (_type_): Request object.
        """
        try:
            host_ipv4 = request.GET['host_ip']
            report_uuid = request.GET['report_uuid']
            task_uuid = request.GET['task_uuid']
            target_uuid = request.GET['target_uuid']
            alert_uuid = request.GET['alert_uuid']
            with GmpScannerWrapper(
                settings.V_SCANNER_USERNAME,
                settings.V_SCANNER_SECRET_KEY,
                settings.V_SCANNER_URL
            ) as scanner:
                if not scanner.enter_ok:
                    return
                with ProteusIPAMWrapper(
                    settings.IPAM_USERNAME,
                    settings.IPAM_SECRET_KEY,
                    settings.IPAM_URL
                ) as ipam:
                    if not ipam.enter_ok:
                        return

                    _, scan_end, results = scanner.extract_report_data(
                        report_uuid
                    )
                    if results is None:
                        return

                    # reset hosts status
                    host = ipam.get_host_info_from_ip(host_ipv4)
                    with PaloAltoWrapper(
                        settings.FIREWALL_USERNAME,
                        settings.FIREWALL_SECRET_KEY,
                        settings.FIREWALL_URL
                    ) as fw:
                        if not fw.enter_ok:
                            return
                        host.status = fw.get_host_status(str(host.ipv4_addr))
                    if not ipam.update_host_info(host):
                        raise RuntimeError("Couldn't update host information!")
                    # get all department names for use below
                    departments = ipam.get_department_names()

                # get HTML report and send via e-mail to admin
                report_html = scanner.get_report_html(report_uuid)
                # deduce admin email addr and filter out departments
                admin_addresses = [admin_id + "@uos.de"
                                   for admin_id in host.admin_ids
                                   if admin_id not in departments]
                __send_report_email(
                    report_html,
                    f"DETERRERS - {str(host.ipv4_addr)} - Scan finished",
                    scan_mail_body(host, scan_end),
                    list(set(admin_addresses)),
                )

                scanner.clean_up_scan_objects(
                    target_uuid,
                    task_uuid,
                    report_uuid,
                    alert_uuid
                )

        except Exception:
            logger.exception("Processing scan alert failed!")

    # run as daemon because v_scanner needs a response before scan objects
    # can be cleaned up
    t = Thread(target=proc_scan_alert, args=[request], daemon=True)
    t.start()

    return HttpResponse("Success!", status=200)


@require_http_methods(['GET', ])
def v_scanner_periodic_alert(request):
    """
    Processes the alert send by the v-scanner when an periodic scan has
    completed. The scan report will be assessed and admins notified.

    Args:
        request (_type_): Request object.

    Returns:
        HTTPResponse: Always returns response with status 200 because
        processing of the alert happens independently in daemon thread.
    """
    logger.info(
        ("Received notification from v-scanner that a "
         + "periodic scan completed.")
    )

    # TODO: check request origin to be scanner

    def proc_periodic_alert(request):
        """
        Inner function for processing the periodic alert in a daemon thread.

        Args:
            request (_type_): Request object.
        """
        try:
            task_uuid = request.GET['task_uuid']
            with GmpScannerWrapper(
                settings.V_SCANNER_USERNAME,
                settings.V_SCANNER_SECRET_KEY,
                settings.V_SCANNER_URL
            ) as scanner:
                if not scanner.enter_ok:
                    return
                with ProteusIPAMWrapper(
                    settings.IPAM_USERNAME,
                    settings.IPAM_SECRET_KEY,
                    settings.IPAM_URL
                ) as ipam:
                    if not ipam.enter_ok:
                        return

                    # update periodic scan target because might have been
                    # changes since it started
                    if not scanner.update_periodic_scan_target(task_uuid):
                        logger.warning(
                            "Couldn't update target of periodic scan!"
                        )

                    admin_mail_copy = ""
                    report_uuid = scanner.get_latest_report_uuid(task_uuid)
                    _, _, scan_results = scanner.extract_report_data(
                        report_uuid
                    )
                    if scan_results is None:
                        return
                    # save scan results for evaluation purposes
                    try:
                        with open(
                            os.path.join(
                                settings.BASE_DIR,
                                f"logs/scan-results_{task_uuid}_{time.time_ns()}.pickle"
                            ),
                            "wb"
                        ) as f:
                            pickle.dump(scan_results, f)
                    except Exception:
                        pass
                    # Risk assessment
                    for host_ipv4, vulnerabilities in scan_results.items():
                        host = ipam.get_host_info_from_ip(host_ipv4)
                        if not host or not host.is_valid():
                            logger.error(
                                "Invalid host during risk assessment: %s",
                                str(host)
                            )
                            continue
                        if len(host.admin_ids) == 0:
                            continue
                        block_reasons, notify_reasons = assess_host_risk(
                            host,
                            vulnerabilities,
                            medium_cvss_threshold=settings.PERIO_MEDIUM_CVSS_T,
                            high_cvss_threshold=settings.PERIO_HIGH_CVSS_T
                        )
                        # block if there were reasons found
                        if len(block_reasons) != 0:
                            logger.info(
                                ("Host %s did not pass the periodic scan "
                                 + "and will be blocked."),
                                str(host.ipv4_addr)
                            )
                            if not set_host_offline(str(host.ipv4_addr)):
                                raise RuntimeError("Couldn't block host")
                            # deduce admin email addr and filter out
                            # departments
                            departments = ipam.get_department_names()
                            admin_addrs = [admin_id + "@uos.de"
                                           for admin_id in host.admin_ids
                                           if admin_id not in departments]
                            email_body = periodic_mail_body(
                                host,
                                block_reasons,
                                notify_reasons
                            )

                            __send_report_email(
                                None,
                                (f"DETERRERS - {str(host.ipv4_addr)} "
                                 + "- Periodic scan - BLOCKED"),
                                email_body,
                                list(set(admin_addrs)),
                            )
                            # copy email body for admin mail
                            admin_mail_copy += f"""To {', '.join(admin_addrs)}:
                            """
                            admin_mail_copy += email_body
                            admin_mail_copy += """


                            """
                        # only send mail if not block
                        elif len(notify_reasons) != 0:
                            departments = ipam.get_department_names()
                            admin_addrs = [admin_id + "@uos.de"
                                           for admin_id in host.admin_ids
                                           if admin_id not in departments]
                            email_body = periodic_mail_body(
                                host,
                                block_reasons,
                                notify_reasons
                            )

                            __send_report_email(
                                None,
                                (f"DETERRERS - {str(host.ipv4_addr)} "
                                 + "- Periodic scan - NOT BLOCKED"),
                                email_body,
                                list(set(admin_addrs)),
                            )
                            # copy email body for admin mail
                            admin_mail_copy += f"""To {', '.join(admin_addrs)}:
                            """
                            admin_mail_copy += email_body
                            admin_mail_copy += """


                            """

                # send complete report to DETERRERS admin
                report_html = None
                admin_addrs = [settings.DJANGO_SUPERUSER_USERNAME+"@uos.de"]
                __send_report_email(
                    report_html,
                    "DETERRERS - Periodic vulnerability scan report",
                    f"""
Complete report of the periodic scan!
You find the report of the vulnerability scan attached to this e-mail.

Admin copy:

{admin_mail_copy}""",
                    list(set(admin_addrs)),
                )

        except Exception:
            logger.exception("Processing periodic alert failed!")

    # run as daemon because v_scanner needs a response before scan objects
    # can be cleaned up
    t = Thread(target=proc_periodic_alert, args=[request], daemon=True)
    t.start()

    return HttpResponse("Success!", status=200)
