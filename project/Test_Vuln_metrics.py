"""Admin views for vulnerability metrics.

These views should stay thin: parse request state, call metric/query helpers,
and render templates. Put calculation code in dedicated modules as the dashboard
grows again.
"""

from collections import defaultdict

from django.contrib import admin
from django.template.response import TemplateResponse

from vulnerability_mgmt.models import Vulnerability

all_vulnerabilities = Vulnerability.objects.using('vulnerability_mgmt').all()



def unique_vulnerabilities(vulnerabilities): #all_vulnerabilities here for date restricted amount of vulnerabilities
    """Returns a list of unique vulnerabilities based on specific fields."""
    seen = set()
    unique_vulnerabilities = []
    for vuln in vulnerabilities:
        #define a key based on the fields that determine uniqueness
        key = (vuln.vulnerability_name, vuln.host_ipv4, vuln.port, vuln.nvt_oid, vuln.task_id, vuln.proto, vuln.nvt_name)
        if key not in seen:
            seen.add(key)
            unique_vulnerabilities.append(vuln)
    return unique_vulnerabilities

def find_mitigated_vulnerabilities(vulnerabilities):
    """First step: prepare vulnerability groupings for later mitigation logic.

    Returns:
        {
            'vulnerabilities_by_host_task': {
                (host, task_id): [...],
            },
        }
    """
    vulnerabilities_by_host_task = defaultdict(list)

    # Group vulnerabilities by (host, task_id) for later mitigation logic.
    for vuln in vulnerabilities:
        vulnerabilities_by_host_task[(vuln.host_ipv4, vuln.task_id)].append(vuln)

    for host_task, vulns in vulnerabilities_by_host_task.items():
        #first find out the newest vuln for each group (by date_time)
        newest_vuln = max(vulns, key=lambda v: v.date_time)
        print(f"{host_task[0]}, {host_task[1]} === {newest_vuln.vulnerability_name} at {newest_vuln.date_time}")

def print_everything(vulnerabilities, arg):
    """Prints all vulnerabilities for debugging purposes."""
    vuln = vulnerabilities[0]  # Just to get the fields for printing
    if arg == "all":
        for vuln in vulnerabilities:
            print(f"Vulnerability: {vuln.vulnerability_name} \n"
                  f"Host: {vuln.host_ipv4} \n"
                  f"Port: {vuln.port} \n"
                  f"Protocol: {vuln.proto} \n"
                  f"hostname: {vuln.hostname} \n"
                  f"NVT Name: {vuln.nvt_name} \n"
                  f"NVT OID: {vuln.nvt_oid} \n"
                  f"qod: {vuln.qod} \n"
                  f"CVSS Version: {vuln.cvss_version} \n"
                  f"CVSS Base Score: {vuln.cvss_base_score} \n"
                  f"CVSS Base Vector: {vuln.cvss_base_vector} \n"
                  f"Refs: {vuln.refs} \n"
                  f"Overrides: {vuln.overrides} \n"
                  f"Task ID: {vuln.task_id} \n"
                  f"Date: {vuln.date_time}"
                  f"Report ID: {vuln.report_id} \n"
                  f"----------------------------------------"
                  )
    elif arg == "dates":
        for vuln in vulnerabilities:
            print(f"Host: {vuln.host_ipv4} \n"
                  f"Date: {vuln.date_time} \n"
                  f"----------------------------------------"
                  )
    elif arg == "newest_date":
        newest_vuln = max(vulnerabilities, key=lambda v: v.date_time)
        print(f"Newest Vulnerability: {newest_vuln.vulnerability_name} \n"
              f"Host: {newest_vuln.host_ipv4} \n"
              f"Date: {newest_vuln.date_time} \n"
              f"----------------------------------------"
              )

def find_mitigated_vulnerabilities(vulnerabilities):
    """First step: prepare vulnerability groupings for later mitigation logic.
    """
    vulnerabilities_by_host_task = defaultdict(list)

    # Group vulnerabilities by (host, task_id, report_id) for later mitigation logic.
    i = 0
    for vuln in vulnerabilities:
        vulnerabilities_by_host_task[(vuln.host_ipv4, vuln.task_id, vuln.report_id)].append(vuln)
        vuln
        print(f"{i}: Grouping: {vuln.host_ipv4}, {vuln.task_id}, {vuln.report_id} === {vuln.vulnerability_name}")
        i += 1

    vulnerabilities_by_host_task = sorted(vulnerabilities_by_host_task.items(), key=lambda x: (x[0][0], x[0][1], x[0][2]))  # Sort by host, task_id, report_id

    for host_task_report, vulns in vulnerabilities_by_host_task:
        print(f"{host_task_report[0]}, {host_task_report[1]}, {host_task_report[2]} : {len(vulns)} vulnerabilities")
        #find newest report groupe for each group (by date_time)
        

        

def test_overview():
    print("Testing overview view")
    #find_mitigated_vulnerabilities(all_vulnerabilities)
    print_everything(all_vulnerabilities, "all")
    #find_mitigated_vulnerabilities(all_vulnerabilities)


test_overview()

def overview(request):
    context = {
        **admin.site.each_context(request),
        'title': 'Vulnerability Metrics',
        'page_title': 'Overview',
        'message': 'Rebuild the overview metrics here.',
        "unique_vulnerabilities_size": len(unique_vulnerabilities(all_vulnerabilities)),
        "top_affected_hosts": top_affected_hosts(all_vulnerabilities),
        'vulnerabilities': all_vulnerabilities,
    }
    return TemplateResponse(request, 'admin/vulnerability_metrics_scratch.html', context)


def latest_reports(request):
    context = {
        **admin.site.each_context(request),
        'title': 'Latest Reports',
        'page_title': 'Latest reports',
        'message': 'Rebuild the latest-report snapshot here.',
        'vulnerabilities': all_vulnerabilities,
    }
    return TemplateResponse(request, 'admin/vulnerability_metrics_scratch.html', context)
