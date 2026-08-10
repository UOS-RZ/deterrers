import os

import django
from collections import defaultdict



os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'application.settings')
django.setup()

from vulnerability_mgmt.models import Vulnerability  # noqa: E402


all_vulnerabilities = Vulnerability.objects.using('vulnerability_mgmt').all()

def find_mitigated_vulnerabilities(vulnerabilities):
    """Return (old_report_id, new_report_id, host, vuln_id) mitigations."""
    mitigated_returns = []
    groups = {}
    for vuln in vulnerabilities:
        if vuln.cvss_base_score is None or vuln.cvss_base_score <= 0:
            continue

        host = vuln.host_ipv4
        task_id = vuln.task_id
        report_id = vuln.report_id
        vuln_id = (
            vuln.vulnerability_name,
            vuln.nvt_oid,
            vuln.port,
            vuln.proto,
        )

        group = groups.setdefault((report_id, host, task_id), {'date_time': vuln.date_time, 'findings': set()})
        group['date_time'] = max(group['date_time'], vuln.date_time)
        group['findings'].add(vuln_id)


    sorted_groups = sorted(
        groups.items(),
        key=lambda x: (
            x[0][1],  # host
            x[0][2],  # task_id
            x[1]['date_time'],
            x[0][0],  # report_id
        ),
    )

    # Group the sorted findings by host so we can inspect the timeline per host.
    hosts_groups = defaultdict(list)
    for group_key, group in sorted_groups:
        report_id, host, task_id = group_key
        hosts_groups[(host, task_id)].append((report_id, task_id, group['date_time'], group['findings']))

    # For each host, walk the reports in chronological order and compare findings.
    # Any finding that disappeared compared to the previous report is treated as mitigated.
    for (host, task_id), reports in hosts_groups.items():
        previous_findings = set()
        previous_report_id = None

        for report in reports:
            report_id, task_id, date_time, findings = report
            mitigated = previous_findings - findings
            if mitigated:
                for vuln_id in mitigated:
                    mitigated_returns.append((previous_report_id, report_id, host, vuln_id))
                    
            previous_findings = set(findings)  # Store the current findings for the next comparison.
            previous_report_id = report_id


    for (host, task_id), reports in hosts_groups.items():
        print(f"Host: {host}, Task ID: {task_id}")
        for report in reports:
            report_id, task_id, date_time, findings = report
            print(f"  Report ID: {report_id}, Task ID: {task_id}, Date: {date_time}, Findings Count: {len(findings)}")
        print("\n")

    return mitigated_returns

mitigated_vulnerabilities = find_mitigated_vulnerabilities(all_vulnerabilities)

for mitigation in mitigated_vulnerabilities:
    old_report_id, new_report_id, host, vuln_id = mitigation
    print(f"Mitigated Vulnerability: {vuln_id} on Host: {host} from Report: {old_report_id} to Report: {new_report_id}")