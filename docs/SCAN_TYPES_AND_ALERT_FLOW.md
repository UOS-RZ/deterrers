# Scan Types And Alert Flow

Audience: contributors and operators who want to understand how Greenbone scan
objects interact with DETERRERS and when scan results become visible in the
admin vulnerability dashboard.

## 1. High-Level Idea

DETERRERS does not poll Greenbone continuously for finished scans. Instead,
DETERRERS creates scan objects in Greenbone and attaches HTTP alerts to them.
When a scan task finishes, Greenbone calls back into DETERRERS. DETERRERS then
fetches the final report, evaluates it, stores it in the database, and the
admin dashboard becomes able to display the new vulnerabilities.

## 2. The Three Relevant Scan Types

### 2.1 Registration Scan

Entry point:

- `project/application/main/views.py`
- function: `register_host(request, ipv4)`

Scanner wrapper method:

- `project/application/main/core/scanner/gmp_wrapper.py`
- method: `create_registration_scan(host_ip, alert_dest_url)`

Purpose:

- first security evaluation of a host during onboarding
- may change host state depending on risk assessment result

After completion, DETERRERS:

- fetches the report
- assesses risk
- blocks or unblocks host
- stores vulnerability rows and report XML
- sends notification email

### 2.2 Ordinary Scan

Entry point:

- `project/application/main/views.py`
- function: `scan_host(request, ipv4)`

Scanner wrapper method:

- `project/application/main/core/scanner/gmp_wrapper.py`
- method: `create_ordinary_scan(host_ip, alert_dest_url)`

Purpose:

- manual scan of an already known host
- does not represent initial registration flow

After completion, DETERRERS:

- fetches report data
- stores vulnerability rows and report XML
- refreshes host status from firewall state
- sends report email

### 2.3 Periodic Scan

Entry point in DETERRERS callback handling:

- `project/application/main/views.py`
- function: `scanner_periodic_alert(request)`

Scanner setup method:

- `project/application/main/core/scanner/gmp_wrapper.py`
- method: `create_periodic_scans(...)`

Purpose:

- recurring scheduled scans managed in Greenbone
- background monitoring of already registered hosts

Special notes:

- periodic tasks persist in Greenbone
- target membership may be updated while scans are running via stash targets
- periodic flow additionally writes JSON scan snapshots into the logs folder

## 3. Greenbone Objects Created For Manual Scans

For ordinary and registration scans, DETERRERS creates these Greenbone
objects:

1. target
2. alert
3. task
4. report (created when task starts/runs)

Relevant methods in `gmp_wrapper.py`:

- `__create_target(...)`
- `__create_http_alert(...)`
- `__create_task(...)`
- `__start_task(...)`
- `__modify_http_alert_data(...)`

The wrapper creates the task with deterministic names such as:

- `DETERRERS - Scan target for host <IP>`
- `DETERRERS - Scan task for host <IP>`
- `DETERRERS - Scan alert for host <IP>`

and for registration scans:

- `DETERRERS - Registration scan target for host <IP>`
- `DETERRERS - Registration scan task for host <IP>`
- `DETERRERS - Registration alert for host <IP>`

## 4. What The HTTP Alert Does

The HTTP alert is the scanner-side callback bridge back into DETERRERS.

Creation method:

- `project/application/main/core/scanner/gmp_wrapper.py`
- `__create_http_alert(alert_name)`

Important settings:

- event: `TASK_RUN_STATUS_CHANGED`
- condition: `ALWAYS`
- event data: `status=Done`
- method: `HTTP_GET`

That means: when Greenbone marks the task as `Done`, it issues an HTTP GET to
DETERRERS.

After task creation, DETERRERS updates the alert URL in:

- `__modify_http_alert_data(...)`

The URL includes query parameters such as:

- `host_ip`
- `target_uuid`
- `task_uuid`
- `report_uuid`
- `alert_uuid`

These identifiers allow DETERRERS to correlate the callback with the scanner
objects that produced it.

## 5. How DETERRERS Receives And Processes Finished Scans

Callback endpoints live in:

- `project/application/main/views.py`

Functions:

- `scanner_registration_alert(request)`
- `scanner_scan_alert(request)`
- `scanner_periodic_alert(request)`

Each callback returns HTTP 200 quickly and processes the real work in a daemon
thread. This avoids blocking the scanner while DETERRERS fetches and parses the
report.

The common post-callback flow is:

1. read `task_uuid` and related identifiers from request
2. resolve latest report UUID via `get_latest_report_uuid(task_uuid)`
3. fetch report XML / parsed results
4. convert report results into `Vulnerability` rows
5. store report XML into `ScanReport`
6. execute scan-type-specific follow-up logic

## 6. Where Scan Results Are Stored

Primary storage for dashboard metrics:

- model `Vulnerability`
- model `ScanReport`
- app: `vulnerability_mgmt`
- DB alias: `vulnerability_mgmt`

Runtime DB tables:

- `vulnerability_mgmt_vulnerability`
- `vulnerability_mgmt_scanreport`

The admin vulnerability dashboard reads from these DB rows, not from raw JSON
files.

Secondary file output:

- periodic callback handler writes `scan-results_*.json`
- in dev these end up under `project/dev-logs`

## 7. When Results Become Visible In The Dashboard

The dashboard in:

- `project/application/vulnerability_mgmt/admin.py`

queries `Vulnerability` rows directly at request time. There is no additional
cache or materialized metrics table.

So dashboard visibility happens after all of the following are true:

1. Greenbone scan task finished with status `Done`
2. Greenbone fired the HTTP alert successfully
3. DETERRERS callback handler fetched and stored the report data
4. dashboard page was refreshed

In practice:

- the scan runtime itself is usually the long part
- the DETERRERS evaluation/persistence step is usually much shorter

## 8. Important Difference: Manual Vs Periodic Objects

Manual one-off scans:

- should be cleaned up after processing
- use deterministic host-specific names
- can block future re-creation if stale objects remain behind

Periodic scans:

- are persistent infrastructure
- should remain in Greenbone for future scheduled runs
- are not cleaned up after each successful scan

## 9. Recent Failure Mode: "Not possible to start scan at the moment"

Observed root cause:

- UI ordinary scan triggered `create_ordinary_scan(...)`
- Greenbone returned `Response Error 400. Target exists already`
- existing objects were already present for the same deterministic host name
- the stale objects had status `Done`, not active

This means a previous manual scan left Greenbone task/target/alert objects
behind, and the next scan creation collided with them.

## 10. Hardening Added For This Case

The scanner wrapper now contains logic to clean stale one-off scan objects
before creating a fresh ordinary or registration scan.

Implementation file:

- `project/application/main/core/scanner/gmp_wrapper.py`

Behavior:

- if no prior object exists: proceed normally
- if prior object exists and task is inactive (`Done`, etc.): clean it up and
  recreate cleanly
- if prior object exists and task is still active (`Queued`, `Requested`,
  `Running`): do not delete it

This prevents harmless leftovers from blocking future manual scans while still
protecting real active scans.

## 11. Useful Live Debugging Steps

### Check whether callback arrived

```bash
cd /root/deterrers/project
grep -nE "registration completed|ordinary scan completed|periodic scan completed|Processing .* alert failed" dev-logs/deterrers-app.log | tail -n 20
```

### Check current DB counts

```bash
cd /root/deterrers/project
docker exec project-dev-web-1 python manage.py shell -c "from vulnerability_mgmt.models import Vulnerability, ScanReport; print('vulns', Vulnerability.objects.using('vulnerability_mgmt').count()); print('reports', ScanReport.objects.using('vulnerability_mgmt').count())"
```

### Inspect newest stored vulnerability rows

```bash
cd /root/deterrers/project
docker exec project-dev-web-1 python manage.py shell -c "from vulnerability_mgmt.models import Vulnerability; qs=Vulnerability.objects.using('vulnerability_mgmt').order_by('-date_time')[:20]; [print(v.date_time, v.host_ipv4, v.report_id, v.nvt_name[:80]) for v in qs]"
```

### Inspect stored report XML sizes

```bash
cd /root/deterrers/project
docker exec project-dev-web-1 python manage.py shell -c "from vulnerability_mgmt.models import ScanReport; qs=ScanReport.objects.using('vulnerability_mgmt').order_by('-report_id')[:10]; [print(r.report_id, len((r.report_xml or '').strip())) for r in qs]"
```

### Inspect stale one-off Greenbone objects for a host

```bash
cd /root/deterrers/project
docker exec project-dev-web-1 python manage.py shell -c "from django.conf import settings; from main.core.scanner.gmp_wrapper import GmpScannerWrapper; host='131.173.17.236';\
with GmpScannerWrapper(settings.SCANNER_USERNAME, settings.SCANNER_SECRET_KEY, settings.SCANNER_HOSTNAME) as scanner:\
    target_name=f'DETERRERS - Scan target for host {host}';\
    task_name=f'DETERRERS - Scan task for host {host}';\
    print('target_uuid', scanner._GmpScannerWrapper__get_target_id(target_name));\
    print('task_info', scanner._GmpScannerWrapper__get_task_info(task_name))"
```
