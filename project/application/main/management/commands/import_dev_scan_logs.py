"""
Management command to import vulnerability data from dev-logs scan result JSON
files into the vulnerability_mgmt database.

Usage:
    python manage.py import_dev_scan_logs
    python manage.py import_dev_scan_logs --logs-dir /path/to/logs
    python manage.py import_dev_scan_logs --clear
"""
import datetime
import json
import os
import re

from django.core.management.base import BaseCommand

from vulnerability_mgmt.models import ScanReport, Vulnerability

# Filename pattern: scan-results_{task_uuid}_{scan_end_iso}.json
FILENAME_RE = re.compile(
    r'^scan-results_(?P<task_id>[^_]+)_(?P<scan_end>.+)\.json$'
)


class Command(BaseCommand):
    help = (
        'Import vulnerability data from dev-logs scan result JSON files '
        'into the vulnerability_mgmt database.'
    )

    def add_arguments(self, parser):
        """Register CLI options for source location and reset behavior."""
        parser.add_argument(
            '--logs-dir',
            default=os.path.join(
                os.path.dirname(__file__),
                '..', '..', '..', '..', 'dev-logs'
            ),
            help='Path to directory containing scan-results JSON files.',
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Delete all existing Vulnerability records before importing.',
        )

    def handle(self, *args, **options):
        """Import scan JSON files into vulnerability tables in idempotent mode."""
        logs_dir = os.path.realpath(options['logs_dir'])

        if not os.path.isdir(logs_dir):
            self.stderr.write(self.style.ERROR(
                f'Logs directory not found: {logs_dir}'
            ))
            return

        if options['clear']:
            # Optional hard reset for reproducible local reviewer imports.
            count, _ = Vulnerability.objects.using('vulnerability_mgmt').all().delete()
            self.stdout.write(self.style.WARNING(
                f'Deleted {count} existing Vulnerability records.'
            ))
            report_count, _ = ScanReport.objects.using('vulnerability_mgmt').all().delete()
            self.stdout.write(self.style.WARNING(
                f'Deleted {report_count} existing ScanReport records.'
            ))

        json_files = sorted([
            f for f in os.listdir(logs_dir)
            if f.startswith('scan-results_') and f.endswith('.json')
        ])

        if not json_files:
            self.stdout.write(self.style.WARNING(
                f'No scan-results JSON files found in {logs_dir}'
            ))
            return

        total_imported = 0
        total_skipped = 0

        for filename in json_files:
            # Filenames encode task + report identity; skip files that do not
            # follow the expected pattern to avoid ambiguous imports.
            m = FILENAME_RE.match(filename)
            if not m:
                self.stdout.write(self.style.WARNING(
                    f'Skipping unrecognised filename: {filename}'
                ))
                continue

            task_id = m.group('task_id')
            # Derive a stable report_id from the filename timestamp
            report_id = m.group('scan_end')

            filepath = os.path.join(logs_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                self.stderr.write(self.style.ERROR(
                    f'Failed to read {filename}: {exc}'
                ))
                continue

            # Keep imported shape compatible with real scan persistence by
            # ensuring a ScanReport row exists for each imported result file.
            ScanReport.objects.using('vulnerability_mgmt').get_or_create(
                report_id=report_id,
                defaults={'report_xml': ''}
            )

            imported = 0
            skipped = 0

            for host_ip, vulnerabilities in data.items():
                for v in vulnerabilities:
                    uuid = v.get('uuid', '')
                    if not uuid:
                        skipped += 1
                        continue

                    # Skip if already imported (idempotent by uuid + report_id)
                    if Vulnerability.objects.using('vulnerability_mgmt').filter(
                        uuid=uuid, report_id=report_id
                    ).exists():
                        skipped += 1
                        continue

                    raw_time = v.get('time_of_detection', '')
                    try:
                        dt = datetime.datetime.strptime(
                            raw_time, '%Y-%m-%dT%H:%M:%SZ'
                        ).replace(tzinfo=datetime.timezone.utc)
                    except ValueError:
                        # Fall back to "now" to keep import resilient when a
                        # dev log contains malformed timestamps.
                        dt = datetime.datetime.now(tz=datetime.timezone.utc)

                    # Persist list fields as JSON strings because the model
                    # stores them in text columns.
                    refs = v.get('refs', [])
                    overrides = v.get('overrides', [])

                    Vulnerability.objects.using('vulnerability_mgmt').create(
                        uuid=uuid,
                        vulnerability_name=v.get('vulnerability_name', ''),
                        host_ipv4=host_ip,
                        port=str(v.get('port', '')),
                        proto=v.get('proto', ''),
                        hostname=v.get('hostname', ''),
                        nvt_name=v.get('nvt_name', ''),
                        nvt_oid=v.get('nvt_oid', ''),
                        qod=int(v.get('qod', 0)),
                        cvss_version=int(v.get('cvss_version', 0)),
                        cvss_base_score=float(v.get('cvss_base_score', 0.0)),
                        cvss_base_vector=v.get('cvss_base_vector', ''),
                        description=v.get('description', ''),
                        refs=json.dumps(refs),
                        overrides=json.dumps(overrides),
                        date_time=dt,
                        task_id=task_id,
                        report_id=report_id,
                        is_silenced=False,
                    )
                    imported += 1

            self.stdout.write(
                f'  {filename}: imported {imported}, skipped {skipped}'
            )
            total_imported += imported
            total_skipped += skipped

        self.stdout.write(self.style.SUCCESS(
            f'Done. Total imported: {total_imported}, skipped: {total_skipped}'
        ))
