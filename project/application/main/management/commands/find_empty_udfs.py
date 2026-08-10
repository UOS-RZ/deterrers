from django.core.management.base import BaseCommand
from django.conf import settings

if settings.IPAM_TYPE == "DUMMY":
    from main.core.data_logic.data_mock \
        import DataMockWrapper as IPAMWrapper
elif settings.IPAM_TYPE == "BlueCatV1":
    from main.core.data_logic.ipam_wrapper \
        import ProteusIPAMWrapper as IPAMWrapper
elif settings.IPAM_TYPE == "BlueCatV2":
    from main.core.data_logic.blueCatV2_wrapper \
        import ProteusV2IPAMWrapper as IPAMWrapper

REQUIRED_UDF_FIELDS = ("admin_name", "admin_email", "admin_phone")


class Command(BaseCommand):
    help = "Find hosts that have empty required UDFs (admin_name, admin_email, admin_phone)."

    def handle(self, *args, **options):
        with IPAMWrapper(
            settings.IPAM_USERNAME,
            settings.IPAM_SECRET_KEY,
            settings.IPAM_URL,
        ) as ipam:
            if not ipam.enter_ok:
                self.stderr.write("Could not connect to IPAM.")
                return

            seen_ids = set()
            results = []

            admin_names = ipam.get_all_admin_names()
            self.stdout.write(f"Checking hosts across {len(admin_names)} admin tag(s)...")

            for admin_name in admin_names:
                for host in ipam.get_hosts_of_admin(admin_name):
                    if host.entity_id in seen_ids:
                        continue
                    seen_ids.add(host.entity_id)

                    # Fetch the raw address object so we can inspect the actual
                    # UDF values — MyHost does not carry admin_* UDF fields.
                    raw = ipam.client.http_get(f"/addresses/{host.entity_id}")
                    udf = raw.get("userDefinedFields") or {}
                    missing = [f for f in REQUIRED_UDF_FIELDS if not udf.get(f)]
                    if missing:
                        results.append((str(host.ipv4_addr), host.entity_id, missing))

            self.stdout.write(f"Checked {len(seen_ids)} unique host(s).\n")

            if results:
                self.stdout.write(
                    self.style.WARNING(
                        f"Found {len(results)} host(s) with empty required UDFs:"
                    )
                )
                for ip, entity_id, fields in results:
                    self.stdout.write(
                        f"  {ip} (id={entity_id}): missing {', '.join(fields)}"
                    )
            else:
                self.stdout.write(
                    self.style.SUCCESS("All hosts have required UDFs set.")
                )
