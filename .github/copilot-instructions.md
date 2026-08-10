# DETERRERS – Copilot Workspace Instructions

DETERRERS is a Django-based **automated network perimeter threat prevention system**. It integrates with external IPAM (BlueCat), perimeter firewalls (Palo Alto, FortiGate), and vulnerability scanners (Greenbone GVM) via a plugin architecture of abstract base classes.

## Architecture

All source code lives under `project/application/`. See [project/README.md](../project/README.md) for the full directory map.

| Component | Path | Role |
|-----------|------|------|
| `main` app | `main/` | Core host management, views, API, webhooks |
| `user` app | `user/` | Custom user model extending `AbstractUser` |
| `vulnerability_mgmt` app | `vulnerability_mgmt/` | Scan result storage (separate DB) |
| IPAM backends | `main/core/data_logic/` | BlueCat V1/V2, DUMMY mock |
| Firewall backends | `main/core/fw/` | Palo Alto, FortiGate, DUMMY mock |
| Scanner backends | `main/core/scanner/` | Greenbone GVM, DUMMY mock |
| Host model | `main/core/host.py` | `MyHost` – internal host representation |
| Enums / contracts | `main/core/contracts.py` | `HostStatus`, `HostServiceProfile`, `HostFW`, policy enums |
| Rule generator | `main/core/rule_generator.py` | `HostBasedPolicy` – host-based FW rules |
| Risk assessor | `main/core/risk_assessor.py` | CVSS-based risk scoring |

**Backend selection** is settings-driven at import time:
```python
if settings.IPAM_TYPE == "BlueCatV2":
    from main.core.data_logic.blueCatV2_wrapper import ProteusV2IPAMWrapper as IPAMWrapper
elif settings.IPAM_TYPE == "DUMMY":
    from main.core.data_logic.data_mock import DataMockWrapper as IPAMWrapper
```
`IPAM_TYPE`, `FIREWALL_TYPE`, and `SCANNER_DUMMY` env vars control which backend is active.

## Build & Test

All application code is **baked into the Docker image** (not volume-mounted). Every code change requires a rebuild:

```bash
cd deterrers/project

# First run / full start
docker compose -f docker-compose.dev.yml up -d --build

# Rebuild only the web container after code changes
docker compose -f docker-compose.dev.yml up -d --build dev-web

# Tail logs (wait ~15 s after rebuild for container to become healthy)
docker compose -f docker-compose.dev.yml logs dev-web --tail 50

# Run Django tests
docker compose -f docker-compose.dev.yml exec dev-web python manage.py test
```

See [CLI_TESTING_TUTORIAL.md](../CLI_TESTING_TUTORIAL.md) for end-to-end CLI testing against the dev instance.

## Conventions

### External service wrappers use context managers
Every IPAM/FW/scanner wrapper implements `__enter__`/`__exit__`. Always use them with `with`:
```python
with IPAMWrapper(username, password, url) as ipam:
    host = ipam.get_host_info_from_ip("1.2.3.4")
```
`enter_ok` is set inside `__enter__` and checked in `__exit__` before attempting logout.

### IPv4 addresses are escaped in URLs
Dots are replaced with underscores in all URL patterns. A custom path converter `IPPathConverter` handles the conversion. Example: `1.2.3.4` → `/hostadmin/host/1_2_3_4/`.

### IPAM host metadata stored as User-Defined Fields
Deterrers-specific state (`deterrers_status`, `deterrers_fw`, `deterrers_service_profile`, `deterrers_rules`, `comment`) is stored as UDFs on the `IPv4Address` object in BlueCat. There are no native BAM fields for these.

### Firewall rules serialised as JSON in a single UDF
`host_based_policies` is a list of `HostBasedPolicy` objects, serialised to a JSON array of strings via `policy.to_string()` and stored in the `deterrers_rules` UDF. Parse back with `HostBasedPolicy.from_string()`.

### Tag hierarchy defines admin ownership
```
TagGroup "Deterrers Host Admins"
└── Tag "<Department>"        ← department tag
    └── Tag "<admin_username>" ← admin tag
```
The tag group name must match exactly (case-sensitive). Admin access to a host is determined by linked tags in the IPAM, not by Django RBAC.

### Dual-database architecture
Two PostgreSQL databases:
- `default` – Django ORM (users, sessions, auth)
- `vulnerability_mgmt` – scan results

A `DatabaseRouter` in `application/routers/db_router.py` routes models automatically. When running migrations, both databases must be migrated:
```bash
python manage.py migrate --database=vulnerability_mgmt
```

### REST API uses token authentication
DRF token auth; no session cookies. Header format: `Authorization: Token <token>`.

## Critical Pitfalls

**BlueCat V2 PUT requires all UDF fields** – `PUT /addresses/{id}` fails on entities with `NULL` required UDFs. The `update_host_info` method works around this by reading current state first, then spreading existing UDFs before overwriting only Deterrers-owned fields.

**TagGroup name is case-sensitive** – `"Deterrers Host Admins"` must exist in BAM exactly as written before any admin operation works.

**`verify=False` in dev only** – `Client(url, verify=False)` disables TLS cert verification. Do not use in production.

**Maintenance mode blocks the API** – if `MAINTENANCE_MODE="True"`, all endpoints return 503, including the CLI and API.

**Python versions differ** – the host venv uses Python 3.10; the Docker container uses Python 3.13. `bluecat-libraries` is only installed inside Docker.

**Host status is not directly settable** – `HostStatus` transitions are triggered by scanner webhook callbacks and firewall sync operations, not by directly writing a status value.
