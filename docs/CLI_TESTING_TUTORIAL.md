# DETERRERS CLI Testing Tutorial

This tutorial describes **every step** needed to set up and test the
DETERRERS CLI (`deterrers-cli`) against a local development instance of the
DETERRERS Django application backed by BlueCat IPAM **V2**.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Repository & Project Structure](#2-repository--project-structure)
3. [Environment Configuration (.dev.env)](#3-environment-configuration-devenv)
4. [Start the Development Containers](#4-start-the-development-containers)
5. [BlueCat UDF Configuration (Required for V2)](#5-bluecat-udf-configuration-required-for-v2)
6. [Create a Python Virtual Environment & Install CLI](#6-create-a-python-virtual-environment--install-cli)
7. [Create a Test User & Generate an API Token](#7-create-a-test-user--generate-an-api-token)
8. [Configure the CLI (~/.deterrers.yml)](#8-configure-the-cli-deterrersyml)
9. [Proxy Bypass (if applicable)](#9-proxy-bypass-if-applicable)
10. [CLI Commands Reference & Testing](#10-cli-commands-reference--testing)
11. [Example Full Workflow](#11-example-full-workflow)
12. [Host Status Lifecycle](#12-host-status-lifecycle)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. System Requirements

| Tool | Tested Version | Purpose |
|------|---------------|---------|
| Python 3 | 3.10+ | Virtual environment for CLI |
| Docker | 29.x | Runs the DETERRERS containers |
| Docker Compose (V2 plugin) | v5.x | Orchestrates dev services |
| pip | latest | Installs `deterrers-cli` |

Ensure Docker is running (`systemctl start docker` or equivalent) before
proceeding.

---

## 2. Repository & Project Structure

Clone or copy the DETERRERS repository. The relevant layout is:

```
deterrers/
  project/
    docker-compose.dev.yml      # Dev orchestration (3 services)
    .dev.env                    # Environment variables for dev
    application/
      Dockerfile                # Builds the Django image
      entrypoint.sh             # Runs migrations, collectstatic, etc.
      manage.py
      requirements.txt
      application/
        settings.py             # Django settings (DB, IPAM, LDAP, …)
      main/
        core/
          data_logic/
            blueCatV2_wrapper.py  # BlueCat V2 IPAM wrapper
            ipam_wrapper.py       # BlueCat V1 IPAM wrapper
    dev-db/                     # Persistent Postgres data (auto-created)
    dev-logs/                   # Application logs
```

### Docker Compose Services (`docker-compose.dev.yml`)

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `dev-web` | `deterrers-application` (built from `application/Dockerfile`) | 80 → 80 | Django dev server (`manage.py runserver`) |
| `postgres` | `postgres:17.2-bookworm` | 5432 (internal) | Vulnerability management database |
| `default` | `postgres:17.2-bookworm` | 5432 (internal) | Default Django database |

**Important:** The application code is baked into the Docker image at build
time (`/home/app/microservice`). The volume mount `.:/microservice:rw` is a
data mount, **not** the application code path. This means any code change
(e.g. in `blueCatV2_wrapper.py`) requires a **container rebuild**:

```bash
cd ~/deterrers/project
docker compose -f docker-compose.dev.yml up -d --build dev-web
```

---

## 3. Environment Configuration (.dev.env)

The file `project/.dev.env` configures the dev environment. Key variables:

```ini
# --- Django ---
xDEV_MODE="True"
DJANGO_DEBUG=True
MAINTENANCE_MODE="False"           # Must be "False" for CLI to work!
DJANGO_ALLOWED_HOSTS="localhost 127.0.0.1 vm305.rz.uni-osnabrueck.de …"

# --- Superuser (created automatically on first start) ---
DJANGO_SUPERUSER_USERNAME=deterrers-admin
DJANGO_SUPERUSER_PASSWORD="<password>"
DJANGO_SUPERUSER_EMAIL=nwintering@uos.de

# --- IPAM (BlueCat V2) ---
IPAM_TYPE="BlueCatV2"                                     # ← Must be BlueCatV2
IPAM_URL="https://proteus-clone.rz.uni-osnabrueck.de"    # ← BlueCat server URL
IPAM_USERNAME="deterrers"
IPAM_SECRET_KEY="<bluecat-api-key>"

# --- PostgreSQL ---
POSTGRES_USER="deterrers-admin"
POSTGRES_PASSWORD="<db-password>"
POSTGRES_HOST="postgres"
POSTGRES_PORT="5432"
POSTGRES_DB="vulnerability-db"

# --- Firewall (use DUMMY for testing) ---
FIREWALL_TYPE="DUMMY"

# --- Scanner ---
SCANNER_DUMMY="False"
SCANNER_HOSTNAME="hulk.rz.uni-osnabrueck.de"

# --- LDAP ---
USE_LDAP="True"
LDAP_AUTH_URL="ldaps://ldap.uni-osnabrueck.de"
```

**Critical settings to verify:**

- `IPAM_TYPE` must be `"BlueCatV2"` (not `"BlueCat"`)
- `MAINTENANCE_MODE` must be `"False"` — otherwise the API returns `503`
- `FIREWALL_TYPE` can be `"DUMMY"` for local testing (no real firewall needed)
- `IPAM_URL` must be reachable from the container
- `IPAM_SECRET_KEY` must be a valid API key for the `IPAM_USERNAME` on the
  BlueCat server

---

## 4. Start the Development Containers

```bash
cd ~/deterrers/project

# Build & start all services
docker compose -f docker-compose.dev.yml up -d --build
```

Wait for all containers to become healthy (~15–30 seconds):

```bash
docker compose -f docker-compose.dev.yml ps
```

Expected output (all services `Up (healthy)`):

```
NAME                  STATUS
project-default-1     Up (healthy)
project-dev-web-1     Up (healthy)
project-postgres-1    Up (healthy)
```

If `dev-web` shows `Up (health: starting)`, wait a few more seconds and
check again. The entrypoint runs migrations and `collectstatic` before the
Django server starts.

### Check Logs for Errors

```bash
docker compose -f docker-compose.dev.yml logs dev-web --tail 50
```

Look for `Starting development server at http://0.0.0.0:80/`. If you see
database connection errors, ensure the Postgres containers are healthy first.

---

## 5. BlueCat UDF Configuration (Required for V2)

> **This is a one-time configuration change on the BlueCat server.** Without
> this step, the `update` and `set` CLI commands will fail with a
> `500 Internal Server Error`.

### Background

The BlueCat V2 `PUT /addresses/{id}` endpoint validates **all** UDF
(User Defined Field) definitions marked as `required`. The IPv4Address
entity type in BlueCat has three UDF fields that are `required` by default:

| UDF Name | Description |
|----------|-------------|
| `admin_name` | Administrative contact name |
| `admin_phone` | Administrative contact phone |
| `admin_email` | Administrative contact email |

Many existing IPv4Address entities have `None` (null) values for these
fields. When DETERRERS reads an entity (GET), the response contains these
`None` values. When it writes the entity back (PUT) in a read-modify-write
cycle, BlueCat rejects the request because the `required` validation fails
on those `None` values.

**The fix:** Change these three UDF definitions from `required: true` to
`required: false` via the BlueCat V2 API.

### Step 5a: Find the UDF Definition IDs

Open a Django shell inside the container:

```bash
docker exec -it project-dev-web-1 python manage.py shell
```

Run the following Python code to discover the UDF definitions for
`IPv4Address`:

```python
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BLUECAT_URL = "https://proteus-clone.rz.uni-osnabrueck.de"

# Authenticate and get a token
login_resp = requests.post(
    f"{BLUECAT_URL}/api/v2/sessions",
    json={"username": "deterrers", "password": "<IPAM_SECRET_KEY from .dev.env>"},
    verify=False
)
token = login_resp.json()["basicAuthenticationCredentials"]
headers = {"Authorization": f"Basic {token}"}

# List all UDF definitions for IPv4Address that are required
resp = requests.get(
    f"{BLUECAT_URL}/api/v2/userDefinedFieldDefinitions",
    params={"limit": 100},
    headers=headers,
    verify=False
)

for udf in resp.json().get("data", []):
    if udf.get("required") and udf.get("resourceType") == "IPv4Address":
        print(f"  ID: {udf['id']}, Name: {udf['name']}, Required: {udf['required']}")
```

This will print something like:

```
  ID: 3571715, Name: admin_name, Required: True
  ID: 3571716, Name: admin_phone, Required: True
  ID: 3571717, Name: admin_email, Required: True
```

Note the **IDs** — they are specific to your BlueCat server instance.

### Step 5b: Change `required` to `false`

Still in the Django shell (or in a new session), run:

```python
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BLUECAT_URL = "https://proteus-clone.rz.uni-osnabrueck.de"

login_resp = requests.post(
    f"{BLUECAT_URL}/api/v2/sessions",
    json={"username": "deterrers", "password": "<IPAM_SECRET_KEY from .dev.env>"},
    verify=False
)
token = login_resp.json()["basicAuthenticationCredentials"]
headers = {"Authorization": f"Basic {token}"}

# Replace these IDs with the ones from Step 5a
udf_ids = [3571715, 3571716, 3571717]

for udf_id in udf_ids:
    # Read current definition
    current = requests.get(
        f"{BLUECAT_URL}/api/v2/userDefinedFieldDefinitions/{udf_id}",
        headers=headers,
        verify=False
    ).json()

    # Set required to False
    current["required"] = False

    # Write back
    resp = requests.put(
        f"{BLUECAT_URL}/api/v2/userDefinedFieldDefinitions/{udf_id}",
        json=current,
        headers=headers,
        verify=False
    )
    print(f"UDF {udf_id} ({current['name']}): {resp.status_code}")
```

Expected output:

```
UDF 3571715 (admin_name): 200
UDF 3571716 (admin_phone): 200
UDF 3571717 (admin_email): 200
```

### Step 5c: Verify the Change

```python
resp = requests.get(
    f"{BLUECAT_URL}/api/v2/userDefinedFieldDefinitions",
    params={"limit": 100},
    headers=headers,
    verify=False
)
for udf in resp.json().get("data", []):
    if udf.get("resourceType") == "IPv4Address" and udf["name"] in ("admin_name", "admin_phone", "admin_email"):
        print(f"  {udf['name']}: required={udf['required']}")
```

Expected output — all three must be `False`:

```
  admin_name: required=False
  admin_phone: required=False
  admin_email: required=False
```

Type `exit()` to leave the Django shell.

> **Note:** This change persists on the BlueCat server. It only needs to be
> done once per BlueCat instance. If you are testing against a different
> BlueCat server (e.g. production), repeat this step on that server.

---

## 6. Create a Python Virtual Environment & Install CLI

```bash
# Create virtual environment (outside the project directory)
python3 -m venv ~/deterrers-venv

# Activate it
source ~/deterrers-venv/bin/activate

# Install the CLI tool (includes deterrers-api as dependency)
pip install deterrers-cli
```

Verify installation:

```bash
deterrers-cli --help
```

Installed versions used in this tutorial:
- `deterrers-cli` 0.8
- `deterrers-api` 0.5

---

## 7. Create a Test User & Generate an API Token

The CLI authenticates via a Django REST Framework auth token. You need a
user in the DETERRERS system.

### Option A: Use an existing LDAP user

If `USE_LDAP="True"` in `.dev.env`, users are created on first login via the
web interface. Navigate to `http://127.0.0.1` in a browser and log in with
LDAP credentials. After that, the user exists in Django.

### Option B: Create a user manually

```bash
docker exec -it project-dev-web-1 python manage.py shell -c "
from user.models import MyUser
user, created = MyUser.objects.get_or_create(
    username='pmaskanakis',
    defaults={'email': 'pmaskanakis@uos.de', 'is_active': True}
)
if created:
    user.set_password('testpassword')
    user.save()
    print('User created')
else:
    print('User already exists')
"
```

### Generate the API token

```bash
docker exec -it project-dev-web-1 python manage.py shell -c "
from rest_framework.authtoken.models import Token
from user.models import MyUser

user = MyUser.objects.get(username='pmaskanakis')
token, created = Token.objects.get_or_create(user=user)
print('Token:', token.key)
"
```

Save the printed token — you will need it in the next step.

> **Note:** If you see `MyUser matching query does not exist`, the user has
> not been created yet. Use Option A or B above first.

---

## 8. Configure the CLI (~/.deterrers.yml)

Create the file `~/.deterrers.yml`:

```yaml
url: http://127.0.0.1
token: <your-token-from-step-7>
```

Example:

```yaml
url: http://127.0.0.1
token: e525594ceae0627e85e79daa041b487a3c5f3de8
```

The CLI reads this file automatically. The `url` points to the dev-web
container which is exposed on port 80.

---

## 9. Proxy Bypass (if applicable)

If your machine routes traffic through an HTTP proxy, requests to
`127.0.0.1` may be sent through the proxy and fail. Bypass it:

```bash
export no_proxy="vm305.rz.uni-osnabrueck.de,localhost,127.0.0.1"
```

Add this to your `~/.bashrc` to make it permanent:

```bash
echo 'export no_proxy="vm305.rz.uni-osnabrueck.de,localhost,127.0.0.1"' >> ~/.bashrc
```

> **Tip:** If `deterrers-cli hosts` hangs or returns a connection error,
> the proxy bypass is likely missing.

---

## 10. CLI Commands Reference & Testing

Always ensure your venv is activated:
```bash
source ~/deterrers-venv/bin/activate
```

### List All Hosts

```bash
deterrers-cli hosts
```

Returns a JSON array of all hosts managed by the authenticated user.

### Get Host Details

```bash
deterrers-cli get <IP>
```

Example:
```bash
deterrers-cli get 131.173.61.9
```

Returns detailed JSON for the host, including status, service profile, firewall, admin IDs, and host-based policies. Returns `null` if the host is not found.

### Add a Host

```bash
deterrers-cli add -a <admin_username> -p <profile> <IP>
```

Options:
- `-a, --admin` (required): Admin username (can be specified multiple times for multiple admins)
- `-p, --profile`: One of `http`, `ssh`, `http+ssh`, `multipurpose`, or empty
- `-f, --firewall`: One of `ufw`, `firewalld`, `nftables`, or empty
- `--register / --no-register`: Register immediately after adding
- `--skip-scan / --no-skip-scan`: Skip initial security scan (only with `--register`)

Example:
```bash
deterrers-cli add -a pmaskanakis -p "http+ssh" 131.173.61.9
```

### Update a Host

```bash
deterrers-cli update --profile <profile> <IP>
```

Options:
- `-p, --profile`: Service profile to set
- `-f, --firewall`: Host firewall to set
- `-a, --admin`: Admin username(s)

Example:
```bash
deterrers-cli update --profile "http" 131.173.61.9
```

### Set (Add or Update)

Like `add`, but if the host already exists, it updates it instead:

```bash
deterrers-cli set -a <admin> -p <profile> <IP>
```

Example:
```bash
deterrers-cli set -a pmaskanakis -p "ssh" 131.173.61.9
```

### Delete a Host

```bash
deterrers-cli delete <IP>
```

Example:
```bash
deterrers-cli delete 131.173.61.9
```

### Register (Activate Firewall Profile)

```bash
deterrers-cli action register --skip-scan <IP>
```

Use `--skip-scan` to skip the vulnerability scan, or `--no-skip-scan` to run it.

Example:
```bash
deterrers-cli action register --skip-scan 131.173.61.9
```

After registration, the host status changes from `Unregistered` to `Online`.

### Block a Host

```bash
deterrers-cli action block <IP>
```

Example:
```bash
deterrers-cli action block 131.173.61.9
```

After blocking, the host status changes to `Blocked`.

---

## 11. Example Full Workflow

```bash
# 1. List current hosts
deterrers-cli hosts

# 2. Add a new host with HTTP+SSH profile
deterrers-cli add -a pmaskanakis -p "http+ssh" 131.173.61.9

# 3. Verify it was added
deterrers-cli get 131.173.61.9

# 4. Register the host in the perimeter firewall (skip scan)
deterrers-cli action register --skip-scan 131.173.61.9

# 5. Verify status is now "Online"
deterrers-cli get 131.173.61.9

# 6. Update the profile to HTTP only
deterrers-cli update --profile "http" 131.173.61.9

# 7. Block the host
deterrers-cli action block 131.173.61.9

# 8. Delete the host
deterrers-cli delete 131.173.61.9

# 9. Confirm deletion
deterrers-cli get 131.173.61.9   # should return null
```

---

## 12. Host Status Lifecycle

```
(not in DETERRERS)
        |
      add/set
        |
        v
  Unregistered  --action register-->  Online
        ^                                |
        |                          action block
      add/set                           |
        |                               v
        +-------- delete <---------  Blocked
```

---

## 13. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Connection refused` or CLI hangs | Proxy intercepting `127.0.0.1` | Set `export no_proxy="…,127.0.0.1"` (Step 9) |
| `401 Unauthorized` | Token invalid or expired | Regenerate the token (Step 7) |
| `503 Service Unavailable` | Maintenance mode enabled | Set `MAINTENANCE_MODE="False"` in `.dev.env`, rebuild |
| `500 Internal Server Error` on `update`/`set` | BlueCat UDF `required` fields not changed | Follow Step 5 to set `required=False` |
| `404 Not Found` on `update`/`get` | Host not in DETERRERS | Use `add` or `set` first |
| `null` response from `get` | IP not managed in DETERRERS | Expected — host does not exist yet |
| `MyUser matching query does not exist` | User not created in Django | Log in via web UI or create manually (Step 7) |
| `dev-web` container not healthy | Migrations or DB not ready | Check logs: `docker compose -f docker-compose.dev.yml logs dev-web` |
| Code changes not taking effect | Docker image uses baked code | Rebuild: `docker compose -f docker-compose.dev.yml up -d --build dev-web` |
| BlueCat SSL errors in container logs | Self-signed cert on proteus-clone | `verify=False` is set in `blueCatV2_wrapper.py` for testing |

### Rebuilding After Code Changes

Any change to files under `application/` requires a container rebuild:

```bash
cd ~/deterrers/project
docker compose -f docker-compose.dev.yml up -d --build dev-web
```

Wait ~15 seconds for the container to become healthy, then test again.
