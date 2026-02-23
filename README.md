# DETERRERS

This is the repository for the <em>automate</em>D<em> n</em>ET<em>work p</em>ER<em>imeter th</em>RE<em>at p</em>R<em>evention </em>S<em>ystem</em> (DETERRERS) project.

It started as the master's thesis of nwintering and is now maintained as an open source project.

A paper on the project was published in the Proceedings of the 1st Workshop on Network Security Operations in conjunction with the 20th International Conference on Network and Service Management (CNSM) and can be accessed [here](https://opendl.ifip-tc6.org/db/conf/cnsm/cnsm2024/1571071907.pdf).


## Test Setup

To test the user interface of DETERRERS, perform the following steps below. This will start a DETERRERS instance without a real data backend, vulnerability scanner or perimeter firewall. All changes are mocked locally.

### Requirements:

- Docker + Docker Compose + Git

#### Install Git

```bash
sudo apt update
sudo apt install -y git
```

#### Install Docker

Docker needs to be installed properly. See the official [Docker installation guide](https://docs.docker.com/engine/install/). For Linux systems using apt, run:

```bash
sudo apt install -y docker.io
```

After installation, follow the [post-install steps](https://docs.docker.com/engine/install/linux-postinstall/) to use Docker without `sudo`.

#### Install Docker Compose

```bash
sudo apt install -y docker-compose
```

### Step-by-step Tutorial:

1. **Clone the repository**

   ```bash
   git clone https://github.com/UOS-RZ/deterrers.git
   ```

2. **Navigate to the project directory**

   ```bash
   cd deterrers/project
   ```

3. **Fill out the `.env.dev` configuration file**

   Edit the `.env.dev` file using nano or your preferred editor:

   ```bash
   nano .env.dev
   ```

   Or using VS Code:

   ```bash
   code .env.dev
   ```

   At a minimum, configure the following:

   ```bash
   DOMAIN_NAME=localhost
   DJANGO_ALLOWED_HOSTS=localhost 127.0.0.1 0.0.0.0 [::1]
   
   POSTGRES_USER=deterrers
   POSTGRES_PASSWORD=deterrers
   POSTGRES_DB=deterrers
   POSTGRES_HOST=postgres
   POSTGRES_PORT=5432
   
   DJANGO_SUPERUSER_USERNAME=admin
   DJANGO_SUPERUSER_PASSWORD=admin
   ```

4. **Build and create the Docker containers**

   ```bash
   docker compose -f docker-compose.dev.yml create --build
   ```

5. **Start the containers**

   ```bash
   docker compose -f docker-compose.dev.yml start
   ```

6. **Verify the setup**

   Check the running containers and their ports:

   ```bash
   docker compose -f docker-compose.dev.yml ps
   ```

   DETERRERS should now be running on port 80. Log in with the credentials specified in your `.env.dev` file (`DJANGO_SUPERUSER_USERNAME` and `DJANGO_SUPERUSER_PASSWORD`).

7. **Interact with DETERRERS**

   You can now interact freely with DETERRERS by adding any valid IP address.

8. **Stop the containers**

   When finished, stop and remove the containers:

   ```bash
   docker compose -f docker-compose.dev.yml down --remove-orphans
   ```


## Deployment

A deployment is currently only possible in conjunction with the following components and API endpoints:

    Data Backend: BlueCat IP Address Manager with the REST API version 1

    Vulnerability Scanner: Greenbone GMP version 22.4

    Perimeter Firewall: Palo Alto with REST and XML API version v10.1 or FortiGate with ForitOS 7.4.3 via REST API

    User/Access Management: LDAP directory

The nginx-Dockerfile expects a `dhparam4096.pem`-file and a `nginx.conf`-file under `project/nginx/`.

The Django app expects the vulnerability scanners public SSH-key under `project/application/main/static/files/greenbone-scanner.key`.

## Configuration

- access credentials for external endpoints (IPAM, Vulnerability Scanner, perimeter FW, LDAP) are set in .env-files
- general settings/"contracts" are defined as Enums in <code>project/application/main/core/contracts.py</code>
- interface-specific settings (e.g. Greenbone GMP configurations UUIDs or AddressGroup-names of the perimeter FW) are defined with the respective API-wrappers
- if the vulnerability scanner should perform authenticated scans on target its public key can be provided in <code>project/application/main/static/files/</code>


## Development

### Linter:

- flake8
