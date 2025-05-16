# DETERRERS

This is the repository for the <em>automate</em>D<em> n</em>ET<em>work p</em>ER<em>imeter th</em>RE<em>at p</em>R<em>evention </em>S<em>ystem</em> (DETERRERS) project.

It started as the master's thesis of nwintering and is now maintained as an open source project.

A paper on the project was published in the Proceedings of the 1st Workshop on Network Security Operations in conjunction with the 20th International Conference on Network and Service Management (CNSM) and can be accessed [here](https://opendl.ifip-tc6.org/db/conf/cnsm/cnsm2024/1571071907.pdf).


## Test Setup

To test the user interface of DETERRERS, perform the following steps below. This will start a DETERRERS instance without a real data backend, vulnerability scanner or perimeter firewall. All changes are mocked locally.

### Requirements:

- Docker + Docker Compose

### Step-by-step Tutorial:

1. Fill out the <code>.env.dev</code>-configuration-file:

    1.1 Add the domain name to <code>DJANGO_ALLOWED_HOSTS</code> and <code>DOMAIN_NAME</code>.

2. Build and create the docker containers by running

        docker compose -f docker-compose.dev.yml create --build

    inside <code>deterrers/project/</code>.

3. Start containers by running

        docker compose -f docker-compose.dev.yml start

    inside <code>deterrers/project/</code>.

4. DETERRERS is now running on port 80. You should be able to log in with the credentials (<code>DJANGO_SUPERUSER_USERNAME</code>, <code>DJANGO_SUPERUSER_PASSWORD</code>) from the configuration file.

5. You can interact freely with DETERRERS by adding any valid IP address.

6. Stop containers by running

        docker compose -f docker-compose.dev.yml down --remove-orphans

    inside <code>deterrers/project/</code>.


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
