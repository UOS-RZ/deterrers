# DETERRERS

This is the repository for the <em>automate</em>D<em> n</em>ET<em>work p</em>ER<em>imeter th</em>RE<em>at p</em>R<em>evention </em>S<em>ystem</em> (DETERRERS) project.

It started as the master's thesis of nwintering and is now maintained as an open source project.


## Test Setup

To test the user interface of DETERRERS, perform the following steps below. This will start a DETERRERS instance without a real data backend, vulnerability scanner or perimeter firewall. All changes are mocked locally.

### Requirements:

- Docker + Docker Compose

### Step-by-step Tutorial:

1. Fill out the <code>.env.dev</code>-configuration-file:

    1.1 Add the domain name to <code>DJANGO_ALLOWED_HOSTS</code> and <code>DOMAIN_NAME</code>.

2. Build and create the docker containers by running

        docker compose -f docker-compose.dev.yml create --build

    inside <code>deterrers/src/</code>.

3. Start containers by running

        docker compose -f docker-compose.dev.yml start

    inside <code>deterrers/src/</code>.

4. DETERRERS is now running on port 80. You should be able to log in with the credentials (<code>DJANGO_SUPERUSER_USERNAME</code>, <code>DJANGO_SUPERUSER_PASSWORD</code>) from the configuration file.

5. You can interact freely with DETERRERS by adding any valid IP address.

6. Stop containers by running

        docker compose -f docker-compose.dev.yml down --remove-orphans

    inside <code>deterrers/src/</code>.


## Deployment

A deployment is currently only possible in conjunction with the following components and API endpoints:

    Data Backend: BlueCat IP Address Manager with the REST API version 1

    Vulnerability Scanner: Greenbone GMP version 22.4

    Perimeter Firewall: Palo Alto with REST and XML API version v10.1

    User/Access Management: LDAP directory

## Configuration

- access credentials for external endpoints (IPAM, Vulnerability Scanner, perimeter FW, LDAP) are set in .env-files
- general settings/"contracts" are defined as Enums in <code>src/deterrers-app/hostadmin/core/contracts.py</code>
- interface-specific settings (e.g. Greenbone GMP configurations UUIDs or AddressGroup-names of the Palo Alto FW) are defined with the respective API-wrappers


## Development

### Linter:

- flake8