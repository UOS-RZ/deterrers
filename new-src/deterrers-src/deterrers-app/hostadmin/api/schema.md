# DETERRERS API Prototyp Schema:

## Authorization:

Authorization is done by a user-specific token. It should be provided by HTTP header of form:

    Authorization: Token <user_token>


## Get all hosts of admin:

    /hostadmin/api/hosts/:
        get:
            description: 'API method for getting hosts of admin.
            Supports GET.'
            parameters: []
            responses:
                '200':
                content:
                    application/json:
                    schema:
                        type: array
                        items: {}
                description: ''

Example:

Get all hosts that are added for me in DETERRERS:

    curl -X GET -H 'Authorization: Token <user_token>' https://deterrers.rz.uos.de:443/hostadmin/api/hosts/

## Edit a host:

    /hostadmin/api/host/:
        patch:
            description: 'API method for setting internet service profile and/or firewall program. If a field should not be set, it can be omitted in the request body.
            Supports PATCH.'
            parameters: []
            requestBody:
                content:
                application/json:
                    schema: {
                        'ipv4_addr' : <ip>,
                        'service_profile' : <'HTTP'|'SSH'|'HTTP+SSH'|'Multipurpose'>,
                        'fw' : <'UFW'|'FirewallD'|'nftables'>
                    }
            responses:
                '200':

Example:

Edit only the internet service profile of host 0.0.0.0 to 'HTTP':

    curl -X PATCH -H 'Authorization: Token <user_token>' -H "Content-Type: application/json" -d '{"ipv4_addr" : "0.0.0.0", "service_provile" : "HTTP"}' https://deterrers.rz.uos.de:443/hostadmin/api/host/

## Register/Block one or more hosts:

    /hostadmin/api/action/:
        post:
            description: 'API method for performing an action on hosts. Not really RESTful but necessary. Actions are 'register' and 'block'.
            Supports POST.'
            parameters: []
            requestBody:
                content:
                application/json:
                    schema: {
                        'action' : <'register'|'block'>,
                        'ipv4_addrs' : [<ip>,]
                    }
            responses:
                '201':

Example:

Start registration of host 0.0.0.0:

    curl -X POST -H 'Authorization: Token <user_token>' -H "Content-Type: application/json" -d '{"action" : "register", "ipv4_addrs" : ["0.0.0.0"]}' https://deterrers.rz.uos.de:443/hostadmin/api/action/