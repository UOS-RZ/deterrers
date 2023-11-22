# Project Structure:

        project/                                            % main python package that holds all source code
            application/                                    % django project folder that will hold all the custom apps for the website executed in one docker container
                application/                                % django project configurations
                    ...
                main/                                       % main app that holds the DETERRERS website logic
                    api/                                    % API views for programmatic access to DETERRERS
                    core/                                   % modules that implement main logic
                        data_logic/                         % data-backend interfaces
                        fw/                                 % perimeter firewall interfaces
                        scanner/                            % vulnerability scanner interfaces
                        contracts.py                        % deployment specific conventions and policies
                        host.py                             % host object schema
                        risk_assessor.py                    % risk assessment module
                        rule_generator.py                   % host-based firewall rule generation module
                    management/                             % holds django commands
                        ...
                    static/                                 % static website content
                        ...
                    templates/                              % holds HTML templates of the DETERRERS website
                        ...
                    tests/                                  % holds the tests
                        ...
                    ...
                templates/                                  % project wide HTML templates
                    ...
                user/                                       % custom user app
                    ...
                Dockerfile                                  % dockerfile for the web app container
                Dockerfile-supercronic                      % dockerfile for the supercronic jobs container
                entrypoint.sh                               % entrypoint script that is executed by docker
                manage.py                                   % django utility for controling the app
                requirements.txt                            % python requirements
            nginx/                                          % nginx folder that holds all files for the nginx docker container
                deterrers_rz_uni-osnabrueck_de_interm.cer
                deterrers_rz_uni-osnabrueck_de.pem
                dhparam4096.pem
                Dockerfile                                  % dockerfile for the nginx container
                nginx.conf
            .dev.env                                        % environment variables for the development docker compose
            .template.prod.env                              % template for the production configuration file
            docker-compose.dev.yml                          % development docker compose config
            docker-compose.prod.yml                         % production docker compose config

                