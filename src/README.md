# Project Structure:

        src/                                                % main python package that holds all source code
            deterrers-app/                                  % django project folder that will hold all the custom apps for the website executed in one docker container
                deterressite/                               % django project configurations
                    ...
                hostadmin/                                  % main app that holds the DETERRERS website logic
                    core/
                        ...
                    management/                             % holds django commands
                        ...
                    templates/                              % holds HTML templates of the DETERRERS website
                        ...
                    tests/                                  % holds the tests
                        ...
                    ...
                myuser/                                     % custom user app
                    ...
                templates/
                    registrations/                          % HTML templates for login and logout
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
            .env.dev                                        % environment variables for the development docker compose
            docker-compose.dev.yml                          % development docker compose config
            docker-compose.prod.yml                         % production docker compose config

                