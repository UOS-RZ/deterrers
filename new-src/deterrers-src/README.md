# Project Structure:

        deterrers/                              % main python package that holds all source code
            __init__.py                         % makes this folder a package
            manage.py                           % django utility for controling the app
            django_project/                     % subpackage that holds the central logic for the web app
                deterressite/                   % django project folder that will hold all the custom apps for the website
                    __init__.py
                    deterrerssite/
                        ...
                    hostadmin/
                        ...
                    ...