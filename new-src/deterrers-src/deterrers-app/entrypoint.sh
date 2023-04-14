#!/bin/bash

python manage.py makemigrations --noinput
python manage.py makemigrations hostadmin --noinput
python manage.py makemigrations myuser --noinput
python manage.py migrate --noinput
python manage.py collectstatic --noinput
python manage.py add_ssh_fingerprints
python manage.py createsuperuser --noinput || true # suppress error msg that is thrown if superuser already exists

# crontab -u ${APP_USER} -l | { cat; echo "*/1 * * * * python ${MICRO_SERVICE}/manage.py commit_to_perimeter_fw"; } | crontab -u ${APP_USER} -
                    
exec "$@"