#!/bin/bash

python manage.py check --deploy
# python manage.py makemigrations --noinput
# python manage.py makemigrations main --noinput
# python manage.py makemigrations user --noinput
# python manage.py makemigrations vulnerability_mgmt --noinput
python manage.py migrate --noinput
python manage.py migrate --database=vulnerability_mgmt
python manage.py collectstatic --noinput
python manage.py clearsessions
python manage.py add_ssh_fingerprints
python manage.py createsuperuser --noinput || true # suppress error msg that is thrown if superuser already exists
                    
exec "$@"