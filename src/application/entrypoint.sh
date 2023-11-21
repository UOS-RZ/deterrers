#!/bin/bash

python manage.py check --deploy
python manage.py makemigrations --noinput
python manage.py makemigrations main --noinput
python manage.py makemigrations myuser --noinput
python manage.py migrate --noinput
python manage.py collectstatic --noinput
python manage.py add_ssh_fingerprints
python manage.py createsuperuser --noinput || true # suppress error msg that is thrown if superuser already exists
                    
exec "$@"