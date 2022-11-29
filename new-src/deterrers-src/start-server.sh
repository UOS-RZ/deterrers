#!/usr/bin/env bash
# start-server.sh
# if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ] ; then
#     (cd deterrerssite; python manage.py createsuperuser --no-input)
# fi
(cd deterrerssite; gunicorn deterrerssite.wsgi --user www-data --bind 0.0.0.0:8010 --workers 13) &
nginx -g "daemon off;"