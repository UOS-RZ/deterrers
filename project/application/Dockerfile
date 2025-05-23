# Dockerfile

FROM python:3.13-slim-bullseye

# install openssh-client for ssh-keyscan
RUN apt-get update
RUN apt-get install -y openssh-client

ENV MICRO_SERVICE=/home/app/microservice
RUN mkdir -p $MICRO_SERVICE
RUN mkdir -p $MICRO_SERVICE/static
RUN mkdir -p $MICRO_SERVICE/logs
RUN mkdir -p $MICRO_SERVICE/db

# where the code lives
WORKDIR $MICRO_SERVICE

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
COPY ./requirements.txt $MICRO_SERVICE
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
COPY ./entrypoint.sh $MICRO_SERVICE
RUN chmod +x $MICRO_SERVICE/entrypoint.sh

# copy project
COPY . $MICRO_SERVICE

# create APP_USER, make APP_USER owner of the app directory and switch to APP_USER
ENV APP_USER=deterrers_user
RUN addgroup $APP_USER && adduser $APP_USER --ingroup $APP_USER
RUN chown -R ${APP_USER}:${APP_USER} ${MICRO_SERVICE}
RUN chown -R ${APP_USER}:${APP_USER} ${MICRO_SERVICE}/static
RUN chown -R ${APP_USER}:${APP_USER} ${MICRO_SERVICE}/logs
RUN chown -R ${APP_USER}:${APP_USER} ${MICRO_SERVICE}/db
USER ${APP_USER}:${APP_USER}

ENTRYPOINT ["/bin/bash", "/home/app/microservice/entrypoint.sh"]