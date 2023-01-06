# Dockerfile

FROM python:3.10-slim-bullseye

ENV MICRO_SERVICE=/home/app/microservice
ENV APP_USER=deterrers_user
# RUN addgroup -S $APP_USER && adduser -S $APP_USER -G $APP_USER
RUN addgroup $APP_USER && adduser $APP_USER --ingroup $APP_USER

RUN mkdir -p $MICRO_SERVICE
RUN mkdir -p $MICRO_SERVICE/static

# where the code lives
WORKDIR $MICRO_SERVICE

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

#copy project
COPY . $MICRO_SERVICE

# install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
COPY ./entrypoint.sh $MICRO_SERVICE
RUN chmod +x $MICRO_SERVICE/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/home/app/microservice/entrypoint.sh"]