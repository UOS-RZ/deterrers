FROM nginx:1.21-alpine

RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d

RUN mkdir -p /etc/ssl/certs
RUN mkdir -p /etc/ssl/private
COPY /etc/ssl/certs/deterrers_rz_uni-osnabrueck_de.pem /etc/ssl/certs/deterrers_rz_uni-osnabrueck_de.pem
COPY /etc/ssl/private/deterrers-server-key.pem /etc/ssl/private/deterrers-server-key.pem