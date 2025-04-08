FROM nginx:latest

RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d

COPY dhparam4096.pem /etc/nginx/dhparam4096.pem
