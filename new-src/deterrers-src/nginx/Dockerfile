FROM nginx:1.21-alpine

RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d

COPY dhparam4096.pem .
COPY deterrers_rz_uni-osnabrueck_de_interm.cer .