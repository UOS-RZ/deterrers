
# install Nginx and copy config file
RUN apt-get update && apt-get install nginx vim -y --no-install-recommends
COPY nginx/nginx.conf /etc/nginx/sites-available/default
RUN ln -sf /dev/stdout /var/log/nginx/access.log && ln -sf /dev/stderr /var/log/nginx/error.log