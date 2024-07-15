# Use a minimal base image
FROM alpine:3.20 AS builder

# Install dependencies required for building nginx
RUN apk add --no-cache \
    gcc \
    libc-dev \
    make \
    openssl-dev \
    pcre2-dev \
    zlib-dev \
    linux-headers \
    wget

# Download and extract nginx
RUN wget https://nginx.org/download/nginx-1.26.1.tar.gz \
    && tar xzf nginx-1.26.1.tar.gz \
    && cd nginx-1.26.1

# Configure, make, and install nginx
RUN cd nginx-1.26.1 \
    && ./configure \
    --build=fastapi-nginx \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --conf-path=/etc/nginx/nginx.conf \
    --pid-path=/run/nginx.pid \
    --lock-path=/var/lock/nginx.lock \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-pcre \
    --with-pcre-jit \
    --without-http_gzip_module \
    --without-http_autoindex_module \
    --without-http_ssi_module \
    --without-http_userid_module \
    --without-http_access_module \
    --without-http_auth_basic_module \
    --without-http_mirror_module \
    --without-http_geo_module \
    --without-http_split_clients_module \
    --without-http_referer_module \
    --without-http_fastcgi_module \
    --without-http_uwsgi_module \
    --without-http_scgi_module \
    --without-http_grpc_module \
    --without-http_memcached_module \
    --without-http_limit_conn_module \
    --without-http_limit_req_module \
    --without-http_empty_gif_module \
    --without-http_browser_module \
    --without-mail_pop3_module \
    --without-mail_imap_module \
    --without-mail_smtp_module \
    --without-stream_limit_conn_module \
    --without-stream_access_module \
    --without-stream_geo_module \
    --without-stream_map_module \
    --without-stream_split_clients_module \
    --without-stream_return_module \
    --without-stream_upstream_hash_module \
    --without-stream_upstream_least_conn_module \
    --without-stream_upstream_random_module \
    --without-stream_upstream_zone_module \
    && make \
    && make install

# Use a clean alpine image to run nginx
FROM alpine:3.20

RUN apk add --no-cache \
    pcre2 \
    bash \
    openssl

COPY ./stuff/_docker-cert /usr/sbin/api-cert

# Copy the nginx binary and configuration files from the builder stage
COPY --from=builder /usr/sbin/nginx /usr/sbin/nginx
COPY --from=builder /etc/nginx /etc/nginx
COPY ./stuff/nginx.conf /etc/nginx/nginx.conf

COPY ./stuff/start.sh /start.sh
RUN chmod +x /start.sh

# Expose port 80
EXPOSE 80
EXPOSE 443

# Run nginx in the foreground
ENTRYPOINT ["/start.sh"]
