# Nginx

## Nginx Configuration

The `nginx.conf` file located in [system/nginx/nginx.conf](system/nginx/nginx.conf) provides the configuration for the Nginx web server. This configuration is tailored to serve the fastapi web-API, ensuring efficient handling of client requests and secure communication.

## Nginx build minimal

```bash
# install Debian deps (pcre2)
apt install libpcre2-dev

# Or download pcre2 https://github.com/PCRE2Project/pcre2/releases
#    and use --with-pcre=<path> in configure

# get nginx sources
wget https://nginx.org/download/nginx-1.26.1.tar.gz
tar xzf nginx-1.26.1.tar.gz
cd nginx-1.26.1

# configure build
./configure \
    --build=fastapi-nginx \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --conf-path=/etc/nginx/nginx.conf \
    --pid-path=/run/nginx.pid \
    --lock-path=/var/lock/nginx.lock \
    \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-pcre \
    --with-pcre-jit \
    \
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
    --without-stream_upstream_zone_module

# make and install
make
make install
```

## Conclusion

The `system` directory contains critical components for the operation and security of the fastapi web-API. It is essential to properly configure and manage these components to ensure the smooth and secure operation of the service.
