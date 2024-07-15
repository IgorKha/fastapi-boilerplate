#!/bin/sh

/usr/sbin/api-cert

exec nginx -g 'daemon off;'
