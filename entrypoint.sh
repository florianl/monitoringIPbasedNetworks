#!/usr/bin/bash

# Set up a dummy network interface and assign an ip address from RFC 1918
# --cap-add=NET_ADMIN
ip link add dummy0 type dummy
case "$?" in
0)
    ip addr add 172.16.0.42/32 dev dummy0
    ip link set dev dummy0 up
    ;;
*):
    ;;
esac

exec "$@"