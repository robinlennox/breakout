#!/bin/bash
#title          :icmp_tunnel_client.sh
#description    :This script will setup the ICMP Tunnel Client Side
#author         :Robin Lennox
#==============================================================================
echo "1" | sudo tee /proc/sys/net/ipv4/icmp_echo_ignore_all
(sudo /opt/icmptunnel/icmptunnel $1 >/dev/null 2>&1) &
sudo /sbin/ifconfig tun0 10.0.0.2 netmask 255.255.255.0 > /dev/null 2>&1

nc -z -w5 10.0.0.1 22
echo $?