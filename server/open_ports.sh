#!/bin/bash
#title          :open_ports.sh
#description    :Installs kernel-level iptables rules to instantly NAT forward authorized port knocks to SSH port 22.
#author         :Robin Lennox
#==============================================================================

echo "Installing kernel port knock rules using iptables recent module..."

# Flush the NAT PREROUTING chain so we can test cleanly
iptables -t nat -F PREROUTING

# 0. EXCLUDE port 53 (DNS) from knock/redirect so the DNS service is unaffected.
iptables -t nat -A PREROUTING -p tcp --dport 53 -j RETURN
iptables -t nat -A PREROUTING -p udp --dport 53 -j RETURN

# 1. EVALUATE FIRST: Check if the IP is already authorized.
# If they have 15 hits in the last 30 seconds, instantly REDIRECT to port 22.
# REDIRECT is a terminating target, so it stops here and forwards the packet.
iptables -t nat -A PREROUTING -p tcp -m recent --rcheck --seconds 30 --hitcount 15 --name knock_list --rsource -j REDIRECT --to-ports 22

# 2. LOG SECOND: If they weren't redirected by Rule 1, record the hit.
iptables -t nat -A PREROUTING -p tcp --syn -m recent --set --name knock_list --rsource

echo "Rules applied!"
echo "To test this from your drop box:"
echo "1. Blast port 8080 15 times: 'for i in {1..20}; do wget --timeout=0.1 http://<SERVER_IP>:8080 & done'"
echo "2. Within 30 seconds, instantly SSH into that same port: 'ssh root@<SERVER_IP> -p 8080'"