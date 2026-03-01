#!/bin/sh
#title          :custom_motd.sh
#description    :Generates a custom Message of the Day (MOTD) banner with tunnel status.
#author         :Robin Lennox
#==============================================================================
if [ -z ${1} ]; then
    echo "Usage: ${0} {location of motd}"
    exit 1
fi

ip=$(ip -br -4 addr show | awk '$1 != "lo" {gsub("/.*", "", $3); print $1 ": " $3}')
up=$(uptime | awk -F'(up |,)' '{gsub(/^[ \t]+/, "", $2); print $2}')
used=$(df -h / | awk 'NR==2 {print $3}')
avail=$(df -h / | awk 'NR==2 {print $4}')
tunneltype=$(awk -F"'" '/tunnelType=/ {print $2; exit}' /opt/breakout/check_ssh.sh)
gatewaywifi=$(awk -F"'" '/gatewayWifi=/ {print $2; exit}' /opt/breakout/check_ssh.sh)
currentuser=$USER
dnsserver=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf)
currentSSID=$(iwgetid -r)
sshIP=$(ss -ntp state established | awk '/"ssh"/ && $4 !~ /127\.0\.0\.1:22/ {sub(/:[^:]+$/, "", $4); print $4}' | sort -u)
echo "
           ____                 _               _    
          |  _ \               | |             | |
          | |_) |_ __ ___  __ _| | _____  _   _| |
          |  _ <| '__/ _ \/ _\` | |/ / _ \| | | | __|
          | |_) | | |  __/ (_| |   < (_) | |_| | |
          |____/|_|  \___|\__,_|_|\_\___/ \__,_|\__|
                  # Coded By Robin Lennox

  [System]   $(hostname) (Up: ${up})
  [Space]    ${used} used, ${avail} free
  [Time]     $(date)
  [Tunnel]   ${tunneltype} - Auth IP: ${sshIP:-None}
  [Network]  $(echo "${ip}" | xargs)
  [DNS]      $(echo "${dnsserver}" | xargs)
  [WiFi]     ${currentSSID:-None} (GW: ${gatewaywifi})
" > ${1}

exit 0