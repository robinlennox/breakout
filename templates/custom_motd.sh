#!/bin/sh
 
if [ -z ${1} ]; then
    echo "Usage: ${0} {location of motd}"
    exit 1
fi

ip=$(/sbin/ifconfig | grep -v "127.0.0.1" | grep -B1 "inet addr" | awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | awk -F: '{ print $1 ": " $3 }';)
up=$(uptime | awk -F"up " '{print $2}' | awk -F"," '{print $1}' | xargs)
used=$(df -h | grep -m 1 '/' | awk '{print $3}')
avail=$(df -h | grep -m 1 '/' | awk '{print $4}')
tunneltype=$(grep tunnelType /opt/breakout/lib/checkSSH.sh | cut -d "'" -f2)
gatewaywifi=$(grep gatewayWifi /opt/breakout/lib/checkSSH.sh | cut -d "'" -f2)
currentuser=$(whoami)
dnsserver=$(cat /etc/resolv.conf | sed -n -e '/nameserver/,$p' | awk '{print $2}')
currentSSID=$(iwgetid -r)
sshIP=$(netstat -tnpa | grep 'ESTABLISHED.*ssh' | grep -v "127.0.0.1:22" | awk '{ print $4 }' | cut -f1 -d':' | sort | uniq)
 
echo "
           ____                 _               _    
          |  _ \               | |             | |
          | |_) |_ __ ___  __ _| | _____  _   _| |
          |  _ <| '__/ _ \/ _\` | |/ / _ \| | | | __|
          | |_) | | |  __/ (_| |   < (_) | |_| | |
          |____/|_|  \___|\__,_|_|\_\___/ \__,_|\__|
          #Coded By Robin Lennox - @robberbear

Current Time......: $(date)
Tunnel Type.......: ${tunneltype}
Tunneling on IP...: ${sshIP}
Uptime............: ${up}
Hostname..........: $(hostname)
Current SSID......: ${currentSSID}
Using WiFi Gateway: ${gatewaywifi}
Used space /......: ${used}
Available space /.: ${avail}

DNS Server
${dnsserver}

IP Address
${ip}" > ${1}

exit 0