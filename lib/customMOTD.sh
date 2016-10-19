#!/bin/sh
 
if [ -z ${1} ]; then
    echo "Usage: ${0} {location of motd}"
    exit 1
fi

ip=$(/sbin/ifconfig | grep -v "127.0.0.1" | grep -B1 "inet addr" | awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | awk -F: '{ print $1 ": " $3 }';)
up=$(uptime | awk -F"up " '{print $2}' | awk -F"," '{print $1}')
used=$(df -h | grep 'dev/root' | awk '{print $3}')
avail=$(df -h | grep 'dev/root' | awk '{print $4}')
tunneltype=$(grep tunnelType /opt/breakout/lib/checkSSH.sh | cut -d "'" -f2)
currentuser=$(who -m | awk '{print $1;}')
lastlogin=$(lastlog | tail -n +2 | grep -v "Never logged in" | awk '{ s = ""; for (i = 4; i <= NF; i++) s = s $i " "; print "User " $1" at " s "from " $3 }')
dnsserver=$(cat /etc/resolv.conf | sed -n -e '/nameserver/,$p' | awk '{print $2}')
 
echo "\033[0;31m
           ____                 _               _    
          |  _ \               | |             | |
          | |_) |_ __ ___  __ _| | _____  _   _| |
          |  _ <| '__/ _ \/ _\` | |/ / _ \| | | | __|
          | |_) | | |  __/ (_| |   < (_) | |_| | |
          |____/|_|  \___|\__,_|_|\_\___/ \__,_|\__|
         \033[0;33m #Coded By Robin Lennox - @robberbear

\033[1;34m"Current Time..: "\033[0;37m$(date)
\033[1;34m"Tunnel Type...: "\033[0;37m${tunneltype}
\033[1;34m"Uptime........: "\033[0;37m${up}
\033[1;34m"Hostname......: "\033[0;37m$(hostname -f)
\033[1;34m"DNS Server....: "\033[0;37m${dnsserver}

\033[1;34mIP Address
\033[0;37m${ip}

\033[1;34mLast Logged in Users
\033[0;37m${lastlogin}
\033[0;31m" > ${1}

exit 0