#!/bin/bash
#title          :tunnel_server.sh
#description    :This script will setup the Tunnel Server Side
#author         :Robin Lennox
#==============================================================================

function icmpTunnel {
	ICMP_DIRECTORY='/opt/icmptunnel'

	if [ ! -f "${ICMP_DIRECTORY}/icmptunnel" ]; then
        rm -rf ${ICMP_DIRECTORY}
	    git clone "https://github.com/jamesbarlow/icmptunnel.git" ${ICMP_DIRECTORY}
	    cd ${ICMP_DIRECTORY}
	    make > /dev/null 2>&1
	fi

	checkProcess=$(ps aux | grep "icmptunnel" | grep -v "SCREEN" | grep -Ev 'color=auto icmptunnel' | wc -l)
	if ! [ "${checkProcess}" -gt "1" ]; then
		echo "1" | sudo tee /proc/sys/net/ipv4/icmp_echo_ignore_all
		${ICMP_DIRECTORY}/icmptunnel -s -d > /dev/null 2>&1 &
		/sbin/ifconfig tun0 10.0.0.1 netmask 255.255.255.0 > /dev/null 2>&1
	fi
}

function dnsTunnel {
	DNS_DIRECTORY='/tmp/iodine'
	if [ -d "${DNS_DIRECTORY}" ]; then
		rm -rf ${DNS_DIRECTORY}
	fi

	if [ ! -f "/usr/local/sbin/iodine" ]; then
        rm -rf ${DNS_DIRECTORY}
	    git clone "https://github.com/yarrick/iodine.git" ${DNS_DIRECTORY}
	    cd ${DNS_DIRECTORY}
	    make > /dev/null 2>&1
	    make install > /dev/null 2>&1
	fi
	checkProcess=$(ps aux | grep "iodined" | grep -v "SCREEN" | grep -Ev 'color=auto iodined' | wc -l)
	if ! [ "${checkProcess}" -gt "1" ]; then
		iodined -f -c -P ${DNS_PASSWORD} 192.168.128.1 thereisnotunnel.openclam.com
	fi
}

DNS_PASSWORD='breakout'

icmpTunnel
dnsTunnel