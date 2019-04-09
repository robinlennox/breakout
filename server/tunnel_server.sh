#!/bin/bash
#title          :tunnel_server.sh
#description    :This script will setup the Tunnel Server Side
#author         :Robin Lennox
#==============================================================================

function udpTunnel {
	TUNNEL_TYPE=$1
	TUNNEL_PORT=$2
	LOCAL_PORT=$3
	
	checkProcess=$(ps aux | grep "udp2raw" | grep ${TUNNEL_PORT} | grep -Ev 'color=auto' | wc -l)
	if [[ ${checkProcess} < 1 ]]; then
		udp2raw -s -l0.0.0.0:${LOCAL_PORT} -r 127.0.0.1:${TUNNEL_PORT} -k "passwd" --raw-mode ${TUNNEL_TYPE} -a & > /dev/null 2>&1
	fi

	checkProcess=$(ps aux | grep "kcptun" | grep ${TUNNEL_PORT} | grep -Ev 'color=auto' | wc -l)
	if [[ ${checkProcess} < 1 ]]; then
		kcptun_server -t "127.0.0.1:22" -l ":${TUNNEL_PORT}" -mode fast2 -mtu 1300 & > /dev/null 2>&1
	fi
}

udpTunnel "icmp" "4000" "8855"
udpTunnel "faketcp" "4001" "8856"
udpTunnel "udp" "4002" "8857"
#dnsTunnel

