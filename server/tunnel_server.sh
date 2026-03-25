#!/bin/bash
#title          :tunnel_server.sh
#description    :Sets up and maintains the UDP/ICMP/TCP/DNS tunnel listeners on the server.
#author         :Robin Lennox
#==============================================================================

function udpTunnel {
	TUNNEL_TYPE=$1
	TUNNEL_PORT=$2
	LOCAL_PORT=$3
	TUNNEL_PASSWORD=${TUNNEL_PASSWORD:-passwd}
	
	checkProcess=$(ps aux | grep "udp2raw" | grep ${TUNNEL_PORT} | grep -Ev 'color=auto' | wc -l)
	if [[ ${checkProcess} < 1 ]]; then
		udp2raw -s -l0.0.0.0:${LOCAL_PORT} -r 127.0.0.1:${TUNNEL_PORT} -k "${TUNNEL_PASSWORD}" --raw-mode ${TUNNEL_TYPE} -a > /dev/null 2>&1 &
	fi

	checkProcess=$(ps aux | grep "kcptun" | grep ${TUNNEL_PORT} | grep -Ev 'color=auto' | wc -l)
	if [[ ${checkProcess} < 1 ]]; then
		kcptun_server -t "127.0.0.1:22" -l ":${TUNNEL_PORT}" -mode fast2 -mtu 1300 > /dev/null 2>&1 &
	fi
}

udpTunnel "icmp" "4000" "8855"
udpTunnel "faketcp" "4001" "8856"
udpTunnel "udp" "4002" "8857"

function dnsTunnel {
	DNS_PASSWORD=${TUNNEL_PASSWORD:-passwd}
	DNS_DOMAIN=${DNS_DOMAIN:-t1.example.com}

	checkProcess=$(ps aux | grep "iodined" | grep -Ev 'color=auto|grep' | wc -l)
	if [[ ${checkProcess} -lt 1 ]]; then
		for i in {0..5}; do ip link delete dns$i 2>/dev/null || true; done
		iodined -f -P "${DNS_PASSWORD}" 10.0.0.1/24 "${DNS_DOMAIN}" & > /dev/null 2>&1
	fi
}

dnsTunnel
