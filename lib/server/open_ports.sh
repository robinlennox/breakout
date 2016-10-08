#!/bin/bash
#title                  :open_ports.sh
#description            :This script will open an SSH port on the server for the specific IP on a specific port. 
#author                 :Robin Lennox
#==============================================================================

function enableUFW {
    # Check that firewall is enabled
    checkUFW=$(sudo ufw status | grep "Status: active")
    if [ -z "${checkUFW}" ]; then
        echo "[+] Enabling UFW and allowing traffic on 22"
        echo y | sudo ufw enable
        sudo ufw allow 22
        sudo ufw allow 53

        # Enable Medium to capture logs
        sudo ufw logging high
    fi
}

function checkSSH {
    #Check SSH hasn't reached hard limit of 5
    #CHECK_MAX=$(journalctl -xe | grep MAX_LISTEN_SOCKS)
    CHECK_SSH_OPEN=$(sudo service ssh status | grep active)
    CHECK_PORT_NUM=$(cat /etc/ssh/sshd_config | grep Port | wc -l)
    if [ "${CHECK_PORT_NUM}" -gt "5" ] || [ -z "${CHECK_SSH_OPEN}" ] ; then
        cp /etc/ssh/sshd_config_orig /etc/ssh/sshd_config
        sudo service sshd restart

        #Force iptable clear
        sudo ufw disable; sudo iptables -F; sudo iptables -X; sudo ip6tables -F; sudo ip6tables -X; echo y | sudo ufw enable

        # Remove all Firewall Rules
        for numb in $(ufw status numbered | awk -F"[" '{print $NF}' | awk '{print $1}' | cut -d ']' -f1 | tail -n+5 | sort -rn); do echo y | ufw delete $numb; done
        sudo ufw allow 22
        sudo ufw allow 53

        # Add 53 as this is being listened to already
        sed -i.bak $"s/Port 22/Port 22\\nPort 53/g" /etc/ssh/sshd_config
        sudo service sshd restart
    fi
}

function openPorts {
    #Backup sshd_config
    if [ ! -f /etc/ssh/sshd_config_orig ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config_orig
    fi
    # Check if port needs to be opened
    sourceIP=$(awk -v d1="$(date --date="-2 min" "+%b %_d %H:%M")" -v d2="$(date "+%b %_d %H:%M")" '$0 > d1 && $0 < d2 || $0 ~ d2' /var/log/ufw.log | grep "\[UFW BLOCK] IN=" | grep -o -P '(?<=SRC=).*(?=DST)' | sort | uniq -c)
    while read -r sourceIP; do
        echo ${sourceIP}
        ipCount=$(echo ${sourceIP} | awk '{print $1}')
        ipAddress=$(echo ${sourceIP} | awk '{print $2}')
        if [ "${ipCount}" -gt "50" ]; then
            echo "[x] The following IP is attempting to connect:" ${ipAddress}
            dstPort=$(awk -v d1="$(date --date="-2 min" "+%b %_d %H:%M")" -v d2="$(date "+%b %_d %H:%M")" '$0 > d1 && $0 < d2 || $0 ~ d2' /var/log/ufw.log | grep "\[UFW BLOCK] IN=" | grep "${ipAddress}" | grep -o -P '(?<=DPT=).*(?=WINDOW)' | sort | uniq)
            while read -r dstPort; do
                echo "[x] Port attempt on" ${dstPort}
                echo "[+] Allowing SSH on port" ${dstPort}
                checkPort=$(cat /etc/ssh/sshd_config | grep "Port ${dstPort}")

                if [ -z "${checkPort}" ]; then
                    echo "port empty" ${dstPort}
                    sed -i.bak $"s/Port 22/Port 22\\nPort ${dstPort}/g" /etc/ssh/sshd_config
                    sudo service sshd restart
                fi

                echo "[+] Allow port" ${dstPort} "from" ${ipAddress}
                sudo ufw allow from ${ipAddress} to any port ${dstPort}
            done <<< "$dstPort"
        fi
    done <<< "$sourceIP"
}

enableUFW
checkSSH
openPorts