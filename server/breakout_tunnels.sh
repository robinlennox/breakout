#!/bin/bash
#title                  :breakout_tunnels.sh
#description            :Lists active reverse SSH tunnels connected to this server and provides a menu to connect.
#author                 :Robin Lennox
#==============================================================================

function getopentunnels() {
    # Fast, single-pass extraction of active tunnel PIDs and IPs
    local tunnels=$(ss -nlpt | awk '
        /"sshd"|"sshd-session"/ && $4 ~ /^127\.0\.0\.1:/ {
            match($0, /pid=[0-9]+/)
            if(RSTART > 0) {
                print substr($0, RSTART+4, RLENGTH-4), $4
            }
        }' | sort -u -k1,1)

    if [ -z "${tunnels}" ]; then
        echo "Connect to Client"
        echo "-----------------"
        echo "[x] No tunnels"
        return 1
    fi

    local options=()
    local choices=()
    
    echo "Connect to Client"
    echo "-----------------"
    
    # Process each tunnel
    while read -r pid ipAddr; do
        # Extract UID and uptime using ps to avoid username truncation
        read -r uid uptime <<< $(ps -p "${pid}" -o uid=,etime= | tail -n1)
        [ -z "${uid}" ] && continue # Skip if process died
        
        # Look up full passwd entry by UID to get the real username and comment
        local passwd_entry=$(getent passwd "${uid}")
        local username=$(echo "${passwd_entry}" | cut -d: -f1)
        local user_comment=$(echo "${passwd_entry}" | cut -d: -f5 | cut -d, -f1)
        
        echo "[+] Successful reverse shell by ${username} (${user_comment}) on ${ipAddr} up for ${uptime}"
        options+=("${username},${user_comment},${ipAddr},${uptime}")
    done <<< "${tunnels}"

    # Menu System
    local prompt="[-] Enter the number of the server to connect to. (ENTER when done): "
    local num=""
    local msg=""

    while true; do
        if [ -n "${msg}" ]; then
            echo "${msg}"
            msg=""
        fi
        
        echo "-----------------"
        for i in "${!options[@]}"; do
            IFS=',' read -r u uc ip up <<< "${options[i]}"
            local mark="${choices[i]:- }"
            printf "[%d][%s] %s (%s) on %s up for %s\n" $((i+1)) "${mark}" "${u}" "${uc}" "${ip}" "${up}"
        done
        echo "-----------------"
        
        read -rp "${prompt}" num
        [ -z "${num}" ] && break # Break on ENTER
        
        # Validate input
        if [[ ! "${num}" =~ ^[0-9]+$ ]] || (( num < 1 || num > ${#options[@]} )); then
            msg="[!] Invalid option: ${num}"
            continue
        fi
        
        # Toggle selection
        local idx=$((num - 1))
        if [ "${choices[idx]}" == "x" ]; then
            choices[idx]=" "
            msg="[*] Removed option ${num}"
        else
            choices[idx]="x"
            msg="[*] Added option ${num}"
        fi
    done

    # Execute selected connections
    local selected=false
    for i in "${!options[@]}"; do
        if [ "${choices[i]}" == "x" ]; then
            selected=true
            IFS=',' read -r u _ ip _ <<< "${options[i]}"
            local target_ip="${ip%:*}"
            local target_port="${ip##*:}"
            
            echo "[*] Connecting to ${ip} using ${u}'s key..."
            ssh -q -o MACs=hmac-sha2-256 -o StrictHostKeyChecking=no -i "/home/${u}/.ssh/id_rsa" "breakout@${target_ip}" -p "${target_port}"
        fi
    done

    if [ "${selected}" = false ]; then
        echo "[-] You selected nothing"
    fi
}

getopentunnels
