#!/bin/bash
#title                  :checkSSH.sh
#description            :This script will verify that the SSH Tunnel to the callback server is up. 
#author                 :Robin Lennox
#source                 :http://serverfault.com/a/298312
#==============================================================================

function getopentunnels {

    sshProcesses=$(netstat -tnpa | grep 'sshd:' | grep '*' | grep '127.0.0.1' | awk {'print $7'} | cut -d'/' -f1 | uniq)
    if [ -z "${sshProcesses}" ]; then
        echo 'Connect to Client'
        echo '-----------------'
        echo "[x] No tunnels"
        exit 1
    else
        options=()
        for processid in ${sshProcesses}
        do
            ipAddr=$(netstat -tnpa | grep 'sshd:' | grep '*' | grep '127.0.0.1' | grep ${processid} | awk '{print $4}')
            username=$(ps auxwww | grep -v 'grep' | grep ${processid} | awk '{print $12}')
            usernameComment=$(grep ${username} /etc/passwd | cut -d':' -f5)
            sshtunneluptime=$(ps -eo pid,etime | grep ${processid} | awk '{print $2}')
            #echo "[+] Successful reverse shell by" ${username}"("${usernameComment}") on" ${ipAddr}" up for" ${sshtunneluptime}
            options+=("${username},${usernameComment},${ipAddr},${sshtunneluptime}")
        done
    fi

    menu() {
        if [ -z ${showmenu} ]; then
            showmenu="1"
            echo 'Connect to Client'
            echo '-----------------'
            for i in ${!options[@]}; do 
                echo "${options[i]}" | while IFS=, read username usernameComment ipAddr sshtunneluptime
                do
                    printf "[%d%s] %s\n" $((i+1)) "${choices[i]}" "${username} (${usernameComment}) on ${ipAddr} up for ${sshtunneluptime}"
                done
            done
            echo '-----------------'
        fi
     
        if [[ $msg == *"Invalid option"* ]]; then
          echo "$msg";:
        elif ! [[ $msg ]]; then
            :
        else
          echo "$msg"; break
        fi
    }

    prompt="[-] Enter the number of the server to connect to. (ENTER when done): "
    while menu && read -rp "$prompt" num && [[ "$num" ]]; do
        [[ "$num" != *[![:digit:]]* ]] &&
        (( num > 0 && num <= ${#options[@]} )) ||
        { msg="[!] Invalid option: $num"; continue; }
         msg="[*] Attempting to connect to number ${num}"; ((num--))
        [[ "${choices[num]}" ]] && choices[num]="" || choices[num]="+"
    done

    if [ -z "${msg}" ]; then
        echo "[-] You selected nothing"
    fi
    for i in ${!options[@]}; do 
        [[ "${choices[i]}" ]] && { 
            ipaddr=$(echo "${options[i]}" | cut -f3 -d"," | cut -f1 -d":");
            port=$(echo "${options[i]}" | cut -f3 -d"," | cut -f2 -d":"); 
            ssh -q -oStricthostKeyChecking=no ubuntu@${ipaddr} -p${port}; 
            msg="";
        }
    done
}

showmenu=""
getopentunnels
