#!/bin/bash
#title          :setup_auto_tunnel.sh
#description    :Sets up the client-server key exchange for auto-tunneling.
#author         :Robin Lennox
#==============================================================================

if which tput >/dev/null 2>&1; then
    ncolors=$(tput colors 2>/dev/null)
fi
if [ -n "$ncolors" ] && [ "$ncolors" -ge 8 ]; then
    RED="\033[91m"
    GREEN="\033[92m"
    YELLOW="\033[93m"
    BLUE="\033[94m"
    NORMAL="\033[0m"
else
    # Fallback to Bright ANSI codes for headless Python subprocesses
    RED="\033[91m"
    GREEN="\033[92m"
    YELLOW="\033[93m"
    BLUE="\033[94m"
    NORMAL="\033[0m"
fi

PLUS="${GREEN}[+]"
STAR="${BLUE}[*]"
EXCL="${YELLOW}[!]"
CROSS="${RED}[x]"
DBG="${YELLOW}[DEBUG]"


function banner {
    printf "${RED}"
    echo "[--|->] b r e a k o u t"
    printf "${YELLOW}"
    echo "# Coded By Robin Lennox      ....let the setup begin!"
    printf "${NORMAL}"
}

function addUser {
    # Generate standalone key for breakout auto-tunnels (no local user needed)
    KEY_DIR="/opt/breakout/keys"
    KEY_PATH="${KEY_DIR}/id_rsa"
    
    if [ "$VERBOSE" -eq 1 ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            echo -e "${PLUS} Checking for breakout tunnel key at ${KEY_PATH}${NORMAL}"
        fi
    fi
    mkdir -p "${KEY_DIR}"
    if [ ! -f "${KEY_PATH}" ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                echo -e "${PLUS} Generating breakout tunnel key at ${KEY_PATH}${NORMAL}"
            fi
        fi
        ssh-keygen -f "${KEY_PATH}" -N "" > /dev/null 2>&1
    else
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                echo -e "${STAR} Breakout tunnel key already exists. Skipping generation.${NORMAL}"
            fi
        fi
    fi
    chown -R root:root "${KEY_DIR}"
    chmod 700 "${KEY_DIR}"
    chmod 600 "${KEY_PATH}"

    # Setup the local 'breakout' user so the server can access this device
    # (If running in Docker, this creates the user inside the container)
    if ! id "breakout" >/dev/null 2>&1; then
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                echo -e "${PLUS} Creating local 'breakout' user for incoming access${NORMAL}"
            fi
        fi
        # Debian/Ubuntu style useradd since alpine's adduser -D doesn't work everywhere
        useradd -m -s /bin/bash breakout 2>/dev/null || adduser --disabled-password --gecos "" breakout 2>/dev/null
        
        mkdir -p /home/breakout/.ssh
        password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
        ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i /opt/breakout/keys/id_rsa ${sshLogin} -p${sshPort} cat /opt/breakout/keys/id_rsa.pub > /home/breakout/.ssh/authorized_keys
        echo -e "${password}\n${password}" | passwd breakout >/dev/null 2>&1
        echo "breakout ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
    fi
    
    # Always ensure the local public key is authorized to access the breakout user
    if [ -f "/opt/breakout/keys/id_rsa.pub" ]; then
        mkdir -p /home/breakout/.ssh
        # Ensure it ends with a newline before appending
        echo "" >> /home/breakout/.ssh/authorized_keys
        cat /opt/breakout/keys/id_rsa.pub >> /home/breakout/.ssh/authorized_keys
        # Clean up any blank lines we just made
        sed -i '/^$/d' /home/breakout/.ssh/authorized_keys
    fi

    chown -R breakout:breakout /home/breakout
    chmod 700 /home/breakout/.ssh
    if [ -f "/home/breakout/.ssh/authorized_keys" ]; then
        chmod 600 /home/breakout/.ssh/authorized_keys
    fi
}

function setupCnCUser {
    # Check if a config already exists and has a username
    CONFIG_PATH="/opt/breakout/configs/config.ini"
    if [ -f "$CONFIG_PATH" ] && grep -q "^SSHUSER" "$CONFIG_PATH" 2>/dev/null; then
        username=$(grep "^SSHUSER" "$CONFIG_PATH" | cut -d'=' -f2 | tr -d ' ')
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                echo -e "${PLUS} Using existing username ${username} from config.ini${NORMAL}"
            fi
        fi
    else
        # We use a unique username for this dropsbox based on its hostname and a random id
        rand_id=$(( ( RANDOM % 1000 ) + 1 ))
        username="tunnel-$(hostname)-${rand_id}"
    fi

    if [ "$VERBOSE" -eq 1 ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            echo -e "${PLUS} Setting up root SSH keys to communicate with server${NORMAL}"
        fi
    fi
    addUser

    SSH_COPY_OPTS=(-o "StrictHostKeyChecking=no")
    SSH_OPTS=(-o "StrictHostKeyChecking=no")
    
    if [ -n "$HOST_SSH_KEY" ] && [ -f "$HOST_SSH_KEY" ]; then
        SSH_COPY_OPTS+=(-o "IdentityFile=$HOST_SSH_KEY")
        SSH_OPTS+=(-o "IdentityFile=$HOST_SSH_KEY")
    fi

    if [ "$VERBOSE" -eq 1 ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            echo -e "${PLUS} Checking if user ${username} exists remotely...${NORMAL}"
        fi
    fi
    USER_EXISTS=$(ssh "${SSH_OPTS[@]}" -p${sshPort} ${sshLogin} "id ${username}" 2>/dev/null)

    if [[ -n "$USER_EXISTS" ]]; then
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                echo -e "${STAR} User ${username} already exists on the remote server. Skipping remote provisioning.${NORMAL}"
            fi
        fi
    else
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                echo -e "${PLUS} User not found. Provisioning keys and creating user ${username} remotely...${NORMAL}"
            fi
        fi
        
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                if [ "$VERBOSE" -eq 1 ]; then
                    echo -e "${DBG} Running: ssh-copy-id -i /opt/breakout/keys/id_rsa.pub ${SSH_COPY_OPTS[@]} -p ${sshPort} ${sshLogin}${NORMAL}"
                fi
            fi
        fi

        COPY_OUTPUT=$(ssh-copy-id -i /opt/breakout/keys/id_rsa.pub "${SSH_COPY_OPTS[@]}" -p ${sshPort} ${sshLogin} 2>&1)
        if [ $? -ne 0 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                if [ "$VERBOSE" -eq 1 ]; then
                    if [ "$VERBOSE" -eq 1 ]; then
                        echo -e "${EXCL} Remote setup failed: $COPY_OUTPUT${NORMAL}"
                    fi
                fi
                if [ "$VERBOSE" -eq 1 ]; then
                    if [ "$VERBOSE" -eq 1 ]; then
                        echo -e "${EXCL} Command was: ssh-copy-id -i /opt/breakout/keys/id_rsa.pub ${SSH_COPY_OPTS[@]} -p ${sshPort} ${sshLogin}${NORMAL}"
                    fi
                fi
            else
                if [ "$VERBOSE" -eq 1 ]; then
                    if [ "$VERBOSE" -eq 1 ]; then
                        echo -e "${EXCL} Remote setup failed${NORMAL}"
                    fi
                fi
            fi
            exit 1
        fi

        addUser

        sshPub=$(cat /opt/breakout/keys/id_rsa.pub | base64 | tr -d '\n')
        sshPriv=$(cat /opt/breakout/keys/id_rsa | base64 | tr -d '\n')
        
        LOCAL_SCRIPT="/opt/breakout/setup/add_user_remote.sh"
        if [ ! -f "$LOCAL_SCRIPT" ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                if [ "$VERBOSE" -eq 1 ]; then
                    echo -e "${EXCL} LOCAL_SCRIPT $LOCAL_SCRIPT not found. Cannot set up remote user.${NORMAL}"
                fi
            fi
            exit 1
        fi

        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                if [ "$VERBOSE" -eq 1 ]; then
                    echo -e "${DBG} Running: ssh ${SSH_OPTS[@]} -p${sshPort} ${sshLogin} \"bash -s\" < $LOCAL_SCRIPT ${username} \"${sshPub}\" \"${sshPriv}\" \"${clientDesc}\"${NORMAL}"
                fi
            fi
        fi

        SSH_OUTPUT=$(ssh "${SSH_OPTS[@]}" -p${sshPort} ${sshLogin} "bash -s" < "$LOCAL_SCRIPT" ${username} "${sshPub}" "${sshPriv}" "${clientDesc}" 2>&1)
        echo ${SSH_OUTPUT}
        if [ $? -ne 0 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                if [ "$VERBOSE" -eq 1 ]; then
                    if [ "$VERBOSE" -eq 1 ]; then
                        echo -e "${EXCL} Remote setup failed: $SSH_OUTPUT${NORMAL}"
                    fi
                fi
                if [ "$VERBOSE" -eq 1 ]; then
                    if [ "$VERBOSE" -eq 1 ]; then
                        echo -e "${EXCL} Command was: ssh ${SSH_OPTS[@]} -p${sshPort} ${sshLogin} \"bash -s\" < $LOCAL_SCRIPT ${username} \"${sshPub}\" \"${sshPriv}\" \"${clientDesc}\"${NORMAL}"
                    fi
                fi
            else
                if [ "$VERBOSE" -eq 1 ]; then
                    if [ "$VERBOSE" -eq 1 ]; then
                        echo -e "${EXCL} Remote setup failed${NORMAL}"
                    fi
                fi
            fi
            exit 1
        fi
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                echo -e "${PLUS} Remote setup complete.${NORMAL}"
            fi
        fi
    fi
    
    # Automatically update config.ini
    CONFIG_PATH="/opt/breakout/configs/config.ini"

    if [ ! -f "$CONFIG_PATH" ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                echo -e "${EXCL} config.ini not found. Generating default config...${NORMAL}"
            fi
        fi
        cat <<EOF > "$CONFIG_PATH"
[DEFAULT]
SHOWBANNER = True

[TUNNEL]
CHECKEXISTING = True
FAKETCP = True
ICMP = True
TCP = False
UDP = False
DNS = True
PASSWORD = passwd
WAITTIME = 10
SSHKEY = /opt/breakout/keys/id_rsa
SSHUSER = tunnel
EOF
    fi

    if [ -f "$CONFIG_PATH" ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                echo -e "${PLUS} Updating ${CONFIG_PATH} with new SSHUSER${NORMAL}"
            fi
        fi
        sed -i.bak "s/^SSHUSER.*/SSHUSER = ${username}/" "$CONFIG_PATH"
        rm -f "${CONFIG_PATH}.bak"
    else
        if [ "$VERBOSE" -eq 1 ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                echo -e "${EXCL} Auto-update failed: Make sure to update your config.ini${NORMAL}"
            fi
        fi
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
  if [ "$VERBOSE" -eq 1 ]; then
      if [ "$VERBOSE" -eq 1 ]; then
          echo -e "${PLUS} Installing only client packages${NORMAL}"
      fi
  fi
  if [ "$VERBOSE" -eq 1 ]; then
      if [ "$VERBOSE" -eq 1 ]; then
          echo -e "${CROSS} For auto tunnel to work a port needs to be specified. E.G bash $(basename -- ${NORMAL}"$0") root@1.2.3.4 22 \"Dropped at Office 123\""
      fi
  fi
  banner
  exit 1
fi

setupCnCUser