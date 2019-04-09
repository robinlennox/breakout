#!/bin/bash
#description            :This script will install the client prerequisites and can setup the auto tunnel.
#author                 :Robin Lennox
#==============================================================================

function banner {
    # Use colors, but only if connected to a terminal, and that terminal
    # supports them.
    if which tput >/dev/null 2>&1; then
        ncolors=$(tput colors)
    fi
    if [ -t 1 ] && [ -n "$ncolors" ] && [ "$ncolors" -ge 8 ]; then
      RED="$(tput setaf 1)"
      GREEN="$(tput setaf 2)"
      YELLOW="$(tput setaf 3)"
      BLUE="$(tput setaf 4)"
      BOLD="$(tput bold)"
      NORMAL="$(tput sgr0)"
    else
      RED=""
      GREEN=""
      YELLOW=""
      BLUE=""
      BOLD=""
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



function createUsername {
  duplicateUser=0
  # Make user doesn't exist
  while [ "$duplicateUser" == "0" ] ; do
      username="sshuser"$(( ( RANDOM % 1000 )  + 1 ))
      echo "[*] Checking if ${username} on callback server"
      checkSSHUserRemote=$(ssh ${sshLogin} -p${sshPort} cat /etc/passwd | grep -o "${username}")
      checkSSHUserLocal=$(cat /etc/passwd | grep -o "${username}")
      if [ -z "${checkSSHUserLocal}" ] && [ -z "${checkSSHUserRemote}" ]; then
          duplicateUser=1
          echo "[+] Creating user ${username} locally"
      else 
          echo "[x] Try again, ${username} already exists."
      fi
  done
}

function addUser {
  # Create the ssh user account
  addgroup -S ${username} && adduser -D -s /bin/false -G ${username} ${username} > /dev/null

  # Setup drop box ssh keys
	mkdir /home/${username}/.ssh > /dev/null
  ssh-keygen -f /home/${username}/.ssh/id_rsa -N "" > /dev/null
	chown -R ${username} /home/${username} > /dev/null

	addgroup -S breakout && adduser -D -s /bin/ash -G breakout breakout
	mkdir /home/breakout/.ssh
  password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
  ssh ${sshLogin} -p${sshPort} cat ~/.ssh/id_rsa.pub > /home/breakout/.ssh/authorized_keys
  echo -e "${password}\n${password}" | passwd breakout
	echo "breakout ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
  sshPub=$(cat /home/${username}/.ssh/id_rsa.pub | base64 | awk 'BEGIN{ORS="";} {print}')
}

function setupCnCUser {
	if [ -z "${checkSSHUser}" ]; then
    ssh-keygen -f ~/.ssh/id_rsa -N "" > /dev/null
    ssh-copy-id ${sshLogin} -p${sshPort}
		createUsername
		addUser
		echo "[+] Creating user ${username} remotely"
		wget https://raw.githubusercontent.com/robinlennox/breakout/master/setup/addUserRemote.sh -O addUserRemote.sh
		ssh ${sshLogin} -p${sshPort} "bash -s" < addUserRemote.sh ${username} "${sshPub}" "${clientDesc}"
		rm addUserRemote.sh
	else
		echo "[x] ${checkSSHUser} already exists."
	fi
}


# Make sure parameters are set
checkSSHUser=$(cat /etc/passwd | grep -o "sshuser")
sshLogin=$1
sshPort=$2
clientDesc=$3
if [ -z "${sshLogin}" ] || [ -z "${sshPort}" ] || [ -z "${clientDesc}" ]; then
  echo "[+] Installing only client packages"
  echo "[x] For auto tunnel to work a port needs to be specified. E.G bash $(basename -- "$0") root@1.2.3.4 22 \"Dropped at Office 123\""
  setup
  exit 1
fi

banner
setupCnCUser
rm -rf ~/.ssh/id_rsa*