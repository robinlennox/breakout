#!/bin/bash
#description            :This script will install the client prerequisites and can setup the auto tunnel.
#author                 :Robin Lennox
#==============================================================================

function setup {
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
    
    # Install PKG #
    for installpkg in git build-essential libz-dev python-pip python-scapy tcpdump dnsutils
    do
        echo "Installing "$installpkg
        sudo apt-get -y install $installpkg > /dev/null
    done

    # Install PIP #
    for installpip in requests netaddr pexpect
    do
        echo "Installing "$installpip
        sudo -H pip install $installpip > /dev/null
    done

    #Install Directory
    BREAKOUT_DIRECTORY='/opt/breakout'
    sudo mkdir ${BREAKOUT_DIRECTORY}
    sudo git clone https://github.com/robinlennox/breakout ${BREAKOUT_DIRECTORY}

    printf "${RED}"
    echo '        ____                 _               _    '
    echo '       |  _ \               | |             | |   '
    echo '       | |_) |_ __ ___  __ _| | _____  _   _| |_  '
    echo '       |  _ <| '"'"'__/ _ \/ _` | |/ / _ \| | | | __| '
    echo '       | |_) | | |  __/ (_| |   < (_) | |_| | |_  '
    echo '       |____/|_|  \___|\__,_|_|\_\___/ \__,_|\__| '
    printf "${YELLOW}"
    echo '       #Coded By Robin Lennox - @robberbear      ....is now installed!'
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
  # Create the drop box user account
  useradd -m -r -s /bin/false ${username} > /dev/null

  # Setup drop box ssh keys
  mkdir /home/${username}/.ssh > /dev/null
  ssh-keygen -f /home/${username}/.ssh/id_rsa -N "" > /dev/null
  chown -R ${username} /home/${username} > /dev/null

  # Enable root login over SSH using a password
  #sed -Ei 's/^PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config > /dev/null

  # Start the SSH service
  update-rc.d ssh enable > /dev/null
  service ssh restart > /dev/null

  sshPub=$(cat /home/${username}/.ssh/id_rsa.pub | base64 | awk 'BEGIN{ORS="";} {print}')
}

function setupCnCUser {
  if [ -z "${checkSSHUser}" ]; then
    createUsername
    addUser
    echo "[+] Creating user ${username} remotely"
    wget https://raw.githubusercontent.com/robinlennox/breakout/master/lib/setup/addUserRemote.sh -O addUserRemote.sh
    ssh ${sshLogin} -p${sshPort} "bash -s" < addUserRemote.sh ${username} "${sshPub}" "${clientDesc}"
    rm addUserRemote.sh
  fi
}

# Make sure script is run as root
if [ ! "$(id -u)" = "0" ]; then
   echo "This script must be run as root" 1>&2
   exit
fi

# Make sure parameters are set
checkSSHUser=$(cat /etc/passwd | grep -o "sshuser")
sshLogin=$1
sshPort=$2
clientDesc=$3
if [ -z "${sshLogin}" ] || [ -z "${sshPort}" ] || [ -z "${clientDesc}" ]; then
  echo "[+] Installing only client packages"
  echo "[x] For auto tunnel to work a port needs to be specified. E.G sudo bash install_client.sh root@1.2.3.4 22 \"Dropped at Office 123\""
  setup
  exit 1
fi

setup
setupCnCUser
