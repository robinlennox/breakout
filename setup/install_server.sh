#!/bin/bash
#title          :install_server.sh
#description    :Installs required dependencies and configures the callback server for TCP, UDP, ICMP, and DNS tunnels.
#author         :Robin Lennox
#==============================================================================

function main {
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
    apt-get update
    apt-get -y upgrade
    for installpkg in git build-essential libz-dev iodine
    do
        checkinstalled=$(dpkg-query -l | grep ${installpkg})
        if [ "" == "${checkinstalled}" ]; then
          echo "Installing "${installpkg}
          apt-get -y install ${installpkg} > /dev/null
        fi
    done

    sed -Ei 's/#Port 22/Port 22/' /etc/ssh/sshd_config
    sed -Ei 's/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config_orig

    echo "0" | tee /proc/sys/net/ipv4/icmp_echo_ignore_all
    wget https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz -P /tmp && \
    tar -xvf /tmp/udp2raw_binaries.tar.gz -C /usr/local/bin/ udp2raw_amd64 && \
    mv /usr/local/bin/udp2raw_amd64 /usr/local/bin/udp2raw && \
    chmod +x /usr/local/bin/udp2raw && \
    rm -rf /tmp/udp2raw_binaries.tar.gz

    wget https://github.com/iaineng/kcptun/releases/download/v20260129/kcptun_linux_amd64.tar.gz -P /tmp && \
    tar -xvf /tmp/kcptun_linux_amd64.tar.gz -C /usr/local/bin/ server_linux_amd64 && \
    mv /usr/local/bin/server_linux_amd64 /usr/local/bin/kcptun_server && \
    chmod +x /usr/local/bin/kcptun_server && \
    rm -rf /tmp/kcptun_linux_amd64.tar.gz

    #Install Directory
    BREAKOUT_DIRECTORY='/opt/breakout'
    mkdir ${BREAKOUT_DIRECTORY}
    wget https://raw.githubusercontent.com/robinlennox/breakout/master/server/breakout_tunnels.sh -P ${BREAKOUT_DIRECTORY}
    wget https://raw.githubusercontent.com/robinlennox/breakout/master/server/tunnel_server.sh -P ${BREAKOUT_DIRECTORY}
    wget https://raw.githubusercontent.com/robinlennox/breakout/master/server/open_ports.sh -P ${BREAKOUT_DIRECTORY}

    #Make link to script
    chmod +x /opt/breakout/breakout_tunnels.sh
    ln -s /opt/breakout/breakout_tunnels.sh /usr/local/bin/breakout_tunnels

    #Setup SSH Keys
    ssh-keygen -f ~/.ssh/id_rsa -N ""

    #Crontab
    echo "*/1 * * * * root bash ${BREAKOUT_DIRECTORY}/tunnel_server.sh > /dev/null 2>&1" | tee -a /etc/crontab
    echo "*/1 * * * * root bash ${BREAKOUT_DIRECTORY}/open_ports.sh > /dev/null 2>&1" | tee -a /etc/crontab

    printf "${RED}"
    echo '                        '
    echo '[--|->] b r e a k o u t'
    printf "${YELLOW}"
    echo '# Coded By Robin Lennox      ....is now installed!'
    printf "${NORMAL}"
}

main
echo "[+] Rebooting to apply changes"
reboot
