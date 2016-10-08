#!/bin/bash

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
    for installpkg in git build-essential libz-dev python-pip python-scapy
    do
        echo "Installing "$installpkg
        sudo apt-get -y install $installpkg > /dev/null
    done

    # Install PIP #
    for installpip in pxssh requests netaddr pexpect
    do
        echo "Installing "$installpip
        sudo pip install $installpkg > /dev/null
    done

    #Install Directory
    BREAKOUT_DIRECTORY='/opt/breakout'
    mkdir ${BREAKOUT_DIRECTORY}
    git clone https://github.com/robinlennox/breakout ${BREAKOUT_DIRECTORY}

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

main
