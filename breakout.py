#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import argparse

from lib.CheckPrerequisite import *
from lib.CreateTunnel import *
from lib.ScriptManagement import *

#Import Colour Scheme
G,Y,B,R,W = colour()

def parser_error(errmsg):
    banner()
    print "Usage: python "+sys.argv[0]+" [Options] use -h for help"
    print R+"[x] Error: "+errmsg+W
    sys.exit()

def parse_args():
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

def getSSID():
    try:
        currentSSID = subprocess.check_output("iwconfig | grep ESSID | cut -d\\\" -f2 | grep -v \"off/any\"", shell=True, stderr=subprocess.STDOUT)
        #Cleanup
        currentSSID = currentSSID.rsplit("no wireless extensions.\n",1)[1:]
        currentSSID = '\n'.join([str(x) for x in currentSSID]).replace('\n', ', ')[2:-2]
    except:
        currentSSID = 'NOT CONNECTED'

    return currentSSID

def startRecon():
    print Y+"\n[*] Running Recon on SMB."+W
    localIP = getIP()
    subnetIP = "%s.0" %('.'.join(localIP.split('.')[:-1]))
    print G+"[+] The IP address is %s" % (localIP)
    print G+"[+] The IP subnet is %s/24" % (subnetIP)

def main():
    PWD = os.path.dirname(os.path.realpath(__file__))
    isPi = os.path.isfile('/sys/class/leds/led1/trigger')

    print B+"\n[-] Scan started at %s" %(time.strftime("%b %-d %H:%M:%S"))+W

    # Stop if already Running
    checkRunningState("breakout.py")

    currentSSID = getSSID()

    aggressive,callbackIP,dnsPassword,nameserver,recon,sshuser,tunnel,verbose = args_check()
   
    if tunnel:
        print B+"[-] Auto Tunnel is enabled"+W
    else:
        banner()
   
    print G+"[+] On SSID: %s" %(currentSSID)+W
    if not os.geteuid() == 0:
        sys.exit(R+'[!] Script must be run as root\n'+W)

    if verbose:
        print B+"[-] Verbosity is enabled"+W

    if aggressive:
        print B+"[-] Aggressive is enabled"+W

    #Prerequisite checks
    checkTools(verbose,)
    checkFolders(PWD,)
    checkWiFiCron(PWD,)

    #Check for open ports and Tunnel
    lib.CreateTunnel.main(aggressive,callbackIP,currentSSID,dnsPassword,isPi,nameserver,PWD,sshuser,tunnel,verbose,)

    if recon:
        startRecon()

if __name__ == "__main__":
    main()
