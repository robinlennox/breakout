#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import argparse
import os
import subprocess
import sys
import time

from lib.CreateTunnel import initialiseTunnel
from lib.IPCheck import getIP
from lib.Layout import banner, colour
from lib.ScriptManagement import checkRunningState

# Import Colour Scheme
G, Y, B, R, W = colour()


def parser_error(errmsg):
    print("Usage: python {0} [Options] use -h for help".format(sys.argv[0]))
    print(R + "[x] Error: {0}".format(errmsg) + W)
    sys.exit()


def parse_args():
    parser = argparse.ArgumentParser(
        epilog="\tExample: \rpython {0} -c 1.2.3.4".format(sys.argv[0]))
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-a', '--aggressive',
                        help='Aggressive scan, all', nargs='?', default=False)
    parser.add_argument(
        '-c', '--callback', help='Enable call back to server', nargs='?', default='')
    parser.add_argument(
        '-n', '--nameserver', help='Provide Nameserver for DNS callback', nargs='?', default='')
    parser.add_argument(
        '-p', '--password', help='Password used for UDP callback', nargs='?', default='passwd')
    parser.add_argument(
        '-r', '--recon', help='Enable the recon module', nargs='?', default=False)
    parser.add_argument(
        '-t', '--tunnel', help='Enable auto tunneling', nargs='?', default=False)
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?',
                        default=False)
    return parser.parse_args()


def args_check():
    args = parse_args()

    global callbackIP
    callbackIP = args.callback
    if callbackIP is None:
        print(
            R + "[x] Error an IP address must be entered for callback to work" + W)
        sys.exit(0)
    elif callbackIP is "":
        callbackIP = None

    global nameserver
    nameserver = args.nameserver
    if nameserver is None:
        print(
            R + "[x] Error an nameserver must be entered for DNS callback to work" + W)
        sys.exit(0)
    elif nameserver is "":
        nameserver = None

    global tunnelPassword
    tunnelPassword = args.password
    if tunnelPassword is None:
        print(R + "[x] Error no password was entered" + W)
        sys.exit(0)
    elif tunnelPassword is "":
        tunnelPassword = None

    if tunnelPassword and nameserver is '':
        print(
            R + "[x] Error an nameserver must be entered for DNS callback to work" + W)
        sys.exit(0)

    tunnel = args.tunnel
    sshuser = ''
    if tunnel or tunnel is None:
        passwd = open('/etc/passwd').read()
        if 'sshuser' in passwd:
            tunnel = True
            for line in passwd.splitlines():
                if "sshuser" in line:
                    sshuser = line.split(':')[0]
        else:
            print(R + "[x] Error: No sshuser!" + W)
            print(
                R + "[x] This needs to be setup for the auto tunnel to work" + W)
            sys.exit(0)

    # Check Verbosity
    global verbose
    verbose = args.verbose
    if verbose or verbose is None:
        verbose = True

    # Check Recon
    global recon
    recon = args.recon
    if recon or recon is None:
        recon = True

    # Check Aggressive
    global aggressive
    aggressive = args.aggressive
    if aggressive or aggressive is None:
        aggressive = True

    return aggressive, callbackIP, tunnelPassword, nameserver, recon, sshuser, tunnel, verbose


def getSSID(verbose):
    try:
        currentSSID = subprocess.check_output(
            "iwconfig | grep ESSID | cut -d\\\" -f2 | grep -v \"off/any\"", shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        # Cleanup
        currentSSID = currentSSID.rsplit("no wireless extensions.\n", 1)[1:]
        currentSSID = '\n'.join(
            [str(x) for x in currentSSID]).replace('\n', ', ')[2:-2]
    except Exception as e:
        if verbose:
            print(e)
        currentSSID = 'NOT CONNECTED'

    return currentSSID


def startRecon():
    print(B + "\n[-] Running Recon" + W)
    localIP = getIP()
    subnetIP = "{0}.0".format('.'.join(localIP.split('.')[:-1]))
    print(Y + "[*] IP Information" + W)
    print(G + "[+] The IP address is {0}".format(localIP)+W)
    print(G + "[+] The IP subnet is {0}/24".format(subnetIP)+W)


def main():
    isPi = os.path.isfile('/sys/class/leds/led1/trigger')

    print(
        G + "[+] Scan started at {0}".format(time.strftime("%b %-d %H:%M:%S") + W))

    # Stop if already Running
    checkRunningState("breakout.py")

    aggressive, callbackIP, tunnelPassword, nameserver, recon, sshuser, tunnel, verbose = args_check()

    currentSSID = getSSID(verbose)

    if tunnel:
        print(B + "[-] Auto Tunnel is enabled" + W)
    else:
        pass
        # banner()

    print(G + "[+] On SSID: {0}".format(currentSSID) + W)
    if not os.geteuid() == 0:
        sys.exit(R + '[!] Script must be run as root\n' + W)

    if verbose:
        print(B + "[-] Verbosity is enabled" + W)

    if aggressive:
        print(B + "[-] Aggressive is enabled" + W)

    # Check for open ports and Tunnel
    initialiseTunnel(aggressive, callbackIP, currentSSID,
                     tunnelPassword, isPi, nameserver, sshuser, tunnel, verbose, )

    if recon:
        startRecon()


if __name__ == "__main__":
    banner()
    main()
