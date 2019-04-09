#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

from lib.Layout import colour
from pexpect import pxssh
from scapy.all import IP, TCP, sr1
import subprocess
import time

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Import Colour Scheme
G, Y, B, R, W = colour()


def openPort(port, ip):
    try:
        response = sr1(IP(dst=ip)/TCP(dport=int(port),
                                      flags="S"), verbose=False, timeout=2)
        while response:
            if response[TCP].flags == 18:
                return True
            else:
                return False
    except Exception as e:
        print("[!] openPort:", e)
        return False


def udp2rawTunnelAttempt(callbackIP, tunnelIP, tunnelType, tunnelPort, listenPort, localPort, tunnelPassword):
    returnResult = False
    try:
        subprocess.check_output(
            'pkill udp2raw && pkill kcptun_client', shell=True)
    except Exception as e:
        pass

    try:
        subprocess.check_output('udp2raw -c -r{0}:{1} -l0.0.0.0:{2} --raw-mode {3} -k"{4}" >/dev/null 2>&1 &'.format(
            callbackIP, listenPort, tunnelPort, tunnelType, tunnelPassword), shell=True)
        subprocess.check_output(
            'kcptun_client -r "127.0.0.1:{0}" -l ":{1}" -mode fast2 -mtu 1300 >/dev/null 2>&1 &'.format(tunnelPort, localPort), shell=True)
        time.sleep(5)
        command = "timeout -t 2 nc 127.0.0.1 {0}".format(localPort)
        output = subprocess.Popen(
            command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "SSH" in str(output.communicate()):
            returnResult = True

        return returnResult
    except Exception as e:
        print(e)
        return returnResult


def udp2rawTunnel(callbackIP, tunnelIP, tunnelType, tunnelPort, localPort, listenPort, tunnelPassword, verbose):
    count = 0
    stopCount = 5
    while (count < stopCount):
        if verbose:
            print(B+"[-] Attempting {0} Tunnel".format(tunnelType)+W)
        time.sleep(5)
        if udp2rawTunnelAttempt(callbackIP, tunnelIP, tunnelType, tunnelPort, listenPort, localPort, tunnelPassword):
            return True
            break
        else:
            # Restricts Attempts
            count = count + 1
    return False


def checkTunnel(ipAddr, portNumber):
    failedMessage = R+"[x] Failed connect, trying again."+W
    # Timeout 10 is used for RAW DNS Tunnel as this is slow to connect.
    s = pxssh.pxssh(timeout=10,)
    try:
        testConn = s.login(ipAddr, 'myusername', 'mypassword',
                           port=portNumber, auto_prompt_reset=False)
        s.close()
        if testConn:
            return True
        else:
            print(failedMessage)
            return False
        # Should never get here
        # print s.login (ipAddr, 'myusername', 'mypassword', auto_prompt_reset=False)
        # print "failedMessage"
        # return False
    except pxssh.ExceptionPxssh as e:
            # DNS Tunnel setup but not routable.
        if "could not set shell prompt" in str(e):
            print(failedMessage)
            # print str(e)
            return False
        else:
            # print G+"[+] SSH Tunnel Created!"+W
            # print str(e)
            return True
    except:
        # Catch all
        print(failedMessage)
        return False
