#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import logging
import random
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool

from scapy.all import IP, TCP, sr1
import requests


from lib.IPCheck import ip_validate
from lib.Layout import colour

# Disable Scapy error messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# Import Colour Scheme
G, Y, B, R, W = colour()

global possiblePorts
possiblePorts = []

global openPorts
openPorts = []


def multiprocessing(aggressive, config, port_list, scan_type, threadcount, verbose):
    global check_count
    check_count = 0
    
    global quitscan
    quitscan = 0

    pool = ThreadPool(threadcount)
    pool.map(partial(scan_type, aggressive=aggressive, config=config, verbose=verbose),
             port_list)
    pool.close()
    pool.join()


def check_port(aggressive, config, scan_type, verbose,):
    common_ports = config.get('SCAN','COMMONPORTS').split(',')

    try:
        multiprocessing(aggressive, config, common_ports, scan_type, config.getint('SCAN','PORTSCANTHREADS'), verbose, )
        if openPorts:
            pass
    except Exception as e:
        #print(e)
        pass

    openPorts = 1
    if not openPorts and aggressive:
        print(Y+"[*] Running Aggressive Scan, no common ports are open"+W)
        print(
            B+"[-] Running full port check. This may take awhile, please wait....."+W)
        port_list = range(1, 65534)
        # Remove common ports
        port_list = [x for x in port_list if x not in common_ports]
        # Random List for searching
        random.shuffle(port_list)
        multiprocessing(aggressive, config, port_list, scan_type, config.getint('SCAN','THREADSAGGRESSIVE'), verbose, )


def traceroute_port_check(portNumber, aggressive, config, verbose):
    global check_count
    global quitscan
    check_none = 0

    # Stop after finding one port open to prevent detection.
    if quitscan >= config.getint('SCAN','QUICKLIMIT'):
        return

    if check_count == 1000:
        print(
            Y+"[*] Still checking for open ports, 1000 checked so far. Trying again."+W)
        check_count = 0

    for i in range(1, 28):
        pkt = IP(dst="8.8.8.8", ttl=i) / TCP(dport=int(portNumber))
        # Send the packet and get a reply
        reply = sr1(pkt, verbose=0, inter=0.5, retry=0, timeout=1)
        if reply is None:
            # No reply =(
            check_none += 1
            # Try two hops before giving up
            if check_none > 2:
                break
        else:
            if check_count != 1 and ip_validate(reply.src) is True and not reply.flags:
                if verbose:
                    print("[+] Found open port: {0}".format(portNumber))
                openPorts.append(str(portNumber))
                quitscan += 1
                check_count += 1
                break

            elif reply.type == 3:
                # We've reached our destination
                check_count += 1
                break
            else:
                # Reset Check None
                check_none = 0
                check_count += 1


def portquiz_scan(portNumber, aggressive, config, verbose):
    global check_count
    global quitscan
    # Stop after finding one port open to prevent detection.
    if quitscan >= config.getint('SCAN','QUICKLIMIT') and aggressive is False:
        return
    elif quitscan >= config.getint('SCAN','QUICKLIMITAGGRESSIVE'):
        return

    if check_count == 1000:
        print(
            Y+"[*] Still checking for open ports, 1000 checked so far. Trying again."+W)
        check_count = 0
    try:
        r = requests.get(
            'http://portquiz.net:{0}'.format(str(portNumber)), timeout=(1, 3))
        # Verify the portquiz website is hit and not proxy page
        if "This server listens on all TCP ports, allowing you to test any outbound TCP port." in r.text:
            if verbose:
                print("[+] Found open port: {0}".format(portNumber))
            openPorts.append(str(portNumber))
            quitscan += 1
            check_count += 1
    # If Timeout
    except requests.exceptions.ConnectTimeout:
        print("[+] Closed port: {0}".format(portNumber))
        check_count += 1
        pass
    # If open but not a HTTP Connection
    except requests.ConnectionError:
        print("[+] Found possible port: {0}".format(portNumber))
        possiblePorts.append(str(portNumber))
        check_count += 1
    except Exception:
        print("[+] Closed port: {0}".format(portNumber))
        check_count += 1
        pass
