#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import requests
import logging
# Disable Scapy error messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from multiprocessing.dummy import Pool as ThreadPool
from netaddr import *
from scapy.all import *

from lib.Layout import *
from lib.IPCheck import *

#Import Colour Scheme
G,Y,B,R,W = colour()

global possiblePorts
possiblePorts = []

global openPorts
openPorts = []

def multiprocessing(port_list,scan_type,threadcount):
    pool = ThreadPool(threadcount)
    results = pool.map(scan_type, port_list)
    pool.close()
    pool.join()

def check_port(scan_type,aggressive,verbose,):
    global check_count
    global quitscan
    quitscan = 0
    check_count = 0

    # Ordered by my common.
    common_ports = [22,23,21,3389,53,123,5901,8080,8443]
    #common_ports = [22,23,21,3389,53,123,80,443,5901,8080,8443]
    #common_ports = [80, 53, 110, 500, 995,from netaddr import * 1723, 443, 21, 110, 123, 143, 264, 587, 993, 465, 6080, 3389, 8001, 8014, 8028, 8081, 8020, 8030, 8023, 8080]
    #common_ports = [1,7,9,13,19,21,22,23,25,37,42,49,53,69,79,80,81,85,105,109,110,111,113,123,135,137,138,139,143,161,179,222,264,384,389,402,407,443,444,445,446,465,500,502,512,513,514,515,523,524,540,548,554,587,617,623,689,705,771,783,888,902,910,912,921,993,995,998,1000,1024,1030,1035,1090,1098,1099,1100,1101,1102,1103,1128,1129,1158,1199,1211,1220,1234,1241,1300,1311,1352,1433,1444,1435,1440,1494,1521,1530,1533,1581,1582,1604,1720,1723,1755,1811,1900,2000,2001,2049,2100,2103,2121,2199,2207,2222,2323,2362,2380,2381,2525,2533,2598,2638,2809,2947,2967,3000,3037,3050,3057,3128,3200,3217,3273,3299,3306,3389,3460,3500,3628,3632,3690,3780,3790,3817,4000,4322,4433,4444,4445,4659,4679,4848,5000,5038,5040,5051,5060,5061,5093,5168,5247,5250,5351,5353,5355,5400,5405,5432,5433,5498,5520,5521,5554,5555,5560,5580,5631,5632,5666,5800,5814,5900,5901,5902,5903,5904,5905,5906,5907,5908,5909,5910,5920,5984,5985,5986,6000,6050,6060,6070,6080,6101,6106,6112,6262,6379,6405,6502,6503,6504,6542,6660,6661,6667,6905,6988,7001,7021,7071,7080,7144,7181,7210,7443,7510,7579,7580,7700,7770,7777,7778,7787,7800,7801,7879,7902,8000,8001,8008,8014,8020,8023,8028,8030,8080,8081,8082,8087,8090,8095,8161,8180,8205,8222,8300,8303,8333,8400,8443,8444,8503,8800,8812,8834,8880,8888,8889,8890,8899,8901,8902,8903,9000,9002,9080,9081,9084,9090,9099,9100,9111,9152,9200,9390,9391,9495,9809,9810,9811,9812,9813,9814,9815,9855,9999,10000,10001,10008,10050,10051,10080,10098,10162,10202,10203,10443,10616,10628,11000,11099,11211,11234,11333,12174,12203,12221,12345,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20010,20031,20034,20101,20111,20171,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,30718,31001,31099,32764,32913,34205,34443,37718,38080,38292,40007,41025,41080,41523,41524,44334,44818,45230,46823,46824,47001,47002,48899,49152,50000,50001,50002,50003,50004,50013,50500,50501,50502,50503,50504,52302,55553,57772,62078,62514,65535]
    #common_ports = [3389]
    
    # Limit test port to 1 thread to avoid detection
    try:
        multiprocessing(common_ports,scan_type,1)
        if openPorts:
            pass
    except:
        pass
    else:
        if aggressive:
            print Y+"[*] Running Aggressive Scan, no common ports are open"+W
            print B+"[-] Running full port check. This may take awhile, please wait....."+W
            port_list = range(1, 65534)
            # Remove common ports
            port_list = [x for x in port_list if x not in common_ports]
            # Random List for searching
            random.shuffle(port_list)
            multiprocessing(port_list,scan_type,400)

def traceroute_port_check(portNumber):
    global check_count
    global quitscan
    check_none = 0

    # Stop after finding one port open to prevent detection.
    if quitscan > 0:
        return

    if check_count == 1000:
        print Y+"[*] Still checking for open ports, 1000 checked so far. Trying again."+W
        check_count = 0

    for i in range(1, 28):
        pkt = IP(dst="8.8.8.8", ttl=i) / TCP(dport=portNumber)
        # Send the packet and get a reply
        reply = sr1(pkt, verbose=0,inter=0.5,retry=0,timeout=1)
        if reply is None:
            # No reply =(
            check_none += 1
            # Try two hops before giving up
            if check_none > 2:
                break
        else:
            #print ip_validate(reply.src)
            if check_count != 1 and ip_validate(reply.src) is True and not reply.flags:
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

def portquiz_scan(portNumber):
    global check_count
    global quitscan
    # Stop after finding one port open to prevent detection.
    if quitscan > 0:
        return

    if check_count == 1000:
        print Y+"[*] Still checking for open ports, 1000 checked so far. Trying again."+W
        check_count = 0
    try:
        r = requests.get('http://portquiz.net:'+str(portNumber), timeout=(1,3))
        # Verify the portquiz website is hit and not proxy page
        if "This server listens on all TCP ports, allowing you to test any outbound TCP port." in r.text:
            #print "[+] Found open port: %s" % (portNumber)
            openPorts.append(str(portNumber))
            quitscan += 1
            check_count += 1
    # If Timeout
    except requests.exceptions.ConnectTimeout as e:
        #print "[+] Closed port: %s" % (portNumber)
        check_count += 1
        pass
    # If open but not a HTTP Connection
    except requests.ConnectionError, e:
        #print "[+] Found possible port: %s" % (portNumber)
        possiblePorts.append(str(portNumber))
        check_count += 1
    except:
        #print "[+] Closed port: %s" % (portNumber)
        check_count += 1
        pass