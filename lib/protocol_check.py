#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

from lib.Layout import colour
from scapy.all import IP, ICMP, sr1
import logging
# Disable Scapy error messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# Import Colour Scheme
G, Y, B, R, W = colour()


def check_icmp():
    packet = IP(dst="8.8.8.8", ttl=20)/ICMP()
    return sr1(packet, timeout=5, verbose=False)


def check_dns():
    count = 0
    stopCount = 3
    while (count < stopCount):
        try:
            answer = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,
                                                             qd=DNSQR(qname="www.google.com")), timeout=5, verbose=0)
            count = stopCount
            return answer[DNS].summary()
        except:
            count = count + 1
            pass
