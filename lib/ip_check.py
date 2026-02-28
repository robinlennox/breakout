#!/usr/bin/env python
# By Robin Lennox - twitter.com/robberbear

import logging
import socket
# Disable Scapy error messages
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from netaddr import *

def ip_validate(ip_addr): #Check if IP is public
    ip_addr = IPAddress(ip_addr)
    return ip_addr.is_unicast() and not ip_addr.is_private() and not ip_addr.is_loopback() and not ip_addr.is_reserved() and not ip_addr.is_hostmask()

def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("gmail.com",80))
    return s.getsockname()[0]
    s.close()