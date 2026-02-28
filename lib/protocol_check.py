#!/usr/bin/env python3
"""ICMP and DNS protocol checks for Breakout."""

import logging
from typing import Optional

from scapy.all import IP, ICMP, UDP, DNS, DNSQR, sr1

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

log = logging.getLogger("breakout")


def check_icmp() -> bool:
    """Return *True* if ICMP echo to 8.8.8.8 gets a reply."""
    packet = IP(dst="8.8.8.8", ttl=20) / ICMP()
    return bool(sr1(packet, timeout=5, verbose=False))


def check_dns() -> Optional[str]:
    """Attempt a DNS lookup via 8.8.8.8 and return the response summary."""
    for _ in range(3):
        try:
            answer = sr1(
                IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="www.google.com")),
                timeout=5, verbose=0,
            )
            if answer:
                return answer[DNS].summary()
        except Exception:
            continue
    return None
