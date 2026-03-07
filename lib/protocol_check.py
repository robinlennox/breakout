#!/usr/bin/env python3
"""ICMP and DNS protocol checks for Breakout."""

import logging
from typing import Optional

from scapy.all import IP, ICMP, UDP, DNS, DNSQR, sr1

from lib.utils import get_config

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

log = logging.getLogger("breakout")


def check_icmp(target: Optional[str] = None) -> bool:
    """Return *True* if ICMP echo to *target* gets a reply.
    """
    if target is None:
        target = get_config().scan.dns_resolver
    packet = IP(dst=target, ttl=20) / ICMP()
    return bool(sr1(packet, timeout=5, verbose=False))


def check_dns(resolver: Optional[str] = None) -> Optional[str]:
    """Attempt a DNS lookup via *resolver* and return the response summary.
    """
    if resolver is None:
        resolver = get_config().scan.dns_resolver
    for _ in range(3):
        try:
            answer = sr1(
                IP(dst=resolver) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="www.google.com")),
                timeout=5, verbose=0,
            )
            if answer:
                return answer[DNS].summary()
        except Exception:
            continue
    return None
