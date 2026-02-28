#!/usr/bin/env python3
"""ICMP and DNS protocol checks for Breakout."""

import logging
from typing import Optional

from scapy.all import IP, ICMP, UDP, DNS, DNSQR, sr1

from lib.utils import DEFAULT_DNS_RESOLVER

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

log = logging.getLogger("breakout")


def check_icmp(target: str = DEFAULT_DNS_RESOLVER) -> bool:
    """Return *True* if ICMP echo to *target* gets a reply.

    Fix #6: uses configurable DNS resolver instead of hardcoded 8.8.8.8.
    """
    packet = IP(dst=target, ttl=20) / ICMP()
    return bool(sr1(packet, timeout=5, verbose=False))


def check_dns(resolver: str = DEFAULT_DNS_RESOLVER) -> Optional[str]:
    """Attempt a DNS lookup via *resolver* and return the response summary.

    Fix #6: uses configurable DNS resolver instead of hardcoded 8.8.8.8.
    """
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
