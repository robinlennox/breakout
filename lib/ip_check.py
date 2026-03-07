#!/usr/bin/env python3
"""IP validation and local-address helpers for Breakout."""

import socket
from typing import Optional

from netaddr import IPAddress

from lib.utils import get_config


def is_public_ip(ip_addr: str) -> bool:
    """Return *True* if *ip_addr* is a publicly routable unicast address."""
    addr = IPAddress(ip_addr)
    return (
        addr.is_unicast()
        and not addr.is_private()
        and not addr.is_loopback()
        and not addr.is_reserved()
        and not addr.is_hostmask()
    )


def get_ip(target: Optional[str] = None) -> Optional[str]:
    """Return the local IP address used to reach the internet.
    """
    if target is None:
        target = get_config().scan.dns_resolver
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        return s.getsockname()[0]
    finally:
        s.close()