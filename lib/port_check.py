#!/usr/bin/env python3
"""Port scanning helpers for Breakout — portquiz and traceroute methods."""

import logging
import random
from dataclasses import dataclass, field
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool
from typing import Callable, List

import requests
from scapy.all import IP, TCP, sr1

from lib.ip_check import is_public_ip
from lib.layout import colour

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

log = logging.getLogger("breakout")

# Import Colour Scheme (still used for some direct print output)
G, Y, B, R, W = colour()


# ---------------------------------------------------------------------------
# Scan results — replaces the old global mutable lists
# ---------------------------------------------------------------------------
@dataclass
class ScanResults:
    """Accumulates port scan findings."""

    open_ports: List[str] = field(default_factory=list)
    possible_ports: List[str] = field(default_factory=list)


# Module-level instance so scan functions can append results
scan_results = ScanResults()


# ---------------------------------------------------------------------------
# Multi-threaded scanner
# ---------------------------------------------------------------------------
_check_count: int = 0
_quit_scan: int = 0


def _multiprocess_scan(
    aggressive: bool,
    config,
    port_list: list,
    scan_func: Callable,
    thread_count: int,
    verbose: bool,
) -> None:
    """Run *scan_func* across *port_list* using a thread pool."""
    global _check_count, _quit_scan
    _check_count = 0
    _quit_scan = 0

    pool = ThreadPool(thread_count)
    pool.map(
        partial(scan_func, aggressive=aggressive, config=config, verbose=verbose),
        port_list,
    )
    pool.close()
    pool.join()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_port(aggressive: bool, config, scan_type: Callable, verbose: bool) -> None:
    """Scan common ports using *scan_type*, then optionally run a full scan."""
    common_ports = config.scan.common_ports

    try:
        _multiprocess_scan(
            aggressive, config, common_ports, scan_type,
            config.scan.port_scan_threads, verbose,
        )
    except Exception:
        pass

    if not scan_results.open_ports and aggressive:
        log.warning("Running Aggressive Scan, no common ports are open")
        log.debug("Running full port check. This may take awhile, please wait.....")
        port_list = [p for p in range(1, 65534) if str(p) not in common_ports]
        random.shuffle(port_list)
        _multiprocess_scan(
            aggressive, config, port_list, scan_type,
            config.scan.threads_aggressive, verbose,
        )


# ---------------------------------------------------------------------------
# Scan methods
# ---------------------------------------------------------------------------

def traceroute_port_check(port_number, *, aggressive: bool, config, verbose: bool) -> None:
    """Check if *port_number* is open using a TTL-incrementing traceroute."""
    global _check_count, _quit_scan
    check_none = 0

    if _quit_scan >= config.scan.quick_limit:
        return

    if _check_count == 1000:
        log.warning("Still checking for open ports, 1000 checked so far. Trying again.")
        _check_count = 0

    for i in range(1, 28):
        pkt = IP(dst="8.8.8.8", ttl=i) / TCP(dport=int(port_number))
        reply = sr1(pkt, verbose=0, inter=0.5, retry=0, timeout=1)
        if reply is None:
            check_none += 1
            if check_none > 2:
                break
        else:
            if _check_count != 1 and is_public_ip(reply.src) and not reply.flags:
                if verbose:
                    log.info(f"Found open port: {port_number}")
                scan_results.open_ports.append(str(port_number))
                _quit_scan += 1
                _check_count += 1
                break
            elif reply.type == 3:
                _check_count += 1
                break
            else:
                check_none = 0
                _check_count += 1


def portquiz_scan(port_number, *, aggressive: bool, config, verbose: bool) -> None:
    """Check if *port_number* is open using portquiz.net."""
    global _check_count, _quit_scan

    if _quit_scan >= config.scan.quick_limit and not aggressive:
        return
    if _quit_scan >= config.scan.quick_limit_aggressive:
        return

    if _check_count == 1000:
        log.warning("Still checking for open ports, 1000 checked so far. Trying again.")
        _check_count = 0

    try:
        r = requests.get(f"http://portquiz.net:{port_number}", timeout=(1, 3))
        if "This server listens on all TCP ports" in r.text:
            if verbose:
                log.info(f"Found open port: {port_number}")
            scan_results.open_ports.append(str(port_number))
            _quit_scan += 1
            _check_count += 1
    except requests.exceptions.ConnectTimeout:
        log.info(f"Closed port: {port_number}")
        _check_count += 1
    except requests.ConnectionError:
        log.info(f"Found possible port: {port_number}")
        scan_results.possible_ports.append(str(port_number))
        _check_count += 1
    except Exception:
        log.info(f"Closed port: {port_number}")
        _check_count += 1
