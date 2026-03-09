#!/usr/bin/env python3
"""Port scanning helpers for Breakout — portquiz and traceroute methods."""

import logging
import random
import threading
from dataclasses import dataclass, field
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool
from typing import Callable, List

import requests
from scapy.all import IP, TCP, sr1

from lib.ip_check import is_public_ip

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

log = logging.getLogger("breakout")


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------
@dataclass
class ScanResults:
    """Accumulates port scan findings. Thread-safe via lock."""

    open_ports: List[str] = field(default_factory=list)
    possible_ports: List[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_open(self, port: str) -> None:
        """Thread-safe append to open_ports."""
        with self._lock:
            self.open_ports.append(port)

    def add_possible(self, port: str) -> None:
        """Thread-safe append to possible_ports."""
        with self._lock:
            self.possible_ports.append(port)


# Module-level instance so scan functions can append results
scan_results = ScanResults()


# ---------------------------------------------------------------------------
# Multi-threaded scanner — thread-safe counters (#5)
# ---------------------------------------------------------------------------
_counter_lock = threading.Lock()
_check_count: int = 0
_quit_scan: int = 0


def _inc_check_count() -> int:
    """Thread-safe increment and return of _check_count."""
    global _check_count
    with _counter_lock:
        _check_count += 1
        return _check_count


def _inc_quit_scan() -> int:
    """Thread-safe increment and return of _quit_scan."""
    global _quit_scan
    with _counter_lock:
        _quit_scan += 1
        return _quit_scan


def _get_quit_scan() -> int:
    """Thread-safe read of _quit_scan."""
    with _counter_lock:
        return _quit_scan


def _multiprocess_scan(
    aggressive: bool,
    config: "BreakoutConfig",
    port_list: list,
    scan_func: Callable,
    thread_count: int,
    verbose: bool,
) -> None:
    """Run *scan_func* across *port_list* using a thread pool."""
    global _check_count, _quit_scan
    with _counter_lock:
        _check_count = 0
        _quit_scan = 0

    # Scapy's sr1() relies on select(), which crashes if the file descriptor number is >= 1024.
    # To prevent this, we cap the thread count for traceroute scans.
    if scan_func.__name__ == "traceroute_port_check" and thread_count > 200:
        log.debug("Capping traceroute scan threads to 200 to avoid file descriptor limits.")
        thread_count = 200

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

def check_port(aggressive: bool, config: "BreakoutConfig", scan_type: Callable, verbose: bool) -> None:
    """Scan common ports using *scan_type*, then optionally run a full scan."""
    common_ports = config.scan.common_ports

    try:
        _multiprocess_scan(
            aggressive, config, common_ports, scan_type,
            config.scan.port_scan_threads, verbose,
        )
    except Exception:
        pass

    if aggressive:
        if not scan_results.open_ports:
            log.warning("Running Aggressive Scan, no common ports are open")
        else:
            log.warning("Running Aggressive Scan to find all possible open ports and trigger knocks")
            
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

def traceroute_port_check(port_number: int | str, *, aggressive: bool, config: "BreakoutConfig", verbose: bool) -> None:
    """Check if *port_number* is open using a TTL-incrementing traceroute."""
    check_none = 0

    if _get_quit_scan() >= config.scan.quick_limit:
        return

    count = _inc_check_count()
    if count % 1000 == 0:
        log.warning("Still checking for open ports, 1000 checked so far. Trying again.")

    for i in range(1, 28):
        pkt = IP(dst="8.8.8.8", ttl=i) / TCP(dport=int(port_number))
        reply = sr1(pkt, verbose=0, inter=0.5, retry=0, timeout=1)
        if reply is None:
            check_none += 1
            if check_none > 2:
                break
        else:
            if count != 1 and is_public_ip(reply.src) and not reply.flags:
                if verbose:
                    log.info(f"Found open port: {port_number}")
                scan_results.add_open(str(port_number))
                _inc_quit_scan()
                break
            elif reply.type == 3:
                break
            else:
                check_none = 0


def portquiz_scan(port_number: int | str, *, aggressive: bool, config: "BreakoutConfig", verbose: bool) -> None:
    """Check if *port_number* is open using portquiz.net (#16: try HTTPS first)."""

    quit_count = _get_quit_scan()
    if quit_count >= config.scan.quick_limit and not aggressive:
        return
    if quit_count >= config.scan.quick_limit_aggressive:
        return

    count = _inc_check_count()
    if count % 1000 == 0:
        log.warning("Still checking for open ports, 1000 checked so far. Trying again.")

    try:
        # Fix #16: try HTTPS first, fall back to HTTP
        try:
            r = requests.get(f"https://portquiz.net:{port_number}", timeout=(1, 3), verify=False)
        except requests.exceptions.SSLError:
            r = requests.get(f"http://portquiz.net:{port_number}", timeout=(1, 3))

        if "This server listens on all TCP ports" in r.text:
            if verbose:
                log.info(f"Found open port: {port_number}")
            scan_results.add_open(str(port_number))
            _inc_quit_scan()
    except requests.exceptions.ConnectTimeout:
        log.info(f"Closed port: {port_number}")
    except requests.ConnectionError:
        log.info(f"Found possible port: {port_number}")
        scan_results.add_possible(str(port_number))
    except Exception:
        log.info(f"Closed port: {port_number}")
