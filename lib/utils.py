#!/usr/bin/env python3
"""Shared utilities for Breakout — centralised config, logging, and common helpers."""

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import configparser
try:
    import netifaces
except ImportError:
    netifaces = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Base directory — configurable via environment variable, default /opt/breakout
# ---------------------------------------------------------------------------
BASE_DIR: Path = Path(os.environ.get("BREAKOUT_DIR", "/opt/breakout"))

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class WifiConfig:
    connect_wifi: bool = False
    wait_time: int = 5

@dataclass
class ScanConfig:
    callback_port: int = 22
    quick: bool = True
    portquiz: bool = True
    traceroute: bool = True
    common_ports: List[str] = field(default_factory=lambda: ["22","23","21","3389","53","123","80","443","5901","8080","8443"])
    quick_limit: int = 3
    quick_limit_aggressive: int = 100
    port_scan_threads: int = 1
    threads_aggressive: int = 400

@dataclass
class TunnelConfig:
    check_existing: bool = True
    faketcp: bool = True
    icmp: bool = True
    tcp: bool = True
    udp: bool = True
    dns: bool = True
    wait_time: int = 10
    password: str = "passwd"

@dataclass
class BreakoutConfig:
    show_banner: bool = True
    wifi: WifiConfig = field(default_factory=WifiConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    tunnel: TunnelConfig = field(default_factory=TunnelConfig)

_config: BreakoutConfig | None = None


def get_config() -> BreakoutConfig:
    """Load and cache the INI configuration file as a typed dataclass."""
    global _config
    if _config is not None:
        return _config

    cp = configparser.ConfigParser()
    config_path = BASE_DIR / "configs" / "config.ini"
    if not config_path.exists():
        config_path = Path(__file__).parent.parent / "configs" / "config.ini"
    cp.read(str(config_path))

    _config = BreakoutConfig(
        show_banner=cp.getboolean("DEFAULT", "SHOWBANNER", fallback=True),
        wifi=WifiConfig(
            connect_wifi=cp.getboolean("WIFI", "CONNECTWIFI", fallback=False),
            wait_time=cp.getint("WIFI", "WAITTIME", fallback=5),
        ),
        scan=ScanConfig(
            callback_port=cp.getint("SCAN", "CALLBACKPORT", fallback=22),
            quick=cp.getboolean("SCAN", "QUICK", fallback=True),
            portquiz=cp.getboolean("SCAN", "PORTQUIZ", fallback=True),
            traceroute=cp.getboolean("SCAN", "TRACEROUTE", fallback=True),
            common_ports=cp.get("SCAN", "COMMONPORTS", fallback="22,80,443").split(","),
            quick_limit=cp.getint("SCAN", "QUICKLIMIT", fallback=3),
            quick_limit_aggressive=cp.getint("SCAN", "QUICKLIMITAGGRESSIVE", fallback=100),
            port_scan_threads=cp.getint("SCAN", "PORTSCANTHREADS", fallback=1),
            threads_aggressive=cp.getint("SCAN", "THREADSAGGRESSIVE", fallback=400),
        ),
        tunnel=TunnelConfig(
            check_existing=cp.getboolean("TUNNEL", "CHECKEXISTING", fallback=True),
            faketcp=cp.getboolean("TUNNEL", "FAKETCP", fallback=True),
            icmp=cp.getboolean("TUNNEL", "ICMP", fallback=True),
            tcp=cp.getboolean("TUNNEL", "TCP", fallback=True),
            udp=cp.getboolean("TUNNEL", "UDP", fallback=True),
            dns=cp.getboolean("TUNNEL", "DNS", fallback=True),
            wait_time=cp.getint("TUNNEL", "WAITTIME", fallback=10),
            password=cp.get("TUNNEL", "PASSWORD", fallback="passwd"),
        ),
    )
    return _config


# ---------------------------------------------------------------------------
# Coloured logging
# ---------------------------------------------------------------------------
class _ColourFormatter(logging.Formatter):
    """Logging formatter that adds ANSI colour codes based on log level."""

    is_windows = sys.platform.startswith("win")

    COLOURS = {
        logging.DEBUG: "\033[94m",     # blue
        logging.INFO: "\033[92m",      # green
        logging.WARNING: "\033[93m",   # yellow
        logging.ERROR: "\033[91m",     # red
        logging.CRITICAL: "\033[91m",  # red
    }
    RESET = "\033[0m"

    PREFIXES = {
        logging.DEBUG: "[-]",
        logging.INFO: "[+]",
        logging.WARNING: "[*]",
        logging.ERROR: "[x]",
        logging.CRITICAL: "[!]",
    }

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        prefix = self.PREFIXES.get(record.levelno, "")
        if self.is_windows:
            return f"{prefix} {msg}"
        colour = self.COLOURS.get(record.levelno, "")
        return f"{colour}{prefix} {msg}{self.RESET}"


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the application logger with coloured output."""
    logger = logging.getLogger("breakout")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_ColourFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    return logger


# Convenience: module-level logger for files that import utils
log: logging.Logger = setup_logging()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def get_wireless_interfaces() -> List[str]:
    """Return a list of wireless network interface names."""
    if netifaces is None:
        raise RuntimeError("netifaces is required — install it with: pip install netifaces")
    return [iface for iface in netifaces.interfaces() if "wl" in iface]


def write_log(filepath: Path, *fields: str) -> None:
    """Append a space-separated log line to *filepath*."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a") as fh:
        fh.write(" ".join(str(f) for f in fields) + "\n")
