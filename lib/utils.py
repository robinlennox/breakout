#!/usr/bin/env python3
"""Shared utilities for Breakout — centralised config, logging, and common helpers."""

import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

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
# Constants — centralised magic numbers
# ---------------------------------------------------------------------------
SOCKS_PROXY_PORT: int = 8123
IODINE_TUNNEL_IP: str = "10.0.0.1"
IODINE_TUNNEL_PORT: int = 22
DNS_INTERFACE: str = "dns0"
UDP2RAW_PORTS = {
    "icmp": {"tunnel": 4000, "listen": 8855, "local": 4444},
    "faketcp": {"tunnel": 4001, "listen": 8856, "local": 4445},
    "udp": {"tunnel": 4002, "listen": 8857, "local": 4446},
}


# Known valid config keys per section
_VALID_KEYS = {
    "DEFAULT": {"show_banner"},
    "WIFI": {"connect_wifi", "wait_time"},
    "SCAN": {
        "callback_port", "quick", "portquiz", "traceroute", "common_ports",
        "quick_limit", "quick_limit_aggressive", "port_scan_threads",
        "threads_aggressive", "dns_resolver",
    },
    "TUNNEL": {
        "check_existing", "fake_tcp", "icmp", "tcp", "udp", "dns",
        "wait_time", "password", "ssh_key", "ssh_user", "force_new_tunnel",
        "knock_hits",
    },
}

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
    dns_resolver: str = "8.8.8.8"

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
    sshkey: str = "/opt/breakout/keys/id_rsa"
    sshuser: str = "tunnel"
    force_new_tunnel: bool = False
    knock_hits: int = 200

@dataclass
class BreakoutConfig:
    show_banner: bool = True
    wifi: WifiConfig = field(default_factory=WifiConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    tunnel: TunnelConfig = field(default_factory=TunnelConfig)

_config: Optional[BreakoutConfig] = None


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

    # Validate config keys
    logger = logging.getLogger("breakout")
    for section in cp.sections():
        valid = _VALID_KEYS.get(section.upper(), None)
        if valid is None:
            logger.warning(f"config.ini: unknown section [{section}]")
            continue
        for key in cp.options(section):
            if key not in valid and key not in _VALID_KEYS.get("DEFAULT", set()):
                logger.warning(f"config.ini: unknown key '{key}' in [{section}]")

    _config = BreakoutConfig(
        show_banner=cp.getboolean("DEFAULT", "SHOW_BANNER", fallback=True),
        wifi=WifiConfig(
            connect_wifi=cp.getboolean("WIFI", "CONNECT_WIFI", fallback=False),
            wait_time=cp.getint("WIFI", "WAIT_TIME", fallback=5),
        ),
        scan=ScanConfig(
            callback_port=cp.getint("SCAN", "CALLBACK_PORT", fallback=22),
            quick=cp.getboolean("SCAN", "QUICK", fallback=True),
            portquiz=cp.getboolean("SCAN", "PORTQUIZ", fallback=True),
            traceroute=cp.getboolean("SCAN", "TRACEROUTE", fallback=True),
            common_ports=cp.get("SCAN", "COMMON_PORTS", fallback="22,80,443").split(","),
            quick_limit=cp.getint("SCAN", "QUICK_LIMIT", fallback=3),
            quick_limit_aggressive=cp.getint("SCAN", "QUICK_LIMIT_AGGRESSIVE", fallback=100),
            port_scan_threads=cp.getint("SCAN", "PORT_SCAN_THREADS", fallback=1),
            threads_aggressive=cp.getint("SCAN", "THREADS_AGGRESSIVE", fallback=400),
            dns_resolver=cp.get("SCAN", "DNS_RESOLVER", fallback="8.8.8.8"),
        ),
        tunnel=TunnelConfig(
            check_existing=cp.getboolean("TUNNEL", "CHECK_EXISTING", fallback=True),
            faketcp=cp.getboolean("TUNNEL", "FAKE_TCP", fallback=True),
            icmp=cp.getboolean("TUNNEL", "ICMP", fallback=True),
            tcp=cp.getboolean("TUNNEL", "TCP", fallback=True),
            udp=cp.getboolean("TUNNEL", "UDP", fallback=True),
            dns=cp.getboolean("TUNNEL", "DNS", fallback=True),
            wait_time=cp.getint("TUNNEL", "WAIT_TIME", fallback=10),
            password=cp.get("TUNNEL", "PASSWORD", fallback="passwd"),
            sshkey=cp.get("TUNNEL", "SSH_KEY", fallback="/opt/breakout/keys/id_rsa"),
            sshuser=cp.get("TUNNEL", "SSH_USER", fallback="tunnel"),
            force_new_tunnel=cp.getboolean("TUNNEL", "FORCE_NEW_TUNNEL", fallback=False),
            knock_hits=cp.getint("TUNNEL", "KNOCK_HITS", fallback=200),
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


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def get_wireless_interfaces() -> List[str]:
    """Return a list of wireless network interface names."""
    if netifaces is None:
        raise RuntimeError("netifaces is required — install it with: pip install netifaces")
    return [iface for iface in netifaces.interfaces() if "wl" in iface]


def get_ssid() -> str:
    """Return the current wireless SSID, or ``'NOT CONNECTED'``."""
    try:
        result = subprocess.run(
            ["iwconfig"], capture_output=True, text=True, check=False,
        )
        for line in result.stdout.splitlines():
            if "ESSID:" in line:
                ssid = line.split("ESSID:")[1].strip().strip('"')
                if ssid and ssid != "off/any":
                    return ssid
        return "NOT CONNECTED"
    except Exception:
        return "NOT CONNECTED"


def write_log(filepath: Path, *fields: str) -> None:
    """Append a space-separated log line to *filepath*."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a") as fh:
        fh.write(" ".join(str(f) for f in fields) + "\n")
