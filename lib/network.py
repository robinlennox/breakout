#!/usr/bin/env python3
"""Routing, gateway management, and network interface checks for Breakout."""

import logging
import shutil
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple

import netifaces

from lib.utils import BASE_DIR, get_wireless_interfaces, write_log

log = logging.getLogger("breakout")

TUNNEL_LOG = BASE_DIR / "logs" / "tunnels.txt"
CHECK_SSH_LOC = BASE_DIR / "check_ssh.sh"

def write_tunnel_log(
    ethernet_up: bool, used_gateway_wifi, successful_connection: bool,
) -> None:
    """Append a tunnel log entry; clear the log on successful connection."""
    if successful_connection:
        TUNNEL_LOG.unlink(missing_ok=True)
    write_log(
        TUNNEL_LOG,
        time.strftime("%b %-d %H:%M:%S"),
        f"Ethernet_Up={ethernet_up}",
        f"Tried_WiFi_Gateway={used_gateway_wifi}",
        f"Successful_Connection={successful_connection}",
    )

def default_route(interface: str) -> Optional[bool]:
    """Attempt to set a default route via DHCP leases for *interface*."""
    try:
        leases = Path("/var/lib/dhcp/dhclient.leases").read_text()
        gateway = None
        in_interface = False
        for line in leases.splitlines():
            if f'interface "{interface}"' in line:
                in_interface = True
            elif in_interface and "routers" in line:
                gateway = line.split("routers")[1].strip().strip(";")
                break
            elif in_interface and "}" in line:
                in_interface = False
        if not gateway:
            raise ValueError(f"No DHCP gateway found for {interface}")

        subprocess.run(
            ["route", "del", "-net", "0.0.0.0", "netmask", "0.0.0.0", "gw", gateway, "dev", interface],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        log.info(f"Set default route to connect to the internet on interface {interface} via gateway {gateway}")
        subprocess.run(
            ["ip", "route", "add", "default", "via", gateway, "dev", interface],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True
    except Exception:
        log.error(f"No DHCP information found for interface {interface}.")
        return None

def is_interface_up(interface: str) -> bool:
    """Return *True* if the network interface *interface* is up."""
    operstate_path = Path(f"/sys/class/net/{interface}/operstate")
    if not operstate_path.exists():
        log.warning(f"Interface {interface} not found")
        return False
    return operstate_path.read_text().strip() != "down"

def setup_gateways(
    ethernet_interface: str, ethernet_up: bool, gateway_wifi,
    successful_connection: bool, timeout: str,
) -> None:
    """Manage gateway failover and log the result."""
    TUNNEL_LOG.parent.mkdir(parents=True, exist_ok=True)
    TUNNEL_LOG.touch()

    attempts = 0
    try:
        cutoff = datetime.now() - timedelta(seconds=int(timeout))
        if TUNNEL_LOG.exists():
            for line in TUNNEL_LOG.read_text().splitlines():
                if "Successful_Connection=False" not in line:
                    continue
                try:
                    parts = line.split()
                    if len(parts) >= 3:
                        time_str = f"{parts[0]} {parts[1]:>2} {parts[2]}" 
                        dt = datetime.strptime(time_str, "%b %d %H:%M:%S")
                        dt = dt.replace(year=datetime.now().year)
                        if dt >= cutoff:
                            attempts += 1
                except Exception:
                    pass
    except Exception:
        pass

    if ethernet_up and attempts > 20:
        log.critical("Unable to tunnel resetting routing tables and rebooting")
        TUNNEL_LOG.unlink(missing_ok=True)
        CHECK_SSH_LOC.unlink(missing_ok=True)
        Path("/etc/motd").unlink(missing_ok=True)
        subprocess.run(["ip", "route", "flush", "table", "main"], check=False)
        # Fix #4: try available DHCP clients instead of assuming udhcpc
        if shutil.which("dhclient"):
            subprocess.run(["dhclient", ethernet_interface], check=False)
        elif shutil.which("udhcpc"):
            subprocess.run(["udhcpc", "-i", ethernet_interface], check=False)
        elif shutil.which("dhcpcd"):
            subprocess.run(["dhcpcd", ethernet_interface], check=False)
        else:
            log.error("No DHCP client found (dhclient, udhcpc, dhcpcd)")
    elif ethernet_up and attempts > 5:
        gateway_wifi = True
        log.critical("Unable to tunnel out using current default routes")
        if not ethernet_interface:
            log.warning("No ethernet interface found to bring down")
        else:
            for wireless_interface in get_wireless_interfaces():
                log.debug(f"Trying to route internet traffic via interface {wireless_interface}")
                result = subprocess.run(
                    ["ip", "link", "set", ethernet_interface, "down"],
                    capture_output=True, text=True, check=False,
                )
                if result.returncode != 0:
                    log.warning(f"Could not bring down interface {ethernet_interface}: {result.stderr.strip()}")
                time.sleep(10)

    write_tunnel_log(ethernet_up, gateway_wifi, successful_connection)

def check_interfaces(current_ssid: str, verbose: bool) -> Tuple[bool, str, bool]:
    """Return (ethernet_up, ethernet_interface, wireless_up)."""
    ethernet_up = True
    wireless_up = False
    ethernet_interface = ""

    for interface in netifaces.interfaces():
        if interface.startswith("e"):
            ethernet_up = is_interface_up(interface)
            ethernet_interface = interface
        if "NOT CONNECTED" not in current_ssid and interface.startswith("w"):
            wireless_up = is_interface_up(interface)

    return ethernet_up, ethernet_interface, wireless_up
