#!/usr/bin/env python3
"""Auto-connect to open WiFi networks for Breakout."""

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from lib.script_management import check_running_state
from lib.utils import BASE_DIR, get_config, get_ssid, get_wireless_interfaces, write_log

log = logging.getLogger("breakout")
config = get_config()

WIFI_LOG = BASE_DIR / "logs" / "wifi.txt"
IGNORE_SSID_FILE = BASE_DIR / "configs" / "ignore_ssid"


# ---------------------------------------------------------------------------
# WiFi connection
# ---------------------------------------------------------------------------

def attempt_wifi_connect(ssid_name: str, wireless_interface: str) -> bool:
    """Try to connect to an open WiFi SSID and return *True* on success.

    Fix #13: uses `ip` commands instead of deprecated `ifconfig`.
    """
    subprocess.run(["rfkill", "unblock", "wifi"], check=False)
    subprocess.run(["rfkill", "unblock", "all"], check=False)
    subprocess.run(["ip", "link", "set", wireless_interface, "down"], check=False)
    subprocess.run(["iwconfig", wireless_interface, "essid", "any"], check=False)
    subprocess.run(["ip", "link", "set", wireless_interface, "up"], check=False)
    subprocess.run(["iwconfig", wireless_interface, "essid", ssid_name], check=False)

    log.debug("Waiting for network to finish setting up")

    # Fix #13: try available DHCP clients
    if shutil.which("dhclient"):
        subprocess.run(["dhclient", wireless_interface], check=False)
    elif shutil.which("dhcpcd"):
        subprocess.run(["dhcpcd", "-i", wireless_interface], check=False)
    elif shutil.which("udhcpc"):
        subprocess.run(["udhcpc", "-i", wireless_interface], check=False)
    else:
        log.error("No DHCP client found (dhclient, dhcpcd, udhcpc)")
        return False

    wait_time = config.wifi.wait_time
    time.sleep(wait_time)

    for attempt in range(5):
        if get_ssid() != "NOT CONNECTED":
            return True
        if attempt == 4:
            log.warning(f"Failed to get DHCP address for SSID {ssid_name} on {wireless_interface}")
            log.error("Try disabling network management of host such as 'sudo service network-manager stop'")

    return False


def _scan_wifi(wireless_interface: str) -> list:
    """Scan for WiFi networks using iwlist (replaces deprecated wifi package #13)."""
    networks = []
    try:
        result = subprocess.run(
            ["iwlist", wireless_interface, "scan"],
            capture_output=True, text=True, check=False,
        )
        current_ssid = None
        encrypted = False
        for line in result.stdout.splitlines():
            line = line.strip()
            if "ESSID:" in line:
                current_ssid = line.split("ESSID:")[1].strip().strip('"')
            elif "Encryption key:on" in line:
                encrypted = True
            elif "Encryption key:off" in line:
                encrypted = False
            elif line.startswith("Cell ") or "Address:" in line:
                if current_ssid is not None:
                    networks.append({"ssid": current_ssid, "encrypted": encrypted})
                current_ssid = None
                encrypted = False
        # Don't forget the last cell
        if current_ssid is not None:
            networks.append({"ssid": current_ssid, "encrypted": encrypted})
    except Exception as exc:
        log.warning(f"WiFi scan failed on {wireless_interface}: {exc}")
    return networks


def open_wifi(is_pi: bool) -> None:
    """Scan and attempt to connect to open WiFi networks."""
    if is_pi:
        Path("/sys/class/leds/led0/brightness").write_text("0\n")

    for wireless_interface in get_wireless_interfaces():
        subprocess.run(["rfkill", "unblock", "wifi"], check=False)
        subprocess.run(["rfkill", "unblock", "all"], check=False)
        log.info(f"Trying interface {wireless_interface}")
        subprocess.run(["ip", "link", "set", wireless_interface, "up"], check=False)

        cells = _scan_wifi(wireless_interface)
        if not cells:
            continue

        skip_list = create_wifi_blocklist() + create_wifi_ignorelist()

        for cell in cells:
            ssid = cell["ssid"]
            if ssid in skip_list or not ssid:
                continue

            timestamp = time.strftime("%b %-d %H:%M:%S")

            if not cell["encrypted"]:
                skip_list.append(ssid)
                log.warning(f"Attempting to connect to SSID {ssid} on {wireless_interface}")

                if attempt_wifi_connect(ssid, wireless_interface):
                    log.info(f"Successfully connected to SSID {ssid} on {wireless_interface}")
                    write_log(WIFI_LOG, timestamp, ssid, "Open=Yes", "Connected=Yes")
                    if is_pi:
                        Path("/sys/class/leds/led0/brightness").write_text("1\n")
                    return  # Connected — stop scanning
                else:
                    log.error(f"Failed to connect to SSID {ssid} on {wireless_interface}")
                    write_log(WIFI_LOG, timestamp, ssid, "Open=Yes", "Connected=No")

            else:
                log.debug(f"Passing encrypted SSID {ssid} on {wireless_interface}")
                skip_list.append(ssid)
                write_log(WIFI_LOG, timestamp, ssid, "Open=No", "Connected=No")


# ---------------------------------------------------------------------------
# SSID helpers
# ---------------------------------------------------------------------------

def create_wifi_ignorelist() -> List[str]:
    """Return SSIDs from the ignore list file."""
    ignorelist: List[str] = []
    if not IGNORE_SSID_FILE.exists():
        return ignorelist

    with open(IGNORE_SSID_FILE) as fh:
        for line in fh:
            ssid = line.strip()
            if ssid:
                log.info(f"Ignoring SSID: {ssid}")
                ignorelist.append(ssid)
    return ignorelist


def create_wifi_blocklist() -> List[str]:
    """Return SSIDs that have been scanned too many times recently."""
    blocklist: List[str] = []
    timeout = 180000

    from collections import Counter
    from datetime import datetime, timedelta

    if not WIFI_LOG.exists():
        return blocklist

    try:
        cutoff = datetime.now() - timedelta(seconds=timeout)
        counts: Counter = Counter()
        for line in WIFI_LOG.read_text().splitlines():
            try:
                parts = line.split()
                if len(parts) >= 4:
                    time_str = f"{parts[0]} {parts[1]:>2} {parts[2]}" 
                    dt = datetime.strptime(time_str, "%b %d %H:%M:%S")
                    dt = dt.replace(year=datetime.now().year)
                    if dt >= cutoff:
                        ssid = parts[3]
                        counts[ssid] += 1
            except Exception:
                pass
                
        for ssid_name, scan_count in counts.items():
            if scan_count > 5:
                log.info(
                    f"Skipping SSID {ssid_name} already scanned {scan_count} times "
                    f"in {timeout // 60} minutes"
                )
                blocklist.append(ssid_name)
    except Exception:
        pass

    return blocklist


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point for WiFi auto-connect."""
    from lib.utils import setup_logging
    setup_logging()
    check_running_state("connect_wifi.py")

    is_pi = os.path.isfile("/sys/class/leds/led1/trigger")
    try:
        current = get_ssid()
        if current != "NOT CONNECTED":
            log.info(f"Already connected to SSID: {current}")
            if is_pi:
                Path("/sys/class/leds/led0/brightness").write_text("1\n")
        else:
            open_wifi(is_pi)
    except subprocess.CalledProcessError:
        open_wifi(is_pi)


if __name__ == "__main__":
    if config.wifi.connect_wifi:
        main()
    else:
        log.info("Config: Skipping Wifi Auto Connect")
