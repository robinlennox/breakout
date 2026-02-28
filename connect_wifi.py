#!/usr/bin/env python3
"""Auto-connect to open WiFi networks for Breakout."""

import logging
import os
import subprocess
import time
from pathlib import Path
from typing import List, Optional

import wifi

from lib.script_management import check_running_state
from lib.utils import BASE_DIR, get_config, get_wireless_interfaces, write_log

log = logging.getLogger("breakout")
config = get_config()

WIFI_LOG = BASE_DIR / "logs" / "wifi.txt"
IGNORE_SSID_FILE = BASE_DIR / "configs" / "ignore_ssid"


# ---------------------------------------------------------------------------
# WiFi connection
# ---------------------------------------------------------------------------

def attempt_wifi_connect(ssid_name: str, wireless_interface: str) -> bool:
    """Try to connect to an open WiFi SSID and return *True* on success."""
    subprocess.run(["rfkill", "unblock", "wifi"], check=False)
    subprocess.run(["rfkill", "unblock", "all"], check=False)
    subprocess.run(["ifconfig", wireless_interface, "down"], check=False)
    subprocess.run(["iwconfig", wireless_interface, "essid", "any"], check=False)
    subprocess.run(["ifconfig", wireless_interface, "up"], check=False)
    subprocess.run(["iwconfig", wireless_interface, "essid", ssid_name], check=False)

    log.debug("Waiting for network to finish setting up")
    subprocess.run(["dhcpcd", "-i", wireless_interface], check=False)

    wait_time = config.wifi.wait_time
    time.sleep(wait_time)

    for attempt in range(5):
        if get_current_ssid() is not None:
            return True
        if attempt == 4:
            log.warning(f"Failed to get DHCP address for SSID {ssid_name} on {wireless_interface}")
            log.error("Try disabling network management of host such as 'sudo service network-manager stop'")

    return False


def open_wifi(is_pi: bool) -> None:
    """Scan and attempt to connect to open WiFi networks."""
    if is_pi:
        Path("/sys/class/leds/led0/brightness").write_text("0\n")

    for wireless_interface in get_wireless_interfaces():
        subprocess.run(["rfkill", "unblock", "wifi"], check=False)
        subprocess.run(["rfkill", "unblock", "all"], check=False)
        log.info(f"Trying interface {wireless_interface}")
        subprocess.run(["ifconfig", wireless_interface, "up"], check=False)

        try:
            cells = wifi.Cell.all(wireless_interface)
        except Exception:
            continue

        skip_list = create_wifi_blocklist() + create_wifi_ignorelist()

        for cell in cells:
            if cell.ssid in skip_list:
                continue

            timestamp = time.strftime("%b %-d %H:%M:%S")

            if not cell.encrypted and cell.ssid:
                skip_list.append(cell.ssid)
                log.warning(f"Attempting to connect to SSID {cell.ssid} on {wireless_interface}")

                if attempt_wifi_connect(cell.ssid, wireless_interface):
                    log.info(f"Successfully connected to SSID {cell.ssid} on {wireless_interface}")
                    write_log(WIFI_LOG, timestamp, cell.ssid, "Open=Yes", "Connected=Yes")
                    if is_pi:
                        Path("/sys/class/leds/led0/brightness").write_text("1\n")
                    return  # Connected — stop scanning
                else:
                    log.error(f"Failed to connect to SSID {cell.ssid} on {wireless_interface}")
                    write_log(WIFI_LOG, timestamp, cell.ssid, "Open=Yes", "Connected=No")

            elif cell.ssid:
                log.debug(f"Passing encrypted SSID {cell.ssid} on {wireless_interface}")
                skip_list.append(cell.ssid)
                write_log(WIFI_LOG, timestamp, cell.ssid, "Open=No", "Connected=No")


# ---------------------------------------------------------------------------
# SSID helpers
# ---------------------------------------------------------------------------

def get_current_ssid() -> Optional[str]:
    """Return the currently connected SSID, or *None*."""
    result = subprocess.run(
        ["iwconfig"], capture_output=True, text=True, check=False,
    )
    ssid = None
    for line in result.stdout.splitlines():
        if "ESSID:" in line:
            parsed = line.split("ESSID:")[1].strip().strip('"')
            if parsed and parsed != "off/any":
                ssid = parsed
                break
    time.sleep(config.wifi.wait_time)
    return ssid


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
        counts = Counter()
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
    check_running_state("connect_wifi.py")

    is_pi = os.path.isfile("/sys/class/leds/led1/trigger")
    try:
        current_ssid = get_current_ssid()
        if current_ssid is not None:
            log.info(f"Already connected to SSID: {current_ssid}")
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
