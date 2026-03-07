#!/usr/bin/env python3
"""Auto-tunnel setup and SSH connection checks for Breakout."""

import logging
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from lib.network import TUNNEL_LOG, write_tunnel_log
from lib.setup_tunnel import is_port_open, check_tunnel
from lib.utils import BASE_DIR, BreakoutConfig

log = logging.getLogger("breakout")

CHECK_SSH_BAK = BASE_DIR / "templates" / "check_ssh.bak"
CHECK_SSH_LOC = BASE_DIR / "check_ssh.sh"

def replace_text(filepath: Path, orig: str, replacement: str) -> None:
    """Replace all occurrences of *orig* with *replacement* in *filepath*."""
    content = filepath.read_text()
    filepath.write_text(content.replace(str(orig), str(replacement)))

def check_ssh_status(callback_ip: str, callback_ssh_port: str) -> bool:
    """Return *True* if an established SSH tunnel to *callback_ip* exists and is healthy."""
    check_ssh_file = CHECK_SSH_LOC
    try:
        result = subprocess.run(
            ["ss", "-tnpa"], capture_output=True, text=True, check=True
        )
        found = False
        for line in result.stdout.splitlines():
            if "ESTAB" in line and "ssh" in line and callback_ip in line and str(callback_ssh_port) in line:
                found = True
                break
        if not found:
            raise subprocess.CalledProcessError(1, "ss")
        if not check_ssh_file.exists():
            return False

        ip: Optional[str] = None
        port: Optional[int] = None
        with open(check_ssh_file) as fh:
            for line in fh:
                match_ip = re.findall(r"(?<=callbackIP=')(.*)(?=')", line)
                if match_ip:
                    ip = match_ip[0]
                match_port = re.findall(r"(?<=callbackPort=')(.*)(?=')", line)
                if match_port:
                    port = int(match_port[0])

        if ip and port:
            log.warning(f"Checking existing SSH port {port} is open on {ip}")
            if not is_port_open(port, ip) or not check_tunnel(ip, port):
                return False
            return True
        return False
    except Exception:
        log.error(f"Existing tunnel {callback_ip} is down")
        return False

def setup_auto_tunnel(gateway_wifi, sshuser: str, sshkey: str, tunnel_ip: str, tunnel_port, tunnel_type: str) -> None:
    """Generate the check_ssh.sh script from the template."""
    shutil.copy(str(CHECK_SSH_BAK), str(CHECK_SSH_LOC))
    replace_text(CHECK_SSH_LOC, "SET_IP", tunnel_ip)
    replace_text(CHECK_SSH_LOC, "SET_PORT", tunnel_port)
    replace_text(CHECK_SSH_LOC, "SET_USER", sshuser)
    replace_text(CHECK_SSH_LOC, "SET_KEY", sshkey)
    replace_text(CHECK_SSH_LOC, "TUNNEL_TYPE", tunnel_type)
    replace_text(CHECK_SSH_LOC, "GATEWAY_WIFI", gateway_wifi)
    log.info("Setup remote tunnel configuration file")

def current_ssh_tunnel(
    config: BreakoutConfig, is_pi: bool, ethernet_up: bool, gateway_wifi,
    successful_connection: bool, verbose: bool,
) -> bool:
    """Return *True* if an existing SSH tunnel is still healthy."""
    if not config.tunnel.check_existing:
        if verbose:
            log.info("Config: Skipping checking existing tunnel")
        return False

    if not CHECK_SSH_LOC.exists():
        return False

    callback_ssh_ip: Optional[str] = None
    callback_ssh_port: Optional[str] = None

    with open(CHECK_SSH_LOC) as fh:
        for line in fh:
            if "callbackIP=" in line:
                callback_ssh_ip = line.split("=")[1].strip().strip("'")
            if "callbackPort=" in line:
                callback_ssh_port = line.split("=")[1].strip().strip("'")

    if callback_ssh_ip and callback_ssh_port and check_ssh_status(callback_ssh_ip, callback_ssh_port):
        log.warning(f"Existing tunnel found and still working on {callback_ssh_ip}:{callback_ssh_port} — skipping new tunnel setup")
        if is_pi:
            Path("/sys/class/leds/led1/trigger").write_text("timer\n")
        write_tunnel_log(ethernet_up, gateway_wifi, True)
        return True

    return False

def check_ssh(check_ssh_loc: Path) -> None:
    """Restart sshd if it has crashed (OpenRC systems only)."""
    try:
        result = subprocess.run(
            ["rc-status", "--crashed"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        # rc-status not available (not an OpenRC system)
        return

    if "sshd" in result.stdout:
        log.critical("SSH crashed!")
        subprocess.run(["rc-service", "sshd", "stop"], check=False)
        subprocess.run(["rc-service", "sshd", "start"], check=False)
        subprocess.run(["bash", str(check_ssh_loc)], check=False)
        log.warning("Setting up SSH")
        time.sleep(10)
