#!/usr/bin/env python3
"""Breakout — automatically break out of a restricted network.

Scans for open firewall ports and establishes a reverse tunnel back to a
callback server via TCP, fake-TCP, UDP, or ICMP.
"""

import argparse
import os
import subprocess
import sys
import time
from typing import Optional, Tuple

from lib.create_tunnel import initialise_tunnel
from lib.ip_check import get_ip
from lib.layout import banner, colour
from lib.script_management import check_running_state
from lib.utils import get_config, setup_logging

config = get_config()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Breakout — network breakout & tunneling tool",
        epilog=f"\tExample: \rpython3 {sys.argv[0]} -c 1.2.3.4",
    )
    parser.add_argument(
        "-a", "--aggressive", action="store_true",
        help="Aggressive scan — try all 65k ports",
    )
    parser.add_argument(
        "-c", "--callback", type=str, default=None,
        help="Callback server IP address",
    )
    parser.add_argument(
        "-n", "--nameserver", type=str, default=None,
        help="Nameserver for DNS callback",
    )
    parser.add_argument(
        "-p", "--password", type=str, default=None,
        help="Password for UDP tunnel (default: from config.ini)",
    )
    parser.add_argument(
        "-r", "--recon", action="store_true",
        help="Enable the reconnaissance module",
    )
    parser.add_argument(
        "-t", "--tunnel", action="store_true",
        help="Enable automatic tunneling",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output",
    )
    return parser.parse_args()


def validate_args(
    args: argparse.Namespace,
) -> Tuple[bool, Optional[str], str, Optional[str], bool, Optional[str], bool, bool]:
    """Validate parsed arguments and return the resolved values.

    Returns:
        (aggressive, callback_ip, tunnel_password, nameserver,
         recon, sshuser, tunnel, verbose)
    """
    log = setup_logging(args.verbose)

    callback_ip = args.callback
    nameserver = args.nameserver
    tunnel_password = args.password if args.password is not None else config.tunnel.password

    if args.tunnel and nameserver and not callback_ip:
        log.error("A callback IP (-c) must be provided when tunneling is enabled")
        sys.exit(1)

    # Discover sshuser from /etc/passwd
    sshuser: Optional[str] = None
    try:
        with open("/etc/passwd") as fh:
            for line in fh:
                if "sshuser" in line:
                    sshuser = line.split(":")[0]
                    break
    except FileNotFoundError:
        pass

    if args.tunnel and sshuser is None:
        log.error("No sshuser found — this needs to be set up for auto tunnel to work")
        sys.exit(1)

    return (
        args.aggressive,
        callback_ip,
        tunnel_password,
        nameserver,
        args.recon,
        sshuser,
        args.tunnel,
        args.verbose,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_ssid(verbose: bool) -> str:
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
    except Exception as exc:
        if verbose:
            print(exc)
        return "NOT CONNECTED"


def start_recon() -> None:
    """Run basic network reconnaissance."""
    log = setup_logging()
    log.debug("Running Recon")
    local_ip = get_ip()
    subnet_ip = ".".join(local_ip.split(".")[:-1]) + ".0"
    log.warning("IP Information")
    log.info(f"The IP address is {local_ip}")
    log.info(f"The IP subnet is {subnet_ip}/24")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point for Breakout."""
    is_pi = os.path.isfile("/sys/class/leds/led1/trigger")

    # Stop if already running
    check_running_state("breakout.py")

    args = parse_args()
    aggressive, callback_ip, tunnel_password, nameserver, recon, sshuser, tunnel, verbose = validate_args(args)

    log = setup_logging(verbose)
    log.info(f"Scan started at {time.strftime('%b %-d %H:%M:%S')}")

    current_ssid = get_ssid(verbose)

    if tunnel:
        log.debug("Auto Tunnel is enabled")

    log.info(f"On SSID: {current_ssid}")

    if os.geteuid() != 0:
        log.error("Script must be run as root")
        sys.exit(1)

    if verbose:
        log.debug("Verbosity is enabled")

    if aggressive:
        log.debug("Aggressive is enabled")

    # Check for open ports and tunnel
    initialise_tunnel(
        aggressive, callback_ip, config, current_ssid,
        tunnel_password, is_pi, nameserver, sshuser, tunnel, verbose,
    )

    if recon:
        start_recon()


if __name__ == "__main__":
    if config.show_banner:
        banner()
    main()
