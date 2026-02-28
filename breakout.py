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
from pathlib import Path

from lib.tunnel import initialise_tunnel
from lib.ip_check import get_ip
from lib.layout import banner, colour
from lib.script_management import check_running_state
from lib.utils import get_config, get_ssid, setup_logging, BASE_DIR

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
        help="Password for tunnel (default: from config.ini)",
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
        "-k", "--key", type=str, default=None,
        help="Path to SSH private key (default: from config.ini)",
    )
    parser.add_argument(
        "-u", "--user", type=str, default=None,
        help="Remote SSH user for auto-tunnel (default: from config.ini)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be done without creating tunnels",
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Show current tunnel status and exit",
    )
    return parser.parse_args()


def validate_args(
    args: argparse.Namespace,
) -> Tuple[bool, Optional[str], str, Optional[str], bool, Optional[str], bool, bool, bool]:
    """Validate parsed arguments and return the resolved values.

    Returns:
        (aggressive, callback_ip, tunnel_password, nameserver,
         recon, sshuser, sshkey, tunnel, verbose, dry_run)
    """
    log = setup_logging(args.verbose)

    callback_ip = args.callback
    nameserver = args.nameserver
    tunnel_password = args.password if args.password is not None else config.tunnel.password

    # DNS-only mode is valid: -n nameserver without -c callback
    if not callback_ip and not nameserver:
        if not args.recon and not args.status:
            log.warning("No callback IP (-c) or nameserver (-n) specified — limited functionality")

    # Resolve sshuser and sshkey
    sshuser: str = args.user if args.user is not None else config.tunnel.sshuser
    sshkey: str = args.key if args.key is not None else config.tunnel.sshkey

    if args.tunnel and not Path(sshkey).exists():
        if callback_ip:
            log.warning(f"SSH key not found at {sshkey} — attempting auto-setup...")
            setup_script = BASE_DIR / "setup" / "setup_auto_tunnel.sh"
            if setup_script.exists():
                try:
                    setup_args = ["bash", str(setup_script), callback_ip, "22", "Auto-provisioned Drop-box"]
                    if args.verbose:
                        setup_args.append("-v")
                    subprocess.run(
                        setup_args,
                        check=True
                    )
                    # Re-read config in case setup_auto_tunnel updated the SSHUSER
                    import configparser
                    cp = configparser.ConfigParser()
                    cp.read(BASE_DIR / "configs" / "config.ini")
                    if cp.has_option("TUNNEL", "SSHUSER"):
                        sshuser = cp.get("TUNNEL", "SSHUSER")
                except subprocess.CalledProcessError:
                    log.error("Auto-setup failed. Please run setup_auto_tunnel.sh manually.")
                    sys.exit(1)
            else:
                log.error(f"Setup script not found at {setup_script}")
                sys.exit(1)
        else:
            log.error(f"SSH key not found at {sshkey} and no callback IP provided to auto-setup!")
            sys.exit(1)

    return (
        args.aggressive,
        callback_ip,
        tunnel_password,
        nameserver,
        args.recon,
        sshuser,
        sshkey,
        args.tunnel,
        args.verbose,
        args.dry_run,
    )


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def show_status() -> None:
    """Show current tunnel status and exit."""
    log = setup_logging()
    log.info("Tunnel Status")

    # Check SOCKS proxy on 8123
    port_check = subprocess.run(
        ["ss", "-tlnp", "sport", "=", "8123"],
        capture_output=True, text=True, check=False,
    )
    if "8123" in port_check.stdout:
        curl_check = subprocess.run(
            ["curl", "--max-time", "5", "--proxy", "socks5h://localhost:8123",
             "-s", "-o", "/dev/null", "-w", "%{http_code}", "https://ipinfo.io"],
            capture_output=True, text=True, check=False,
        )
        if curl_check.returncode == 0 and curl_check.stdout.strip() == "200":
            log.info("SOCKS proxy on port 8123: ACTIVE and working")
        else:
            log.warning("SOCKS proxy on port 8123: STALE (port in use but not working)")
    else:
        log.error("SOCKS proxy on port 8123: NOT RUNNING")

    # Check iodine tunnel
    dns_check = subprocess.run(
        ["ip", "-4", "addr", "show", "dns0"],
        capture_output=True, text=True, check=False,
    )
    if "inet " in dns_check.stdout:
        iodine_running = subprocess.run(
            ["pgrep", "-x", "iodine"], capture_output=True, check=False,
        ).returncode == 0
        if iodine_running:
            log.info("DNS tunnel (iodine): ACTIVE — dns0 interface up")
        else:
            log.warning("DNS tunnel (iodine): STALE — dns0 exists but iodine not running")
    else:
        log.error("DNS tunnel (iodine): NOT RUNNING")

    # Check SSH tunnels
    ssh_check = subprocess.run(
        ["ss", "-tnpa"], capture_output=True, text=True, check=False,
    )
    ssh_tunnels = [l for l in ssh_check.stdout.splitlines() if "ESTAB" in l and "ssh" in l]
    if ssh_tunnels:
        log.info(f"SSH tunnels: {len(ssh_tunnels)} established connection(s)")
        for t in ssh_tunnels:
            parts = t.split()
            if len(parts) >= 5:
                log.info(f"  {parts[4]}")
    else:
        log.error("SSH tunnels: NONE")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def start_recon() -> None:
    """Run basic network reconnaissance."""
    log = setup_logging()
    log.debug("Running Recon")
    local_ip = get_ip()
    subnet_ip = ".".join(local_ip.split(".")[:3]) + ".0"
    log.warning("IP Information")
    log.info(f"The IP address is {local_ip}")
    log.info(f"The IP subnet is {subnet_ip}/24")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """Entry point for Breakout. Returns exit code."""
    is_pi = os.path.isfile("/sys/class/leds/led1/trigger")

    # Stop if already running
    check_running_state("breakout.py")

    args = parse_args()

    # --status: show tunnel status and exit
    if args.status:
        show_status()
        return 0

    aggressive, callback_ip, tunnel_password, nameserver, recon, sshuser, sshkey, tunnel, verbose, dry_run = validate_args(args)

    log = setup_logging(verbose)
    log.info(f"Scan started at {time.strftime('%b %-d %H:%M:%S')}")

    current_ssid = get_ssid()

    if tunnel:
        log.debug("Auto Tunnel is enabled")

    if dry_run:
        log.warning("DRY RUN — no tunnels will be created")

    log.info(f"On SSID: {current_ssid}")

    if os.geteuid() != 0:
        log.error("Script must be run as root")
        return 1

    if verbose:
        log.debug("Verbosity is enabled")

    if aggressive:
        log.debug("Aggressive is enabled")

    # Check for open ports and tunnel
    success = initialise_tunnel(
        aggressive, callback_ip, config, current_ssid,
        tunnel_password, is_pi, nameserver, sshuser, sshkey, tunnel, verbose,
        dry_run=dry_run,
    )

    if recon:
        start_recon()

    return 0 if success else 1


if __name__ == "__main__":
    if config.show_banner:
        banner()
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log = setup_logging()
        log.warning("\nInterrupted — cleaning up")
        sys.exit(130)
