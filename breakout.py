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
        "-f", "--force", action="store_true",
        help="Force tunnel recreation — kill existing tunnels and skip health checks",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be done without creating tunnels",
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Show current tunnel status and exit",
    )
    parser.add_argument(
        "--auto-install", action="store_true",
        help="Automatically install Breakout server scripts if missing on the remote server",
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
    host_ssh_key = os.environ.get("HOST_SSH_KEY")

    if args.tunnel:
        run_setup = False
        if not Path(sshkey).exists():
            log.warning(f"SSH key not found at {sshkey}")
            run_setup = True
        elif callback_ip:
            log.info(f"Verifying remote tunnel account {sshuser} on {callback_ip}...")
            ssh_args = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "PasswordAuthentication=no"]
            if host_ssh_key:
                ssh_args.extend(["-i", host_ssh_key])
            if not sys.stdout.isatty():
                ssh_args.extend(["-o", "BatchMode=yes"])
            ssh_args.extend([callback_ip, f"id {sshuser}"])
            
            try:
                res = subprocess.run(ssh_args, capture_output=True, text=True, timeout=10)
                if res.returncode != 0:
                    if args.verbose:
                        log.warning(f"Remote account {sshuser} missing or check failed. Forcing setup.")
                    run_setup = True
            except Exception as e:
                log.debug(f"SSH Remote check error: {e}")

        if run_setup:
            if callback_ip:
                if args.verbose:
                    log.warning("Attempting auto-setup to provision remote account...")
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
                    except subprocess.CalledProcessError:
                        log.error("Auto-setup failed. Please run setup_auto_tunnel.sh manually.")
                        sys.exit(1)
                else:
                    log.error(f"Setup script not found at {setup_script}")
                    sys.exit(1)
            else:
                log.error(f"SSH key missing or account check failed, and no callback IP provided to auto-setup!")
                sys.exit(1)

        # Check if the remote server has breakout server scripts installed
        if callback_ip:
            install_url = "https://raw.githubusercontent.com/robinlennox/breakout/master/setup/install_server.sh"
            ssh_base = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "PasswordAuthentication=no"]
            if host_ssh_key:
                ssh_base.extend(["-i", host_ssh_key])
                
            def update_remote_config():
                update_script = []
                if nameserver:
                    update_script.append(f"sed -i 's/.*DNS_DOMAIN=.*/DNS_DOMAIN=\\${{DNS_DOMAIN:-{nameserver}}}/' /opt/breakout/tunnel_server.sh")
                if config.tunnel.dns_password:
                    update_script.append(f"sed -i 's/.*DNS_PASSWORD=.*/DNS_PASSWORD=\\${{DNS_PASSWORD:-{config.tunnel.dns_password}}}/' /opt/breakout/tunnel_server.sh")
                if config.tunnel.tunnel_password:
                    update_script.append(f"sed -i 's/.*TUNNEL_PASSWORD=.*/TUNNEL_PASSWORD=\\${{TUNNEL_PASSWORD:-{config.tunnel.tunnel_password}}}/' /opt/breakout/tunnel_server.sh")
                if update_script:
                    update_script.append("pkill -9 iodined || true")
                    update_script.append("pkill -9 udp2raw || true")
                    update_script.append("pkill -9 kcptun_server || true")
                    update_cmd = ssh_base + [callback_ip, " && ".join(update_script)]
                    subprocess.run(update_cmd, capture_output=True)
                    log.info("Remote tunnel_server.sh updated with current credentials.")
                    
            ssh_check = ssh_base + ["-o", "ConnectTimeout=5", callback_ip, "test -f /opt/breakout/breakout_tunnels.sh"]
            try:
                res = subprocess.run(ssh_check, capture_output=True, text=True, timeout=10)
                if res.returncode == 255:
                    log.warning(f"Unable to verify the remote server setup on {callback_ip}. It may not respond or is unreachable.")
                elif res.returncode != 0:
                    if args.auto_install:
                        log.warning(f"Breakout server scripts not found on {callback_ip} — installing automatically")
                        install_cmd = ssh_base + [callback_ip, f"curl -sL {install_url} | bash"]
                        try:
                            install_res = subprocess.run(install_cmd, capture_output=True, text=True, timeout=300)
                            if install_res.returncode != 0:
                                log.error(f"Failed to connect to {callback_ip} for server install")
                                log.error(f"Run manually on the server: curl -sL {install_url} | bash")
                                sys.exit(1)
                            log.info("Installed: udp2raw, kcptun_server, iodine, breakout server scripts")
                            log.warning(f"Server {callback_ip} is rebooting to apply changes — waiting for it to come back...")
                            # Wait for server to come back online after reboot
                            time.sleep(15)  # Give it time to start rebooting
                            for attempt in range(18):  # Try for up to 3 minutes
                                ping_cmd = ssh_base + ["-o", "ConnectTimeout=5", callback_ip, "echo ok"]
                                try:
                                    ping_res = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=10)
                                    if ping_res.returncode == 0:
                                        log.info(f"Server {callback_ip} is back online")
                                        
                                        update_remote_config()
                                            
                                        break
                                except Exception:
                                    pass
                                log.info(f"Waiting for server to reboot... ({(attempt + 1) * 10}s)")
                                time.sleep(10)
                            else:
                                log.error(f"Server {callback_ip} did not come back after 3 minutes — check manually")
                        except subprocess.CalledProcessError:
                            log.error(f"Server install failed. Run manually on the server:")
                            log.error(f"  curl -sL {install_url} | bash")
                    else:
                        log.warning(f"Unable to verify the remote server setup on {callback_ip}. Target scripts may be missing.")
                        log.warning(f"Use --auto-install to provision automatically or install manually: curl -sL {install_url} | bash")
                elif res.returncode == 0:
                    if args.verbose:
                        log.info(f"Breakout server scripts verified on {callback_ip}")
                    if args.auto_install:
                        update_remote_config()
            except subprocess.TimeoutExpired:
                log.warning(f"Unable to verify the remote server setup on {callback_ip}. It may not respond as it cannot be reached.")
            except Exception as e:
                log.debug(f"Server check skipped: {e}")

    # Always re-read config for SSH_USER in case it was auto-provisioned
    # or updated from a previous run
    import configparser
    cp = configparser.ConfigParser()
    cp.read(BASE_DIR / "configs" / "config.ini")
    if cp.has_option("TUNNEL", "SSH_USER"):
        sshuser = cp.get("TUNNEL", "SSH_USER")

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
    force = args.force or config.tunnel.force_new_tunnel

    log = setup_logging(verbose)

    if force:
        log.warning("Force mode — existing tunnels will be torn down")

    log.info(f"Scan started at {time.strftime('%b %-d %H:%M:%S %Z')}")

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

    # Verify sshd is running before attempting tunnels
    sshd_check = subprocess.run(
        ["ss", "-nlpt"], capture_output=True, text=True, check=False,
    )
    if 'sshd"' not in sshd_check.stdout:
        log.critical("sshd is not running — reverse tunnels need a local SSH daemon. Start sshd first.")
        return 1

    # Run recon if requested
    if recon:
        start_recon()

    # If only recon was requested (no callback/nameserver/tunnel), exit early
    if not callback_ip and not nameserver and not tunnel:
        return 0

    # Check for open ports and tunnel
    success = initialise_tunnel(
        aggressive, callback_ip, config, current_ssid,
        tunnel_password, is_pi, nameserver, sshuser, sshkey, tunnel, verbose,
        dry_run=dry_run,
    )

    if tunnel and success:
        log.info("Keeping container alive for tunneling (Press Ctrl+C to exit)...")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            pass

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
