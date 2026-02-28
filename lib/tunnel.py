#!/usr/bin/env python3
"""Core tunnel orchestration for Breakout."""

import logging
import os
import shutil
import subprocess
import time
from typing import List, Optional, Tuple

from lib.autotunnel import CHECK_SSH_LOC, setup_auto_tunnel, current_ssh_tunnel, check_ssh
from lib.network import check_interfaces, setup_gateways, TUNNEL_LOG
from lib.port_check import check_port, portquiz_scan, traceroute_port_check, scan_results
from lib.protocol_check import check_icmp, check_dns
from lib.setup_tunnel import is_port_open, check_tunnel, udp2raw_tunnel, dns_tunnel, kill_iodine
from lib.utils import BreakoutConfig

log = logging.getLogger("breakout")

def success_message(ip_addr: str, port, sshuser: Optional[str]) -> None:
    """Print connection instructions after a successful tunnel."""
    log.info("------------------------------")
    if sshuser:
        log.info(
            f"Port forward using: ssh -f -N -D 8123 {sshuser}@{ip_addr} "
            f"-p{port} -i /home/{sshuser}/.ssh/id_rsa"
        )
    else:
        log.info(f"Port forward example: ssh -f -N -D 8123 root@{ip_addr} -p{port}")
    log.info("Check it's working using: curl --proxy socks5h://localhost:8123 https://ipinfo.io")
    log.info("------------------------------")

def check_ports(aggressive: bool, config: BreakoutConfig, verbose: bool) -> List[str]:
    """Scan for open outbound ports and return a list of open port strings."""
    callback_port: List[str] = []

    if config.scan.portquiz:
        log.debug("Running test for commonly open ports.")
        if verbose:
            log.warning("Checking for open ports using portquiz.net")
        check_port(aggressive, config, portquiz_scan, verbose)
    elif verbose:
        log.info("Config: Skipping portquiz.net scan")

    # Portquiz might be blocked — try traceroute
    if not scan_results.open_ports:
        if config.scan.traceroute:
            if verbose:
                log.error("portquiz.net returned no open ports")
                log.debug("Running test for commonly open ports.")
                log.warning("Checking for open ports using traceroute")
            check_port(aggressive, config, traceroute_port_check, verbose)
        elif verbose:
            log.info("Config: Skipping traceroute scan")

    if scan_results.open_ports:
        callback_port = scan_results.open_ports
        log.info(f"{len(callback_port)} open port/s found")
    else:
        log.error("No open port found.")

    if scan_results.possible_ports:
        log.warning(f"{len(scan_results.possible_ports)} possible port/s found")

    return callback_port

def callback_tcp(
    callback_ip: str, config: BreakoutConfig, sshuser: Optional[str],
    tunnel_password: str, nameserver: Optional[str], verbose: bool,
    callback_port: List[str],
) -> Tuple[str, Optional[str], Optional[str], bool]:
    """Attempt to create a TCP tunnel through open ports."""
    status = False
    tunnel_type: Optional[str] = None
    attempt_port: Optional[str] = None

    if callback_port:
        log.debug("Attempting to create TCP tunnel.")
        if config.tunnel.tcp:
            for attempt_port in callback_port:
                stop_count = 100
                if verbose:
                    log.warning(f"Calling back to IP {callback_ip} on port {attempt_port}")
                for count in range(stop_count):
                    if is_port_open(attempt_port, callback_ip):
                        if check_tunnel(callback_ip, attempt_port):
                            log.info("SSH is Open")
                            success_message(callback_ip, attempt_port, sshuser)
                            return callback_ip, attempt_port, "Open Port", True
                        else:
                            log.error(f"Port {attempt_port} open on IP {callback_ip} but unable to connect via SSH")
                            break
                    else:
                        if verbose:
                            log.debug(f"Waiting for port {attempt_port} to be open on IP {callback_ip}")
                        if count + 1 == stop_count:
                            log.error(f"Port {attempt_port} not open on IP {callback_ip} after {stop_count} attempts")
        elif verbose:
            log.info("Config: Skipping TCP tunnel")
    else:
        log.error(f"Can't attempt TCP Tunnel, no ports found open on IP {callback_ip}")

    return callback_ip, attempt_port, tunnel_type, status

def _setup_non_tcp_tunnel(
    callback_ip: str, nameserver: Optional[str], tunnel_ip: str,
    tunnel_type: str, tunnel_port: int, local_port: int, listen_port: int,
    sshuser: Optional[str], tunnel_password: str, verbose: bool,
) -> bool:
    """Try to establish a single non-TCP tunnel type."""
    log.warning(f"Trying a Udp2raw-tunnel using {tunnel_type}.")
    if udp2raw_tunnel(callback_ip, tunnel_ip, tunnel_type, tunnel_port,
                      local_port, listen_port, tunnel_password, verbose):
        if check_tunnel(tunnel_ip, local_port):
            log.info(f"A Udp2raw-tunnel {tunnel_type} tunnel can be setup!")
            log.debug(f"An {tunnel_type} Tunnel is not as fast as a TCP Tunnel")
            success_message(tunnel_ip, local_port, sshuser)
            return True
        else:
            log.error(f"{tunnel_type} Enabled but unable to create {tunnel_type} Tunnel")
    else:
        log.error(f"{tunnel_type} Enabled but unable to create {tunnel_type} Tunnel")
    return False

def callback_non_tcp(
    callback_ip: str, config: BreakoutConfig, sshuser: Optional[str],
    tunnel_password: str, nameserver: Optional[str], verbose: bool,
) -> Tuple[str, int, Optional[str], bool]:
    """Attempt non-TCP tunnels: faketcp → UDP → ICMP."""
    log.debug("Attempting to create Non TCP tunnel.")
    tunnel_ip = "127.0.0.1"
    local_port = 3322

    # Check required binaries are installed
    missing = []
    if not shutil.which("udp2raw"):
        missing.append("udp2raw")
    if not shutil.which("kcptun_client"):
        missing.append("kcptun_client")
    if missing:
        log.error(f"Non-TCP tunnels require {', '.join(missing)} — install before using")
        return tunnel_ip, local_port, None, False

    tunnel_configs = [
        ("FAKETCP", "faketcp", 4001, 8856),
        ("UDP",     "udp",     4003, 8857),
    ]

    for config_key, tunnel_type, tunnel_port, listen_port in tunnel_configs:
        if getattr(config.tunnel, config_key.lower()):
            if _setup_non_tcp_tunnel(
                callback_ip, nameserver, tunnel_ip, tunnel_type,
                tunnel_port, local_port, listen_port, sshuser, tunnel_password, verbose,
            ):
                return tunnel_ip, local_port, tunnel_type, True
        elif verbose:
            log.info(f"Config: Skipping {config_key} tunnel")

    # ICMP — needs an extra check
    if config.tunnel.icmp:
        if check_icmp():
            if verbose:
                log.info("ICMP is enabled")
            if _setup_non_tcp_tunnel(
                callback_ip, nameserver, tunnel_ip, "icmp",
                4000, local_port, 8855, sshuser, tunnel_password, verbose,
            ):
                return tunnel_ip, local_port, "icmp", True
        else:
            log.error("ICMP is Disabled")
    elif verbose:
        log.info("Config: Skipping ICMP tunnel")

    return tunnel_ip, local_port, None, False

def callback_dns(
    config: BreakoutConfig, sshuser: Optional[str],
    tunnel_password: str, nameserver: Optional[str], verbose: bool,
) -> Tuple[str, int, Optional[str], bool]:
    """Attempt a DNS tunnel via iodine as a last-resort fallback."""
    tunnel_ip = "10.0.0.1"  # iodine default tunnel IP
    tunnel_port = 22

    # Check if an iodine tunnel is already running and connected
    addr_check = subprocess.run(
        ["ip", "-4", "addr", "show", "dns0"],
        capture_output=True, text=True, check=False,
    )
    if "inet " in addr_check.stdout:
        if verbose:
            log.info("Found existing dns0 interface, checking if tunnel is alive...")
        # Check if iodine client process is still running (exact match)
        iodine_running = subprocess.run(
            ["pgrep", "-x", "iodine"], capture_output=True, check=False,
        ).returncode == 0

        if iodine_running:
            # Verify tunnel is actually functional
            ping = subprocess.run(
                ["ping", "-c", "1", "-W", "2", tunnel_ip],
                capture_output=True, check=False,
            )
            if ping.returncode == 0:
                log.info("Existing iodine tunnel detected and working — reusing it")
                success_message(tunnel_ip, tunnel_port, sshuser)
                return tunnel_ip, tunnel_port, "dns", True
            else:
                if verbose:
                    log.warning("iodine process running but tunnel not responding — tearing down")
                kill_iodine()

        # Clean up stale interfaces
        if verbose:
            log.warning("Stale iodine tunnel detected — cleaning up")
        subprocess.run(["ip", "link", "delete", "dns0"], capture_output=True, check=False)
        for i in range(1, 5):
            subprocess.run(["ip", "link", "delete", f"dns{i}"], capture_output=True, check=False)

    if not config.tunnel.dns:
        if verbose:
            log.info("Config: Skipping DNS tunnel")
        return tunnel_ip, tunnel_port, None, False

    if not nameserver:
        log.warning("DNS tunnel requires a nameserver (-n flag) — skipping")
        return tunnel_ip, tunnel_port, None, False

    if not shutil.which("iodine"):
        log.error("DNS tunnel requires iodine — install before using")
        return tunnel_ip, tunnel_port, None, False

    # Verify DNS connectivity
    dns_check = check_dns()
    if not dns_check:
        log.error("DNS is not reachable — cannot create DNS tunnel")
        return tunnel_ip, tunnel_port, None, False

    # Verify NS record exists for the nameserver domain
    try:
        ns_result = subprocess.run(
            ["dig", "+short", "NS", nameserver],
            capture_output=True, text=True, check=False, timeout=10,
        )
        if not ns_result.stdout.strip():
            log.error(
                f"No NS record found for {nameserver} — "
                f"create an NS record pointing to your server before using DNS tunneling"
            )
            return tunnel_ip, tunnel_port, None, False
        if verbose:
            log.info(f"NS record found for {nameserver}: {ns_result.stdout.strip()}")
    except FileNotFoundError:
        log.warning("dig not available — skipping NS record check")
    except Exception as exc:
        log.warning(f"NS record check failed: {exc} — continuing anyway")

    if verbose:
        log.info(f"Attempting DNS tunnel via iodine to {nameserver}")

    if dns_tunnel(tunnel_password, nameserver, verbose):
        log.info("DNS tunnel established via iodine")
        # Verify SSH is reachable through the tunnel
        if check_tunnel(tunnel_ip, tunnel_port):
            success_message(tunnel_ip, tunnel_port, sshuser)
            return tunnel_ip, tunnel_port, "dns", True
        else:
            log.error("DNS tunnel up but SSH not reachable on tunnel interface")
            kill_iodine()
    else:
        log.error("DNS tunnel setup failed")

    return tunnel_ip, tunnel_port, None, False

def quick_scan(callback_port: str, callback_ip: str, config: BreakoutConfig, sshuser: Optional[str], verbose: bool) -> bool:
    """Quick-check if the callback port is already open and SSH-capable."""
    if not config.scan.quick:
        if verbose:
            log.info("Config: Skipping Quick Scan")
        return False

    if is_port_open(callback_port, callback_ip) and check_tunnel(callback_ip, callback_port):
        if verbose:
            log.warning(f"Quick check if port {callback_port} is accessible.")
        log.info("SSH tunnel possible!")
        success_message(callback_ip, callback_port, sshuser)
        return True

    if verbose:
        log.error(f"Quick check failed, Port {callback_port} not accessible.")
    return False

def initialise_tunnel(
    aggressive: bool, callback_ip: Optional[str], config: BreakoutConfig,
    current_ssid: str, tunnel_password: str, is_pi: bool,
    nameserver: Optional[str], sshuser: Optional[str],
    tunnel: bool, verbose: bool,
) -> None:
    """Main entry point — scan for open ports and establish the best available tunnel."""
    successful_connection = False
    timeout = "1800"  # 30 minutes

    # Check if port 8123 SOCKS proxy is already in use
    port_check = subprocess.run(
        ["ss", "-tlnp", "sport", "=", "8123"],
        capture_output=True, text=True, check=False,
    )
    if "8123" in port_check.stdout:
        log.info("Port 8123 is in use, checking if SOCKS proxy is still working...")
        curl_check = subprocess.run(
            ["curl", "--max-time", "5", "--proxy", "socks5h://localhost:8123",
             "-s", "-o", "/dev/null", "-w", "%{http_code}", "https://ipinfo.io"],
            capture_output=True, text=True, check=False,
        )
        if curl_check.returncode == 0 and curl_check.stdout.strip() == "200":
            log.info("Existing SOCKS proxy on port 8123 is working — no tunnel setup needed")
            log.info("Check it's working using: curl --proxy socks5h://localhost:8123 https://ipinfo.io")
            return
        else:
            log.warning("Stale SOCKS proxy on port 8123 detected — killing it")
            subprocess.run(["fuser", "-k", "8123/tcp"], capture_output=True, check=False)

    ethernet_up, ethernet_interface, wireless_up = check_interfaces(current_ssid, verbose)
    check_ssh(CHECK_SSH_LOC)

    if not ethernet_up and not wireless_up:
        log.critical("No Interface is up.")
        if is_pi:
            Path("/sys/class/leds/led1/trigger").write_text("input\n")
        raise SystemExit(1)

    # Check if gateway is set
    try:
        if TUNNEL_LOG.exists():
            gateway_wifi_str = subprocess.run(
                ["tail", "-n", "1", str(TUNNEL_LOG)],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            gateway_wifi = False
            for part in gateway_wifi_str.split():
                if "Tried_WiFi_Gateway=" in part:
                    val = part.split("=")[1].strip()
                    gateway_wifi = (val == "True")
                    break
        else:
            gateway_wifi = False
    except Exception:
        gateway_wifi = False

    if current_ssh_tunnel(config, is_pi, ethernet_up, gateway_wifi, successful_connection, verbose):
        return

    # Check which gateway to use — Ethernet or WiFi
    setup_gateways(ethernet_interface, ethernet_up, gateway_wifi, successful_connection, timeout)

    if is_pi:
        Path("/sys/class/leds/led1/trigger").write_text("input\n")

    # Kill only breakout-spawned reverse SSH tunnels (not user sessions)
    try:
        result = subprocess.run(
            ["pgrep", "-a", "ssh"],
            capture_output=True, text=True, check=False,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and "-R" in parts[1]:
                pid = parts[0]
                log.debug(f"Killing reverse SSH tunnel (PID {pid}): {parts[1]}")
                subprocess.run(["kill", pid], capture_output=True, check=False)
    except Exception:
        pass

    callback_port = str(config.scan.callback_port)
    tunnel_ip = callback_ip
    tunnel_port = callback_port
    tunnel_type = "Open Port"

    tunnel_status = quick_scan(callback_port, callback_ip, config, sshuser, verbose)

    if not tunnel_status:
        open_ports = check_ports(aggressive, config, verbose)

        if all(v is None for v in [callback_ip, nameserver]):
            log.warning("Unable to create tunnel as no nameserver or callback IP was provided.")
        else:
            tunnel_ip, tunnel_port, tunnel_type, tunnel_status = callback_tcp(
                callback_ip, config, sshuser, tunnel_password, nameserver, verbose, open_ports,
            )
            if not tunnel_status:
                tunnel_ip, tunnel_port, tunnel_type, tunnel_status = callback_non_tcp(
                    callback_ip, config, sshuser, tunnel_password, nameserver, verbose,
                )

        # DNS tunnel only needs nameserver, not callback_ip — always try as last resort
        if not tunnel_status:
            tunnel_ip, tunnel_port, tunnel_type, tunnel_status = callback_dns(
                config, sshuser, tunnel_password, nameserver, verbose,
            )

    if not tunnel_status:
        log.critical("Tunnel not possible, as no possible tunnels to the callback server could be found")
    elif tunnel:
        setup_auto_tunnel(gateway_wifi, sshuser, tunnel_ip, tunnel_port, tunnel_type)
        result = subprocess.run(
            ["bash", str(CHECK_SSH_LOC)], capture_output=True, text=True, check=False,
        )
        wait_time = config.tunnel.wait_time
        log.warning(f"Waiting {wait_time} seconds for tunnel to start")
        time.sleep(wait_time)
        log.info(result.stdout)
