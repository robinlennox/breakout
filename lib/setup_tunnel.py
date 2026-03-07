#!/usr/bin/env python3
"""Tunnel setup and verification helpers for Breakout."""

import logging
import os
import socket
import subprocess
import time
from typing import Optional

from scapy.all import IP, TCP, sr1

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

log = logging.getLogger("breakout")


def is_port_open(port: int | str, ip: str) -> bool:
    """Send a TCP SYN to *ip*:*port* and return *True* if SYN-ACK is received."""
    try:
        response = sr1(
            IP(dst=ip) / TCP(dport=int(port), flags="S"),
            verbose=False, timeout=2,
        )
        if response and response.haslayer(TCP) and response[TCP].flags == 18:
            return True
        return False
    except Exception as exc:
        log.warning(f"is_port_open: {exc}")
        return False


def port_knock(port: int | str, ip: str, hits: int = 15) -> None:
    """Send *hits* TCP SYN packets to *ip*:*port* as fast as possible to trigger NAT knock rules."""
    log.debug(f"Sending {hits} TCP SYN packets to {ip}:{port} for port knocking...")
    try:
        # Instead of waiting for a response with sr1, we use send() for fire-and-forget
        from scapy.all import send
        pkt = IP(dst=ip) / TCP(dport=int(port), flags="S")
        
        # Send packets rapidly
        send(pkt, count=hits, verbose=False)
        log.debug(f"Knock complete for {ip}:{port}.")
        
        # Give the iptables rule a tiny moment to apply
        time.sleep(1)
    except Exception as exc:
        log.warning(f"port_knock failed: {exc}")


def udp2raw_tunnel_attempt(
    callback_ip: str,
    tunnel_ip: str,
    tunnel_type: str,
    tunnel_port: int,
    listen_port: int,
    local_port: int,
    tunnel_password: str,
) -> bool:
    """Attempt a single udp2raw + kcptun tunnel connection."""
    try:
        subprocess.run(["pkill", "udp2raw"], capture_output=True, check=False)
    except Exception:
        pass

    udp2raw_cmd = [
        "udp2raw", "-c", f"-r{callback_ip}:{listen_port}", f"-l0.0.0.0:{tunnel_port}",
        "--raw-mode", tunnel_type, "-k", tunnel_password, "-a"
    ]
    kcptun_cmd = [
        "kcptun_client", "-r", f"127.0.0.1:{tunnel_port}", "-l", f":{local_port}",
        "-mode", "fast2", "-mtu", "1300"
    ]

    try:
        log.debug(f"Running: {' '.join(udp2raw_cmd)}")
        subprocess.Popen(
            udp2raw_cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        log.debug(f"Running: {' '.join(kcptun_cmd)}")
        subprocess.Popen(
            kcptun_cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        time.sleep(5)

        # Fix #7: replaced shell=True with direct subprocess call
        log.debug(f"Verifying tunnel: nc 127.0.0.1 {local_port}")
        result = subprocess.run(
            ["nc", "-w", "5", "127.0.0.1", str(local_port)],
            capture_output=True, text=True, check=False,
            timeout=10, stdin=subprocess.DEVNULL,
        )
        nc_output = (result.stdout + result.stderr).strip()
        if nc_output:
            log.debug(f"nc response: {nc_output}")

        return "SSH" in result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        log.debug("nc timed out — tunnel not responding")
        return False
    except Exception as exc:
        log.error(f"Tunnel attempt failed: {exc}")
        return False


def udp2raw_tunnel(
    callback_ip: str,
    tunnel_ip: str,
    tunnel_type: str,
    tunnel_port: int,
    local_port: int,
    listen_port: int,
    tunnel_password: str,
    verbose: bool,
) -> bool:
    """Retry *udp2raw_tunnel_attempt* up to 5 times."""
    
    # Prerequisite port check

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', local_port))
    except OSError:
        log.error(f"Port {local_port} is already in use by another process. Skipping {tunnel_type} tunnel.")
        return False

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', tunnel_port))
    except OSError:
        log.error(f"Internal proxy port {tunnel_port} is already in use. Skipping {tunnel_type} tunnel.")
        return False

    for attempt in range(5):
        if verbose:
            log.debug(
                f"Attempting {tunnel_type} tunnel (attempt {attempt + 1}/5) "
                f"to {callback_ip} — udp2raw port {listen_port}, "
                f"kcptun port {tunnel_port}, local port {local_port}"
            )
        time.sleep(5)
        if udp2raw_tunnel_attempt(
            callback_ip, tunnel_ip, tunnel_type, tunnel_port,
            listen_port, local_port, tunnel_password,
        ):
            return True
    return False


def check_tunnel(ip_addr: str, port_number: int | str) -> bool:
    """Test if *ip_addr*:*port_number* has an SSH service by reading the banner.

    Fix #2: replaced fake-credential pxssh login with a simple TCP banner check.
    This avoids triggering fail2ban and is faster.
    """
    try:
        sock = socket.create_connection((ip_addr, int(port_number)), timeout=5)
        try:
            banner = sock.recv(256).decode(errors="replace")
            return "SSH" in banner
        finally:
            sock.close()
    except (ConnectionRefusedError, ConnectionResetError):
        log.debug(f"Connection refused to {ip_addr}:{port_number}")
        return False
    except (socket.timeout, OSError) as exc:
        log.debug(f"check_tunnel failed: {exc}")
        return False


# ---------------------------------------------------------------------------
# DNS Tunnel (iodine)
# ---------------------------------------------------------------------------

def kill_iodine() -> None:
    """Kill any running iodine processes."""
    subprocess.run(["pkill", "iodine"], capture_output=True, check=False)


def call_iodine(mode_flags: str, password: str, nameserver: str, verbose: bool, timeout: int = 30) -> bool:
    """Start iodine with the given mode flags and verify the tunnel is connected."""
    kill_iodine()
    time.sleep(1)

    cmd = ["iodine", "-f"]
    cmd.extend(mode_flags.split())
    cmd.extend(["-P", password, nameserver])

    if verbose:
        log.debug(f"Running: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        # Wait for the tunnel to actually connect (not just interface creation)
        for i in range(timeout):
            time.sleep(1)

            # Check if iodine is still running
            if proc.poll() is not None:
                remaining = proc.stderr.read().decode(errors="replace").strip() if proc.stderr else ""
                if "No suitable DNS query type" in remaining:
                    log.error("DNS tunnel failed — nameserver is not resolving queries (check your DNS records)")
                elif "bad password" in remaining.lower():
                    log.error("DNS tunnel failed — incorrect password")
                elif "connection refused" in remaining.lower():
                    log.error("DNS tunnel failed — iodined server is not running or unreachable")
                elif remaining:
                    log.error(f"DNS tunnel failed — {remaining.splitlines()[-1]}")
                else:
                    log.error("DNS tunnel failed — iodine exited unexpectedly")
                return False

            # Check if dns0 has an IP address assigned (not just created)
            result = subprocess.run(
                ["ip", "-4", "addr", "show", "dns0"],
                capture_output=True, text=True, check=False,
            )
            if "inet " not in result.stdout:
                if verbose and i % 5 == 0:
                    log.debug(f"Waiting for iodine tunnel... ({i}/{timeout}s)")
                continue

            # dns0 has an IP and iodine is still running — tunnel is up
            log.info("iodine tunnel connected and verified")
            return True

        log.error("iodine tunnel timed out — interface never came up or no connectivity")
        return False
    except FileNotFoundError:
        log.error("iodine binary not found — install iodine first")
        return False
    except Exception as exc:
        log.error(f"iodine failed: {exc}")
        return False


def dns_tunnel(password: str, nameserver: str, verbose: bool) -> bool:
    """Try to establish a DNS tunnel via iodine — RAW mode first, then fallback."""
    # Try RAW mode first (fastest)
    if verbose:
        log.info("Attempting DNS tunnel using RAW mode")
    if call_iodine("-O RAW", password, nameserver, verbose, 30):
        log.info("DNS Tunnel using RAW mode setup.")
        return True
    kill_iodine()

    # Fallback: direct mode (slow but more compatible)
    if verbose:
        log.info("RAW mode failed, attempting DNS tunnel in direct mode (slow)")
    if call_iodine("-r -I1", password, nameserver, verbose, 100):
        log.info("DNS Tunnel in direct mode setup (slow).")
        return True
    kill_iodine()

    return False
