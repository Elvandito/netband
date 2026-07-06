<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-green" alt="version">
  <img src="https://img.shields.io/badge/python-3.8+-blue" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-yellow" alt="license">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Android-red" alt="platform">
</p>

<h1 align="center">netband</h1>

<p align="center">
  <b>ARP-based bandwidth manager for Linux & Android</b><br>
  <sub>Monitor, analyze, limit, and block bandwidth on your local network</sub>
</p>

---

## Preview

```
   ███╗  ██╗███████╗████████╗██████╗  █████╗ ███╗  ██╗██████╗
   ████╗ ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗████╗ ██║██╔══██╗
   ██╔██╗██║█████╗     ██║   ██████╔╝███████║██╔██╗██║██║  ██║
   ██║╚████║██╔══╝     ██║   ██╔══██╗██╔══██║██║╚████║██║  ██║
   ██║ ╚███║███████╗   ██║   ██████╔╝██║  ██║██║ ╚███║██████╔╝
   ╚═╝  ╚══╝╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚══╝╚═════╝
   by Elvan ~ limit devices on your network    v1.1
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Interface: wlan0    
   Local IP:  192.168.1.6
   Gateway:   192.168.1.1 (aa:bb:cc:dd:ee:ff)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Features

- **ARP Spoofing** — intercept traffic between targets and gateway
- **Bandwidth Limiting** — rate-limit upload/download per host
- **Internet Blocking** — full block with DNS filtering
- **Real-time Monitoring** — live RX/TX stats for limited hosts
- **Traffic Analysis** — passive bandwidth analysis without limits
- **IP Change Watch** — detect hosts that reconnect with new IPs
- **Android Support** — raw socket fallback for rooted Termux
- **Auto-detection** — interface, gateway, and MAC resolved automatically
- **Clean Exit** — restores ARP tables and flushes iptables/tc on quit

## Requirements

- Linux (Ubuntu/Debian/Arch) or Android (rooted Termux)
- Python 3.8+
- Root privileges
- `scapy` for packet injection

## Installation

### Linux

```bash
git clone https://github.com/Elvandito/netband.git
cd netband
sudo python3 setup.py install
sudo netband
```

### Android (Termux)

```bash
pkg update && pkg upgrade
pkg install python root-repo
pip install setuptools scapy
git clone https://github.com/Elvandito/netband.git
cd netband
sudo python3 setup.py install
sudo netband
```

> **Note:** Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/), not Play Store. Device must be rooted.

## Quick Start

```bash
sudo netband              # launch
> scan                    # discover devices
> hosts                   # list found devices
> limit 1,2,3 200kbit     # limit bandwidth
> block 4                 # block internet
> free all                # remove all limits
> quit                    # cleanup and exit
```

## Commands

| Command | Description |
|---------|-------------|
| `scan [--range IP-IP]` | Scan network for online hosts |
| `hosts` | Display discovered hosts with status |
| `limit IDs RATE [--upload\|--download]` | Limit bandwidth (bit, kbit, mbit, gbit) |
| `block IDs [--upload\|--download]` | Block internet completely |
| `free IDs\|all` | Remove all limits and blocks |
| `add IP [--mac MAC]` | Manually add host to list |
| `monitor [--interval MS]` | Real-time bandwidth monitoring |
| `analyze IDs [--duration S]` | Passive traffic analysis |
| `status` | Show active limits and blocks |
| `watch` | IP change detection status |
| `watch add IDs` | Add hosts to watchlist |
| `watch remove IDs\|all` | Remove from watchlist |
| `watch set range\|interval VAL` | Configure watch settings |
| `clear` | Clear terminal |
| `help` | Show all commands |
| `quit` | Exit (auto-restores ARP) |

## CLI Arguments

| Argument | Description |
|----------|-------------|
| `-i IFACE` | Force network interface |
| `-g IP` | Force gateway IP |
| `-m MAC` | Force gateway MAC |
| `-n NETMASK` | Force netmask |
| `-f` | Flush all tc/iptables rules |
| `--colorless` | Disable colored output |

## How It Works

| Step | Mechanism |
|------|-----------|
| **ARP Spoofing** | Sends forged ARP replies so targets route traffic through your machine |
| **Traffic Shaping** | `tc` HTB qdisc + `iptables` mangle MARK for per-host rate control |
| **Blocking** | `iptables` FORWARD/OUTPUT/INPUT DROP + DNS port 53 block |
| **Cleanup** | Restores real ARP tables, flushes iptables chains, removes tc qdisc |

## Project Structure

```
netband/
  netband/
    __init__.py        # version & metadata
    netband.py         # main source code
  setup.py             # package installer
  README.md
  .gitignore
```

## Android Support

On Android (Termux), netband automatically detects the environment and falls back to **raw sockets** for ARP spoofing when scapy is not fully supported. The tool also resolves binary paths for `tc`, `iptables`, and `sysctl` from Termux's prefix directory.

## Limitations

| Limitation | Detail |
|-----------|--------|
| IPv4 only | ARP protocol is IPv4-exclusive |
| Root required | Needs CAP_NET_RAW + iptables/tc access |
| WiFi reconnection | Targets may auto-reconnect after ARP restore |
| ARP ignore | Some devices ignore unsolicited ARP replies |
| Android iptables | Some ROMs require Magisk for iptables access |

## License

MIT License

## Credits

Inspired by [evillimiter](https://github.com/bitbrute/evillimiter) by bitbrute.

---

<p align="center">
  <sub>Made with Python by <b>Elvan</b></sub>
</p>
