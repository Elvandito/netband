# netband

ARP-based bandwidth manager for Linux and Android. Monitor, analyze, and limit bandwidth of devices on your local network.

by Elvan

## Requirements

- Linux (tested on Ubuntu/Debian) or Android (Termux with root)
- Python 3.8+
- scapy (`pip3 install scapy`)
- root privileges (for ARP spoofing and traffic control)

## Installation

### Linux

```bash
git clone https://github.com/Elvandito/netband.git
cd netband
sudo python3 setup.py install
```

### Android (Termux)

```bash
pkg update && pkg upgrade
pkg install python scapy root-repo
git clone https://github.com/Elvandito/netband.git
cd netband
sudo python3 setup.py install
```

## Usage

```bash
sudo netband       # Linux
sudo netband       # Android (Termux with root)
```

### CLI Arguments

| Argument | Description |
|----------|-------------|
| `-i` | Network interface (auto-detected if omitted) |
| `-g` | Gateway IP (auto-detected if omitted) |
| `-m` | Gateway MAC (auto-detected if omitted) |
| `-n` | Netmask |
| `-f` | Flush all tc/iptables rules |
| `--colorless` | Disable colored output |

### Commands

| Command | Description |
|---------|-------------|
| `scan [--range IP-IP]` | Scan network for hosts |
| `hosts` | Show discovered hosts |
| `limit IDs RATE [--upload\|--download]` | Limit bandwidth. Rates: bit, kbit, mbit, gbit |
| `block IDs [--upload\|--download]` | Block internet completely |
| `free IDs\|all` | Remove all limits/blocks |
| `add IP [--mac MAC]` | Add custom host to list |
| `monitor [--interval MS]` | Monitor bandwidth of limited hosts |
| `analyze IDs [--duration S]` | Analyze traffic without limiting |
| `status` | Show active limits and blocks |
| `watch` | Show watch status |
| `watch add IDs` | Add hosts to watchlist |
| `watch remove IDs\|all` | Remove from watchlist |
| `watch set range\|interval VALUE` | Change watch settings |
| `clear` | Clear terminal |
| `help` | Show commands |
| `quit` | Exit (auto-restores ARP) |

### Examples

```
netband> scan
netband> hosts
netband> limit 1,2,3 200kbit --download
netband> block 4
netband> free all
netband> monitor --interval 1000
netband> analyze 1,2 --duration 60
```

## How It Works

1. **ARP Spoofing** - Tells the gateway that target IPs are at your MAC, and tells targets that the gateway IP is at your MAC. Traffic flows through your machine.

2. **Traffic Shaping** - Uses `tc` (traffic control) with HTB qdisc to rate-limit traffic. Packets are marked with `iptables` mangle rules, then filtered by `tc`.

3. **Blocking** - Inserts iptables FORWARD/OUTPUT/INPUT DROP rules at the top of the chain, plus blocks DNS (port 53).

4. **Cleanup** - On exit, restores original ARP tables and removes all iptables/tc rules.

## Android Support

On Android, netband uses raw sockets instead of scapy for ARP spoofing. This allows it to work on rooted devices without full scapy support.

## Limitations

- IPv4 only (ARP is IPv4-only)
- Requires root
- WiFi clients may reconnect automatically after ARP restoration
- Some devices ignore ARP replies
- Android: some ROMs restrict iptables, may need Magisk

## License

MIT

## Credits

Inspired by [evillimiter](https://github.com/bitbrute/evillimiter) by bitbrute.
