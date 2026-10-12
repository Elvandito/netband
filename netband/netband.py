#!/usr/bin/env python3
"""
netband - ARP-based local network bandwidth manager.
Usage: sudo netband [-i IFACE] [-g GW_IP] [-m GW_MAC] [--colorless] [-f]
"""

import os, sys, re, time, json, signal, argparse, threading, struct
import socket as _socket
import ipaddress
import subprocess
import shlex
import contextlib
import io
from pathlib import Path

IS_ANDROID = os.path.exists("/system/build.prop") or "ANDROID_ROOT" in os.environ
IS_WINDOWS = os.name == "nt"

_stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')
try:
    from scapy.all import ARP, Ether, sendp, sr1
    import warnings; warnings.filterwarnings("ignore")
    SCAPY_OK = not IS_ANDROID
except ImportError:
    SCAPY_OK = False
finally:
    sys.stderr.close()
    sys.stderr = _stderr

BROADCAST = "ff:ff:ff:ff:ff:ff"
VERSION = "1.4"
TOOL_NAME = "netband"

# ── config ───────────────────────────────────────────────────────────

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

# ── colors ───────────────────────────────────────────────────────────

class C:
    RST="\033[0m"; RED="\033[91m"; GRN="\033[92m"; YEL="\033[93m"
    BLU="\033[94m"; CYN="\033[96m"; BLD="\033[1m"; DIM="\033[2m"
    MAG="\033[95m"

def no_color():
    for a in dir(C):
        if a.isupper(): setattr(C, a, "")

# ── shell ────────────────────────────────────────────────────────────

def _ps_quote(value):
    """Quote a value as a PowerShell single-quoted string."""
    return "'" + str(value).replace("'", "''") + "'"


def sh(cmd):
    if IS_WINDOWS:
        try:
            r = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd],
                capture_output=True, text=True, timeout=8, encoding="utf-8", errors="replace"
            )
            return r.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    try:
        return subprocess.run(
            ["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=8,
            encoding="utf-8", errors="replace"
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def shq(cmd):
    if IS_WINDOWS:
        # Turn PowerShell terminating errors into a non-zero process result.
        script = "$ErrorActionPreference='Stop'; try { " + cmd + "; exit 0 } catch { exit 1 }"
        try:
            r = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8
            )
            return r.returncode
        except (OSError, subprocess.SubprocessError):
            return 1
    try:
        return subprocess.run(["/bin/sh", "-c", cmd], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=8).returncode
    except (OSError, subprocess.SubprocessError):
        return 1

# ── raw ARP (Android-safe) ───────────────────────────────────────────

def _arp_packet(eth_src, arp_src, arp_src_ip, eth_dst, arp_dst, arp_dst_ip, op=2):
    def mac2b(m): return bytes(int(x, 16) for x in m.split(":"))
    def ip2b(i): return _socket.inet_aton(i)
    eth = mac2b(eth_dst) + mac2b(eth_src) + b'\x08\x06'
    arp = struct.pack("!HHBBH", 0x0001, 0x0800, 6, 4, op)
    arp += mac2b(arp_src) + ip2b(arp_src_ip) + mac2b(arp_dst) + ip2b(arp_dst_ip)
    return eth + arp

def _send_raw_arp(iface, pkt):
    try:
        s = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(0x0806))
        s.bind((iface, 0))
        s.send(pkt)
        s.close()
    except Exception:
        pass

# ── detection ────────────────────────────────────────────────────────

def _detect_network():
    iface, gw_ip = None, None
    if IS_WINDOWS:
        out = sh("Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway} | Select-Object -First 1 InterfaceAlias,IPv4DefaultGateway | ConvertTo-Json -Compress")
        try:
            d = json.loads(out)
            gw = d.get("IPv4DefaultGateway")
            if isinstance(gw, list): gw = gw[0]
            return d.get("InterfaceAlias"), gw.get("NextHop") if gw else None
        except Exception:
            return None, None
    try:
        lines = Path("/proc/net/route").read_text().splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "00000000" and parts[2] != "00000000":
                iface = parts[0]
                gw_ip = _socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
                return iface, gw_ip
    except Exception: pass

    out = sh("ip route show table all 2>/dev/null")
    for line in out.splitlines():
        m = re.search(r"default\s+via\s+([0-9\.]+)\s+dev\s+(\S+)", line)
        if m: return m.group(2), m.group(1)

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
    if IS_WINDOWS:
        out = sh(f"Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias {_ps_quote(iface)} -ErrorAction SilentlyContinue | Where-Object {{$_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1'}} | Select-Object -First 1 -ExpandProperty IPAddress")
        if out: return out.splitlines()[0].strip()
        return None
    addresses = re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)", sh(f"ip -4 addr show dev {shlex.quote(str(iface))} 2>/dev/null"))
    for address in [*addresses, None]:
        s = None
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            if address: s.bind((address, 0))
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            pass
        finally:
            try: s.close()
            except Exception: pass

def detect_gw(iface=None):
    _, g = _detect_network()
    if g: return g
    if iface:
        loc = get_local_ip(iface)
        if loc:
            net = ".".join(loc.split(".")[:3])
            for last in ["1", "254", "0"]:
                test_gw = f"{net}.{last}"
                if test_gw == loc:
                    continue
                if IS_WINDOWS:
                    try:
                        ping_ok = subprocess.run(["ping", "-n", "1", "-w", "700", test_gw],
                                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                                 timeout=1.5).returncode == 0
                    except (OSError, subprocess.SubprocessError):
                        ping_ok = False
                else:
                    ping_ok = shq(f"ping -c 1 -W 1 {test_gw}") == 0
                if ping_ok:
                    return test_gw
            return f"{net}.1"
    return None

def get_mac(ip, iface=None):
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    if IS_WINDOWS:
        try:
            subprocess.run(["ping", "-n", "1", "-w", "700", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            out = sh(f"Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{$_.IPAddress -eq {_ps_quote(ip)}}} | Select-Object -First 1 -ExpandProperty LinkLayerAddress")
            if out and re.fullmatch(r"(?i)[0-9a-f]{2}([-:][0-9a-f]{2}){5}", out.strip()):
                return out.strip().replace("-", ":").lower()
            out = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=2).stdout
            m = re.search(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out)
            if m: return m.group(1).replace("-", ":").lower()
        except Exception: pass
        return None
    # Trigger ARP by connecting UDP
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.sendto(b"", (ip, 1))
        s.close()
    except Exception: pass

    # Read kernel ARP table
    try:
        for line in open("/proc/net/arp").read().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == ip:
                mac = parts[3].lower()
                if mac != "00:00:00:00:00:00": return mac
    except Exception: pass

    # ip neigh
    out = sh(f"ip neigh show {ip} 2>/dev/null")
    m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
    if m: return m.group(1).lower()

    # arping
    iface_flag = f"-I {shlex.quote(str(iface))}" if iface else ""
    out2 = sh(f"{ARPING} -c 2 -w 2 -f {iface_flag} {ip} 2>/dev/null")
    m2 = re.search(r"\[([0-9a-fA-F:]{17})\]", out2)
    if m2: return m2.group(1).lower()

    if SCAPY_OK:
        try:
            r = sr1(ARP(op=1, pdst=ip), timeout=1, verbose=0)
            if r: return r.hwsrc.lower()
        except: pass
    return None

def get_local_mac(iface):
    """Get local MAC, multiple fallbacks."""
    if IS_WINDOWS:
        out = sh(f"Get-NetAdapter -Name {_ps_quote(iface)} -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty MacAddress")
        return out.strip().replace("-", ":").lower() if out else "00:00:00:00:00:00"
    try:
        return open(f"/sys/class/net/{iface}/address").read().strip().lower()
    except Exception: pass
    m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", sh(f"ip link show {shlex.quote(str(iface))} 2>/dev/null"))
    if m: return m.group(1).lower()
    out = sh(f"cat /sys/class/net/{iface}/address 2>/dev/null")
    if out and ":" in out: return out.strip().lower()
    return "00:00:00:00:00:00"

def get_subnet(iface):
    if IS_WINDOWS:
        out = sh(f"Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias {_ps_quote(iface)} -ErrorAction SilentlyContinue | Where-Object {{$_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1'}} | Select-Object -First 1 IPAddress,PrefixLength | ConvertTo-Json -Compress")
        try:
            d = json.loads(out); return d.get("IPAddress"), int(d.get("PrefixLength", 24))
        except Exception: return None, None
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", sh(f"ip -4 addr show dev {shlex.quote(str(iface))} 2>/dev/null"))
    if not m: return None, None
    return m.group(1), int(m.group(2))

# ── hostname resolution ───────────────────────────────────────────────

def _resolve_mdns(ip, timeout=1.0):
    """Query mDNS (224.0.0.251:5353) untuk hostname .local"""
    try:
        # Build mDNS PTR query untuk reverse lookup
        # e.g. 55.110.168.192.in-addr.arpa
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        name_parts = rev.encode().split(b".")

        # DNS query packet
        txid   = b"\x00\x01"
        flags  = b"\x00\x00"
        qdcnt  = b"\x00\x01"
        ancnt  = b"\x00\x00"
        nscnt  = b"\x00\x00"
        arcnt  = b"\x00\x00"
        header = txid + flags + qdcnt + ancnt + nscnt + arcnt

        qname = b""
        for part in name_parts:
            qname += bytes([len(part)]) + part
        qname += b"\x00"
        qtype  = b"\x00\x0c"  # PTR
        qclass = b"\x00\x01"  # IN (unicast bit NOT set for mDNS compat)
        query  = header + qname + qtype + qclass

        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        # Send directly to host (unicast mDNS query)
        s.sendto(query, (ip, 5353))
        data, _ = s.recvfrom(512)
        s.close()

        # Parse answer section — cari string setelah header (12 bytes) + question
        # Simple: cari null-terminated label setelah RDATA
        # Cukup grep printable string dari response
        idx = 12 + len(qname) + 4  # skip header + question
        if idx >= len(data): return None

        # Skip pointer/labels di answer, ambil RDATA
        # Cari nama di answer: skip name(2 byte ptr atau labels), type(2), class(2), ttl(4), rdlen(2)
        i = idx
        # skip name
        while i < len(data):
            ll = data[i]
            if ll == 0: i += 1; break
            if ll & 0xc0 == 0xc0: i += 2; break
            i += 1 + ll
        i += 10  # type + class + ttl + rdlen
        if i >= len(data): return None

        # Parse rdata labels
        name = []
        while i < len(data):
            ll = data[i]
            if ll == 0: break
            if ll & 0xc0 == 0xc0:
                ptr = ((ll & 0x3f) << 8) | data[i+1]
                # Follow pointer — parse from that offset
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


def _resolve_netbios(ip, timeout=1.0):
    """Query NetBIOS Name Service (UDP 137) untuk Windows/Samba hostname."""
    try:
        # NBNS query: node status request
        txid   = b"\xab\xcd"
        flags  = b"\x00\x00"
        qdcnt  = b"\x00\x01"
        ancnt  = b"\x00\x00"
        nscnt  = b"\x00\x00"
        arcnt  = b"\x00\x00"
        # Encoded wildcard name "*" padded to 16 bytes, L1-encoded
        # "*\x00" + 14 bytes null, then L2 null
        raw_name = b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
        qtype  = b"\x00\x21"  # NBSTAT
        qclass = b"\x00\x01"
        query  = txid + flags + qdcnt + ancnt + nscnt + arcnt + raw_name + qtype + qclass

        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(query, (ip, 137))
        data, _ = s.recvfrom(1024)
        s.close()

        # Response: skip 56 bytes header area, then num_names (1 byte)
        # Each name: 15 bytes name + 1 byte type + 2 bytes flags
        if len(data) < 57: return None
        num = data[56]
        for i in range(num):
            offset = 57 + i * 18
            if offset + 15 > len(data): break
            name  = data[offset:offset+15].decode("ascii", errors="ignore").rstrip("\x00").strip()
            ntype = data[offset+15]
            if ntype == 0x00 and name and name != "\x00" * 15:
                return name.strip()
    except Exception:
        pass
    return None


def _resolve_rdns(ip, timeout=1.0):
    """Standard reverse DNS."""
    try:
        result = _socket.gethostbyaddr(ip)[0]
        return result if result != ip else None
    except Exception:
        return None


def resolve_hostname(ip, timeout=1.0):
    """
    Resolve hostname dengan 3 metode paralel:
    mDNS (.local), NetBIOS (Windows), reverse DNS.
    Return string atau "" kalau semua gagal.
    """
    results = {}
    lock    = threading.Lock()

    def _run(fn, key):
        r = fn(ip, timeout)
        if r:
            with lock: results[key] = r

    threads = [
        threading.Thread(target=_run, args=(_resolve_mdns,   "mdns"),    daemon=True),
        threading.Thread(target=_run, args=(_resolve_netbios, "netbios"), daemon=True),
        threading.Thread(target=_run, args=(_resolve_rdns,   "rdns"),    daemon=True),
    ]
    for t in threads: t.start()
    for t in threads: t.join(timeout=timeout + 0.2)

    # Prioritas: mDNS > NetBIOS > rDNS
    return results.get("mdns") or results.get("netbios") or results.get("rdns") or ""


def resolve_hostnames_bulk(ip_list, timeout=1.0, max_workers=30):
    """Resolve hostname untuk banyak IP secara paralel."""
    results = {}
    lock    = threading.Lock()
    sem     = threading.Semaphore(max_workers)

    def _worker(ip):
        with sem:
            hn = resolve_hostname(ip, timeout)
            with lock:
                results[ip] = hn

    threads = [threading.Thread(target=_worker, args=(ip,), daemon=True) for ip in ip_list]
    for t in threads: t.start()
    for t in threads: t.join(timeout=timeout + 1.0)
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

# ── store ────────────────────────────────────────────────────────────

def load(p):
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, UnicodeError, json.JSONDecodeError):
        # A damaged settings file should not prevent the app from starting.
        return {}

def save(p, d):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(d, indent=2), encoding="utf-8")

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
        self.local_mac = get_local_mac(iface)
        self._targets = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._fwd_orig = None

    def _start_thread(self):
        if self._running: return
        self._running = True
        if self._fwd_orig is None:
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
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return
        if IS_WINDOWS:
            return
        if SCAPY_OK:
            sendp(Ether(dst=self.gw_mac)/ARP(op=2, psrc=ip, pdst=self.gw_ip, hwdst=self.gw_mac, hwsrc=self.local_mac), verbose=0, iface=self.iface)
            sendp(Ether(dst=mac)/ARP(op=2, psrc=self.gw_ip, pdst=ip, hwdst=mac, hwsrc=self.local_mac), verbose=0, iface=self.iface)
        else:
            _send_raw_arp(self.iface, _arp_packet(self.local_mac, self.local_mac, self.gw_ip, mac, mac, ip, op=2))
            _send_raw_arp(self.iface, _arp_packet(self.local_mac, self.local_mac, ip, self.gw_mac, self.gw_mac, self.gw_ip, op=2))

    def add(self, ip, mac):
        try:
            if IS_WINDOWS or ipaddress.ip_address(ip).version != 4:
                return
        except ValueError:
            return
        with self._lock:
            if ip in self._targets: return
            self._targets[ip] = mac
        self._start_thread()

    def remove(self, ip):
        with self._lock:
            mac = self._targets.pop(ip, None)
        if mac: self._restore(ip, mac)
        with self._lock:
            last = not self._targets
        if last:
            self._stop(wait=True)

    def _stop(self, wait=False):
        self._running = False
        def stop_now():
            with self._lock:
                if self._targets or self._fwd_orig is None:
                    return
                original = self._fwd_orig
                self._fwd_orig = None
            shq(f"{SYSCTL} -w {IP_FWD}={original or '0'}")
            # Never flush global conntrack; unrelated connections must survive.
        if wait:
            stop_now()
        else:
            threading.Thread(target=stop_now, daemon=True).start()

    def _restore(self, ip, mac):
        for _ in range(4):
            if SCAPY_OK:
                sendp(Ether(dst=self.gw_mac)/ARP(op=2, psrc=ip, hwsrc=mac, pdst=self.gw_ip, hwdst=BROADCAST), verbose=0, iface=self.iface)
                sendp(Ether(dst=mac)/ARP(op=2, psrc=self.gw_ip, hwsrc=self.gw_mac, pdst=ip, hwdst=BROADCAST), verbose=0, iface=self.iface)
            else:
                _send_raw_arp(self.iface, _arp_packet(self.local_mac, self.gw_mac, self.gw_ip, mac, BROADCAST, ip, op=2))
                _send_raw_arp(self.iface, _arp_packet(self.local_mac, mac, ip, self.gw_mac, BROADCAST, self.gw_ip, op=2))
                _send_raw_arp(self.iface, _arp_packet(self.local_mac, self.gw_mac, self.gw_ip, BROADCAST, BROADCAST, ip, op=2))
                _send_raw_arp(self.iface, _arp_packet(self.local_mac, mac, ip, BROADCAST, BROADCAST, self.gw_ip, op=2))
            time.sleep(0.1)

    def restore_all(self):
        with self._lock:
            targets = dict(self._targets)
            self._targets.clear()
        for ip, mac in targets.items():
            self._restore(ip, mac)
        self._stop(wait=True)

    @property
    def count(self):
        with self._lock: return len(self._targets)

# ── tc + iptables limiter ────────────────────────────────────────────

class Limiter:
    def __init__(self, iface):
        self.iface = iface
        self._hosts = {}
        self._lock = threading.RLock()
        self._id_counter = 10
        self._owns_qdisc = False

    def _next_id(self):
        self._id_counter += 1
        return self._id_counter

    def _ensure_root(self):
        if "htb" not in sh(f"{TC} qdisc show dev {shlex.quote(str(self.iface))}"):
            if shq(f"{TC} qdisc add dev {shlex.quote(str(self.iface))} root handle 1: htb default 1") == 0:
                if shq(f"{TC} class add dev {shlex.quote(str(self.iface))} parent 1: classid 1:1 htb rate 1000gbit ceil 1000gbit") == 0:
                    self._owns_qdisc = True
                else:
                    shq(f"{TC} qdisc del dev {shlex.quote(str(self.iface))} root")

    def limit(self, ip, rate, direction):
        if IS_WINDOWS:
            print(f"{C.YEL}Windows QoS rate limiting is not enabled in this build; use block/free or run on a Linux gateway.{C.RST}")
            return False
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            print(f"{C.YEL}IPv6 rate limiting is not supported by this backend.{C.RST}")
            return False
        self._ensure_root()
        with self._lock:
            if ip in self._hosts: self._unlimit(ip)
            ids = {"uid": self._next_id(), "did": self._next_id()}
            self._hosts[ip] = {"ids": ids, "rate": rate, "dir": direction, "blocked": False}
        if direction & Dir.UP:
            uid = ids["uid"]
            shq(f"{TC} class add dev {shlex.quote(str(self.iface))} parent 1: classid 1:{uid} htb rate {rate} ceil {rate} burst 64k cburst 64k")
            shq(f"{TC} filter add dev {shlex.quote(str(self.iface))} parent 1: protocol ip prio {uid} handle {uid} fw flowid 1:{uid}")
            shq(f"{IPT} -t mangle -A POSTROUTING -s {ip} -j MARK --set-mark {uid}")
        if direction & Dir.DOWN:
            did = ids["did"]
            shq(f"{TC} class add dev {shlex.quote(str(self.iface))} parent 1: classid 1:{did} htb rate {rate} ceil {rate} burst 64k cburst 64k")
            shq(f"{TC} filter add dev {shlex.quote(str(self.iface))} parent 1: protocol ip prio {did} handle {did} fw flowid 1:{did}")
            shq(f"{IPT} -t mangle -A PREROUTING -d {ip} -j MARK --set-mark {did}")
        return True

    def block(self, ip, direction):
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if IS_WINDOWS:
            # This restricts communication between this PC and the given remote
            # host; it cannot disconnect that host from the network itself.
            name = "NetBand-" + parsed_ip.compressed.replace(":", "-").replace(".", "-")
            remote = parsed_ip.compressed
            self._unlimit(ip)
            commands = []
            if direction & Dir.UP:
                commands.append(f"New-NetFirewallRule -DisplayName '{name}-Out' -Direction Outbound -RemoteAddress '{remote}' -Action Block -Profile Any -ErrorAction Stop | Out-Null")
            if direction & Dir.DOWN:
                commands.append(f"New-NetFirewallRule -DisplayName '{name}-In' -Direction Inbound -RemoteAddress '{remote}' -Action Block -Profile Any -ErrorAction Stop | Out-Null")
            if not commands or any(shq(command) != 0 for command in commands):
                shq(f"Get-NetFirewallRule -DisplayName '{name}-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
                return False
            with self._lock:
                self._hosts[ip] = {"ids": {"uid": 0, "did": 0}, "rate": None, "dir": direction, "blocked": True}
            return True
        if parsed_ip.version != 4:
            print(f"{C.YEL}IPv6 blocking is not supported by the Linux iptables backend.{C.RST}")
            return False
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
        return True

    def unlimit(self, ip):
        return self._unlimit(ip)

    def _unlimit(self, ip):
        if IS_WINDOWS:
            name = "NetBand-" + ip.replace(":", "-").replace(".", "-")
            shq(f"Get-NetFirewallRule -DisplayName '{name}-Out' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
            shq(f"Get-NetFirewallRule -DisplayName '{name}-In' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
            with self._lock:
                return self._hosts.pop(ip, None) is not None
        with self._lock:
            info = self._hosts.pop(ip, None)
        if not info:
            return False

        ids, direction = info["ids"], info["dir"]
        if info["rate"] is not None:
            if direction & Dir.UP:
                shq(f"{TC} filter del dev {shlex.quote(str(self.iface))} parent 1: prio {ids['uid']}")
                shq(f"{TC} class del dev {shlex.quote(str(self.iface))} parent 1: classid 1:{ids['uid']}")
                shq(f"{IPT} -t mangle -D POSTROUTING -s {ip} -j MARK --set-mark {ids['uid']}")
            if direction & Dir.DOWN:
                shq(f"{TC} filter del dev {shlex.quote(str(self.iface))} parent 1: prio {ids['did']}")
                shq(f"{TC} class del dev {shlex.quote(str(self.iface))} parent 1: classid 1:{ids['did']}")
                shq(f"{IPT} -t mangle -D PREROUTING -d {ip} -j MARK --set-mark {ids['did']}")
        else:
            if direction & Dir.UP:
                shq(f"{IPT} -D FORWARD -s {ip} -j DROP")
                shq(f"{IPT} -D OUTPUT -s {ip} -j DROP")
            if direction & Dir.DOWN:
                shq(f"{IPT} -D FORWARD -d {ip} -j DROP")
                shq(f"{IPT} -D INPUT -d {ip} -j DROP")

        self._maybe_remove_root()
        return True

    def _maybe_remove_root(self):
        with self._lock:
            owns = self._owns_qdisc
            has_rate = any(v.get("rate") is not None for v in self._hosts.values())
        if owns and not has_rate:
            if shq(f"{TC} qdisc del dev {shlex.quote(str(self.iface))} root") == 0:
                with self._lock:
                    self._owns_qdisc = False

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

    def flush(self, all_rules=False):
        if IS_WINDOWS:
            shq("Get-NetFirewallRule -DisplayName 'NetBand-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
            with self._lock: self._hosts.clear()
            return
        # Never flush global iptables chains: those may contain firewall rules
        # owned by Docker, VPNs, the OS, or other applications.
        with self._lock:
            ips = list(self._hosts)
        for ip in ips:
            self.unlimit(ip)
        if self._owns_qdisc:
            shq(f"{TC} qdisc del dev {shlex.quote(str(self.iface))} root")
        if all_rules:
            print(f"{C.YEL}Safety: removed only rules tracked by this process; global firewall chains were left untouched.{C.RST}")
        self._owns_qdisc = False

    @property
    def count(self):
        with self._lock: return len(self._hosts)

# ── scan ─────────────────────────────────────────────────────────────

def _build_ip_list(gw_ip, custom=None, local_ip=None, prefix=None, max_hosts=4096):
    """Return a bounded IPv4 scan list; reject malformed or huge ranges."""
    if custom:
        parts = custom.strip().split("-", 1)
        if len(parts) != 2 or not all(part.strip() for part in parts):
            raise ValueError("range must use IP-IP syntax, e.g. 192.168.1.10-80")
        start_text, end_text = (part.strip() for part in parts)
        if "." not in end_text:
            try:
                start_addr = ipaddress.IPv4Address(start_text)
            except ipaddress.AddressValueError as exc:
                raise ValueError("range contains an invalid IPv4 address") from exc
            end_text = ".".join(start_text.split(".")[:3]) + "." + end_text
        try:
            start_addr = ipaddress.IPv4Address(start_text)
            end_addr = ipaddress.IPv4Address(end_text)
        except ipaddress.AddressValueError as exc:
            raise ValueError("range contains an invalid IPv4 address") from exc
        first, last = int(start_addr), int(end_addr)
        if first > last:
            raise ValueError("range start must not exceed range end")
        count = last - first + 1
        if count > max_hosts:
            raise ValueError(f"range has {count} addresses; maximum scan size is {max_hosts}")
        return [str(ipaddress.IPv4Address(value)) for value in range(first, last + 1)]

    try:
        if local_ip and prefix is not None:
            network = ipaddress.ip_network(f"{local_ip}/{int(prefix)}", strict=False)
        else:
            network = ipaddress.ip_network(f"{gw_ip}/24", strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError("could not determine a valid IPv4 subnet; use scan --range START-END") from exc
    hosts = list(network.hosts())
    if len(hosts) > max_hosts:
        raise ValueError(f"detected subnet has {len(hosts)} hosts; narrow it with scan --range START-END (max {max_hosts})")
    return [str(ip) for ip in hosts]


def _scan_phase_raw_arp(iface, ips, local_mac, local_ip):
    """ARP request blast — works on Android without Scapy. Very fast."""
    for idx, ip in enumerate(ips):
        pkt = _arp_packet(local_mac, local_mac, local_ip, BROADCAST, BROADCAST, ip, op=1)
        _send_raw_arp(iface, pkt)
        # Small pause tiap 50 paket biar kernel tidak drop
        if idx % 50 == 49:
            time.sleep(0.01)


def _scan_phase_ping_async(ips):
    """Ping addresses with bounded concurrency to avoid spawning thousands of threads."""
    if not ips:
        return

    def ping_one(ip):
        try:
            if IS_WINDOWS:
                subprocess.run(["ping", "-n", "1", "-w", "500", ip],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5)
            else:
                subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5)
        except (OSError, subprocess.SubprocessError):
            pass

    def run_batch():
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(64, len(ips))) as pool:
            list(pool.map(ping_one, ips))

    threading.Thread(target=run_batch, name="netband-ping-scan", daemon=True).start()



def _read_neigh(iface):
    """Read kernel neighbour table, return dict ip -> mac."""
    result = {}
    if IS_WINDOWS:
        out = sh(f"Get-NetNeighbor -InterfaceAlias {_ps_quote(iface)} -ErrorAction SilentlyContinue | Where-Object {{$_.State -notin @('Unreachable','Incomplete')}} | Select-Object IPAddress,LinkLayerAddress | ConvertTo-Json -Compress")
        try:
            rows = json.loads(out) if out else []
            if isinstance(rows, dict): rows = [rows]
            for row in rows:
                ip, mac = row.get("IPAddress", ""), row.get("LinkLayerAddress", "").replace("-", ":").lower()
                try: ipaddress.IPv4Address(ip)
                except ValueError: continue
                if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac) and mac != "00:00:00:00:00:00":
                    result[ip] = mac
        except Exception: pass
        return result
    for line in sh(f"ip neigh show dev {shlex.quote(str(iface))}").splitlines():
        p = line.split()
        # format: IP dev IFACE lladdr MAC STATE
        if len(p) < 4: continue
        ip = p[0]
        # find lladdr
        try:
            ll_idx = p.index("lladdr")
            mac = p[ll_idx + 1].lower()
        except (ValueError, IndexError):
            continue
        if mac == "00:00:00:00:00:00" or ":" not in mac: continue
        # Accept all non-failed states
        state = p[-1].upper() if p else ""
        if state in ("FAILED", "INCOMPLETE", "NONE"): continue
        result[ip] = mac
    return result


def scan(iface, gw_ip, custom=None, limiter=None, spoofer=None, gw_mac=None):
    # Get local info before selecting the subnet to scan.
    if spoofer and spoofer.local_mac and spoofer.local_ip:
        local_mac = spoofer.local_mac
        local_ip  = spoofer.local_ip
    else:
        local_ip  = get_local_ip(iface)
        local_mac = get_local_mac(iface)
    _, prefix = get_subnet(iface)
    ips = _build_ip_list(gw_ip, custom, local_ip, prefix)

    print(f"{C.DIM}Scanning {len(ips)} addresses...{C.RST}")

    # Flush stale entries (non-blocking)
    if not IS_WINDOWS:
        shq(f"ip neigh flush dev {shlex.quote(str(iface))} nud failed 2>/dev/null")
        shq(f"ip neigh flush dev {shlex.quote(str(iface))} nud incomplete 2>/dev/null")
        shq(f"ip neigh flush dev {shlex.quote(str(iface))} nud none 2>/dev/null")

    # Phase 1: raw ARP blast (sangat cepat, ~0.1-0.5s untuk 254 IP)
    if not IS_WINDOWS and local_mac and local_ip and local_mac != "00:00:00:00:00:00":
        print(f"{C.DIM}  ARP blast...{C.RST}", end="\r", flush=True)
        _scan_phase_raw_arp(iface, ips, local_mac, local_ip)
    else:
        print(f"{C.YEL}  [!] Could not get local MAC{C.RST}")

    # Phase 2: async ping untuk host yang butuh ICMP (fire and forget)
    print(f"{C.DIM}  Waiting for replies...{C.RST}", end="\r", flush=True)
    _scan_phase_ping_async(ips)

    # Tunggu reply ARP masuk — cukup 1.5s
    time.sleep(1.5)

    print(f"                               \r", end="", flush=True)

    # Read existing saved devices
    devices = load(DEVICES_FILE)
    active_devices = {}

    # Keep limited hosts even if offline
    for mac, d in devices.items():
        if limiter and limiter.is_limited(d["ip"]):
            d["online"] = False
            active_devices[mac] = d

    # Read neighbour table
    neigh = _read_neigh(iface)

    seen_macs = set()
    scanned_ips = set(ips)
    for ip, mac in neigh.items():
        try: ipaddress.IPv4Address(ip)
        except ValueError: continue
        if ip not in scanned_ips:
            continue
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

    # Resolve hostnames untuk host baru (yang belum punya nama)
    need_resolve = [
        d["ip"] for d in active_devices.values()
        if d.get("online") and not d.get("hostname")
    ]
    if need_resolve:
        print(f"{C.DIM}  Resolving {len(need_resolve)} hostnames...{C.RST}", end="\r", flush=True)
        resolved = resolve_hostnames_bulk(need_resolve, timeout=1.0)
        for d in active_devices.values():
            ip = d["ip"]
            if ip in resolved and resolved[ip]:
                d["hostname"] = resolved[ip]
        print(f"                                        \r", end="", flush=True)

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
        except: return [999, 999, 999, 999]

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

# ── watch ────────────────────────────────────────────────────────────

def watch_check(iface, watchlist, devices, gw_ip):
    local_ip, prefix = get_subnet(iface)
    try:
        network = ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False) if local_ip and prefix is not None else ipaddress.ip_network(f"{gw_ip}/24", strict=False)
        candidates = [str(host) for host in network.hosts()]
        if len(candidates) <= 4096:
            _scan_phase_ping_async(candidates)
            time.sleep(1.5)
    except (ValueError, TypeError):
        pass
    neigh = {mac: ip for ip, mac in _read_neigh(iface).items()}
    changes = []
    for mac in list(watchlist.get("hosts", [])):
        if mac not in devices: continue
        dev = devices[mac]
        old_ip = dev["ip"]
        new_ip = neigh.get(mac)
        if new_ip and new_ip != old_ip:
            changes.append((mac, dev.get("hostname",""), old_ip, new_ip))
            dev["ip"] = new_ip
            dev["online"] = True
    if changes: save(DEVICES_FILE, devices)
    return changes

# ── monitor ──────────────────────────────────────────────────────────

def get_traffic():
    d = {}
    if IS_WINDOWS:
        out = sh("Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Json -Compress")
        try:
            rows = json.loads(out) if out else []
            if isinstance(rows, dict): rows = [rows]
            return {r["Name"]: {"rx": int(r["ReceivedBytes"]), "tx": int(r["SentBytes"])} for r in rows}
        except Exception: return d
    try:
        for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
            p = line.split()
            if len(p) >= 10: d[p[0].rstrip(":")] = {"rx": int(p[1]), "tx": int(p[9])}
    except: pass
    return d

def get_tc_stats(iface):
    out = sh(f"{TC} -s class show dev {shlex.quote(str(iface))} 2>/dev/null")
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

# ── banner ───────────────────────────────────────────────────────────

def print_banner(iface, gw_ip, gw_mac, local_ip):
    mode = f" {C.YEL}[Windows local-firewall mode]{C.RST}" if IS_WINDOWS else (f" {C.YEL}[Android/raw-socket mode]{C.RST}" if IS_ANDROID else "")
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
    w_id, w_ip, w_mac, w_host, w_stat = 4, 15, 17, 20, 8

    print(f"{C.DIM}┌{'─'*(w_id+2)}┬{'─'*(w_ip+2)}┬{'─'*(w_mac+2)}┬{'─'*(w_host+2)}┬{'─'*(w_stat+2)}┐{C.RST}")

    h_id   = "ID".ljust(w_id)
    h_ip   = "IP address".ljust(w_ip)
    h_mac  = "MAC address".ljust(w_mac)
    h_host = "Hostname".ljust(w_host)
    h_stat = "Status".ljust(w_stat)
    print(f"{C.DIM}│{C.RST} {C.BLD}{h_id}{C.RST} {C.DIM}│{C.RST} {C.BLD}{h_ip}{C.RST} {C.DIM}│{C.RST} {C.BLD}{h_mac}{C.RST} {C.DIM}│{C.RST} {C.BLD}{h_host}{C.RST} {C.DIM}│{C.RST} {C.BLD}{h_stat}{C.RST} {C.DIM}│{C.RST}")

    print(f"{C.DIM}├{'─'*(w_id+2)}┼{'─'*(w_ip+2)}┼{'─'*(w_mac+2)}┼{'─'*(w_host+2)}┼{'─'*(w_stat+2)}┤{C.RST}")

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
                stat_raw, stat_color = ("Firewall", C.RED) if IS_WINDOWS else ("Blocked", C.RED)
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

        print(f"{C.DIM}│{C.RST} {c_id} {C.DIM}│{C.RST} {ip_str} {C.DIM}│{C.RST} {mac_str} {C.DIM}│{C.RST} {c_host} {C.DIM}│{C.RST} {c_stat} {C.DIM}│{C.RST}")

    print(f"{C.DIM}└{'─'*(w_id+2)}┴{'─'*(w_ip+2)}┴{'─'*(w_mac+2)}┴{'─'*(w_host+2)}┴{'─'*(w_stat+2)}┘{C.RST}")

# ── main ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="netband - ARP-based bandwidth manager")
    ap.add_argument("-i", help="interface")
    ap.add_argument("-g", help="gateway IP")
    ap.add_argument("-m", help="gateway MAC")
    ap.add_argument("-n", help="netmask")
    ap.add_argument("-f", action="store_true", help="remove NetBand rules tracked by this process; never flush global firewall chains")
    ap.add_argument("--colorless", action="store_true")
    args = ap.parse_args()

    if args.colorless: no_color()

    if IS_WINDOWS:
        try:
            elevated = bool(sh("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)").lower() == "true")
        except Exception: elevated = False
        if not elevated:
            print(f"{C.RED}Run PowerShell as Administrator.{C.RST}"); sys.exit(1)
    elif os.geteuid() != 0:
        print(f"{C.RED}Must run as root.{C.RST}"); sys.exit(1)

    if args.f:
        iface = args.i or detect_iface()
        if not iface:
            print(f"{C.RED}No interface. Use -i.{C.RST}"); sys.exit(1)
        Limiter(iface).flush(all_rules=True)
        print(f"{C.GRN}Cleanup completed for rules tracked by this process.{C.RST}"); return

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
            if IS_WINDOWS:
                subprocess.run(["ping", "-n", "1", "-w", "1000", gw_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                shq(f"ping -c 1 -W 1 {gw_ip}")
            gw_mac = get_mac(gw_ip, iface)

    if not iface:  print(f"{C.RED}No interface. Use -i.{C.RST}"); sys.exit(1)
    if not gw_ip:  print(f"{C.RED}No gateway. Use -g.{C.RST}");   sys.exit(1)
    if not gw_mac: print(f"{C.RED}No gateway MAC. Use -m.{C.RST}"); sys.exit(1)

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
        cmd   = parts[0].lower()
        arg   = parts[1] if len(parts) > 1 else ""

        # ── help ──────────────────────────────────────────────────────
        if cmd in ("help", "?"):
            print_help()

        # ── scan ──────────────────────────────────────────────────────
        elif cmd == "scan":
            custom  = arg.split("--range",1)[1].strip() if "--range" in arg else None
            try:
                devices = scan(iface, gw_ip, custom, limiter, spoofer, gw_mac)
            except ValueError as exc:
                print(f"{C.RED}Invalid scan range: {exc}.{C.RST}"); continue
            total   = len(devices)
            online  = sum(1 for d in devices.values() if d.get("online", True))
            print(f"\n{C.BLD}Found {online} online hosts ({total} total):{C.RST}")
            _print_host_table(devices, gw_ip, limiter)

        # ── hosts ─────────────────────────────────────────────────────
        elif cmd == "hosts":
            if not devices:
                print(f"{C.DIM}No hosts. Run 'scan'.{C.RST}"); continue
            _print_host_table(devices, gw_ip, limiter)

        # ── limit ─────────────────────────────────────────────────────
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
                if limiter.limit(d["ip"], rate, direction):
                    spoofer.add(d["ip"], d["mac"])
                    d["limits"] = {"rate": rate, "direction": direction}
                    success_ips.append(d["ip"])
                else:
                    print(f"{C.RED}Failed to install limit for {d['ip']}{C.RST}")
            save(DEVICES_FILE, devices)
            if success_ips:
                print(f"{C.GRN}Limited {', '.join(success_ips)} → {rate} ({Dir.name(direction)}){C.RST}")

        # ── block ─────────────────────────────────────────────────────
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
                if limiter.block(d["ip"], direction):
                    spoofer.add(d["ip"], d["mac"])
                    d["limits"] = {"rate": None, "direction": direction, "blocked": True}
                    if IS_WINDOWS:
                        print(f"{C.YEL}Added local firewall rules for {d['ip']}. This only affects this PC, not the remote device.{C.RST}")
                    else:
                        print(f"{C.RED}Blocked {d['ip']}{C.RST}")
                else:
                    print(f"{C.RED}Failed to block {d['ip']}{C.RST}")
            save(DEVICES_FILE, devices)

        # ── free ──────────────────────────────────────────────────────
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

        # ── add ───────────────────────────────────────────────────────
        elif cmd == "add":
            if not arg:
                print(f"{C.RED}Usage: add IP [--mac MAC]{C.RST}"); continue
            w = arg.split()
            ip = w[0]
            if "--mac" in w:
                mac_index = w.index("--mac") + 1
                if mac_index >= len(w) or w[mac_index].startswith("--"):
                    print(f"{C.RED}Usage: add IP [--mac MAC]{C.RST}"); continue
                mac = w[mac_index]
            else:
                mac = get_mac(ip, iface)
            if not mac:
                print(f"{C.RED}Cannot resolve MAC for {ip}. Use --mac.{C.RST}"); continue
            mac = mac.lower()
            idx = max((d["id"] for d in devices.values()), default=0) + 1
            hn  = resolve_hostname(ip, timeout=1.0)
            devices[mac] = {"id": idx, "ip": ip, "mac": mac, "hostname": hn, "limits": {}, "online": True}
            save(DEVICES_FILE, devices)
            print(f"{C.GRN}Added {ip} ({mac}) as ID {idx}{C.RST}")

        # ── monitor ───────────────────────────────────────────────────
        elif cmd == "monitor":
            if IS_WINDOWS:
                print(f"{C.YEL}Per-host traffic monitoring requires the Linux tc backend; it is not available in Windows mode.{C.RST}")
                continue
            interval = 0.5
            w = arg.split()
            if "--interval" in w:
                option_index = w.index("--interval") + 1
                if option_index >= len(w):
                    print(f"{C.RED}Usage: monitor [--interval MS]{C.RST}"); continue
                ms_str = w[option_index]
                interval = int(ms_str)/1000 if ms_str.isdigit() else 0.5
            limited = {d["ip"]: d for d in devices.values() if limiter.is_limited(d["ip"])}
            if not limited:
                print(f"{C.DIM}No limited hosts.{C.RST}"); continue
            print(f"{C.BLD}Monitoring (Ctrl+C to stop)...{C.RST}")
            prev_tc = get_tc_stats(iface)
            prev_time = time.time()
            previous_sigint = signal.signal(signal.SIGINT, signal.default_int_handler)
            try:
                while True:
                    time.sleep(interval)
                    now  = time.time()
                    dt   = max(now - prev_time, 0.001)
                    curr_tc = get_tc_stats(iface)
                    print(f"\n{C.CYN}{'ID':<4} {'IP':<16} {'Rate':>10} {'RX/s':>10} {'TX/s':>10} {'Total RX':>10} {'Total TX':>10}{C.RST}")
                    print("-" * 80)
                    for ip, d in limited.items():
                        info = limiter.get_status(ip) or {}
                        ids = info.get("ids", {})
                        uid = ids.get("uid")
                        did = ids.get("did")
                        total_rx = curr_tc.get(did, {}).get("bytes", 0) if info.get("dir", 0) & Dir.DOWN else 0
                        total_tx = curr_tc.get(uid, {}).get("bytes", 0) if info.get("dir", 0) & Dir.UP else 0
                        rx_bytes = max(total_rx - (prev_tc.get(did, {}).get("bytes", 0) if did is not None else 0), 0)
                        tx_bytes = max(total_tx - (prev_tc.get(uid, {}).get("bytes", 0) if uid is not None else 0), 0)
                        rate = limiter.get_rate(ip) or "blocked"
                        print(f"{d['id']:<4} {ip:<16} {rate:>10} {_fmt(rx_bytes/dt):>10} {_fmt(tx_bytes/dt):>10} {_fmt(total_rx):>10} {_fmt(total_tx):>10}")
                    prev_tc = curr_tc
                    prev_time = now
            except KeyboardInterrupt:
                print(f"\n{C.DIM}Stopped.{C.RST}")
            finally:
                signal.signal(signal.SIGINT, previous_sigint)

        # ── analyze ───────────────────────────────────────────────────
        elif cmd == "analyze":
            if IS_WINDOWS:
                print(f"{C.YEL}Passive per-host analysis requires a Linux gateway with iptables and ARP forwarding; it is unavailable in Windows mode.{C.RST}")
                continue
            if not arg:
                print(f"{C.RED}Usage: analyze IDs [--duration S]{C.RST}"); continue
            w = arg.split()
            duration = 30
            if "--duration" in w:
                option_index = w.index("--duration") + 1
                if option_index >= len(w):
                    print(f"{C.RED}Usage: analyze IDs [--duration S]{C.RST}"); continue
                di = w[option_index]
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
                    if len(p) < 3: continue
                    try:
                        bc  = int(p[0])
                        src = p[-2]
                        dst = p[-1]
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
            previous_sigint = signal.signal(signal.SIGINT, signal.default_int_handler)

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
                signal.signal(signal.SIGINT, previous_sigint)
            print(f"\n{C.DIM}Done.{C.RST}")

        # ── status ────────────────────────────────────────────────────
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

        # ── watch ─────────────────────────────────────────────────────
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

        # ── clear ─────────────────────────────────────────────────────
        elif cmd == "clear":
            print("\033c", end="")

        # ── quit ──────────────────────────────────────────────────────
        elif cmd in ("quit","exit","q"):
            cleanup()

        else:
            print(f"{C.DIM}Unknown command. Type 'help'.{C.RST}")


def _logic_selftest():
    """Side-effect-free smoke tests; never execute firewall or traffic-control commands."""
    assert parse_rate("200kbit") == "200.0kbit"
    assert parse_rate("5mbit") == "5.0mbit"
    assert parse_rate("1mbps") == "1.0mbit"
    assert parse_rate("invalid") is None
    assert _build_ip_list("192.168.1.1", "192.168.1.2-4") == [
        "192.168.1.2", "192.168.1.3", "192.168.1.4"
    ]
    assert len(_build_ip_list("192.168.1.1", local_ip="192.168.1.50", prefix=24)) == 254
    try:
        _build_ip_list("192.168.1.1", "192.168.1.254-192.168.2.10")
    except ValueError:
        # Cross-octet ranges are valid IP ranges; count is small and should pass.
        raise AssertionError("valid IPv4 range was rejected")
    try:
        _build_ip_list("192.168.1.1", "0.0.0.0-255.255.255.255")
    except ValueError:
        pass
    else:
        raise AssertionError("unbounded range should be rejected")

    # Verify state bookkeeping without touching system firewall/qdisc rules.
    global shq, sh, IS_WINDOWS
    old_shq, old_sh, old_windows = shq, sh, IS_WINDOWS
    try:
        shq = lambda _cmd: 0
        sh = lambda _cmd: ""
        IS_WINDOWS = False
        obj = Limiter("test0")
        obj._ensure_root = lambda: None
        obj._maybe_remove_root = lambda: None
        assert obj.limit("192.0.2.10", "1mbit", Dir.BOTH)
        assert obj.limit("192.0.2.10", "2mbit", Dir.DOWN)
        assert obj.get_rate("192.0.2.10") == "2mbit"
        assert obj.block("192.0.2.10", Dir.BOTH)
        assert obj.is_blocked("192.0.2.10")
        assert obj.unlimit("192.0.2.10")
        assert not obj.is_limited("192.0.2.10")

        # Check Windows command routing without invoking PowerShell.
        IS_WINDOWS = True
        commands = []
        shq = lambda command: (commands.append(command) or 0)
        win = Limiter("Wi-Fi")
        assert win.block("192.0.2.20", Dir.BOTH)
        assert sum("New-NetFirewallRule" in c for c in commands) == 2
        win.unlimit("192.0.2.20")
        assert any("Remove-NetFirewallRule" in c for c in commands)
        with contextlib.redirect_stdout(io.StringIO()):
            assert win.limit("192.0.2.20", "1mbit", Dir.BOTH) is False
    finally:
        shq, sh, IS_WINDOWS = old_shq, old_sh, old_windows


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--test", "--self-test"):
        _logic_selftest()
        print("NetBand self-test passed (no firewall/network changes were made).")
    else:
        main()
