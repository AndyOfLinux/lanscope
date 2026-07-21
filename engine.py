"""engine.py — unprivileged scanning/enrichment engine for lanscope.

Discovery:
  * Preferred: launch the privileged `lanscope-helper` via pkexec and stream
    its JSON-lines output (live ARP replies -> instant rows, like LanScan).
  * Fallback (helper refused/missing): unprivileged ping sweep, then harvest
    MACs from the kernel neighbour table (`ip -j neigh` / /proc/net/arp).

Enrichment (all unprivileged, all optional, degrade gracefully):
  * Vendor        — IEEE OUI file (arp-scan's ieee-oui.txt et al.)
  * Ping          — /bin/ping -c1
  * DNS Name      — reverse DNS (PTR) via the resolver (router's .lan names)
  * mDNS Name     — avahi-resolve-address
  * Identification— one-shot `avahi-browse` pass, model= from _device-info TXT
  * SMB Name/Dom  — nmblookup -A
"""

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER_CANDIDATES = [
    "/usr/local/libexec/lanscope-helper",
    os.path.join(HERE, "lanscope-helper"),
]

OUI_FILES = [
    "/usr/share/arp-scan/ieee-oui.txt",       # arp-scan package
    "/usr/lib/arp-scan/ieee-oui.txt",
    "/var/lib/ieee-data/oui.txt",             # ieee-data package
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/nmap/nmap-mac-prefixes",      # nmap package
]

SUBPROC_TIMEOUT = 6


# --------------------------------------------------------------------------
# Vendor (OUI) lookup
# --------------------------------------------------------------------------
class OuiDB:
    def __init__(self):
        self._db = None
        self._lock = threading.Lock()

    def _load(self):
        db = {}
        for path in OUI_FILES:
            if not os.path.exists(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # arp-scan / nmap: "0000C5\tVendor"  |  "0000C5 Vendor"
                        m = re.match(r"^([0-9A-Fa-f]{6})[\t ]+(.+)$", line)
                        if m:
                            db.setdefault(m.group(1).upper(), m.group(2).strip())
                            continue
                        # IEEE oui.txt: "00-00-C5   (hex)\t\tVendor"
                        m = re.match(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                        if m:
                            db.setdefault((m.group(1) + m.group(2) + m.group(3)).upper(),
                                          m.group(4).strip())
            except OSError:
                continue
            if db:
                break
        return db

    def lookup(self, mac):
        if not mac:
            return ""
        with self._lock:
            if self._db is None:
                self._db = self._load()
        prefix = mac.replace(":", "").replace("-", "").upper()[:6]
        # Locally-administered bit => randomized/private MAC (phones do this)
        try:
            if int(prefix[1], 16) & 0x2:
                return self._db.get(prefix, "(private/randomized)")
        except (ValueError, IndexError):
            pass
        return self._db.get(prefix, "")


# --------------------------------------------------------------------------
# Per-host enrichment probes
# --------------------------------------------------------------------------
def _run(cmd, timeout=SUBPROC_TIMEOUT):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def probe_ping(ip):
    r = _run(["ping", "-c", "1", "-W", "1", ip], timeout=3)
    return bool(r and r.returncode == 0)


def probe_rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def probe_mdns(ip):
    if not shutil.which("avahi-resolve-address"):
        return ""
    r = _run(["avahi-resolve-address", ip], timeout=4)
    if r and r.returncode == 0 and r.stdout.strip():
        parts = r.stdout.split()
        if len(parts) >= 2:
            return parts[1].rstrip(".")
    return ""


NBT_UNIQUE = re.compile(r"^\s+(\S+)\s+<00>\s+-\s+(?:[BMPH]\s+)?<ACTIVE>", re.M)
NBT_GROUP = re.compile(r"^\s+(\S+)\s+<00>\s+-\s+<GROUP>", re.M)


def probe_netbios(ip):
    if not shutil.which("nmblookup"):
        return "", ""
    r = _run(["nmblookup", "-A", ip], timeout=4)
    if not r or r.returncode != 0:
        return "", ""
    name = NBT_UNIQUE.search(r.stdout)
    dom = NBT_GROUP.search(r.stdout)
    return (name.group(1) if name else ""), (dom.group(1) if dom else "")


# --------------------------------------------------------------------------
# One-shot mDNS service browse -> "Identification" column
# --------------------------------------------------------------------------
def browse_mdns_identities():
    """Map ip -> human identification string, from a single avahi-browse pass.

    Parses terse (-p) resolved lines:
      =;iface;proto;name;type;domain;host;address;port;"txt" "txt" ...
    Prefers model= from _device-info._tcp; falls back to service instance name.
    """
    if not shutil.which("avahi-browse"):
        return {}
    r = _run(["avahi-browse", "-arpt"], timeout=10)
    if not r:
        return {}
    ident, fallback = {}, {}
    for line in r.stdout.splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 10 or parts[2] != "IPv4":
            continue
        name, stype, addr, txt = parts[3], parts[4], parts[7], parts[9]
        if not addr or ":" in addr:
            continue
        m = re.search(r'model=([^"]+)', txt)
        if stype == "_device-info._tcp" and m:
            ident[addr] = m.group(1)
        elif m and addr not in ident:
            ident.setdefault(addr, m.group(1))
        else:
            # De-escape avahi's \032 style encoding for display names
            pretty = re.sub(r"\\(\d{3})", lambda g: chr(int(g.group(1))), name)
            fallback.setdefault(addr, pretty)
    for addr, val in fallback.items():
        ident.setdefault(addr, val)
    return ident


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------
def find_helper():
    for p in HELPER_CANDIDATES:
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    return None


def default_network():
    """Best-effort (iface, IPv4Network) of the default route, unprivileged."""
    r = _run(["ip", "-j", "route", "get", "1.1.1.1"])
    iface = None
    if r and r.returncode == 0:
        try:
            iface = json.loads(r.stdout)[0].get("dev")
        except (json.JSONDecodeError, IndexError, KeyError):
            pass
    if not iface:
        return None, None
    r = _run(["ip", "-j", "-4", "addr", "show", "dev", iface])
    if r and r.returncode == 0:
        try:
            for entry in json.loads(r.stdout):
                for a in entry.get("addr_info", []):
                    if a.get("family") == "inet":
                        net = ipaddress.IPv4Network(
                            f"{a['local']}/{a['prefixlen']}", strict=False)
                        return iface, net
        except (json.JSONDecodeError, KeyError, ValueError):
            pass
    return iface, None


def neighbour_macs():
    """ip -> mac from the kernel neighbour table (fallback path)."""
    out = {}
    r = _run(["ip", "-j", "neigh"])
    if r and r.returncode == 0:
        try:
            for n in json.loads(r.stdout):
                ip, mac = n.get("dst"), n.get("lladdr")
                state = n.get("state", [])
                if ip and mac and "." in ip and "FAILED" not in state:
                    out[ip] = mac.lower()
        except json.JSONDecodeError:
            pass
    return out


class Scanner:
    """Drives one scan. Callbacks fire on worker threads — marshal to the UI
    thread yourself (GLib.idle_add in the GTK frontend)."""

    def __init__(self, on_device, on_update, on_status, on_done):
        self.on_device = on_device      # (ip, mac)              new row
        self.on_update = on_update      # (ip, field, value)     cell update
        self.on_status = on_status      # (str)                  status bar
        self.on_done = on_done          # (count)                scan finished
        self.oui = OuiDB()
        self._stop = threading.Event()
        self._pool = None

    # -- public ------------------------------------------------------------
    def start(self):
        threading.Thread(target=self._scan, daemon=True).start()

    def stop(self):
        self._stop.set()

    # -- internals ---------------------------------------------------------
    def _scan(self):
        self._pool = ThreadPoolExecutor(max_workers=16)
        count = 0
        try:
            # Identification map fills in parallel with discovery.
            ident_holder = {}

            def browse():
                ident_holder.update(browse_mdns_identities())
                for ip, val in ident_holder.items():
                    self.on_update(ip, "identification", val)
            self._pool.submit(browse)

            helper = find_helper()
            used_helper = False
            if helper and shutil.which("pkexec"):
                self.on_status("Requesting authorization for ARP scan…")
                used_helper, count = self._discover_arp(helper, ident_holder)
            if not used_helper:
                self.on_status("ARP helper unavailable — ping-sweep fallback")
                count = self._discover_fallback(ident_holder)
        finally:
            self._pool.shutdown(wait=True)
            self.on_done(count)

    def _handle_device(self, ip, mac, ident_map):
        self.on_device(ip, mac)
        self.on_update(ip, "vendor", self.oui.lookup(mac))
        if ip in ident_map:
            self.on_update(ip, "identification", ident_map[ip])
        self._pool.submit(self._enrich, ip)

    def _discover_arp(self, helper, ident_map):
        cmd = ([helper] if os.geteuid() == 0 else ["pkexec", helper])
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
        except OSError:
            return False, 0
        count = 0
        started = False
        for line in proc.stdout:
            if self._stop.is_set():
                proc.terminate()
                break
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "error" in msg:
                self.on_status(f"Helper: {msg['error']}")
                proc.wait()
                return started, count
            if "info" in msg:
                started = True
                self.on_status(f"ARP scan of {msg['info']['network']} "
                               f"on {msg['info']['interface']}")
            elif "ip" in msg:
                started = True
                count += 1
                self._handle_device(msg["ip"], msg["mac"], ident_map)
            elif msg.get("done"):
                started = True
        rc = proc.wait()
        if rc != 0 and not started:
            return False, 0        # pkexec dismissed/denied -> fallback
        return started, count

    def _discover_fallback(self, ident_map):
        iface, net = default_network()
        if not net:
            self.on_status("Could not determine local network")
            return 0
        if net.num_addresses > 4096:
            self.on_status(f"Network {net} too large for ping sweep")
            return 0
        self.on_status(f"Ping sweep of {net} on {iface}")
        alive = set()
        lock = threading.Lock()

        def ping_one(ip):
            if not self._stop.is_set() and probe_ping(ip):
                with lock:
                    alive.add(ip)
        with ThreadPoolExecutor(max_workers=64) as sweep:
            sweep.map(ping_one, (str(h) for h in net.hosts()))
        macs = neighbour_macs()
        # Include neighbour-table entries in-subnet even if ping-silent
        for ip in sorted(set(alive) | {i for i in macs
                                       if ipaddress.ip_address(i) in net},
                         key=lambda s: ipaddress.ip_address(s)):
            if self._stop.is_set():
                break
            self._handle_device(ip, macs.get(ip, ""), ident_map)
        return len(alive)

    def _enrich(self, ip):
        if self._stop.is_set():
            return
        up = probe_ping(ip)
        self.on_update(ip, "ping", "up" if up else "down")
        self.on_update(ip, "dns", probe_rdns(ip))
        self.on_update(ip, "mdns", probe_mdns(ip))
        nb_name, nb_dom = probe_netbios(ip)
        if nb_name:
            self.on_update(ip, "smb_name", nb_name)
        if nb_dom:
            self.on_update(ip, "smb_domain", nb_dom)
