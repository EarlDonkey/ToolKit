"""
Shared helpers for the net package.

Keeps the same spirit as core.http: small, single-purpose, safe to import
from any submodule without side effects.
"""

import ipaddress
import logging
import random
import socket
import struct
import sys
import time
from threading import Lock

from scapy.all import conf, get_if_addr, get_if_list

# Silence scapy's chatty runtime errors — we handle errors ourselves.
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

# scapy isn't fully thread-safe; serialize sends through this lock.
SCAPY_LOCK = Lock()

# Serialize console writes so progress bars don't tear.
PRINT_LOCK = Lock()

# Cap on how many IPs we'll expand a CIDR to, to avoid accidental /8 blasts.
MAX_IPS_PER_SUBNET = 65536

# Suppress duplicate error messages from within a scan.
_SEEN_ERRORS = set()
_SEEN_ERRORS_LOCK = Lock()


def note_error(kind, detail=""):
    """Log the first occurrence of each error class; suppress the rest."""
    with _SEEN_ERRORS_LOCK:
        if kind in _SEEN_ERRORS:
            return
        _SEEN_ERRORS.add(kind)
    from core.output import warn
    warn(f"[{kind}] {detail}")


# ---------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------

class ProgressBar:
    """Minimal dependency-free progress bar. Fits 80-col terminals."""

    def __init__(self, total, prefix="", width=36, enabled=True):
        self.total = max(1, total)
        self.prefix = prefix
        self.width = width
        self.enabled = enabled
        self.start = time.time()
        self._last_len = 0

    def update(self, current):
        if not self.enabled:
            return
        current = min(current, self.total)
        frac = current / self.total
        filled = int(self.width * frac)
        bar = "#" * filled + "-" * (self.width - filled)
        elapsed = time.time() - self.start
        rate = current / elapsed if elapsed > 0 else 0
        eta = (self.total - current) / rate if rate > 0 else 0
        line = (f"\r{self.prefix} [{bar}] {current}/{self.total} "
                f"({frac * 100:5.1f}%) {rate:6.1f}/s ETA {eta:5.1f}s")
        pad = max(0, self._last_len - len(line))
        self._last_len = len(line)
        sys.stdout.write(line + (" " * pad))
        sys.stdout.flush()

    def finish(self):
        if self.enabled:
            sys.stdout.write("\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------
# Interface helpers
# ---------------------------------------------------------------------

def get_local_subnets():
    """
    Return a deduped list of ipaddress.IPv4Network for every interface,
    using the real netmask from the OS.
    """
    subnets = []
    seen = set()
    try:
        import psutil
        for _iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family != socket.AF_INET or not addr.netmask:
                    continue
                try:
                    net = ipaddress.ip_network(
                        f"{addr.address}/{addr.netmask}", strict=False)
                except Exception:
                    continue
                key = str(net)
                if key in seen:
                    continue
                seen.add(key)
                subnets.append(net)
    except ImportError:
        # Fallback to /24 assumption if psutil isn't installed.
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if not ip or ip == "0.0.0.0":
                    continue
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                key = str(net)
                if key in seen:
                    continue
                seen.add(key)
                subnets.append(net)
            except Exception:
                pass
    return subnets


def get_local_source_ip(target_ip):
    """Return the source IP we'd use to reach target_ip, or '0.0.0.0'."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        src = s.getsockname()[0]
        s.close()
        return src
    except Exception:
        return "0.0.0.0"


# ---------------------------------------------------------------------
# CIDR expansion
# ---------------------------------------------------------------------

def expand_cidr(subnet, cap=MAX_IPS_PER_SUBNET):
    """Turn a CIDR string into a list of host IPs. Caps huge ranges."""
    try:
        ip_str, bits = subnet.split("/")
        bits = int(bits)
        host_bits = 32 - bits

        if host_bits == 0:
            return [ip_str]
        if host_bits == 1:
            net = ipaddress.ip_network(subnet, strict=False)
            return [str(net.network_address), str(net.broadcast_address)]

        num_hosts = 1 << host_bits
        if num_hosts > cap:
            num_hosts = cap

        struct_ip = struct.unpack(">I", socket.inet_aton(ip_str))[0]
        start_ip = (struct_ip >> host_bits) << host_bits
        return [
            socket.inet_ntoa(struct.pack(">I", (start_ip + i) & 0xFFFFFFFF))
            for i in range(1, num_hosts - 1)
        ]
    except Exception:
        return []


def is_local_l2(ip, local_nets):
    """True only if `ip` is on a segment we can ARP directly."""
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    return any(addr in net for net in local_nets)


# ---------------------------------------------------------------------
# Stealth helpers
# ---------------------------------------------------------------------

def shuffle(lst):
    """Return a shuffled copy — never mutate the caller's list."""
    out = list(lst)
    random.shuffle(out)
    return out


def jittered_sleep(base, jitter=0.5):
    """Sleep for base seconds, +/- jitter fraction. Makes timing non-metronomic."""
    if base <= 0:
        return
    delay = base * (1 + random.uniform(-jitter, jitter))
    time.sleep(max(0, delay))


def random_ip_id():
    """Random IP ID — real hosts vary this; scapy defaults to 0."""
    return random.randint(1, 65535)


def random_source_port():
    """Random ephemeral source port."""
    return random.randint(1024, 65535)


def chunked(lst, size):
    """Yield successive chunks of `size` from `lst`."""
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def random_chunks(lst, min_size=20, max_size=80):
    """Yield chunks of random size between min_size and max_size."""
    i = 0
    n = len(lst)
    while i < n:
        size = random.randint(min_size, max_size)
        yield lst[i:i + size]
        i += size


def detect_auto_subnet():
    """Best-effort guess at the host's primary /24."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"
    finally:
        s.close()


# ---------------------------------------------------------------------
# Stealth-aware send helpers
# ---------------------------------------------------------------------

class SendStrategy:
    """
    Controls how packets are dispatched during a scan.

    Attributes:
      max_pps      — hard cap on packets per second (None = unthrottled)
      jitter       — timing jitter fraction (0.0 = metronomic, 1.0 = wild)
      shuffle_ips  — randomize the order we hit targets
      shuffle_ports — randomize the order we hit ports
      random_id    — randomize IP ID + source port
      burst        — random-sized bursts with gaps between
      enabled      — master switch
    """

    def __init__(self, stealth=False, max_pps=None):
        self.enabled = True
        self.max_pps = max_pps
        self.jitter = 0.5
        self.shuffle_ips = True
        self.shuffle_ports = True
        self.random_id = True
        self.burst = True

        if stealth:
            # Stealth mode: hard rate limit, more jitter, bigger bursts gaps
            if self.max_pps is None:
                self.max_pps = 25
            self.jitter = 0.8

    def sleep_between(self):
        """Enforce rate limit + jitter between packet chunks."""
        if self.max_pps:
            base = 1.0 / self.max_pps
        else:
            base = 0.0
        jittered_sleep(base, self.jitter)