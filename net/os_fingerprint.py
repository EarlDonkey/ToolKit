"""
Passive OS fingerprinting via TTL + TCP window-size heuristics.

Not Nmap. Not accurate. But good enough to say "probably Linux" or
"probably Windows" without needing a signature database.
"""

import asyncio

from scapy.all import IP, ICMP, TCP, sr1

from core.output import info, success, warn
from net.util import SCAPY_LOCK


# Heuristic table. Initial TTL bucket -> likely OS family.
TTL_BUCKETS = [
    (0, 32, "embedded / network gear"),
    (33, 64, "Linux / Unix / macOS / Android"),
    (65, 128, "Windows"),
    (129, 255, "Cisco / Juniper / Solaris / AIX"),
]


def _classify_ttl(ttl):
    for lo, hi, family in TTL_BUCKETS:
        if lo <= ttl <= hi:
            return family
    return "unknown"


# TCP window sizes seen from common stacks on a SYN-ACK. Rough, but
# a couple of these are very distinct.
WINDOW_HINTS = {
    65535: "possible Windows / BSD",
    65535 - 1: "possible Windows / BSD",  # some stacks do 65534
    5840: "Linux (older kernels)",
    29200: "Linux (modern)",
    64240: "Linux (recent)",
    65535: "Windows",
    8192: "Cisco / older Unix",
    16384: "Windows / older FreeBSD",
}


async def fingerprint(ip, timeout=1.5):
    """
    Returns:
      {
        "ip": ip,
        "ttl": observed ttl,
        "ttl_guess": os family,
        "tcp_window": int | None,
        "tcp_options": list[str],
        "tcp_guess": hint | None,
      }
    """
    result = {
        "ip": ip, "ttl": None, "ttl_guess": "unknown",
        "tcp_window": None, "tcp_options": [], "tcp_guess": None,
    }

    # ICMP echo to read the reply TTL.
    try:
        with SCAPY_LOCK:
            reply = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=False)
        if reply and reply.haslayer(IP):
            result["ttl"] = reply[IP].ttl
            result["ttl_guess"] = _classify_ttl(reply[IP].ttl)
    except Exception:
        pass

    # TCP SYN to port 80 (or 443 if that fails) to read the SYN-ACK.
    for port in (80, 443, 22):
        try:
            with SCAPY_LOCK:
                reply = sr1(IP(dst=ip) / TCP(dport=port, flags="S"),
                            timeout=timeout, verbose=False)
            if reply and reply.haslayer(TCP) and reply[TCP].flags == "SA":
                result["tcp_window"] = reply[TCP].window
                opts = reply[TCP].options or []
                result["tcp_options"] = [o[0] for o in opts if isinstance(o, tuple)]
                hint = WINDOW_HINTS.get(reply[TCP].window)
                if hint:
                    result["tcp_guess"] = hint
                break
        except Exception:
            continue

    return result


async def fingerprint_many(ips, timeout=1.5, verbose=False):
    """Serial loop — this is slow anyway, and parallel sr1 is unreliable."""
    results = {}
    for ip in ips:
        r = await fingerprint(ip, timeout=timeout)
        results[ip] = r
        if verbose:
            info(f"{ip}: ttl={r['ttl']} ({r['ttl_guess']}), "
                 f"window={r['tcp_window']} ({r['tcp_guess']})")
    return results


async def run(target, verbose=False):
    """CLI entry point."""
    from net.util import expand_cidr
    from core.dns import resolve_a

    if "/" in target:
        hosts = expand_cidr(target)
    else:
        ips = await resolve_a(target)
        hosts = ips or [target]

    info(f"OS fingerprinting {len(hosts)} host(s)")
    results = await fingerprint_many(hosts, verbose=verbose)

    print()
    success(f"fingerprinted {len(results)} host(s)")
    for ip, r in sorted(results.items()):
        print(f"  {ip:18s} ttl={str(r['ttl']):4s} "
              f"({r['ttl_guess']}) "
              f"win={str(r['tcp_window']):6s} "
              f"({r['tcp_guess'] or '?'})")

    return results