"""
Traceroute with ICMP-first, TCP:80 and TCP:443 fallbacks.
"""

import asyncio
import ipaddress

from scapy.all import IP, ICMP, TCP, sr1

from core.output import info, success, warn
from net.util import SCAPY_LOCK


async def trace(target_ip, max_hops=20, timeout=1.0, verbose=False):
    """Return list of hop dicts: {ttl, hop_ip, method}."""
    hops = []

    for ttl in range(1, max_hops + 1):
        hop_ip = None
        method = None

        probes = [
            (IP(dst=target_ip, ttl=ttl) / ICMP(), "icmp"),
            (IP(dst=target_ip, ttl=ttl) / TCP(dport=80, flags="S"), "tcp80"),
            (IP(dst=target_ip, ttl=ttl) / TCP(dport=443, flags="S"), "tcp443"),
        ]

        for probe, kind in probes:
            try:
                with SCAPY_LOCK:
                    reply = sr1(probe, timeout=timeout, verbose=False)
            except Exception:
                continue
            if reply is None:
                continue

            if reply.haslayer(ICMP):
                icmp = reply[ICMP]
                if icmp.type == 11:
                    hop_ip = reply[IP].src
                    method = kind
                    break
                if icmp.type == 0:
                    hop_ip = reply[IP].src
                    method = kind + "+dest"
                    break
            elif reply.haslayer(TCP):
                if reply[TCP].flags in ("SA", "RA"):
                    hop_ip = reply[IP].src
                    method = kind + "+dest"
                    break

        if hop_ip is None:
            hops.append({"ttl": ttl, "hop_ip": None, "method": "timeout"})
            if verbose:
                info(f"  {ttl:2d}  *  *  *")
        else:
            hops.append({"ttl": ttl, "hop_ip": hop_ip, "method": method})
            if verbose:
                info(f"  {ttl:2d}  {hop_ip}  ({method})")
            if method.endswith("+dest"):
                break

    return hops


async def trace_many(ips, max_hops=20, timeout=1.0, verbose=False):
    results = {}
    for ip in ips:
        if verbose:
            info(f"tracing {ip}")
        results[ip] = await trace(ip, max_hops=max_hops, timeout=timeout,
                                  verbose=verbose)
    return results


def render_ascii(hops, target):
    lines = [f"traceroute to {target}"]
    for h in hops:
        if h["hop_ip"] is None:
            lines.append(f"  {h['ttl']:2d}  *  *  *")
        else:
            lines.append(f"  {h['ttl']:2d}  {h['hop_ip']}  ({h['method']})")
    return "\n".join(lines)


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


async def run(target, max_hops=20, timeout=1.0, verbose=False):
    from core.dns import resolve_a

    if _is_ip(target):
        ips = [target]
    else:
        ips = await resolve_a(target)
        if not ips:
            ips = [target]

    info(f"traceroute to {target} ({len(ips)} address(es))")
    results = await trace_many(ips, max_hops=max_hops, timeout=timeout,
                               verbose=verbose)

    print()
    for ip, hops in results.items():
        print(render_ascii(hops, ip))
        print()

    return results