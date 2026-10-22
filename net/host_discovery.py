"""
Bulk-blast host discovery with stealth-aware ordering.

Split into two engines:
  - ARP sweep for local L2 targets (fast, one sniff pass, chunked sends).
  - ICMP + TCP SYN blast for routed targets (Sniffer catches replies).

All sends are shuffled + jittered so the packet sequence doesn't look
like a textbook scan.
"""

import asyncio
import time
import random

from scapy.all import (
    ARP, Ether, IP, ICMP, TCP, AsyncSniffer, send, sendp, srp, sr1,
)

from core.output import info, success, warn, error
from net.util import (
    ProgressBar, SCAPY_LOCK, PRINT_LOCK,
    SendStrategy, get_local_subnets, get_local_source_ip,
    expand_cidr, is_local_l2, chunked, random_chunks,
    shuffle, jittered_sleep, random_ip_id, random_source_port,
    note_error,
)


DEFAULT_THREADS = 64
DEFAULT_TIMEOUT_SCALE = 1.0
TCP_FALLBACK_PORTS = (80, 443, 22, 445)


class HostInfo(dict):
    """Dict with attribute access. Keeps things readable without dataclasses."""
    pass


# ---------------------------------------------------------------------
# Send helpers
# ---------------------------------------------------------------------

def _chunked_send_l3(pkts, strategy):
    """scapy silently drops packets past a few hundred; chunk + jitter the send."""
    iterator = (random_chunks(pkts, 20, 80) if strategy.burst
                else chunked(pkts, 100))
    for chunk in iterator:
        try:
            with SCAPY_LOCK:
                send(chunk, verbose=False, inter=random.uniform(0.001, 0.008))
        except (PermissionError, OSError) as e:
            note_error("send_l3", str(e))
            return
        strategy.sleep_between()


def _chunked_send_l2(pkts, strategy):
    iterator = (random_chunks(pkts, 20, 80) if strategy.burst
                else chunked(pkts, 100))
    for chunk in iterator:
        try:
            with SCAPY_LOCK:
                sendp(chunk, verbose=False, inter=random.uniform(0.001, 0.008))
        except (PermissionError, OSError) as e:
            note_error("send_l2", str(e))
            return
        strategy.sleep_between()


# ---------------------------------------------------------------------
# ARP sweep
# ---------------------------------------------------------------------

async def _bulk_arp_sweep(ips, timeout_scale, strategy):
    """ARP blast + single sniff pass. Returns {ip: mac}."""
    found = {}
    ip_set = set(ips)

    def handle(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 2 and pkt[ARP].psrc in ip_set:
            found[pkt[ARP].psrc] = pkt[ARP].hwsrc

    sniffer = None
    try:
        sniffer = AsyncSniffer(filter="arp", store=False, prn=handle)
        sniffer.start()
    except Exception as e:
        note_error("sniffer_arp", str(e))
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass
        return await _per_packet_arp(ips, timeout_scale)

    await asyncio.sleep(0.2)

    targets = shuffle(ips) if strategy.shuffle_ips else list(ips)
    pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in targets]
    _chunked_send_l2(pkts, strategy)

    await asyncio.sleep(max(0.8, 1.5 * timeout_scale))
    try:
        sniffer.stop()
    except Exception:
        pass
    return found


async def _per_packet_arp(ips, timeout_scale):
    """Fallback when AsyncSniffer can't start. Serial, slow."""
    found = {}
    for ip in ips:
        try:
            with SCAPY_LOCK:
                ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                          timeout=0.6 * timeout_scale, verbose=False)[0]
            if ans:
                found[ip] = ans[0][1].hwsrc
        except Exception:
            pass
    return found


# ---------------------------------------------------------------------
# L3 sweep (ICMP + TCP)
# ---------------------------------------------------------------------

async def _bulk_l3_sweep(ips, timeout_scale, use_tcp_fallback, strategy):
    """ICMP + TCP SYN blast on routed targets. Returns {ip: method}."""
    found = {}
    ip_set = set(ips)

    # We need our source IP to build a tight BPF filter — otherwise the
    # sniffer catches every TCP packet on the wire and drops ours.
    # Pick a representative target for the route lookup.
    sample = next(iter(ips))
    src_ip = get_local_source_ip(sample)

    if src_ip and src_ip != "0.0.0.0":
        bpf = f"icmp or (tcp and dst host {src_ip})"
    else:
        bpf = "icmp or tcp"

    def handle(pkt):
        if not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        if src not in ip_set:
            return
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 0:
            found.setdefault(src, "ICMP")
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags in ("SA", "RA"):
                found.setdefault(src, f"TCP:{pkt[TCP].sport}")

    sniffer = None
    try:
        sniffer = AsyncSniffer(filter=bpf, store=False, prn=handle)
        sniffer.start()
    except Exception as e:
        note_error("sniffer_l3", str(e))
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass
        return await _per_packet_l3(ips, timeout_scale, use_tcp_fallback)

    await asyncio.sleep(0.2)

    targets = shuffle(ips) if strategy.shuffle_ips else list(ips)
    probe_ports = TCP_FALLBACK_PORTS if use_tcp_fallback else ()
    pkts = []
    for ip in targets:
        if strategy.random_id:
            pkts.append(IP(dst=ip, id=random_ip_id()) / ICMP())
            for port in probe_ports:
                pkts.append(IP(dst=ip, id=random_ip_id()) /
                            TCP(sport=random_source_port(),
                                dport=port, flags="S"))
        else:
            pkts.append(IP(dst=ip) / ICMP())
            for port in probe_ports:
                pkts.append(IP(dst=ip) / TCP(dport=port, flags="S"))

    info(f"  blasting {len(pkts)} probe packets...")
    _chunked_send_l3(pkts, strategy)

    await asyncio.sleep(max(1.0, 2.0 * timeout_scale))
    try:
        sniffer.stop()
    except Exception:
        pass
    return found


async def _per_packet_l3(ips, timeout_scale, use_tcp_fallback):
    """Serial fallback for L3 sweep."""
    found = {}
    for ip in ips:
        try:
            with SCAPY_LOCK:
                ans = sr1(IP(dst=ip) / ICMP(),
                          timeout=0.8 * timeout_scale, verbose=False)
            if ans and ans.haslayer(ICMP):
                found[ip] = "ICMP"
                continue
        except Exception:
            pass
        if not use_tcp_fallback:
            continue
        for port in TCP_FALLBACK_PORTS:
            try:
                with SCAPY_LOCK:
                    ans = sr1(IP(dst=ip) / TCP(dport=port, flags="S"),
                              timeout=0.5 * timeout_scale, verbose=False)
                if ans and ans.haslayer(TCP) and ans[TCP].flags in ("SA", "RA"):
                    found[ip] = f"TCP:{port}"
                    break
            except Exception:
                continue
    return found


# ---------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------

async def discover(subnets, timeout_scale=1.0, use_tcp_fallback=True,
                   show_progress=True, verbose=False,
                   strategy=None):
    """
    Discover live hosts on the given subnets.

    strategy: a SendStrategy instance. If None, uses stealth defaults.
    """
    if strategy is None:
        strategy = SendStrategy()

    all_ips = []
    for subnet in subnets:
        info(f"expanding {subnet}")
        all_ips.extend(expand_cidr(subnet))

    if not all_ips:
        error("no targets to scan")
        return {}

    local_nets = get_local_subnets()
    local_ips = [ip for ip in all_ips if is_local_l2(ip, local_nets)]
    routed_ips = [ip for ip in all_ips if not is_local_l2(ip, local_nets)]

    info(f"targets: {len(all_ips)} total "
         f"(local L2: {len(local_ips)}, routed: {len(routed_ips)})")

    bar = ProgressBar(len(all_ips), prefix="Discovery", enabled=show_progress)
    inventory = {}
    done = 0

    if local_ips:
        info("phase 1/2: ARP sweep on local segment")
        found = await _bulk_arp_sweep(local_ips, timeout_scale, strategy)
        for ip, mac in found.items():
            inventory[ip] = HostInfo(
                ip=ip, mac=mac, status="online",
                hostname="pending", ports=[], discovery="arp",
            )
        done += len(local_ips)
        with PRINT_LOCK:
            bar.update(done)

    if routed_ips:
        info(f"phase 2/2: ICMP+TCP sweep on {len(routed_ips)} routed targets")
        found = await _bulk_l3_sweep(
            routed_ips, timeout_scale, use_tcp_fallback, strategy)
        for ip, method in found.items():
            if ip not in inventory:
                inventory[ip] = HostInfo(
                    ip=ip, mac="via-routed-gateway", status="online",
                    hostname="pending", ports=[], discovery=method,
                )
        done += len(routed_ips)
        with PRINT_LOCK:
            bar.update(done)

    bar.finish()
    success(f"discovered {len(inventory)} live host(s)")
    return inventory


async def run(target, threads=DEFAULT_THREADS, timeout_scale=1.0,
              use_tcp_fallback=True, verbose=False,
              stealth=False, max_pps=None):
    """CLI entry point."""
    info(f"host discovery on {target}")
    strategy = SendStrategy(stealth=stealth, max_pps=max_pps)
    subnets = [target] if "/" in target else [f"{target}/32"]
    inventory = await discover(
        subnets, timeout_scale=timeout_scale,
        use_tcp_fallback=use_tcp_fallback, verbose=verbose,
        strategy=strategy,
    )

    print()
    if not inventory:
        warn("no live hosts found")
        return inventory

    success(f"{len(inventory)} live host(s):")
    for ip, host in sorted(inventory.items()):
        print(f"  {ip:18s} {host['discovery']:12s} {host['mac']}")

    return inventory