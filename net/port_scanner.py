"""
TCP SYN scanner with connect-scan fallback, plus UDP probe.

The SYN scan is fast and half-open. The connect scan is a fallback for
environments where scapy can't operate. All sends are shuffled + jittered.
"""

import asyncio
import random
import socket

from scapy.all import IP, TCP, UDP, ICMP, AsyncSniffer, send

from core.output import info, success, warn
from net.util import (
    ProgressBar, SCAPY_LOCK, PRINT_LOCK, SendStrategy,
    get_local_source_ip, expand_cidr, chunked, random_chunks,
    shuffle, jittered_sleep, random_ip_id, random_source_port,
    note_error,
)


TOP_1000 = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 500, 512, 513,
    514, 515, 520, 548, 554, 587, 631, 636, 646, 873, 902, 989, 990, 993,
    995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1433, 1434, 1521, 1701,
    1720, 1723, 1755, 1812, 1813, 1900, 2000, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2222, 2483, 2484, 3000, 3128, 3260, 3268, 3269, 3283, 3306,
    3389, 3690, 4000, 4125, 4243, 4443, 4444, 4500, 5000, 5060, 5061, 5222,
    5269, 5357, 5432, 5555, 5632, 5800, 5900, 5901, 5985, 5986, 6000, 6379,
    6666, 7001, 7002, 7443, 8000, 8008, 8010, 8080, 8081, 8082, 8083, 8088,
    8090, 8181, 8200, 8333, 8443, 8888, 9000, 9001, 9090, 9100, 9200, 9300,
    9418, 9999, 10000, 11211, 27017, 27018, 50000,
]


def _parse_ports(ports_arg, top):
    if ports_arg:
        out = []
        for piece in ports_arg.split(","):
            piece = piece.strip()
            if "-" in piece:
                a, b = piece.split("-", 1)
                out.extend(range(int(a), int(b) + 1))
            elif piece.isdigit():
                out.append(int(piece))
        return sorted(set(out))
    return TOP_1000[:top]


# ---------------------------------------------------------------------
# TCP SYN scan
# ---------------------------------------------------------------------

async def _syn_scan_host(ip, ports, timeout=0.6, verbose=False, strategy=None):
    if strategy is None:
        strategy = SendStrategy()

    open_ports = []
    port_set = set(ports)

    # Tight BPF: only replies TO us FROM the target.
    src_ip = get_local_source_ip(ip)
    if src_ip and src_ip != "0.0.0.0":
        bpf = f"tcp and src host {ip} and dst host {src_ip}"
    else:
        bpf = f"tcp and src host {ip}"

    def handle(pkt):
        if not pkt.haslayer(IP) or pkt[IP].src != ip:
            return
        if not pkt.haslayer(TCP):
            return
        sport = pkt[TCP].sport
        if sport not in port_set:
            return
        if pkt[TCP].flags == "SA":
            if sport not in open_ports:
                open_ports.append(sport)

    sniffer = None
    try:
        sniffer = AsyncSniffer(filter=bpf, store=False, prn=handle)
        sniffer.start()
    except Exception as e:
        note_error("sniffer_syn", str(e))
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass
        return await _connect_scan_host(ip, ports, timeout)

    await asyncio.sleep(0.05)

    targets = shuffle(ports) if strategy.shuffle_ports else list(ports)
    pkts = []
    for p in targets:
        if strategy.random_id:
            pkts.append(IP(dst=ip, id=random_ip_id()) /
                        TCP(sport=random_source_port(), dport=p, flags="S"))
        else:
            pkts.append(IP(dst=ip) / TCP(dport=p, flags="S"))

    iterator = (random_chunks(pkts, 20, 60) if strategy.burst
                else chunked(pkts, 100))
    for chunk in iterator:
        try:
            with SCAPY_LOCK:
                send(chunk, verbose=False, inter=random.uniform(0.001, 0.008))
        except Exception:
            break
        strategy.sleep_between()

    await asyncio.sleep(max(0.6, 1.2 * timeout))
    try:
        sniffer.stop()
    except Exception:
        pass

    # Politely RST every half-open SYN we sent.
    if open_ports:
        rsts = [IP(dst=ip) / TCP(dport=p, flags="R") for p in open_ports]
        for c in chunked(rsts, 100):
            try:
                with SCAPY_LOCK:
                    send(c, verbose=False, inter=0.002)
            except Exception:
                break

    return sorted(open_ports)


async def _connect_scan_host(ip, ports, timeout=0.6, concurrency=200):
    """Fallback: full TCP connect scan via asyncio. Slower, noisier, no root needed."""
    sem = asyncio.Semaphore(concurrency)
    open_ports = []

    async def one(p):
        async with sem:
            try:
                fut = asyncio.open_connection(ip, p)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                open_ports.append(p)
            except Exception:
                pass

    await asyncio.gather(*[one(p) for p in ports])
    return sorted(open_ports)


# ---------------------------------------------------------------------
# UDP probe (best-effort)
# ---------------------------------------------------------------------

async def _udp_probe_host(ip, ports, timeout=1.0):
    """
    Send an empty UDP datagram to each port. If the target replies with
    ICMP port-unreachable, the port is closed. If it stays silent, the
    port is 'open | filtered'.

    NOTE: reading the original UDP dport from the ICMP error requires
    digging into the nested payload. scapy's ICMP layer is followed by
    the ORIGINAL IP header, then the original UDP header.
    """
    found = []
    port_set = set(ports)

    def handle(pkt):
        if not pkt.haslayer(IP) or pkt[IP].src != ip:
            return
        if not pkt.haslayer(ICMP):
            return
        icmp = pkt[ICMP]
        if icmp.type != 3 or icmp.code != 3:
            return
        # Nesting: ICMP / IP / UDP
        inner = icmp.payload
        if hasattr(inner, "payload") and inner.payload and \
                hasattr(inner.payload, "dport"):
            found.append(inner.payload.dport)

    sniffer = None
    try:
        sniffer = AsyncSniffer(
            filter=f"icmp and src host {ip}", store=False, prn=handle)
        sniffer.start()
    except Exception as e:
        note_error("sniffer_udp", str(e))
        if sniffer:
            try:
                sniffer.stop()
            except Exception:
                pass
        return []

    await asyncio.sleep(0.05)
    pkts = [IP(dst=ip) / UDP(dport=p) for p in ports]
    for c in chunked(pkts, 100):
        try:
            with SCAPY_LOCK:
                send(c, verbose=False, inter=0.002)
        except Exception:
            break
    await asyncio.sleep(timeout * 2)
    try:
        sniffer.stop()
    except Exception:
        pass

    closed = set(found)
    return sorted(p for p in port_set if p not in closed)


# ---------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------

async def scan_hosts(hosts, ports, timeout=0.6, show_progress=True,
                     verbose=False, strategy=None):
    """Scan a list of IPs for open TCP ports. Returns {ip: [ports]}."""
    if strategy is None:
        strategy = SendStrategy()

    results = {}
    bar = ProgressBar(len(hosts), prefix="Port scan", enabled=show_progress)
    done = 0

    for ip in hosts:
        open_ports = await _syn_scan_host(
            ip, ports, timeout=timeout, verbose=verbose, strategy=strategy)
        results[ip] = open_ports
        done += 1
        with PRINT_LOCK:
            bar.update(done)
        if verbose and open_ports:
            info(f"{ip}: {len(open_ports)} open ports")

    bar.finish()
    return results


async def run(target, ports_arg=None, top=100, timeout=0.6, verbose=False,
              stealth=False, max_pps=None):
    """CLI entry point."""
    from core.dns import resolve_a

    ports = _parse_ports(ports_arg, top)
    info(f"scanning {len(ports)} ports")

    if "/" in target:
        hosts = expand_cidr(target)
    else:
        ips = await resolve_a(target)
        hosts = ips or [target]

    info(f"targets: {len(hosts)} host(s)")
    strategy = SendStrategy(stealth=stealth, max_pps=max_pps)
    results = await scan_hosts(hosts, ports, timeout=timeout,
                               verbose=verbose, strategy=strategy)

    print()
    total_open = sum(len(v) for v in results.values())
    success(f"{total_open} open port(s) across {len(results)} host(s)")
    for ip, open_ports in sorted(results.items()):
        if open_ports:
            print(f"  {ip}: {', '.join(str(p) for p in open_ports)}")

    return results