"""
Passive host discovery — zero packets sent.

Sniffs ambient network traffic for a fixed window and harvests host
information from what other devices are already broadcasting:

  - ARP requests/replies → ip + mac
  - DHCP discover/request → hostname + mac
  - mDNS queries/responses → hostname
  - SSDP (UPnP) → device description URLs
  - LLMNR / NBNS → Windows hostnames

This is the only reconnaissance method that leaves no trace on the wire.
An IDS watching for scans will see nothing because we're just listening.
"""

import asyncio
import re
import time

from scapy.all import (
    ARP, Ether, IP, IPv6,
    DHCP, BOOTP,
    DNS, DNSQR, DNSRR,
    UDP, TCP,
    AsyncSniffer,
)

from core.output import info, success, warn
from net.util import ProgressBar, PRINT_LOCK


# Ports we care about
MDNS_PORT = 5353
SSDP_PORT = 1900
LLMNR_PORT = 5355
NBNS_PORT = 137
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


class PassiveCollector:
    """Accumulates everything we learn without sending a thing."""

    def __init__(self):
        self.hosts = {}     # ip -> dict
        self.services = {}  # ip -> set of "port/proto"
        self.start_time = time.time()

    def _ensure(self, ip, mac=None):
        if ip not in self.hosts:
            self.hosts[ip] = {
                "ip": ip,
                "mac": mac or "",
                "hostnames": set(),
                "sources": set(),
                "first_seen": time.time(),
            }
        elif mac and not self.hosts[ip]["mac"]:
            self.hosts[ip]["mac"] = mac
        return self.hosts[ip]

    def add_arp(self, pkt):
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        if arp.op == 1 and arp.psrc != "0.0.0.0":     # who-has
            h = self._ensure(arp.psrc, arp.hwsrc)
            h["sources"].add("arp-request")
        elif arp.op == 2:                              # is-at (reply)
            h = self._ensure(arp.psrc, arp.hwsrc)
            h["sources"].add("arp-reply")

    def add_dhcp(self, pkt):
        if not pkt.haslayer(BOOTP):
            return
        bootp = pkt[BOOTP]
        mac = bootp.chaddr[:6].hex(":") if bootp.chaddr else ""
        if bootp.ciaddr and bootp.ciaddr != "0.0.0.0":
            h = self._ensure(bootp.ciaddr, mac)
            h["sources"].add("dhcp")
            if bootp.options:
                for opt in bootp.options:
                    if isinstance(opt, tuple) and len(opt) == 2:
                        if opt[0] == "hostname":
                            h["hostnames"].add(str(opt[1]))

    def add_mdns(self, pkt):
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        ip = pkt[IP].src if pkt.haslayer(IP) else None
        if not ip:
            return
        h = self._ensure(ip)
        h["sources"].add("mdns")

        # Queries
        qd = dns.qd
        while qd:
            if qd.qname:
                name = qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                if name and not name.startswith("_"):
                    h["hostnames"].add(name)
            qd = qd.payload if hasattr(qd, "payload") else None

        # Answers
        an = dns.an
        while an:
            if hasattr(an, "rrname") and an.rrname:
                name = an.rrname.decode("utf-8", errors="ignore").rstrip(".")
                if name and not name.startswith("_"):
                    h["hostnames"].add(name)
            an = an.payload if hasattr(an, "payload") else None

    def add_ssdp(self, pkt):
        """SSDP M-SEARCH / NOTIFY — extracts hostname from Server header."""
        if not pkt.haslayer(UDP):
            return
        udp = pkt[UDP]
        if udp.dport != SSDP_PORT and udp.sport != SSDP_PORT:
            return
        ip = pkt[IP].src if pkt.haslayer(IP) else None
        if not ip:
            return
        h = self._ensure(ip)
        h["sources"].add("ssdp")

        try:
            payload = bytes(udp.payload).decode("utf-8", errors="ignore")
        except Exception:
            return

        for line in payload.split("\r\n"):
            if line.lower().startswith("server:"):
                h["hostnames"].add(line.split(":", 1)[1].strip())

    def add_llmnr(self, pkt):
        if not pkt.haslayer(DNS) or not pkt.haslayer(UDP):
            return
        if pkt[UDP].dport != LLMNR_PORT and pkt[UDP].sport != LLMNR_PORT:
            return
        ip = pkt[IP].src if pkt.haslayer(IP) else None
        if not ip:
            return
        h = self._ensure(ip)
        h["sources"].add("llmnr")
        qd = pkt[DNS].qd
        if qd and qd.qname:
            name = qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            h["hostnames"].add(name)

    def add_tcp_service(self, pkt):
        """Any TCP SYN-ACK we see implies an open port."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        tcp = pkt[TCP]
        if tcp.flags == "SA":
            src = pkt[IP].src
            port = tcp.sport
            self.services.setdefault(src, set()).add(f"{port}/tcp")
            self._ensure(src)["sources"].add("tcp-synack")

    def add_udp_service(self, pkt):
        """UDP traffic from a host implies it's running something."""
        if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
            return
        udp = pkt[UDP]
        src = pkt[IP].src
        self.services.setdefault(src, set()).add(f"{udp.sport}/udp")
        self._ensure(src)["sources"].add("udp")


def _handle_factory(collector):
    """Build the prn callback that dispatches to the right collector method."""
    def handle(pkt):
        try:
            if pkt.haslayer(ARP):
                collector.add_arp(pkt)
            if pkt.haslayer(BOOTP):
                collector.add_dhcp(pkt)
            if pkt.haslayer(UDP):
                dport = pkt[UDP].dport
                sport = pkt[UDP].sport
                if MDNS_PORT in (dport, sport):
                    collector.add_mdns(pkt)
                elif SSDP_PORT in (dport, sport):
                    collector.add_ssdp(pkt)
                elif LLMNR_PORT in (dport, sport):
                    collector.add_llmnr(pkt)
                else:
                    collector.add_udp_service(pkt)
            if pkt.haslayer(TCP):
                collector.add_tcp_service(pkt)
        except Exception:
            # Passive collection must never crash — one bad packet, skip it.
            pass
    return handle


async def discover(duration=60, show_progress=True, verbose=False,
                   target_filter=None):
    """
    Sniff ambient traffic for `duration` seconds.

    target_filter: optional ipaddress.IPv4Network — only keep hosts within it.
    Returns {ip: host_dict} similar to host_discovery's output.
    """
    collector = PassiveCollector()

    info(f"passive discovery: sniffing ambient traffic for {duration}s "
         f"(no packets sent)")

    sniffer = AsyncSniffer(store=False, prn=_handle_factory(collector))
    try:
        sniffer.start()
    except Exception as e:
        warn(f"could not start sniffer: {type(e).__name__}: {e}")
        return {}

    bar = ProgressBar(duration, prefix="Passive   ", enabled=show_progress)
    try:
        for i in range(duration):
            await asyncio.sleep(1)
            with PRINT_LOCK:
                bar.update(i + 1)
                if verbose and collector.hosts:
                    # Non-destructive status update
                    pass
    except asyncio.CancelledError:
        pass
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
        bar.finish()

    # Filter by subnet if requested
    hosts = collector.hosts
    if target_filter is not None:
        filtered = {}
        for ip, h in hosts.items():
            try:
                import ipaddress
                if ipaddress.ip_address(ip) in target_filter:
                    filtered[ip] = h
            except Exception:
                continue
        hosts = filtered

    # Merge observed TCP/UDP services in
    inventory = {}
    for ip, h in hosts.items():
        inventory[ip] = {
            "ip": ip,
            "mac": h["mac"] or "passive",
            "hostname": next(iter(h["hostnames"])) if h["hostnames"] else "",
            "hostnames": sorted(h["hostnames"]),
            "status": "online",
            "discovery": "passive:" + ",".join(sorted(h["sources"])),
            "open_ports": sorted(
                int(s.split("/")[0]) for s in collector.services.get(ip, set())),
            "services_observed": sorted(collector.services.get(ip, set())),
        }

    return inventory


async def run(target=None, duration=60, verbose=False):
    """CLI entry point."""
    import ipaddress

    target_filter = None
    if target:
        try:
            target_filter = ipaddress.ip_network(target, strict=False)
        except Exception:
            warn(f"could not parse target {target} as CIDR; showing all hosts")

    info("passive discovery — no packets will be sent")
    inventory = await discover(duration=duration, verbose=verbose,
                               target_filter=target_filter)

    print()
    if not inventory:
        warn(f"no hosts observed in {duration}s "
             f"(try a longer window or a busier segment)")
        return {}

    success(f"observed {len(inventory)} host(s) passively")
    for ip, h in sorted(inventory.items()):
        hostname = f" ({h['hostname']})" if h["hostname"] else ""
        services = ", ".join(h["services_observed"][:6])
        print(f"  {ip:18s} {h['mac']:18s}{hostname}")
        if services:
            print(f"    services seen: {services}")

    return inventory