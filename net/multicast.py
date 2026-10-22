"""
Multicast device discovery via mDNS, SSDP, and WS-Discovery.

Unlike ARP/ICMP sweeps, multicast queries reach devices you can't
otherwise see: IoT gear behind wireless APs that filter broadcast,
printers that stay silent until asked, Chromecasts and Sonos speakers
that only announce themselves on their own protocols.

We send one query per protocol and collect responses for a short
window, then parse each response for:

    - hostname
    - service / device type
    - manufacturer + model
    - firmware version
    - description URL (fetched lazily; skipped with --no-descriptions)

Every responding device is enriched with its MAC vendor (via
net.oui) and written to the store.

Protocols:

    mDNS            UDP/5353  multicast 224.0.0.251
    SSDP            UDP/1900  multicast 239.255.255.250
    WS-Discovery    UDP/3702  multicast 239.255.255.250

Usage:

    from net.multicast import discover, run

    devices = await discover(duration=5)
    await run(store=store, duration=5)

    # CLI:
    python -m net.multicast
    python -m net.multicast --protocol mdns
    python -m net.multicast --duration 10 --store
"""

import asyncio
import re
import socket
import struct
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

from scapy.all import IP, UDP, AsyncSniffer

from core.output import info, success, warn, error
from net.util import PRINT_LOCK, note_error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

MDNS_PORT = 5353
MDNS_GROUP = "224.0.0.251"
SSDP_PORT = 1900
SSDP_GROUP = "239.255.255.250"
WSD_PORT = 3702
WSD_GROUP = "239.255.255.250"

DEFAULT_DURATION = 5.0
DESCRIPTION_TIMEOUT = 3.0
MAX_DESCRIPTIONS = 200


# mDNS service types to query. Each type gets a PTR query. When we
# query _services._dns-sd._udp.local we get the list of all service
# types on the network, but that's verbose; we query the specific
# ones we care about and let responses come in passively.
MDNS_SERVICE_TYPES = [
    "_services._dns-sd._udp.local",   # service type enumeration
    "_http._tcp.local",                 # web services
    "_https._tcp.local",
    "_ipp._tcp.local",                  # printers (IPP)
    "_ipps._tcp.local",
    "_printer._tcp.local",              # printers (LPD)
    "_pdl-datastream._tcp.local",       # printers (raw)
    "_googlecast._tcp.local",           # Chromecast
    "_airplay._tcp.local",              # Apple AirPlay
    "_raop._tcp.local",                 # AirPlay audio (RAOP)
    "_sonos._tcp.local",                # Sonos
    "_spotify-connect._tcp.local",      # Spotify Connect
    "_smb._tcp.local",                  # SMB shares
    "_afpovertcp._tcp.local",           # AFP shares
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_rfb._tcp.local",                  # VNC
    "_workstation._tcp.local",          # generic workstations
    "_companion-link._tcp.local",       # Apple Continuity
    "_sleep-proxy._udp.local",          # Apple sleep proxy
    "_device-info._tcp.local",          # Apple device info
]


# SSDP search targets. ST: ssdp:all is the "tell me everything" query.
SSDP_SEARCH_TARGETS = [
    "ssdp:all",
    "upnp:rootdevice",
    # Common device types:
    "urn:schemas-upnp-org:device:MediaRenderer:1",
    "urn:schemas-upnp-org:device:MediaServer:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:WANConnectionDevice:1",
]


# WS-Discovery: standard Probe action
WSD_PROBE = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
    b'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    b'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    b'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    b'<e:Header>'
    b'<w:MessageID>uuid:{msg_id}</w:MessageID>'
    b'<w:To e:mustUnderstand="true">'
    b'urn:schemas-xmlsoap-org:ws:2005:04:discovery'
    b'</w:To>'
    b'<w:Action e:mustUnderstand="true">'
    b'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe'
    b'</w:Action>'
    b'</e:Header>'
    b'<e:Body>'
    b'<d:Probe>'
    b'<d:Types>dn:NetworkVideoTransmitter</d:Types>'
    b'</d:Probe>'
    b'</e:Body>'
    b'</e:Envelope>'
)


# ---------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------

@dataclass
class Device:
    """One discovered multicast device."""
    ip: str = ""
    src_mac: str = ""
    hostnames: set = field(default_factory=set)
    services: set = field(default_factory=set)   # service type strings
    models: set = field(default_factory=set)
    manufacturers: set = field(default_factory=set)
    firmware: set = field(default_factory=set)
    serials: set = field(default_factory=set)
    locations: set = field(default_factory=set)  # XML description URLs
    servers: set = field(default_factory=set)    # Server: headers
    protocols: set = field(default_factory=set)  # mdns/ssdp/wsd
    vendor: str = ""
    first_seen: float = 0.0

    def merge(self, other: "Device"):
        if not self.ip and other.ip:
            self.ip = other.ip
        if not self.src_mac and other.src_mac:
            self.src_mac = other.src_mac
        self.hostnames |= other.hostnames
        self.services |= other.services
        self.models |= other.models
        self.manufacturers |= other.manufacturers
        self.firmware |= other.firmware
        self.serials |= other.serials
        self.locations |= other.locations
        self.servers |= other.servers
        self.protocols |= other.protocols
        if other.vendor and not self.vendor:
            self.vendor = other.vendor

    def summary(self) -> str:
        """One-line summary for console output."""
        parts = []
        if self.hostnames:
            parts.append(next(iter(sorted(self.hostnames))))
        if self.manufacturers:
            parts.append(next(iter(self.manufacturers)))
        if self.models:
            parts.append(next(iter(self.models)))
        if not parts and self.ip:
            parts.append(self.ip)
        return " — ".join(parts) or "?"


# ---------------------------------------------------------------------
# Query builders
# ---------------------------------------------------------------------

def _build_mdns_query(service_type: str) -> bytes:
    """Build an mDNS PTR query for a service type."""
    # We use scapy to construct this cleanly
    from scapy.all import DNS, DNSQR
    pkt = (
        IP(dst=MDNS_GROUP, ttl=255)
        / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
        / DNS(
            id=0,
            qr=0, opcode=0, aa=0, rd=0, ra=0, z=0, rcode=0,
            qdcount=1, ancount=0, nscount=0, arcount=0,
            qd=DNSQR(qname=service_type, qtype="PTR", qclass=1),
        )
    )
    return bytes(pkt)


def _build_ssdp_query(st: str, mx: int = 2) -> bytes:
    """Build an SSDP M-SEARCH request."""
    return (
        f"M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_GROUP}:{SSDP_PORT}\r\n"
        f'MAN: "ssdp:discover"\r\n'
        f"MX: {mx}\r\n"
        f"ST: {st}\r\n"
        f"USER-AGENT: toolkit/0.1 UPnP/1.1\r\n"
        f"\r\n"
    ).encode("ascii")


def _build_wsd_probe() -> bytes:
    """Build a WS-Discovery Probe SOAP message."""
    import uuid as _uuid
    msg_id = str(_uuid.uuid4())
    return WSD_PROBE.replace(b"{msg_id}", msg_id.encode("ascii"))


# ---------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------

def _parse_mdns_response(pkt) -> Device | None:
    """Parse an mDNS response packet into a Device."""
    if not pkt.haslayer(UDP) or pkt[UDP].sport != MDNS_PORT:
        return None
    if not pkt.haslayer("DNS") or pkt["DNS"].qr != 1:
        return None
    try:
        dns = pkt["DNS"]
        ip = pkt[IP].src if pkt.haslayer(IP) else ""
        mac = pkt["Ether"].src if pkt.haslayer("Ether") else ""
    except Exception:
        return None

    dev = Device(ip=ip, src_mac=mac, first_seen=time.time())
    dev.protocols.add("mdns")

    # Parse answer records
    an = dns.an
    while an:
        try:
            rr_type = an.type
            rr_name = an.rrname
            if isinstance(rr_name, bytes):
                rr_name = rr_name.decode("utf-8", errors="ignore")
            rr_name = rr_name.rstrip(".")

            if rr_type == 12:   # PTR — service instance
                target = getattr(an, "ptrdname", None)
                if isinstance(target, bytes):
                    target = target.decode("utf-8", errors="ignore")
                if target:
                    dev.services.add(target.rstrip("."))
                    # Instance name is the label before the service type
                    parts = rr_name.split(".")
                    if parts:
                        dev.hostnames.add(parts[0])

            elif rr_type == 16:  # TXT
                # TXT records carry key=value pairs
                txt_data = getattr(an, "rdata", [])
                if isinstance(txt_data, (list, tuple)):
                    for item in txt_data:
                        if isinstance(item, bytes):
                            try:
                                item = item.decode("utf-8", errors="replace")
                            except Exception:
                                continue
                        if not isinstance(item, str):
                            continue
                        if "=" in item:
                            key, _, val = item.partition("=")
                            key = key.lower().strip()
                            val = val.strip()
                            if key == "model":
                                dev.models.add(val)
                            elif key == "manufacturer" or key == "mfg":
                                dev.manufacturers.add(val)
                            elif key in ("fw", "firmware", "version"):
                                dev.firmware.add(val)
                            elif key in ("serialnumber", "sn", "serial"):
                                dev.serials.add(val)
                            elif key == "fn" or key == "name":
                                dev.hostnames.add(val)
                            elif key == "md" or key == "modelname":
                                dev.models.add(val)
            elif rr_type == 1:   # A record
                pass             # IP is in the source; no new info
            elif rr_type == 33:  # SRV — service location
                target = getattr(an, "target", None)
                if isinstance(target, bytes):
                    target = target.decode("utf-8", errors="ignore")
                if target:
                    dev.hostnames.add(target.rstrip("."))
        except Exception:
            pass
        an = an.payload if hasattr(an, "payload") else None

    return dev if (dev.hostnames or dev.services) else None


def _parse_ssdp_response(pkt) -> Device | None:
    """Parse an SSDP response packet into a Device."""
    if not pkt.haslayer(UDP) or pkt[UDP].sport != SSDP_PORT:
        return None
    if not pkt.haslayer(IP):
        return None
    try:
        payload = bytes(pkt[UDP].payload).decode("utf-8", errors="ignore")
    except Exception:
        return None
    if not payload.startswith("HTTP/1.1"):
        return None

    dev = Device(ip=pkt[IP].src, first_seen=time.time())
    dev.protocols.add("ssdp")
    if pkt.haslayer("Ether"):
        dev.src_mac = pkt["Ether"].src

    for line in payload.split("\r\n"):
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if key == "server":
            dev.servers.add(val)
            # Try to extract manufacturer from Server header
            # e.g. "Linux/3.14 UPnP/1.0 Sonos/63.2-29010"
            for token in val.split():
                if "/" in token:
                    name, _, ver = token.partition("/")
                    if name.lower() not in (
                        "linux", "upnp", "darwin", "windows",
                        "android", "freebsd", "http",
                    ):
                        dev.manufacturers.add(name)
                        dev.firmware.add(ver)
        elif key == "location":
            dev.locations.add(val)
        elif key == "st":  # search target
            dev.services.add(val)
        elif key == "usn":  # unique service name
            dev.services.add(val)

    return dev


def _parse_wsd_response(pkt) -> Device | None:
    """Parse a WS-Discovery response into a Device."""
    if not pkt.haslayer(UDP) or pkt[UDP].sport != WSD_PORT:
        return None
    if not pkt.haslayer(IP):
        return None
    try:
        payload = bytes(pkt[UDP].payload)
    except Exception:
        return None

    # The SOAP response has XML with Scopes and XAddrs
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return None

    dev = Device(ip=pkt[IP].src, first_seen=time.time())
    dev.protocols.add("wsd")
    if pkt.haslayer("Ether"):
        dev.src_mac = pkt["Ether"].src

    # Pull out Scopes
    m = re.search(r"<[^>]*Scopes[^>]*>([^<]+)</[^>]*Scopes>", text)
    if m:
        for scope in m.group(1).split():
            dev.services.add(scope)
            # Scopes look like:
            # onvif://www.onvif.org/type/NetworkVideoTransmitter
            # onvif://www.onvif.org/name/IPCAM
            # onvif://www.onvif.org/hardware/Model123
            if "/name/" in scope:
                dev.hostnames.add(scope.rsplit("/name/", 1)[1])
            if "/hardware/" in scope:
                dev.models.add(scope.rsplit("/hardware/", 1)[1])
            if "manufacturer" in scope.lower():
                dev.manufacturers.add(scope.rsplit("/", 1)[-1])

    # Pull out XAddrs (device service URLs)
    m = re.search(r"<[^>]*XAddrs[^>]*>([^<]+)</[^>]*XAddrs>", text)
    if m:
        for url in m.group(1).split():
            dev.locations.add(url)

    return dev if (dev.services or dev.locations) else None


# ---------------------------------------------------------------------
# Description fetching
# ---------------------------------------------------------------------

def _fetch_description_xml(url: str, timeout=DESCRIPTION_TIMEOUT) -> dict | None:
    """Fetch and parse a UPnP/WS-Discovery XML description.

    Returns a dict with manufacturer, model, firmware, serial,
    friendly_name — or None on any failure.
    """
    try:
        req = urllib.request.Request(
            url,
            headers={},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(64 * 1024)      # cap at 64 KB
    except Exception:
        return None

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None

    # UPnP descriptions use namespace http://schemas.xmlsoap.org/.../device-1-0
    # We strip namespaces to make the tree simpler to navigate.
    def _strip_ns(tag):
        return tag.split("}", 1)[1] if "}" in tag else tag

    out = {
        "manufacturer": None,
        "manufacturer_url": None,
        "model_name": None,
        "model_number": None,
        "model_description": None,
        "friendly_name": None,
        "serial_number": None,
        "firmware_version": None,
        "udn": None,
        "device_type": None,
    }

    for elem in root.iter():
        tag = _strip_ns(elem.tag)
        text = (elem.text or "").strip()
        if not text:
            continue
        if tag == "manufacturer":
            out["manufacturer"] = text
        elif tag == "manufacturerURL":
            out["manufacturer_url"] = text
        elif tag == "modelName":
            out["model_name"] = text
        elif tag == "modelNumber":
            out["model_number"] = text
        elif tag == "modelDescription":
            out["model_description"] = text
        elif tag == "friendlyName":
            out["friendly_name"] = text
        elif tag == "serialNumber":
            out["serial_number"] = text
        elif tag in ("firmwareVersion", "firmware"):
            out["firmware_version"] = text
        elif tag == "UDN":
            out["udn"] = text
        elif tag == "deviceType":
            out["device_type"] = text

    return out


# ---------------------------------------------------------------------
# Send queries
# ---------------------------------------------------------------------

def _send_multicast(payload: bytes, group: str, port: int,
                     ttl: int = 2, iface: str | None = None):
    """Send a UDP payload to a multicast group."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        if iface:
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(socket.gethostbyname(socket.gethostname())))
            except Exception:
                pass
        sock.sendto(payload, (group, port))
        sock.close()
    except Exception as e:
        note_error("multicast_send", f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------
# Sniffer collection
# ---------------------------------------------------------------------

class Collector:
    """Accumulates devices from multicast responses."""

    def __init__(self):
        self.devices: dict[str, Device] = {}       # keyed by IP
        self.lock = asyncio.Lock() if False else None  # marker; we use threading

    def _key_for(self, dev: Device) -> str:
        # Prefer MAC (stable) then IP
        return dev.src_mac or dev.ip or "unknown"

    def add(self, dev: Device):
        key = self._key_for(dev)
        existing = self.devices.get(key)
        if existing:
            existing.merge(dev)
        else:
            self.devices[key] = dev


def _dispatch(pkt, collector: Collector):
    """Route an incoming multicast packet to the right parser."""
    try:
        if not pkt.haslayer(UDP):
            return
        sport = pkt[UDP].sport
        if sport == MDNS_PORT:
            dev = _parse_mdns_response(pkt)
        elif sport == SSDP_PORT:
            dev = _parse_ssdp_response(pkt)
        elif sport == WSD_PORT:
            dev = _parse_wsd_response(pkt)
        else:
            return
        if dev:
            collector.add(dev)
    except Exception:
        pass


# ---------------------------------------------------------------------
# Description fetching (async wrapper)
# ---------------------------------------------------------------------

async def _fetch_descriptions(collector: Collector, verbose: bool = False,
                               max_count: int = MAX_DESCRIPTIONS):
    """Fetch XML descriptions for every Location we haven't seen yet."""
    locations_to_fetch: list[tuple[str, Device]] = []
    for dev in collector.devices.values():
        for loc in dev.locations:
            if loc.startswith("http"):
                locations_to_fetch.append((loc, dev))
    if not locations_to_fetch:
        return

    info(f"multicast: fetching {len(locations_to_fetch)} device "
         f"description(s)")
    sem = asyncio.Semaphore(8)

    async def _one(url: str, dev: Device):
        async with sem:
            data = await asyncio.get_event_loop().run_in_executor(
                None, _fetch_description_xml, url)
            if not data:
                return
            if data.get("manufacturer"):
                dev.manufacturers.add(data["manufacturer"])
            if data.get("model_name"):
                dev.models.add(data["model_name"])
            if data.get("model_number"):
                dev.models.add(data["model_number"])
            if data.get("friendly_name"):
                dev.hostnames.add(data["friendly_name"])
            if data.get("serial_number"):
                dev.serials.add(data["serial_number"])
            if data.get("firmware_version"):
                dev.firmware.add(data["firmware_version"])
            if verbose:
                info(f"  {dev.ip:16s} {data.get('friendly_name', '?')} "
                     f"({data.get('manufacturer', '?')} "
                     f"{data.get('model_name', '?')})")

    await asyncio.gather(*[_one(u, d) for u, d in locations_to_fetch])


# ---------------------------------------------------------------------
# Enrich with OUI vendor
# ---------------------------------------------------------------------

def _enrich_vendor(collector: Collector):
    """Add MAC vendor names via net.oui."""
    try:
        from net import oui
        db = oui.get_db()
    except Exception as e:
        note_error("oui_load", str(e))
        return
    for dev in collector.devices.values():
        if not dev.src_mac:
            continue
        vendor = db.lookup(dev.src_mac)
        if vendor:
            dev.vendor = vendor


# ---------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------

async def discover(duration: float = DEFAULT_DURATION,
                    protocols: list[str] | None = None,
                    fetch_descriptions: bool = True,
                    verbose: bool = False) -> dict[str, Device]:
    """Run multicast discovery and return a dict of devices.

    protocols: subset of {'mdns', 'ssdp', 'wsd'}. Default: all three.
    """
    protocols = protocols or ["mdns", "ssdp", "wsd"]
    collector = Collector()

    info(f"multicast: starting discovery for {duration}s "
         f"(protocols={','.join(protocols)})")

    # Start the sniffer BEFORE sending queries, so we don't miss fast replies
    sniffer = AsyncSniffer(
        store=False,
        prn=lambda pkt: _dispatch(pkt, collector),
        filter=(
            f"udp and (port {MDNS_PORT} or port {SSDP_PORT} "
            f"or port {WSD_PORT})"
        ),
    )
    try:
        sniffer.start()
    except Exception as e:
        error(f"multicast: could not start sniffer: {type(e).__name__}: {e}")
        return {}

    await asyncio.sleep(0.3)   # let the sniffer warm up

    # Send queries
    if "mdns" in protocols:
        for svc in MDNS_SERVICE_TYPES:
            _send_multicast(_build_mdns_query(svc), MDNS_GROUP, MDNS_PORT)
            await asyncio.sleep(0.01)   # tiny spacing between queries

    if "ssdp" in protocols:
        for st in SSDP_SEARCH_TARGETS:
            _send_multicast(_build_ssdp_query(st), SSDP_GROUP, SSDP_PORT)
            await asyncio.sleep(0.02)

    if "wsd" in protocols:
        _send_multicast(_build_wsd_probe(), WSD_GROUP, WSD_PORT)

    # Collect responses for the rest of the window
    await asyncio.sleep(max(0.5, duration - 0.3))

    try:
        sniffer.stop()
    except Exception:
        pass

    # Enrich with OUI vendor info (always on)
    _enrich_vendor(collector)

    # Fetch XML descriptions
    if fetch_descriptions:
        await _fetch_descriptions(collector, verbose=verbose)

    info(f"multicast: {len(collector.devices)} device(s) discovered")
    return collector.devices


def _persist(devices: dict[str, Device], store):
    """Write discovered devices to the store."""
    if not store:
        return
    for key, dev in devices.items():
        # Host record
        hostname = next(iter(sorted(dev.hostnames))) if dev.hostnames else None
        store.upsert_host(
            dev.ip or key,
            mac=dev.src_mac or None,
            hostname=hostname,
            discovery=f"multicast ({','.join(sorted(dev.protocols))})",
            tags=[f"vendor:{dev.vendor}"] if dev.vendor else [],
        )

        # Finding
        services = ", ".join(sorted(dev.services)[:10])
        manufacturer = next(iter(dev.manufacturers), "")
        model = next(iter(dev.models), "")
        store.add_finding({
            "module": "multicast",
            "type": "informational",
            "severity": "info",
            "target": dev.ip or key,
            "evidence": dev.summary(),
            "data": {
                "src_mac": dev.src_mac,
                "vendor": dev.vendor,
                "hostnames": sorted(dev.hostnames),
                "services": sorted(dev.services),
                "manufacturer": manufacturer,
                "model": model,
                "firmware": sorted(dev.firmware),
                "serials": sorted(dev.serials),
                "locations": sorted(dev.locations),
                "servers": sorted(dev.servers),
                "protocols": sorted(dev.protocols),
            },
        })


async def run(store=None, workspace=None, duration: float = DEFAULT_DURATION,
              protocols: list[str] | None = None,
              fetch_descriptions: bool = True,
              verbose: bool = False) -> dict[str, Device]:
    """CLI-style entry point."""
    devices = await discover(
        duration=duration,
        protocols=protocols,
        fetch_descriptions=fetch_descriptions,
        verbose=verbose,
    )

    print()
    if not devices:
        warn("multicast: no devices responded")
        return devices

    success(f"multicast: {len(devices)} device(s) discovered")
    for key, dev in sorted(devices.items(), key=lambda x: x[1].ip or ""):
        line = f"  {dev.ip:16s} "
        if dev.src_mac:
            line += f"{dev.src_mac:18s} "
        else:
            line += " " * 19
        line += f"{dev.summary():60s}"
        if dev.vendor:
            line += f" [{dev.vendor}]"
        print(line)
        if dev.services and verbose:
            for svc in sorted(dev.services)[:8]:
                print(f"      {svc}")
        if dev.locations and verbose:
            for loc in sorted(dev.locations)[:3]:
                print(f"      {loc}")

    if store is not None:
        _persist(devices, store)
        success(f"multicast: wrote {len(devices)} device(s) to store")

    return devices


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="net.multicast",
        description="Multicast device discovery (mDNS, SSDP, WS-Discovery).",
    )
    p.add_argument("--protocol", action="append",
                   choices=["mdns", "ssdp", "wsd"],
                   help="limit to specific protocol(s); repeatable")
    p.add_argument("--duration", "-d", type=float, default=DEFAULT_DURATION,
                   help=f"collection window in seconds (default "
                        f"{DEFAULT_DURATION})")
    p.add_argument("--no-descriptions", action="store_true",
                   help="skip fetching XML device descriptions")
    p.add_argument("--store", action="store_true",
                   help="write findings to the active workspace")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    store = None
    workspace = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; "
                 "use `toolkit workspace switch <name>` first")
            return
        workspace = get_workspace(active)
        store = open_store(workspace.db_path, workspace_name=active)

    asyncio.run(run(
        store=store,
        workspace=workspace,
        duration=args.duration,
        protocols=args.protocol or None,
        fetch_descriptions=not args.no_descriptions,
        verbose=args.verbose,
    ))


if __name__ == "__main__":
    _cli()