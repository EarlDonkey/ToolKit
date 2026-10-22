"""
SNMP walker for network reconnaissance.

SNMP is the single highest-leverage reconnaissance protocol on a
corporate LAN. One query to a router can reveal:

    - Every host in its ARP cache (i.e. the whole /24 behind it)
    - All interfaces and their IPs
    - The routing table (next-hop IPs)
    - Device model, firmware, and vendor
    - Uptime and traffic counters

Almost all enterprise network gear (Cisco, Juniper, Fortinet, HP,
Ubiquiti, MikroTik, Dell iDRAC, HP iLO, printers) speaks SNMP v2c with
the read-only community 'public' still enabled by default. Vendors
have shipped it that way for 30 years and sysadmins rarely change it.

This module walks a target, pulls the interesting OIDs, and writes
everything to the store. Findings are:

    - 'snmp_default_community' when the community string is a
      well-known default (severity: high)
    - 'snmp_device' for each successfully identified device
      (severity: info)
    - 'open_port' for 161/udp (severity: info)

Usage:

    from net.snmp import walk, run
    result = await walk("172.16.11.1", communities=["public"])
    await run("172.16.11.1", store=store)

    # Or CLI:
    python -m net.snmp 172.16.11.1
    python -m net.snmp 172.16.11.0/24 --community-file wordlists/snmp.txt
"""

import asyncio
import ipaddress
import time
import warnings
from pathlib import Path

from core.output import info, success, warn, error

# pysnmp-lextudio (the maintained fork for Python 3.13+) emits a
# RuntimeWarning at import time saying "use upstream pysnmp instead."
# We can't — upstream doesn't support Python 3.14 yet. Silence it.
warnings.filterwarnings(
    "ignore",
    message=".*pysnmp-lextudio.*deprecated.*",
    category=RuntimeWarning,
)

# pysnmp has two API flavors. We prefer the asyncio variant because
# everything else in the toolkit is async.
try:
    from pysnmp.hlapi.asyncio import (
        getCmd, bulkCmd, SnmpEngine,
        CommunityData, UsmUserData,
        UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmDESPrivProtocol, usmAesCfb128Protocol,
        usmNoAuthProtocol, usmNoPrivProtocol,
    )
    _HAS_PYSNMP = True
    _PYSNMP_VARIANT = "hlapi.asyncio"
except ImportError:
    try:
        # Fallback to the lextudio fork's module layout
        from pysnmp.hlapi.v3arch.asyncio import (   # type: ignore
            getCmd, bulkCmd, SnmpEngine,
            CommunityData, UsmUserData,
            UdpTransportTarget, ContextData,
            ObjectType, ObjectIdentity,
            usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
            usmDESPrivProtocol, usmAesCfb128Protocol,
            usmNoAuthProtocol, usmNoPrivProtocol,
        )
        _HAS_PYSNMP = True
        _PYSNMP_VARIANT = "hlapi.v3arch.asyncio"
    except ImportError:
        _HAS_PYSNMP = False
        _PYSNMP_VARIANT = None


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

SNMP_PORT = 161

# Well-known community strings worth trying by default. Corporate gear
# almost always has 'public' (read-only) still enabled. 'private' is
# the write community historically, and vendors used their own name as
# the default read community.
DEFAULT_COMMUNITIES = [
    "public",
    "private",
    "cisco",
    "admin",
    "readonly",
    "read",
]

# OIDs we care about. Each entry is
#     (oid, human_label, postprocess_fn_or_None)
OIDS = {
    # -- System --
    "sysDescr":   ("1.3.6.1.2.1.1.1.0", "System description", None),
    "sysObjectID":("1.3.6.1.2.1.1.2.0", "System OID (vendor hint)", None),
    "sysUpTime":  ("1.3.6.1.2.1.1.3.0", "System uptime", None),
    "sysContact": ("1.3.6.1.2.1.1.4.0", "System contact", None),
    "sysName":    ("1.3.6.1.2.1.1.5.0", "System hostname", None),
    "sysLocation":("1.3.6.1.2.1.1.6.0", "System location", None),

    # -- Interfaces --
    "ifDescr":    ("1.3.6.1.2.1.2.2.1.2",  "Interface descriptions", None),
    "ifPhysAddr": ("1.3.6.1.2.1.2.2.1.6",  "Interface MAC addresses", None),
    "ifOperStatus":("1.3.6.1.2.1.2.2.1.8", "Interface operational status", None),
    "ifInOctets": ("1.3.6.1.2.1.2.2.1.10", "Interface RX bytes", None),
    "ifOutOctets":("1.3.6.1.2.1.2.2.1.16", "Interface TX bytes", None),

    # -- IP --
    "ipForwarding":("1.3.6.1.2.1.4.1.0",   "IP forwarding enabled", None),
    "ipAddrTable": ("1.3.6.1.2.1.4.20.1.1", "Interface IPv4 addresses", None),
    "ipNetToMedia":("1.3.6.1.2.1.4.22.1.2", "ARP cache — MACs", None),
    "ipNetToMediaIf":("1.3.6.1.2.1.4.22.1.1", "ARP cache — interfaces", None),
    "ipNetToMediaNet":("1.3.6.1.2.1.4.22.1.3", "ARP cache — IP addresses", None),

    # -- Routing --
    "ipRouteNextHop":("1.3.6.1.2.1.4.21.1.7", "Routing table next-hops", None),
    "ipRouteDest":  ("1.3.6.1.2.1.4.21.1.1", "Routing table destinations", None),
}


# Vendor hints for sysObjectID.
ENTERPRISE_VENDORS = {
    "9":     "Cisco",
    "311":   "Microsoft",
    "2021":  "HP",
    "11":    "HP (older)",
    "232":   "Compaq (HP)",
    "171":   "D-Link",
    "2636":  "Juniper",
    "12356": "Fortinet",
    "1588":  "F5 Networks",
    "6486":  "Alcatel-Lucent",
    "674":   "Dell",
    "6027":  "Force10 (Dell)",
    "8072":  "Net-SNMP (Linux hosts)",
    "890":   "NetApp",
    "1916":  "Extreme Networks",
    "1991":  "Arista",
    "2011":  "Huawei",
    "30065": "Arista",
    "14988": "MikroTik",
    "41112": "Ubiquiti",
    "12325": "Avaya",
    "4526":  "Netgear",
    "3955":  "Ricoh (printers)",
    "367":   "Ricoh",
    "641":   "Lexmark",
    "1602":  "Canon",
    "2435":  "Epson",
    "1248":  "Kyocera",
}


# ---------------------------------------------------------------------
# Transport construction (handles pysnmp API variants)
# ---------------------------------------------------------------------

async def _make_transport(ip, timeout, retries):
    """Build a UdpTransportTarget across pysnmp API variants.

    pysnmp has cycled through three constructor styles:

      4.x (upstream, old):
          UdpTransportTarget((ip, port), timeout=..., retries=...)   # callable

      5.x (upstream, newer):
          await UdpTransportTarget.create((ip, port), timeout=..., retries=...)

      6.x (lextudio fork):
          UdpTransportTarget((ip, port), timeout=..., retries=...)   # callable again

    This helper tries each in order. Returns the constructed transport.
    """
    target = (ip, SNMP_PORT)
    # Style 5.x — async factory
    if hasattr(UdpTransportTarget, "create"):
        try:
            return await UdpTransportTarget.create(
                target, timeout=timeout, retries=retries)
        except TypeError:
            # Some variants take timeout/retries positionally, or as
            # different kwargs. Fall through to the callable form.
            pass
    # Style 4.x / 6.x — callable constructor
    return UdpTransportTarget(
        target, timeout=timeout, retries=retries)


# ---------------------------------------------------------------------
# Low-level walks
# ---------------------------------------------------------------------

async def _walk_oid(ip, community, oid, timeout=2.0, retries=1,
                    max_rows=5000, verbose=False):
    """Walk an OID subtree using SNMP v2c bulk walk.

    Returns a list of (oid_str, value_str) tuples, or [] on failure.
    """
    if not _HAS_PYSNMP:
        return []

    results = []
    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=1)  # v2c
    try:
        transport = await _make_transport(ip, timeout, retries)
    except Exception as e:
        if verbose:
            warn(f"snmp: transport build failed for {ip}: "
                 f"{type(e).__name__}: {e}")
        return []
    context = ContextData()

    try:
        current_oid = oid
        rows = 0
        while rows < max_rows:
            error_indication, error_status, error_index, var_binds = \
                await bulkCmd(
                    engine, auth, transport, context,
                    0, 25,                              # non-repeaters, max-reps
                    ObjectType(ObjectIdentity(current_oid)),
                    lexicographicMode=False,            # stop at subtree end
                )
            if error_indication:
                if verbose:
                    warn(f"snmp: {ip} community={community!r} "
                         f"oid={oid} error: {error_indication}")
                return results
            if error_status:
                if verbose:
                    warn(f"snmp: {ip} community={community!r} "
                         f"oid={oid} status: "
                         f"{error_status.prettyPrint()}")
                return results
            if not var_binds:
                break

            got_any = False
            for name, value in var_binds:
                rows += 1
                results.append((str(name), str(value)))
                current_oid = str(name)
                got_any = True

            if not got_any:
                break
    except Exception as e:
        if verbose:
            warn(f"snmp: {ip} community={community!r} oid={oid} "
                 f"exception: {type(e).__name__}: {e}")
        return results
    finally:
        try:
            engine.transportDispatcher.closeDispatcher()  # type: ignore
        except Exception:
            pass

    return results


async def _snmp_get(ip, community, oid, timeout=2.0, retries=1):
    """Single SNMP GET. Returns a string value or None."""
    if not _HAS_PYSNMP:
        return None

    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=1)
    try:
        transport = await _make_transport(ip, timeout, retries)
    except Exception:
        return None
    context = ContextData()

    try:
        error_indication, error_status, error_index, var_binds = \
            await getCmd(engine, auth, transport, context,
                         ObjectType(ObjectIdentity(oid)))
        if error_indication or error_status:
            return None
        for name, value in var_binds:
            return str(value)
    except Exception:
        return None
    finally:
        try:
            engine.transportDispatcher.closeDispatcher()  # type: ignore
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------
# Community discovery
# ---------------------------------------------------------------------

async def _probe_community(ip, community, timeout=1.5, verbose=False):
    """Try one community string. Returns device info dict or None."""
    sysdescr = await _snmp_get(ip, community,
                                OIDS["sysDescr"][0], timeout=timeout)
    if not sysdescr:
        return None
    # sysDescr is the strongest "we're alive and this works" signal.
    # Populate the rest of the system group with individual GETs.
    system = {
        "sysDescr": sysdescr,
        "sysObjectID": await _snmp_get(ip, community,
                                        OIDS["sysObjectID"][0],
                                        timeout=timeout),
        "sysUpTime":   await _snmp_get(ip, community,
                                        OIDS["sysUpTime"][0],
                                        timeout=timeout),
        "sysContact":  await _snmp_get(ip, community,
                                        OIDS["sysContact"][0],
                                        timeout=timeout),
        "sysName":     await _snmp_get(ip, community,
                                        OIDS["sysName"][0],
                                        timeout=timeout),
        "sysLocation": await _snmp_get(ip, community,
                                        OIDS["sysLocation"][0],
                                        timeout=timeout),
    }
    system["community"] = community
    system["vendor_hint"] = _vendor_from_oid(system.get("sysObjectID"))
    if verbose:
        success(f"snmp: {ip} responded to community {community!r}: "
                f"{sysdescr[:60]}")
    return system


def _vendor_from_oid(oid_value):
    """Extract a vendor name from a sysObjectID like '1.3.6.1.4.1.9.1.1234'."""
    if not oid_value:
        return None
    parts = str(oid_value).strip(".").split(".")
    if len(parts) >= 7 and parts[0:6] == ["1", "3", "6", "1", "4", "1"]:
        enterprise = parts[6]
        return ENTERPRISE_VENDORS.get(enterprise)
    return None


# ---------------------------------------------------------------------
# Full walk
# ---------------------------------------------------------------------

async def walk(ip, communities=None, community_file=None, timeout=1.5,
               verbose=False, custom_oids=None, max_rows=5000):
    """Full SNMP reconnaissance against one IP.

    Order of community attempts:
        1. `communities` argument (list), if provided
        2. `community_file` contents, if provided
        3. DEFAULT_COMMUNITIES

    Returns a dict with system info, interfaces, ARP cache, routes.
    """
    if not _HAS_PYSNMP:
        return {
            "ip": ip, "community": None, "system": {},
            "errors": ["pysnmp not installed — pip install pysnmp-lextudio"],
        }

    # Build the community list
    candidates = []
    if communities:
        candidates.extend(communities)
    if community_file:
        try:
            lines = Path(community_file).read_text(
                encoding="utf-8", errors="ignore").splitlines()
            candidates.extend(l.strip() for l in lines
                              if l.strip() and not l.startswith("#"))
        except Exception as e:
            warn(f"snmp: could not read community file: {e}")
    if not candidates:
        candidates = list(DEFAULT_COMMUNITIES)
    # Dedup preserving order
    seen = set()
    candidates = [c for c in candidates
                  if not (c in seen or seen.add(c))]

    if verbose:
        info(f"snmp: trying {len(candidates)} community string(s) "
             f"against {ip}")

    # Phase 1: find a working community string
    working = None
    system = None
    for community in candidates:
        system = await _probe_community(ip, community, timeout=timeout,
                                        verbose=verbose)
        if system:
            working = community
            break

    if not working:
        return {
            "ip": ip,
            "community": None,
            "system": {},
            "errors": ["no working community string found"],
        }

    # Phase 2: walk the interesting OID trees with the working community
    result = {
        "ip": ip,
        "community": working,
        "system": system,
        "vendor_hint": system.get("vendor_hint"),
        "interfaces": [],
        "arp_cache": [],
        "interfaces_ip": [],
        "routes": [],
        "custom": {},
        "errors": [],
    }

    # --- Interfaces ---
    if_descr = await _walk_oid(ip, working, OIDS["ifDescr"][0],
                                timeout=timeout, max_rows=max_rows,
                                verbose=verbose)
    if_phys = await _walk_oid(ip, working, OIDS["ifPhysAddr"][0],
                               timeout=timeout, max_rows=max_rows,
                               verbose=verbose)
    if_oper = await _walk_oid(ip, working, OIDS["ifOperStatus"][0],
                               timeout=timeout, max_rows=max_rows,
                               verbose=verbose)

    def _index_by_oid(entries):
        out = {}
        for oid_str, val in entries:
            idx = oid_str.rsplit(".", 1)[-1]
            out[idx] = val
        return out

    descr_by_idx = _index_by_oid(if_descr)
    phys_by_idx = _index_by_oid(if_phys)
    oper_by_idx = _index_by_oid(if_oper)
    for idx in sorted(set(descr_by_idx) | set(phys_by_idx)):
        result["interfaces"].append({
            "index": idx,
            "descr": descr_by_idx.get(idx, ""),
            "mac":   phys_by_idx.get(idx, ""),
            "oper":  oper_by_idx.get(idx, ""),
        })

    # --- Interface IPs ---
    ips_raw = await _walk_oid(ip, working, OIDS["ipAddrTable"][0],
                               timeout=timeout, max_rows=max_rows,
                               verbose=verbose)
    for oid_str, val in ips_raw:
        result["interfaces_ip"].append(val)

    # --- ARP cache ---
    arp_mac = await _walk_oid(ip, working, OIDS["ipNetToMedia"][0],
                               timeout=timeout, max_rows=max_rows,
                               verbose=verbose)
    arp_if = await _walk_oid(ip, working, OIDS["ipNetToMediaIf"][0],
                              timeout=timeout, max_rows=max_rows,
                              verbose=verbose)
    arp_ip = await _walk_oid(ip, working, OIDS["ipNetToMediaNet"][0],
                              timeout=timeout, max_rows=max_rows,
                              verbose=verbose)

    def _arp_key(oid_str):
        parts = oid_str.rsplit(".", 5)
        if len(parts) < 6:
            return None
        try:
            if_idx = parts[-5]
            ip_parts = parts[-4:]
            ip = ".".join(ip_parts)
            return (if_idx, ip)
        except Exception:
            return None

    arp = {}
    for oid_str, mac in arp_mac:
        k = _arp_key(oid_str)
        if k:
            arp.setdefault(k, {})["mac"] = mac
    for oid_str, val in arp_if:
        k = _arp_key(oid_str)
        if k:
            arp.setdefault(k, {})["if_index"] = k[0]
    for oid_str, val in arp_ip:
        k = _arp_key(oid_str)
        if k:
            arp.setdefault(k, {})["ip"] = k[1]

    for k, v in arp.items():
        entry = {
            "if_index": k[0],
            "ip":       v.get("ip") or k[1],
            "mac":      v.get("mac", ""),
        }
        if entry["mac"] and entry["mac"].startswith(("01:", "ff:", "33:")):
            continue
        result["arp_cache"].append(entry)

    # --- Routing table ---
    route_dst = await _walk_oid(ip, working, OIDS["ipRouteDest"][0],
                                 timeout=timeout, max_rows=max_rows,
                                 verbose=verbose)
    route_hop = await _walk_oid(ip, working, OIDS["ipRouteNextHop"][0],
                                 timeout=timeout, max_rows=max_rows,
                                 verbose=verbose)
    hop_by_dst = {oid: val for oid, val in route_hop}
    for oid_str, dst in route_dst:
        hop = hop_by_dst.get(oid_str, "")
        result["routes"].append({"dest": dst, "next_hop": hop})

    # --- Custom OIDs ---
    if custom_oids:
        for oid in custom_oids:
            entries = await _walk_oid(ip, working, oid, timeout=timeout,
                                       max_rows=max_rows, verbose=verbose)
            result["custom"][oid] = [
                {"oid": o, "value": v} for o, v in entries
            ]

    return result


# ---------------------------------------------------------------------
# Store integration
# ---------------------------------------------------------------------

async def run(target, store=None, communities=None, community_file=None,
              timeout=1.5, verbose=False, custom_oids=None):
    """Walk one target (IP or CIDR) and persist findings to `store`."""
    if not _HAS_PYSNMP:
        error("pysnmp is not installed.")
        error("install with: py -3.14 -m pip install --user pysnmp-lextudio")
        return {}

    # Expand CIDR
    targets = []
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
            if len(hosts) > 4096:
                warn(f"capping {len(hosts)} hosts to 4096")
                hosts = hosts[:4096]
            targets = [str(h) for h in hosts]
        except Exception as e:
            error(f"invalid CIDR {target}: {e}")
            return {}
    else:
        targets = [target]

    info(f"snmp: walking {len(targets)} target(s) "
         f"with up to {len(communities or DEFAULT_COMMUNITIES)} "
         f"community string(s) each")

    results = {}
    # Sequential-ish with a small async concurrency cap so we don't
    # hammer a router with parallel SNMP queries (many rate-limit to
    # 1 req/s per source).
    sem = asyncio.Semaphore(4)

    async def _one(ip):
        async with sem:
            r = await walk(ip, communities=communities,
                           community_file=community_file,
                           timeout=timeout, verbose=verbose,
                           custom_oids=custom_oids)
            return ip, r

    tasks = [_one(ip) for ip in targets]
    for coro in asyncio.as_completed(tasks):
        ip, r = await coro
        results[ip] = r
        _report_one(ip, r, verbose=verbose)
        if store is not None:
            _persist(ip, r, store)

    # Summary
    responders = [ip for ip, r in results.items() if r.get("community")]
    print()
    if not responders:
        warn("snmp: no SNMP responders on any target")
    else:
        success(f"snmp: {len(responders)} device(s) responded")
        for ip in responders:
            r = results[ip]
            vendor = r.get("vendor_hint") or "?"
            name = r["system"].get("sysName") or "?"
            arp_count = len(r.get("arp_cache", []))
            print(f"  {ip:18s} community={r['community']:10s} "
                  f"vendor={vendor:12s} name={name:24s} "
                  f"arp={arp_count}")

    return results


def _report_one(ip, r, verbose=False):
    """Print a one-line summary as each device finishes."""
    if not r.get("community"):
        if verbose:
            warn(f"  {ip:18s} no SNMP response")
        return
    vendor = r.get("vendor_hint") or "?"
    name = r["system"].get("sysName") or "?"
    info(f"  {ip:18s} community={r['community']!r} "
         f"vendor={vendor} name={name!r}")


def _persist(ip, r, store):
    """Write findings and host/service records into the store."""
    if not r.get("community"):
        return

    community = r["community"]
    system = r.get("system") or {}
    vendor = r.get("vendor_hint") or ""

    # 1. Default community string finding (HIGH if well-known default)
    is_default = community in DEFAULT_COMMUNITIES
    severity = "high" if is_default else "info"
    store.add_finding({
        "module": "snmp",
        "type": "snmp_default_community" if is_default else "informational",
        "severity": severity,
        "target": ip,
        "port": SNMP_PORT,
        "evidence": (
            f"SNMP v2c responded to community string '{community}'"
            + (" (well-known default)" if is_default else "")
        ),
        "data": {
            "community": community,
            "is_default": is_default,
            "sysDescr": system.get("sysDescr"),
            "sysName": system.get("sysName"),
            "sysLocation": system.get("sysLocation"),
            "sysContact": system.get("sysContact"),
            "vendor_hint": vendor,
        },
    })

    # 2. Device identification finding
    store.add_finding({
        "module": "snmp",
        "type": "informational",
        "severity": "info",
        "target": ip,
        "port": SNMP_PORT,
        "evidence": (f"SNMP device: {system.get('sysDescr', 'unknown')} "
                     f"(vendor: {vendor or 'unknown'})"),
        "data": {
            "sysDescr": system.get("sysDescr"),
            "sysName": system.get("sysName"),
            "sysObjectID": system.get("sysObjectID"),
            "sysUpTime": system.get("sysUpTime"),
            "vendor_hint": vendor,
            "interfaces": r.get("interfaces", [])[:50],
            "arp_count": len(r.get("arp_cache", [])),
            "route_count": len(r.get("routes", [])),
        },
    })

    # 3. Host record
    store.upsert_host(
        ip,
        hostname=system.get("sysName") or None,
        discovery="snmp",
        tags=[f"vendor:{vendor}"] if vendor else [],
    )

    # 4. ARP cache → host records for every discovered neighbor.
    #    This is the big win: a router's ARP cache reveals the entire
    #    subnet behind it, which ICMP sweeps alone can miss.
    arp = r.get("arp_cache", [])
    if arp:
        for entry in arp:
            neighbor_ip = entry.get("ip")
            mac = entry.get("mac")
            if not neighbor_ip:
                continue
            existing = store.query_hosts(ip=neighbor_ip)
            if existing:
                continue
            store.upsert_host(
                neighbor_ip,
                mac=mac or None,
                discovery=f"snmp-arp ({ip})",
            )


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="net.snmp",
        description="SNMP walker for network reconnaissance.",
    )
    p.add_argument("target",
                   help="IP or CIDR to walk")
    p.add_argument("--community", action="append",
                   help="community string to try (repeatable). "
                        "If omitted, uses built-in defaults.")
    p.add_argument("--community-file",
                   help="file with one community string per line")
    p.add_argument("--timeout", type=float, default=1.5,
                   help="per-query timeout in seconds (default 1.5)")
    p.add_argument("--oid", action="append",
                   help="extra OID to walk (repeatable)")
    p.add_argument("--store", action="store_true",
                   help="write findings to the active workspace")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    store = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; "
                 "use `toolkit workspace switch <name>` first")
            return
        ws = get_workspace(active)
        store = open_store(ws.db_path, workspace_name=active)

    asyncio.run(run(
        args.target,
        store=store,
        communities=args.community,
        community_file=args.community_file,
        timeout=args.timeout,
        verbose=args.verbose,
        custom_oids=args.oid,
    ))


if __name__ == "__main__":
    _cli()