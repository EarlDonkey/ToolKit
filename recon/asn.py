"""
ASN / BGP / netblock intelligence.

Given an IP, hostname, or ASN, reports:

  - Autonomous System number + name
  - All netblocks (CIDRs) announced by that AS
  - Upstream ASNs (peering relationships)
  - RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC)

Data sources, tried in order:

  1. RIPE Stat (stat.ripe.net) — free, no key, HTTPS, reliable
  2. Team Cymru (DNS-based)    — works when HTTPS is blocked

The bgpview.io API used in an earlier version is dead — their API
subdomain no longer resolves. RIPE Stat is a suitable replacement.

Findings written to the store:
    one row per target with AS + netblock info in `data`
"""

import asyncio
import ipaddress
import json
import re
import socket
from urllib.parse import quote

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


# RIPE Stat endpoints — all free, no API key
RIPE_PREFIX = "https://stat.ripe.net/data/prefix-overview/data.json"
RIPE_AS_OVERVIEW = "https://stat.ripe.net/data/as-overview/data.json"
RIPE_ANNOUNCED = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_NEIGHBOURS = "https://stat.ripe.net/data/asn-neighbours/data.json"

# Team Cymru DNS whois — no HTTP, uses DNS TXT records
CYMRU_IP_ORIGIN = "{reversed_ip}.origin.asn.cymru.com"
CYMRU_AS_NAME = "{asn}.asn.cymru.com"


# ---------------------------------------------------------------------
# Target classification
# ---------------------------------------------------------------------

def _classify_target(target: str) -> tuple[str, str]:
    """Return (kind, value) where kind is 'ip', 'asn', or 'domain'."""
    m = re.match(r"^(?:as)?(\d+)$", target.strip(), re.IGNORECASE)
    if m:
        return "asn", m.group(1)

    try:
        ipaddress.ip_address(target)
        return "ip", target
    except Exception:
        pass

    return "domain", target


async def _resolve_to_ip(target: str) -> str | None:
    """Resolve a hostname to its first A record."""
    try:
        from core.dns import resolve_a
        ips = await resolve_a(target)
        return ips[0] if ips else None
    except Exception:
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None


# ---------------------------------------------------------------------
# RIPE Stat API
# ---------------------------------------------------------------------

async def _ripe_get(base_url: str, resource: str, session, limiter,
                     verbose=False) -> dict | None:
    """GET a RIPE Stat endpoint. Returns the `.data` block or None."""
    url = f"{base_url}?resource={quote(resource)}"
    try:
        status, _headers, body, _ = await fetch(session, url, limiter,
                                                  timeout=20.0)
    except Exception as e:
        if verbose:
            warn(f"RIPE request failed ({base_url}): "
                 f"{type(e).__name__}: {e}")
        return None
    if status != 200 or not body:
        if verbose:
            warn(f"RIPE returned status={status} for {url}")
        return None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        if verbose:
            warn(f"RIPE returned invalid JSON for {url}")
        return None
    if payload.get("status") != "ok":
        if verbose:
            warn(f"RIPE status: {payload.get('status')} for {url}")
        return None
    return payload.get("data") or {}


async def lookup_ip_via_ripe(ip: str, session, limiter,
                              verbose=False) -> dict:
    """Get AS + prefix info for an IP from RIPE Stat."""
    data = await _ripe_get(RIPE_PREFIX, ip, session, limiter,
                            verbose=verbose)
    if not data:
        return {}

    out = {
        "ip": ip,
        "asn": None,
        "asn_name": None,
        "asn_description": None,
        "asn_country": None,
        "prefix": None,
        "prefix_name": None,
        "is_announced": data.get("announced", False),
        "is_less_specific": data.get("is_less_specific", False),
    }

    asns = data.get("asns") or []
    if asns:
        a = asns[0]
        out["asn"] = a.get("asn")
        out["asn_name"] = a.get("holder")
        out["asn_description"] = a.get("holder")
        out["asn_country"] = a.get("country")

    # The prefix itself is at data["resource"] (the resolved resource)
    out["prefix"] = data.get("resource") or ip
    out["prefix_name"] = data.get("block") or out["prefix"]

    return out


async def lookup_asn_via_ripe(asn: str, session, limiter,
                               verbose=False) -> dict:
    """Get AS details, prefixes, and upstreams from RIPE Stat."""
    asn_str = f"AS{asn.lstrip('AS').lstrip('as')}"

    # RIPE doesn't support asyncio.gather directly through our fetch
    # wrapper, so we do sequential calls. That's fine — 3 requests,
    # each ~200ms.
    overview = await _ripe_get(RIPE_AS_OVERVIEW, asn_str, session, limiter,
                                verbose=verbose)
    prefixes = await _ripe_get(RIPE_ANNOUNCED, asn_str, session, limiter,
                                verbose=verbose)
    neighbours = await _ripe_get(RIPE_NEIGHBOURS, asn_str, session, limiter,
                                  verbose=verbose)

    out = {
        "asn": int(asn.lstrip("AS").lstrip("as")),
        "name": None,
        "description": None,
        "country": None,
        "rir": None,
        "prefixes_v4": [],
        "prefixes_v6": [],
        "upstreams": [],
    }

    if overview:
        out["name"] = overview.get("holder") or overview.get("name")
        out["description"] = overview.get("holder")
        out["country"] = overview.get("country")
        # RIPE Stat doesn't directly expose RIR; leave None

    if prefixes:
        for p in prefixes.get("prefixes") or []:
            prefix_str = p.get("prefix", "")
            timeline = p.get("timelines") or []
            if ":" in prefix_str:
                out["prefixes_v6"].append({"prefix": prefix_str})
            else:
                out["prefixes_v4"].append({
                    "prefix": prefix_str,
                    "name": "",
                    "description": "",
                })

    if neighbours:
        for n in neighbours.get("neighbours") or []:
            # RIPE gives type: "left" (upstream) / "right" (downstream) /
            # "uncertain". We only want upstreams (left).
            if n.get("type") == "left":
                out["upstreams"].append({
                    "asn": n.get("asn"),
                    "name": None,
                    "description": None,
                    "country": n.get("country"),
                    "power": n.get("power"),
                })

    return out


# ---------------------------------------------------------------------
# Team Cymru fallback (DNS-based, no HTTP)
# ---------------------------------------------------------------------

def _cymru_lookup_ip(ip: str, timeout: float = 5.0) -> dict:
    """Query Team Cymru's DNS whois for an IP. Blocking; call in executor."""
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return {}

    if addr.version == 4:
        octets = str(addr).split(".")
        rev = ".".join(reversed(octets))
        domain = f"{rev}.origin.asn.cymru.com"
    else:
        import binascii
        packed = binascii.hexlify(addr.packed).decode("ascii")
        rev = ".".join(reversed(packed))
        domain = f"{rev}.origin6.asn.cymru.com"

    # Use system nslookup — cross-platform
    try:
        import subprocess
        out = subprocess.run(
            ["nslookup", "-type=TXT", domain],
            capture_output=True, text=True, timeout=timeout,
        )
        text = out.stdout
    except Exception:
        return {}

    # Response format: "15169 | 8.8.8.0/24 | US | arin | 2014-03-28"
    m = re.search(r'"(\d+)\s*\|\s*([^\s|]+)\s*\|\s*([A-Z]{2})\s*\|\s*([^\s|]+)',
                  text)
    if not m:
        return {}
    return {
        "asn": int(m.group(1)),
        "prefix": m.group(2).strip(),
        "country": m.group(3).strip(),
        "rir": m.group(4).strip(),
        "source": "team-cymru",
    }


def _cymru_lookup_asn(asn: int, timeout: float = 5.0) -> dict:
    """Query Team Cymru for an ASN's name."""
    domain = f"AS{asn}.asn.cymru.com"
    try:
        import subprocess
        out = subprocess.run(
            ["nslookup", "-type=TXT", domain],
            capture_output=True, text=True, timeout=timeout,
        )
        text = out.stdout
    except Exception:
        return {}

    # Response format: "15169 | US | arin | 2000-03-30 | GOOGLE, US"
    m = re.search(r'"(\d+)\s*\|\s*([A-Z]{2})\s*\|\s*([^\s|]+)\s*\|\s*([^\s|]+)\s*\|\s*(.+)"',
                  text)
    if not m:
        return {}
    return {
        "name": m.group(5).strip(),
        "country": m.group(2).strip(),
        "rir": m.group(3).strip(),
        "source": "team-cymru",
    }


async def lookup_ip_via_cymru(ip: str, verbose=False) -> dict:
    """Async wrapper around the DNS-based IP lookup."""
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, _cymru_lookup_ip, ip)
        # Also fetch the AS name
        if result.get("asn"):
            asn_info = await asyncio.get_event_loop().run_in_executor(
                None, _cymru_lookup_asn, result["asn"])
            result["asn_name"] = asn_info.get("name")
            result["asn_description"] = asn_info.get("name")
        return result
    except Exception as e:
        if verbose:
            warn(f"cymru lookup failed: {type(e).__name__}: {e}")
        return {}


# ---------------------------------------------------------------------
# Combined IP lookup (RIPE primary, Cymru fallback)
# ---------------------------------------------------------------------

async def lookup_ip(ip: str, session=None, verbose=False) -> dict:
    """Full AS + prefix info for an IP. Tries RIPE, falls back to Cymru."""
    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(3.0)

    try:
        result = await lookup_ip_via_ripe(ip, session, limiter,
                                            verbose=verbose)
        if result.get("asn"):
            # Enrich with full AS details
            asn_details = await lookup_asn_via_ripe(
                str(result["asn"]), session, limiter, verbose=verbose)
            result["asn_details"] = asn_details
            return result
    finally:
        if own_session:
            await session.close()

    if verbose:
        warn(f"RIPE returned no ASN for {ip}; trying Team Cymru")
    cymru = await lookup_ip_via_cymru(ip, verbose=verbose)
    if cymru:
        cymru["ip"] = ip
        return cymru
    return {"ip": ip, "asn": None, "errors": ["no ASN data available"]}


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def lookup(target: str, session=None, verbose=False) -> dict:
    """ASN intelligence for an IP, hostname, or ASN."""
    # Normalize via core.target so URLs and host:port inputs work.
    from core.target import parse as _parse_target
    try:
        t = _parse_target(target)
    except ValueError:
        t = None

    if t is not None:
        if t.kind == "asn":
            kind, value = "asn", str(t.asn)
        elif t.is_ip:
            kind, value = "ip", t.host
        else:
            kind, value = "domain", t.registrable or t.host
    else:
        kind, value = _classify_target(target)
    result = {
        "target": target,
        "kind": kind,
        "resolved_ip": None,
        "ip_info": {},
        "asn_info": {},
        "errors": [],
    }

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(3.0)

    try:
        if kind == "asn":
            info(f"looking up AS{value}")
            result["asn_info"] = await lookup_asn_via_ripe(
                value, session, limiter, verbose=verbose)

        elif kind == "ip":
            info(f"looking up AS for {value}")
            result["ip_info"] = await lookup_ip(
                value, session=session, verbose=verbose)
            if result["ip_info"].get("asn_details"):
                result["asn_info"] = result["ip_info"]["asn_details"]
            elif result["ip_info"].get("asn"):
                result["asn_info"] = await lookup_asn_via_ripe(
                    str(result["ip_info"]["asn"]), session, limiter,
                    verbose=verbose)

        else:  # domain
            info(f"resolving {value}")
            ip = await _resolve_to_ip(value)
            if not ip:
                result["errors"].append("could not resolve domain")
                return result
            result["resolved_ip"] = ip
            result["ip_info"] = await lookup_ip(
                ip, session=session, verbose=verbose)
            if result["ip_info"].get("asn_details"):
                result["asn_info"] = result["ip_info"]["asn_details"]
            elif result["ip_info"].get("asn"):
                result["asn_info"] = await lookup_asn_via_ripe(
                    str(result["ip_info"]["asn"]), session, limiter,
                    verbose=verbose)
    finally:
        if own_session:
            await session.close()

    return result


# ---------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose=False) -> dict:
    """CLI entry. Writes finding to store if provided."""
    result = await lookup(target, verbose=verbose)

    print()
    _print_result(result, verbose=verbose)

    if store is not None:
        ip_info = result.get("ip_info") or {}
        asn_info = result.get("asn_info") or {}
        pieces = []
        if asn_info.get("asn"):
            pieces.append(f"AS{asn_info['asn']}")
        if asn_info.get("name"):
            pieces.append(asn_info["name"])
        if ip_info.get("prefix"):
            pieces.append(ip_info["prefix"])
        store.add_finding({
            "module": "asn",
            "type": "informational",
            "severity": "info",
            "target": target,
            "evidence": " / ".join(pieces) or "no ASN data",
            "data": result,
        })
        success(f"finding written to store")

    return result


def _print_result(result: dict, verbose=False):
    kind = result["kind"]

    if result["errors"]:
        for e in result["errors"]:
            warn(f"  {e}")

    if kind == "asn":
        asn = result["asn_info"]
        if not asn:
            warn(f"no data for AS{result['target']}")
            return
        success(f"AS{asn.get('asn')} — {asn.get('name') or '?'}")
        if asn.get("description"):
            print(f"  description: {asn['description']}")
        if asn.get("country"):
            print(f"  country:     {asn['country']}")
        if asn.get("rir"):
            print(f"  rir:         {asn['rir']}")

        if asn.get("prefixes_v4"):
            print()
            print(f"  IPv4 prefixes ({len(asn['prefixes_v4'])}):")
            for p in asn["prefixes_v4"][:20]:
                print(f"    {p['prefix']}")
            if len(asn["prefixes_v4"]) > 20:
                print(f"    ... and {len(asn['prefixes_v4']) - 20} more")

        if asn.get("upstreams"):
            print()
            print(f"  Upstreams ({len(asn['upstreams'])}):")
            for u in asn["upstreams"][:10]:
                name = u.get("name") or u.get("description") or ""
                upstream_asn = u.get("asn")
                # RIPE can return upstreams with a null ASN.
                if upstream_asn is None:
                    asn_label = "AS?"
                else:
                    asn_label = f"AS{upstream_asn}"
                print(f"    {asn_label:<10} {name}")
        return

    # IP or domain — show IP info then AS details
    ip_info = result.get("ip_info") or {}
    if not ip_info or not ip_info.get("asn"):
        warn(f"no ASN data for {result['target']}")
        return

    if kind == "domain" and result.get("resolved_ip"):
        # Use the hostname, not the raw input (which may be a URL)
        display = result.get("target", "?")
        if display.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            display = urlparse(display).hostname or display
        info(f"resolved {display} → {result['resolved_ip']}")

    holder = ip_info.get("asn_name") or ip_info.get("asn_description") or ""
    success(f"{ip_info.get('ip', result['target'])} — "
            f"AS{ip_info['asn']} {holder}")
    if ip_info.get("asn_country"):
        print(f"  country:     {ip_info['asn_country']}")
    if ip_info.get("prefix"):
        print(f"  prefix:      {ip_info['prefix']}")
    if ip_info.get("rir"):
        print(f"  rir:         {ip_info['rir']}")
    if ip_info.get("source"):
        print(f"  source:      {ip_info['source']}")

    asn = result.get("asn_info") or {}
    if asn.get("prefixes_v4"):
        print()
        print(f"  Other prefixes announced by AS{asn.get('asn')} "
              f"({len(asn['prefixes_v4'])}):")
        for p in asn["prefixes_v4"][:15]:
            print(f"    {p['prefix']}")
        if len(asn["prefixes_v4"]) > 15:
            print(f"    ... and {len(asn['prefixes_v4']) - 15} more")


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.asn",
        description="ASN / BGP / netblock intelligence.",
    )
    p.add_argument("target",
                   help="IP, domain, or ASN (e.g. '8.8.8.8', 'as13335')")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--store", action="store_true",
                   help="write finding to active workspace")
    args = p.parse_args()

    store = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; use `toolkit workspace switch`")
            return
        ws = get_workspace(active)
        store = open_store(ws.db_path, workspace_name=active)

    asyncio.run(run(args.target, store=store, verbose=args.verbose))


if __name__ == "__main__":
    _cli()