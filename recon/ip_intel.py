"""
IP intelligence aggregator.

Given a bare IP, run every applicable recon module and produce a
combined dossier:

  1. RDAP           — org, netblock, abuse contact, country
  2. ASN            — autonomous system, name, prefixes, upstreams
  3. Geo            — country, org, confidence, CDN detection
  4. PTR            — reverse DNS, current + historical
  5. TLS cert       — what cert the IP serves (if it speaks TLS)
  6. Ports          — top-100 TCP scan
  7. Services       — banner grabbing on any open ports
  8. Reverse IP     — other domains pointing at this IP
  9. Passive DNS    — historical hostnames seen resolving here

Design:

  - Each sub-module is called in isolation. If one fails, we continue.
  - Rate limiters are shared so we don't hammer any single upstream.
  - The result is a dict with a `summary` field (one-line human
    description) and a `sections` dict with the raw output of each
    sub-module.
  - Runs in ~15-30s for a normal IP, longer for targets with lots of
    open ports.

Usage:

    from recon.ip_intel import lookup

    result = await lookup("1.2.3.4")
    print(result["summary"])

    # CLI
    python -m recon.ip_intel 1.2.3.4
    python -m recon.ip_intel 1.2.3.4 -v
    python -m recon.ip_intel 1.2.3.4 --no-ports --store
"""

import asyncio
import time
from datetime import datetime, timezone

from core.http import new_session, RateLimiter
from core.output import info, success, warn
from core.target import parse


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Top 100 ports — we reuse the toolkit's existing list.
DEFAULT_TOP_PORTS = 100


# ---------------------------------------------------------------------
# Sub-module wrappers
# ---------------------------------------------------------------------

async def _rdap_and_asn(ip: str, session, verbose: bool) -> dict:
    """RDAP + ASN in one section (they overlap heavily)."""
    out = {"rdap": {}, "asn": {}, "errors": []}

    # RDAP via net.geo
    try:
        from net import geo
        rdap = await geo.rdap_lookup(ip, timeout=10.0)
        if rdap:
            out["rdap"] = rdap
    except Exception as e:
        out["errors"].append(f"rdap: {type(e).__name__}: {e}")

    # ASN via recon.asn
    try:
        from recon import asn
        asn_result = await asn.lookup(ip, verbose=verbose)
        out["asn"] = asn_result
    except Exception as e:
        out["errors"].append(f"asn: {type(e).__name__}: {e}")

    return out


async def _geo(ip: str, verbose: bool) -> dict:
    """Geolocation with confidence scoring."""
    try:
        from net import geo
        result = await geo.locate_ip(ip, verbose=verbose)
        return result or {}
    except Exception as e:
        return {"errors": [f"geo: {type(e).__name__}: {e}"]}


async def _ptr(ip: str) -> dict:
    """Reverse DNS via dnspython."""
    try:
        from recon import dns_util
        names = await dns_util.reverse_ptr(ip, timeout=5.0)
        return {"hostnames": names}
    except Exception as e:
        return {"hostnames": [], "error": f"{type(e).__name__}: {e}"}


async def _tls(ip: str, verbose: bool) -> dict:
    """TLS certificate grab."""
    try:
        from recon import tls_cert
        result = await tls_cert.grab(ip, verbose=verbose)
        return result or {}
    except Exception as e:
        return {"error": f"tls: {type(e).__name__}: {e}"}


async def _ports(ip: str, top: int, verbose: bool) -> dict:
    """TCP port scan via net.port_scanner."""
    try:
        from net.port_scanner import scan_hosts, _parse_ports
        ports = _parse_ports(None, top)
        result = await scan_hosts(
            [ip], ports, timeout=0.6,
            show_progress=False, verbose=verbose)
        open_ports = result.get(ip, [])
        return {"open_ports": open_ports, "ports_scanned": len(ports)}
    except Exception as e:
        return {"open_ports": [], "error": f"ports: {type(e).__name__}: {e}"}


async def _services(ip: str, open_ports: list[int],
                    verbose: bool) -> dict:
    """Service fingerprint on the open ports."""
    if not open_ports:
        return {"services": []}
    try:
        from net.service_fingerprint import fingerprint_host
        services = await fingerprint_host(
            ip, open_ports, timeout=3.0, verbose=verbose)
        return {"services": services}
    except Exception as e:
        return {"services": [], "error": f"services: {type(e).__name__}: {e}"}


async def _reverse_ip(ip: str, session, verbose: bool) -> dict:
    """Domains pointing at this IP."""
    try:
        from recon import reverse_ip
        result = await reverse_ip.lookup(
            ip, session=session, verbose=verbose)
        return result or {}
    except Exception as e:
        return {"domains": [], "error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------
# Passive DNS (best-effort, uses free sources)
# ---------------------------------------------------------------------

async def _passive_dns(ip: str, session, limiter,
                       verbose: bool) -> dict:
    """Historical hostnames for an IP.

    Sources:
      - URLScan's IP search (substring match — must be verified)

    Verification: URLScan's ``q=ip:1.2.3.4`` matches hostnames that
    merely *mention* the IP somewhere on the page. We resolve each
    candidate and keep only those whose current A record includes
    the target IP. Otherwise we return garbage like 73 hostnames
    for 127.0.0.1.
    """
    out = {"historical_hostnames": [], "sources": [], "errors": []}

    # ── SESSION R1 ── URLScan search + verification ──
    candidates = set()
    try:
        from core.http import fetch
        url = f"https://urlscan.io/api/v1/search/?q=ip:{ip}&size=100"
        r = await fetch(session, url, limiter, timeout=20.0,
                        headers={"Accept": "application/json"})
        if r and r[0] == 200 and r[2]:
            import json
            try:
                data = json.loads(r[2])
            except Exception:
                data = {}
            for row in data.get("results", []):
                page = row.get("page") or {}
                host = page.get("domain")
                if host:
                    candidates.add(host.lower())
            out["sources"].append("urlscan")
    except Exception as e:
        out["errors"].append(f"urlscan: {type(e).__name__}: {e}")

    # Verify each candidate actually resolves to `ip` right now.
    # Historical matches that no longer resolve are dropped — they're
    # technically "used to point here" but we can't confirm it, and
    # the false-positive rate on substring matches is high.
    if candidates:
        try:
            from core.dns import resolve_a
            verified = set()
            for host in candidates:
                try:
                    ips = await resolve_a(host)
                    if ip in ips:
                        verified.add(host)
                except Exception:
                    continue
            out["historical_hostnames"] = sorted(verified)
            if verbose:
                info(f"  passive dns: {len(candidates)} candidate(s), "
                     f"{len(verified)} verified")
        except Exception as e:
            out["errors"].append(f"verify: {type(e).__name__}: {e}")
            out["historical_hostnames"] = []
    # ── END SESSION R1 ──

    return out


# ---------------------------------------------------------------------
# CDN classification (used in summary)
# ---------------------------------------------------------------------

# Well-known anycast networks. When the IP is on one of these, the
# reverse-IP results are useless (they're the CDN's other customers)
# and the geo country is the CDN's HQ, not where the server is.
KNOWN_CDN_ASNS = {
    # ASN: (name, notes)
    13335: ("Cloudflare", "anycast — geo country is HQ, not server location"),
    20940: ("Akamai", "anycast — geo country is HQ, not server location"),
    54113: ("Fastly", "anycast — geo country is HQ, not server location"),
    16509: ("Amazon AWS", "cloud — check if region is authoritative"),
    14618: ("Amazon AWS", "cloud — check if region is authoritative"),
    15169: ("Google", "anycast — geo country is HQ, not server location"),
    396982: ("Google Cloud", "cloud — check if region is authoritative"),
    8075:  ("Microsoft Azure", "cloud — check if region is authoritative"),
    8068:  ("Microsoft", "cloud — check if region is authoritative"),
    12076: ("Microsoft", "cloud — check if region is authoritative"),
    14061: ("DigitalOcean", "cloud — check if region is authoritative"),
    63949: ("Linode", "cloud — check if region is authoritative"),
    20473: ("Vultr", "cloud — check if region is authoritative"),
    24940: ("Hetzner", "cloud — check if region is authoritative"),
    16276: ("OVH", "cloud — check if region is authoritative"),
    12876: ("Scaleway", "cloud — check if region is authoritative"),
    51167: ("Contabo", "cloud — check if region is authoritative"),
    45102: ("Alibaba Cloud", "cloud — check if region is authoritative"),
    37963: ("Alibaba Cloud", "cloud — check if region is authoritative"),
    55990: ("Huawei Cloud", "cloud — check if region is authoritative"),
}


def _cdn_classification(asn_section: dict) -> dict:
    """Return CDN/cloud classification if the IP's ASN is known."""
    asn = None
    asn_section = asn_section or {}
    if isinstance(asn_section.get("ip_info"), dict):
        asn = asn_section["ip_info"].get("asn")
    if asn is None and isinstance(asn_section.get("asn_info"), dict):
        asn = asn_section["asn_info"].get("asn")
    if asn is None and isinstance(asn_section.get("asn"), int):
        asn = asn_section["asn"]
    if asn is None:
        return {}
    info_ = KNOWN_CDN_ASNS.get(asn)
    if not info_:
        return {}
    return {"asn": asn, "provider": info_[0], "note": info_[1]}


# ---------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------

def _build_summary(ip: str, sections: dict) -> str:
    """One-line human description of what this IP is."""
    parts = []

    # Network ownership
    asn_section = sections.get("rdap_asn") or {}
    asn_info = asn_section.get("asn", {}) or {}
    ip_info = asn_info.get("ip_info") or {}
    a = asn_info.get("asn_info") or {}
    asn = a.get("asn") or ip_info.get("asn")
    if asn:
        holder = a.get("name") or ip_info.get("asn_name") or ""
        holder = holder.strip(", ")[:40]
        parts.append(f"AS{asn}" + (f" ({holder})" if holder else ""))

    # Country
    geo_section = sections.get("geo") or {}
    country = geo_section.get("country_name") or geo_section.get("country")
    if country:
        parts.append(country)

    # Reverse-IP count
    reverse_section = sections.get("reverse_ip") or {}
    n_rev = len(reverse_section.get("domains") or [])
    if n_rev:
        parts.append(f"{n_rev} domain(s) share this IP")

    # Open ports
    ports_section = sections.get("ports") or {}
    open_ports = ports_section.get("open_ports") or []
    if open_ports:
        preview = ", ".join(str(p) for p in open_ports[:5])
        if len(open_ports) > 5:
            preview += f", +{len(open_ports) - 5}"
        parts.append(f"ports: {preview}")

    # TLS CN
    tls_section = sections.get("tls") or {}
    tls_cn = tls_section.get("subject_cn")
    if tls_cn:
        parts.append(f"TLS CN: {tls_cn}")

    return " | ".join(parts) if parts else "no useful signals"


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def lookup(ip: str, verbose: bool = False,
                 include_ports: bool = True,
                 include_reverse: bool = True,
                 top_ports: int = DEFAULT_TOP_PORTS,
                 session=None) -> dict:
    """Gather intelligence on a bare IP.

    Returns a dict with these top-level keys:
      - target            the input string
      - kind              always "ip" for this module
      - summary           one-line human description
      - sections          the raw output of each sub-module
      - errors            any sub-module that failed
      - elapsed           seconds
    """
    t = parse(ip)
    if not t.is_ip:
        raise ValueError(f"ip_intel: not an IP: {ip!r}")
    ip = t.host
    
    # ── SESSION R1 ── Non-routable IP short-circuit ──
    # RDAP, ASN, passive DNS, reverse IP, and TLS all assume a real
    # routable IP. For loopback, RFC1918, link-local, multicast, and
    # reserved ranges, every one of those queries wastes time and
    # produces garbage. Skip them all and return an honest result.
    try:
        from net.geo import _ip_special_category
        special = _ip_special_category(ip)
    except Exception:
        special = None

    if special:
        if verbose:
            info(f"ip_intel: {ip} is {special}; skipping network queries")
        return {
            "target": ip,
            "kind": "ip",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "summary": f"non-routable ({special}) — no registry data",
            "sections": {"special": special},
            "errors": [],
            "elapsed": 0.0,
        }

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(rate=5.0)

    start = time.time()
    result = {
        "target": ip,
        "kind": "ip",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "summary": "",
        "sections": {},
        "errors": [],
        "elapsed": 0.0,
    }
    sections = result["sections"]

    info(f"ip_intel: gathering intel on {ip}")

    try:
        # --- Phase 1: fast, offline-ish queries in parallel ---
        # RDAP + ASN + geo + PTR + TLS can all happen concurrently.
        info("  phase 1/3: rdap, asn, geo, ptr, tls")
        rdap_asn_task = _rdap_and_asn(ip, session, verbose)
        geo_task = _geo(ip, verbose)
        ptr_task = _ptr(ip)
        tls_task = _tls(ip, verbose)

        rdap_asn, geo, ptr, tls = await asyncio.gather(
            rdap_asn_task, geo_task, ptr_task, tls_task,
            return_exceptions=True)

        sections["rdap_asn"] = rdap_asn if isinstance(rdap_asn, dict) else {}
        sections["geo"] = geo if isinstance(geo, dict) else {}
        sections["ptr"] = ptr if isinstance(ptr, dict) else {}
        sections["tls"] = tls if isinstance(tls, dict) else {}

        for name, value in (("rdap_asn", rdap_asn), ("geo", geo),
                            ("ptr", ptr), ("tls", tls)):
            if isinstance(value, Exception):
                result["errors"].append(f"{name}: {value!r}")

        # --- Phase 2: reverse IP + passive DNS in parallel ---
        info("  phase 2/3: reverse ip, passive dns")
        rev_task = (_reverse_ip(ip, session, verbose)
                    if include_reverse else _noop())
        pdns_task = _passive_dns(ip, session, limiter, verbose)

        rev, pdns = await asyncio.gather(
            rev_task, pdns_task, return_exceptions=True)

        sections["reverse_ip"] = rev if isinstance(rev, dict) else {}
        sections["passive_dns"] = pdns if isinstance(pdns, dict) else {}

        for name, value in (("reverse_ip", rev), ("passive_dns", pdns)):
            if isinstance(value, Exception):
                result["errors"].append(f"{name}: {value!r}")

        # --- Phase 3: port scan + service fingerprint ---
        if include_ports:
            info(f"  phase 3/3: port scan (top {top_ports})")
            ports = await _ports(ip, top_ports, verbose)
            sections["ports"] = ports
            open_ports = ports.get("open_ports") or []
            if open_ports:
                info(f"    {len(open_ports)} open port(s); fingerprinting")
                services = await _services(ip, open_ports, verbose)
                sections["services"] = services
            else:
                sections["services"] = {"services": []}
        else:
            sections["ports"] = {"open_ports": [], "skipped": True}
            sections["services"] = {"services": [], "skipped": True}

        # --- Summary + CDN classification ---
        result["summary"] = _build_summary(ip, sections)
        cdn = _cdn_classification(sections.get("rdap_asn") or {})
        if cdn:
            sections["cdn_classification"] = cdn

        result["elapsed"] = round(time.time() - start, 2)
        return result
    finally:
        if own_session:
            await session.close()


async def _noop():
    return {}


# ---------------------------------------------------------------------
# Store integration
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
              include_ports: bool = True,
              include_reverse: bool = True,
              top_ports: int = DEFAULT_TOP_PORTS) -> dict:
    """CLI entry. Writes findings to store if provided."""
    result = await lookup(
        target, verbose=verbose,
        include_ports=include_ports,
        include_reverse=include_reverse,
        top_ports=top_ports)
    ip = result["target"]
    print()
    success(f"ip_intel: {result['target']} ({result['elapsed']}s)")
    info(f"  summary: {result['summary']}")

    sections = result["sections"]

    # --- RDAP + ASN ---
    rdap = (sections.get("rdap_asn") or {}).get("rdap") or {}
    if rdap:
        info("  rdap:")
        for k in ("handle", "name", "org", "country", "type"):
            v = rdap.get(k)
            if v:
                print(f"    {k:10s} {v}")
        for email in rdap.get("emails") or []:
            print(f"    email      {email}")

    asn_block = (sections.get("rdap_asn") or {}).get("asn") or {}
    ip_info = asn_block.get("ip_info") or {}
    asn_info = asn_block.get("asn_info") or {}
    asn = asn_info.get("asn") or ip_info.get("asn")
    if asn:
        name = asn_info.get("name") or ip_info.get("asn_name") or ""
        info(f"  asn: AS{asn} {name}")
        prefix = ip_info.get("prefix")
        if prefix:
            print(f"    prefix     {prefix}")
        country = asn_info.get("country") or ip_info.get("asn_country")
        if country:
            print(f"    country    {country}")

    # --- Geo ---
    geo = sections.get("geo") or {}
    if geo.get("country_name"):
        info(f"  geo: {geo['country_name']} "
             f"({geo.get('confidence', '?')})")
        if geo.get("org"):
            print(f"    org        {geo['org']}")
        if geo.get("justification"):
            print(f"    basis      {geo['justification']}")

    # --- CDN classification ---
    cdn = sections.get("cdn_classification")
    if cdn:
        warn(f"  CDN/cloud: {cdn['provider']} (AS{cdn['asn']})")
        warn(f"    {cdn['note']}")

    # --- PTR ---
    ptr = sections.get("ptr") or {}
    if ptr.get("hostnames"):
        info(f"  reverse dns: {', '.join(ptr['hostnames'])}")

    # --- TLS ---
    tls = sections.get("tls") or {}
    if tls.get("subject_cn"):
        info(f"  tls: CN={tls['subject_cn']} "
             f"issuer={tls.get('issuer_cn')}")
        sans = tls.get("sans") or []
        if sans:
            limit = None if verbose else 20
            shown = sans if limit is None else sans[:limit]
            for s in shown:
                print(f"    SAN: {s}")
            if limit is not None and len(sans) > limit:
                print(f"    ... and {len(sans) - limit} more")

    # --- Ports ---
    ports = (sections.get("ports") or {}).get("open_ports") or []
    if ports:
        success(f"  {len(ports)} open TCP port(s): "
                f"{', '.join(str(p) for p in ports)}")
    elif not (sections.get("ports") or {}).get("skipped"):
        info("  no open TCP ports in top list")

    # --- Services ---
    services = (sections.get("services") or {}).get("services") or []
    if services:
        info(f"  {len(services)} service(s):")
        for svc in services:
            version = f" {svc.get('version')}" if svc.get("version") else ""
            title = f" — {svc.get('title')}" if svc.get("title") else ""
            print(f"    {svc.get('port'):<6} {svc.get('service')}"
                  f"{version}{title}")

    # --- Reverse IP ---
    rev = sections.get("reverse_ip") or {}
    domains = rev.get("domains") or []
    if domains:
        success(f"  reverse IP: {len(domains)} domain(s)")
        limit = None if verbose else 30
        shown = domains if limit is None else domains[:limit]
        for d in shown:
            print(f"    {d}")
        if limit is not None and len(domains) > limit:
            info(f"    ... and {len(domains) - limit} more (use -v for all)")

    # --- Passive DNS ---
    pdns = sections.get("passive_dns") or {}
    hosts = pdns.get("historical_hostnames") or []
    if hosts:
        success(f"  passive DNS: {len(hosts)} historical hostname(s)")
        limit = None if verbose else 20
        shown = hosts if limit is None else hosts[:limit]
        for h in shown:
            print(f"    {h}")
        if limit is not None and len(hosts) > limit:
            info(f"    ... and {len(hosts) - limit} more (use -v for all)")

    if result["errors"]:
        for e in result["errors"]:
            warn(f"  {e}")

    # --- Store ---
    if store is not None:
        store.add_finding({
            "module": "ip_intel",
            "type": "informational",
            "severity": "info",
            "target": result["target"],
            "evidence": result["summary"],
            "data": result,
        })
        # Also register discovered hostnames as hosts
        try:
            for d in domains:
                store.upsert_host(
                    ip=d, hostname=d,
                    discovery=f"reverse_ip ({ip})",
                    tags=["reverse-ip"],
                )
            for h in hosts:
                store.upsert_host(
                    ip=h, hostname=h,
                    discovery="passive-dns",
                    tags=["passive-dns"],
                )
            for s in (tls.get("sans") or []):
                if s and "." in s and not s.startswith("*"):
                    store.upsert_host(
                        ip=s, hostname=s,
                        discovery=f"tls-cert ({ip})",
                        tags=["san"],
                    )
        except Exception:
            pass
        success("finding written to store")

    return result


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.ip_intel",
        description="Full IP intelligence dossier.",
    )
    p.add_argument("target", help="IP address")
    p.add_argument("--no-ports", action="store_true",
                   help="skip the TCP port scan")
    p.add_argument("--no-reverse", action="store_true",
                   help="skip reverse-IP lookup")
    p.add_argument("--top-ports", type=int, default=DEFAULT_TOP_PORTS,
                   help=f"number of top ports to scan (default "
                        f"{DEFAULT_TOP_PORTS})")
    p.add_argument("--store", action="store_true",
                   help="write finding to active workspace")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="uncap all display limits and show internal "
                        "progress from sub-modules")
    args = p.parse_args()

    store = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; use `toolkit workspace switch`")
        else:
            ws = get_workspace(active)
            store = open_store(ws.db_path, workspace_name=active)

    asyncio.run(run(
        args.target, store=store, verbose=args.verbose,
        include_ports=not args.no_ports,
        include_reverse=not args.no_reverse,
        top_ports=args.top_ports))


if __name__ == "__main__":
    _cli()