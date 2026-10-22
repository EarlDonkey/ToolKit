"""
WHOIS + RDAP + reverse lookup.

Combines three sources of registry data:

  1. Classic WHOIS on TCP/43 — domain registration intel
       - Registrant / admin / tech contacts
       - Registration / expiry / last-update dates
       - Name servers, registrar, status codes

  2. RDAP over HTTPS — IP ownership intel (delegated to net.geo)
       - Org, netblock, ASN, address

  3. Reverse WHOIS via ViewDNS.info — "what else did this registrant
     register?"
       - Free tier, rate-limited to ~10/day
       - Best-effort: warn and skip if rate-limited

Findings written to the store:
    one row per target with the full WHOIS dossier in `data`
"""

import asyncio
import re
import socket
from datetime import datetime, timezone
from urllib.parse import quote

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

WHOIS_PORT = 43
WHOIS_TIMEOUT = 6.0

# IANA's whois server assignment list. We look up the correct server
# for a TLD by querying whois.iana.org once. Cached for the session.
_WHOIS_SERVER_CACHE: dict[str, str] = {}

# Common registrar redactions — when the WHOIS record has been scrubbed
# by a privacy proxy, the fields look like these. We detect and warn.
REDACTION_MARKERS = [
    "redacted for privacy",
    "privacy service",
    "data protected",
    "not disclosed",
    "withheld for privacy",
    "whoisguard",
    "domains by proxy",
    "perfect privacy",
    "contact privacy",
    "statutory masking",
    "gdpr",
]

# Reverse WHOIS providers
VIEWDNS_URL = "https://viewdns.info/reversewhois/?q={query}"


# ---------------------------------------------------------------------
# Classic WHOIS (TCP/43)
# ---------------------------------------------------------------------

def _find_whois_server(tld: str) -> str | None:
    """Look up the correct WHOIS server for a TLD via IANA."""
    tld = tld.lower().lstrip(".")
    if tld in _WHOIS_SERVER_CACHE:
        return _WHOIS_SERVER_CACHE[tld]

    try:
        s = socket.create_connection(("whois.iana.org", WHOIS_PORT),
                                      timeout=WHOIS_TIMEOUT)
        s.sendall((tld + "\r\n").encode("ascii"))
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
        s.close()
        text = b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception:
        return None

    # IANA's response contains a line like "whois: whois.verisign-grs.com"
    m = re.search(r"^whois:\s*(\S+)", text, re.MULTILINE | re.IGNORECASE)
    if m:
        server = m.group(1).strip()
        _WHOIS_SERVER_CACHE[tld] = server
        return server

    # Fallback — hardcoded known servers
    fallback = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "edu": "whois.educause.edu",
        "gov": "whois.nic.gov",
        "io":  "whois.nic.io",
        "tw":  "whois.twnic.net.tw",
        "cn":  "whois.cnnic.cn",
        "jp":  "whois.jprs.jp",
        "uk":  "whois.nic.uk",
        "de":  "whois.denic.de",
        "fr":  "whois.nic.fr",
    }
    if tld in fallback:
        _WHOIS_SERVER_CACHE[tld] = fallback[tld]
        return fallback[tld]
    return None


def _whois_query_sync(server: str, query: str) -> str:
    """Blocking whois query on port 43."""
    try:
        s = socket.create_connection((server, WHOIS_PORT),
                                      timeout=WHOIS_TIMEOUT)
        s.sendall((query + "\r\n").encode("ascii", errors="ignore"))
        chunks = []
        total = 0
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if total > 256 * 1024:   # cap at 256 KB
                break
        s.close()
        return b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception as e:
        raise


async def query_whois(domain: str) -> dict:
    """Query classic WHOIS for a domain. Returns normalized dict.

    Handles:
        - TLD → whois server resolution (via IANA)
        - Multi-hop WHOIS (thin registry → registrar's whois)
        - Redaction detection
    """
    result = {
        "source": "whois",
        "domain": domain,
        "registrar": None,
        "registrar_url": None,
        "registrar_whois": None,
        "registrant": {},
        "admin": {},
        "tech": {},
        "nameservers": [],
        "status": [],
        "created": None,
        "updated": None,
        "expires": None,
        "dnssec": None,
        "redacted": False,
        "raw": None,
        "errors": [],
    }

    tld = domain.rsplit(".", 1)[-1].lower()
    server = _find_whois_server(tld)
    if not server:
        result["errors"].append(f"no WHOIS server known for TLD .{tld}")
        return result

    try:
        text = await asyncio.get_event_loop().run_in_executor(
            None, _whois_query_sync, server, domain)
    except Exception as e:
        result["errors"].append(f"{type(e).__name__}: {e}")
        return result

    result["raw"] = text
    _parse_whois_text(text, result)

    # Thin registry (COM/NET) — parse may reveal a Registrar WHOIS URL.
    # Follow one more hop to get the full record.
    if result.get("registrar_whois") and \
       result["registrar_whois"] != server and \
       not result.get("registrant", {}).get("email"):
        try:
            extra = await asyncio.get_event_loop().run_in_executor(
                None, _whois_query_sync, result["registrar_whois"], domain)
            extra_result = {
                "source": "whois",
                "domain": domain,
                "registrar": None,
                "registrar_url": None,
                "registrar_whois": None,
                "registrant": {},
                "admin": {},
                "tech": {},
                "nameservers": [],
                "status": [],
                "created": None,
                "updated": None,
                "expires": None,
                "dnssec": None,
                "redacted": False,
                "raw": None,
                "errors": [],
            }
            _parse_whois_text(extra, extra_result)
            # Merge: prefer extra (registrar) values when result is empty
            for key in ("registrar", "registrar_url", "registrar_whois",
                        "dnssec"):
                if extra.get(key) and not result.get(key):
                    result[key] = extra[key]
            for contact_type in ("registrant", "admin", "tech"):
                for field, value in extra.get(contact_type, {}).items():
                    if value and not result[contact_type].get(field):
                        result[contact_type][field] = value
            if extra["nameservers"]:
                for ns in extra["nameservers"]:
                    if ns not in result["nameservers"]:
                        result["nameservers"].append(ns)
            result["raw"] = text + "\n\n=== Registrar WHOIS ===\n" + \
                             (extra.get("raw") or "")
        except Exception:
            pass

    # Detect redaction
    result["redacted"] = _is_redacted(result["raw"] or "")
    return result


def _parse_whois_text(text: str, out: dict):
    """Parse a WHOIS response into structured fields."""
    text_low = text.lower()

    # Regexes for common fields
    # NOTE: every pattern starts with ^\s* because WHOIS servers
    # commonly pad fields with leading whitespace (Verisign's COM
    # server uses 3 spaces, ARIN uses various, TWNIC uses none).
    field_map = {
        "registrar":       [r"^\s*Registrar:\s*(.+)$",
                            r"^\s*Sponsoring Registrar:\s*(.+)$",
                            r"^\s*registrar:\s*(.+)$"],
        "registrar_url":   [r"^\s*Registrar URL:\s*(.+)$",
                            r"^\s*Registrar WHOIS Server:\s*(.+)$"],
        "registrar_whois": [r"^\s*Registrar WHOIS Server:\s*(.+)$"],
        "status":          [r"^\s*Domain Status:\s*(.+)$",
                            r"^\s*Status:\s*(.+)$",
                            r"^\s*domain status:\s*(.+)$"],
        "created":         [r"^\s*Creation Date:\s*(.+)$",
                            r"^\s*Created On:\s*(.+)$",
                            r"^\s*Registered on:\s*(.+)$",
                            r"^\s*Domain Registration Date:\s*(.+)$",
                            r"^\s*Record created on:\s*(.+)$"],
        "updated":         [r"^\s*Updated Date:\s*(.+)$",
                            r"^\s*Last Updated On:\s*(.+)$",
                            r"^\s*Last Modified:\s*(.+)$",
                            r"^\s*Record last updated on:\s*(.+)$"],
        "expires":         [r"^\s*Registry Expiry Date:\s*(.+)$",
                            r"^\s*Expiration Date:\s*(.+)$",
                            r"^\s*Registrar Registration Expiration Date:\s*(.+)$",
                            r"^\s*Expiry date:\s*(.+)$",
                            r"^\s*Record expires on:\s*(.+)$"],
        "dnssec":          [r"^\s*DNSSEC:\s*(.+)$"],
    }

    for key, patterns in field_map.items():
        for pat in patterns:
            m = re.search(pat, text, re.MULTILINE | re.IGNORECASE)
            if m:
                value = m.group(1).strip()
                if key == "status":
                    if value and value not in out["status"]:
                        out["status"].append(value)
                elif key == "registrar_whois" and out.get("registrar_whois"):
                    pass   # keep first
                elif not out.get(key):
                    out[key] = value
                break

    # Name servers
    ns_patterns = [
        r"^\s*Name Server:\s*(.+)$",
        r"^\s*Nameserver:\s*(.+)$",
        r"^\s*Name server:\s*(.+)$",
        r"^\s*nserver:\s*(.+)$",
        r"^\s*NS:\s*(.+)$",
    ]
    for pat in ns_patterns:
        for m in re.finditer(pat, text, re.MULTILINE | re.IGNORECASE):
            ns = m.group(1).strip().split()[0].lower().rstrip(".")
            if ns and ns not in out["nameservers"]:
                out["nameservers"].append(ns)

    # Contact blocks. Different registries use different keys.
    _extract_contacts(text, out)


def _extract_contacts(text: str, out: dict):
    """Parse registrant / admin / tech contact blocks."""
    lines = text.splitlines()

    # Method 1 — tagged blocks (RIPE-style, some gTLDs)
    current = None
    for line in lines:
        stripped = line.strip()
        if not stripped:
            current = None
            continue
        lower = stripped.lower()
        if lower.startswith("registrant "):
            current = "registrant"
        elif lower.startswith("admin ") or lower.startswith("administrative "):
            current = "admin"
        elif lower.startswith("tech ") or lower.startswith("technical "):
            current = "tech"
        elif current and ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if not value:
                continue
            block = out.setdefault(current, {})
            if key in ("name", "org", "organization", "email",
                       "phone", "country", "state", "city", "address"):
                if key in ("org", "organization"):
                    key = "organization"
                if not block.get(key):
                    block[key] = value

    # Method 2 — flat WHOIS fields (public suffix registrars).
    # Look for "Registrant Email:", "Registrant Organization:", etc.
    flat_patterns = {
        "registrant": [
            ("name",         r"^\s*Registrant Name:\s*(.+)$"),
            ("organization", r"^\s*Registrant Organization:\s*(.+)$"),
            ("email",        r"^\s*Registrant Email:\s*(.+)$"),
            ("phone",        r"^\s*Registrant Phone:\s*(.+)$"),
            ("address",      r"^\s*Registrant Street:\s*(.+)$"),
            ("city",         r"^\s*Registrant City:\s*(.+)$"),
            ("state",        r"^\s*Registrant State/Province:\s*(.+)$"),
            ("country",      r"^\s*Registrant Country:\s*(.+)$"),
        ],
        "admin": [
            ("name",         r"^\s*Admin Name:\s*(.+)$"),
            ("organization", r"^\s*Admin Organization:\s*(.+)$"),
            ("email",        r"^\s*Admin Email:\s*(.+)$"),
            ("phone",        r"^\s*Admin Phone:\s*(.+)$"),
        ],
        "tech": [
            ("name",         r"^\s*Tech Name:\s*(.+)$"),
            ("organization", r"^\s*Tech Organization:\s*(.+)$"),
            ("email",        r"^\s*Tech Email:\s*(.+)$"),
            ("phone",        r"^\s*Tech Phone:\s*(.+)$"),
        ],
    }

    for contact_type, patterns in flat_patterns.items():
        block = out.setdefault(contact_type, {})
        for field, pat in patterns:
            m = re.search(pat, text, re.MULTILINE | re.IGNORECASE)
            if m and not block.get(field):
                block[field] = m.group(1).strip()


def _is_redacted(text: str) -> bool:
    """Return True if the WHOIS record looks redacted by a privacy service."""
    if not text:
        return False
    low = text.lower()
    for marker in REDACTION_MARKERS:
        if marker in low:
            return True
    return False


# ---------------------------------------------------------------------
# Reverse WHOIS via ViewDNS.info
# ---------------------------------------------------------------------

async def reverse_viewdns(query: str, session=None,
                          verbose: bool = False) -> list[str]:
    """Query ViewDNS.info for domains registered by `query`.

    `query` can be an email, a registrant name, or an organization.
    Returns a list of domain strings (empty on failure).

    ViewDNS free tier rate-limits aggressively. If we hit the limit,
    we return [] and let the caller warn.
    """
    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(1.0)

    url = VIEWDNS_URL.format(query=quote(query))
    try:
        status, _headers, body, _ = await fetch(session, url, limiter,
                                                  timeout=30.0)
    except Exception as e:
        if verbose:
            warn(f"ViewDNS failed: {type(e).__name__}: {e}")
        return []
    finally:
        if own_session:
            await session.close()

    if status != 200 or not body:
        if verbose:
            warn(f"ViewDNS returned status={status}")
        return []

    # ViewDNS returns an HTML table. Extract the domain column.
    # Table structure: <table ...> ... <tr><td>domain</td><td>...</td></tr>
    domains = []
    # Find rows with a domain-shaped string in a <td>
    for m in re.finditer(
        r"<tr[^>]*>\s*<td[^>]*>\s*([a-z0-9][a-z0-9\-\.]*\.[a-z]{2,})\s*</td>",
        body, re.IGNORECASE,
    ):
        d = m.group(1).strip().lower()
        if d and d not in domains:
            domains.append(d)

    if not domains and verbose:
        warn("ViewDNS returned no results (rate limit or empty result set)")
    return domains


# ---------------------------------------------------------------------
# IP WHOIS via RDAP (delegates to net.geo)
# ---------------------------------------------------------------------

async def query_ip_whois(ip: str, verbose: bool = False) -> dict:
    """Query RDAP for an IP. Reuses net.geo's RDAP implementation."""
    try:
        from net import geo
        return await geo.rdap_lookup(ip, timeout=10.0) or {}
    except Exception as e:
        if verbose:
            warn(f"IP RDAP failed: {type(e).__name__}: {e}")
        return {}


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def lookup(target: str, session=None, verbose: bool = False,
                 reverse: bool = True) -> dict:
    """Full WHOIS + RDAP + reverse lookup for a domain or IP.

    Accepts URLs, hostnames with ports, and bare hostnames. The
    registrable domain is extracted before WHOIS is queried, so
    https://www.example.co.uk/path correctly becomes example.co.uk.
    """
    # Normalize via core.target
    from core.target import parse as _parse_target
    try:
        t = _parse_target(target)
    except ValueError as e:
        return {
            "target": target, "type": "unknown",
            "whois": {}, "ip_rdap": {}, "reverse": [],
            "redacted": False,
            "errors": [f"could not parse target: {e}"],
        }

    is_ip = t.is_ip
    # For domain targets, use the registrable domain (example.co.uk,
    # not www.example.co.uk) — that's what WHOIS answers for.
    normalized = t.host if is_ip else (t.registrable or t.host)

    result = {
        "target": normalized,
        "type": "ip" if is_ip else "domain",
        "whois": {},
        "ip_rdap": {},
        "reverse": [],
        "redacted": False,
        "errors": [],
    }

    if is_ip:
        # IP target → RDAP only
        rdap = await query_ip_whois(normalized, verbose=verbose)
        result["whois"] = rdap
        return result

    target = normalized

    is_ip = t.is_ip
    # Use the registrable domain for domain targets
    if not is_ip:
        target = t.registrable or t.host

    result = {
        "target": target,
        "type": "ip" if is_ip else "domain",
        "whois": {},
        "ip_rdap": {},
        "reverse": [],
        "redacted": False,
        "errors": [],
    }

    if is_ip:
        # IP target → RDAP only
        rdap = await query_ip_whois(target, verbose=verbose)
        result["whois"] = rdap
        return result

    # Domain target → classic WHOIS
    info(f"querying WHOIS for {target}")
    whois = await query_whois(target)
    result["whois"] = whois
    result["redacted"] = whois.get("redacted", False)

    if whois.get("errors"):
        result["errors"].extend(whois["errors"])

    # Resolve to IPs and query RDAP for each unique netblock
    try:
        from core.dns import resolve_a
        ips = await resolve_a(target, verbose=verbose)
    except Exception:
        ips = []

    if ips:
        rdaps = []
        seen = set()
        for ip in ips[:3]:   # cap at 3 IPs to keep it fast
            rdap = await query_ip_whois(ip, verbose=verbose)
            org = rdap.get("org") or ""
            if org in seen:
                continue
            seen.add(org)
            rdap["_ip"] = ip
            rdaps.append(rdap)
        result["ip_rdap"] = rdaps

    # Reverse WHOIS on the most identifying field
    if reverse:
        query_value = None
        for contact_type in ("registrant", "admin", "tech"):
            block = whois.get(contact_type) or {}
            if block.get("email"):
                query_value = block["email"]
                break
            if block.get("organization"):
                query_value = block["organization"]
                break

        if query_value and not whois.get("redacted"):
            info(f"reverse WHOIS lookup on {query_value!r}")
            domains = await reverse_viewdns(query_value, verbose=verbose)
            result["reverse"] = domains

    return result


# ---------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
              reverse: bool = True) -> dict:
    """CLI entry. Writes finding to store if provided."""
    result = await lookup(target, verbose=verbose, reverse=reverse)

    print()
    if result["type"] == "ip":
        _print_ip_result(result)
    else:
        _print_domain_result(result, verbose=verbose)

    if store is not None:
        store.add_finding({
            "module": "whois",
            "type": "informational",
            "severity": "info",
            "target": target,
            "evidence": _build_evidence(result),
            "data": result,
        })
        success(f"finding written to store")

    return result


def _print_domain_result(result: dict, verbose: bool = False):
    whois = result["whois"]
    if not whois:
        warn(f"no WHOIS data for {result['target']}")
        return

    if result.get("redacted"):
        warn(f"WHOIS record is redacted (privacy service)")

    print()
    success(f"WHOIS for {result['target']}")

    if whois.get("registrar"):
        print(f"  registrar:  {whois['registrar']}")
    if whois.get("created"):
        print(f"  created:    {whois['created']}")
    if whois.get("updated"):
        print(f"  updated:    {whois['updated']}")
    if whois.get("expires"):
        print(f"  expires:    {whois['expires']}")
    if whois.get("dnssec"):
        print(f"  dnssec:     {whois['dnssec']}")

    if whois.get("status"):
        print(f"  status:")
        for s in whois["status"][:5]:
            print(f"    {s}")

    if whois.get("nameservers"):
        print(f"  nameservers:")
        for ns in whois["nameservers"]:
            print(f"    {ns}")

    for contact_type in ("registrant", "admin", "tech"):
        block = whois.get(contact_type) or {}
        if not block:
            continue
        print(f"  {contact_type}:")
        for field in ("name", "organization", "email", "phone",
                      "city", "state", "country"):
            if block.get(field):
                print(f"    {field:14s} {block[field]}")

    if result.get("ip_rdap"):
        print()
        info(f"IP RDAP (resolved)")
        for rdap in result["ip_rdap"]:
            org = rdap.get("org") or "?"
            country = rdap.get("country") or "?"
            handle = rdap.get("handle") or "?"
            print(f"  {rdap.get('_ip', '?'):16s} {country:4s} "
                  f"{handle:20s} {org}")

    if result.get("reverse"):
        print()
        success(f"Reverse WHOIS: {len(result['reverse'])} other domain(s)")
        for d in result["reverse"][:30]:
            print(f"    {d}")
        if len(result["reverse"]) > 30:
            print(f"    ... and {len(result['reverse']) - 30} more")
    elif reverse_enabled(result):
        print()
        info("reverse WHOIS: no results (rate limit or privacy-protected)")

    if verbose and whois.get("raw"):
        print()
        print("  Raw WHOIS (first 40 lines):")
        for line in whois["raw"].splitlines()[:40]:
            print(f"    {line}")


def _print_ip_result(result: dict):
    whois = result["whois"]
    if not whois:
        warn(f"no RDAP data for {result['target']}")
        return
    print()
    success(f"RDAP for {result['target']}")
    for field in ("handle", "name", "org", "country", "type"):
        if whois.get(field):
            print(f"  {field:10s} {whois[field]}")
    if whois.get("address"):
        print(f"  address    {' / '.join(whois['address'])}")


def reverse_enabled(result: dict) -> bool:
    return result["type"] == "domain" and not result.get("redacted")


def _build_evidence(result: dict) -> str:
    if result["type"] == "ip":
        rdap = result.get("whois") or {}
        return f"RDAP: {rdap.get('org', '?')} ({rdap.get('country', '?')})"
    whois = result.get("whois") or {}
    parts = []
    if whois.get("registrar"):
        parts.append(f"registrar={whois['registrar']}")
    if whois.get("created"):
        parts.append(f"created={whois['created'][:10]}")
    if result.get("redacted"):
        parts.append("redacted")
    if result.get("reverse"):
        parts.append(f"reverse={len(result['reverse'])} domains")
    return ", ".join(parts) or "WHOIS record retrieved"


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.whois",
        description="Domain / IP WHOIS + reverse lookup.",
    )
    p.add_argument("target", help="domain or IP")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show raw WHOIS output")
    p.add_argument("--no-reverse", action="store_true",
                   help="skip ViewDNS reverse lookup")
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

    asyncio.run(run(args.target, store=store, verbose=args.verbose,
                    reverse=not args.no_reverse))


if __name__ == "__main__":
    _cli()