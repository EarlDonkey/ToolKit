"""
Certificate Transparency log analysis.

Queries public CT logs for every certificate ever issued for a domain.
Unlike `recon/subdomains.py` (which just extracts names), this module
also reports:

  - Issuance dates       (chronological growth of infrastructure)
  - Issuing CAs          (Let's Encrypt vs DigiCert vs private)
  - Wildcard certs       (*.example.com — reveals parent scope)
  - Full SAN lists       (every name on every cert)
  - Internal hostnames   (vpn., owa., jenkins. — often leaked before
                          DNS was cleaned up)

Data sources, tried in order:

  1. crt.sh        — fast, comprehensive, occasionally flaky
  2. certspotter   — SSLMate's API, free tier, different uptime profile

Findings written to the store:
    one row per target with the full CT history in `data`
"""

import json
import re
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import quote

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


CRTSH_URL = "https://crt.sh/?q={query}&output=json"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert"

# Names we don't want to report as "interesting subdomains"
BORING_PREFIXES = (
    "www.", "mail.", "smtp.", "pop.", "imap.", "webmail.",
    "ns1.", "ns2.", "ns3.", "ns4.", "dns.", "dns1.", "dns2.",
)


# ---------------------------------------------------------------------
# Source 1: crt.sh
# ---------------------------------------------------------------------

async def fetch_crtsh(domain: str, session=None,
                      verbose: bool = False) -> list[dict]:
    """Fetch raw CT entries from crt.sh. Returns list of dicts (empty on failure)."""
    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(2.0)   # crt.sh rate-limits

    url = CRTSH_URL.format(query=quote(domain))
    try:
        status, _headers, body, _ = await fetch(session, url, limiter,
                                                  timeout=60.0)
    except Exception as e:
        if verbose:
            warn(f"crt.sh failed: {type(e).__name__}: {e}")
        status, body = None, None
    finally:
        if own_session:
            await session.close()

    if status != 200 or not body:
        if verbose:
            warn(f"crt.sh returned status={status}")
        return []

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        warn("crt.sh returned invalid JSON")
        return []

    if not isinstance(data, list):
        return []

    entries = []
    for row in data:
        # crt.sh fields: issuer_ca_id, issuer_name, common_name,
        # name_value, not_before, not_after, serial_number, id
        entries.append({
            "source": "crt.sh",
            "id": row.get("id"),
            "issuer": row.get("issuer_name", ""),
            "common_name": row.get("common_name", ""),
            "name_value": row.get("name_value", ""),
            "not_before": row.get("not_before", ""),
            "not_after": row.get("not_after", ""),
            "serial": row.get("serial_number", ""),
        })
    return entries


# ---------------------------------------------------------------------
# Source 2: certspotter
# ---------------------------------------------------------------------

async def fetch_certspotter(domain: str, session=None,
                             verbose: bool = False) -> list[dict]:
    """Fetch CT entries from certspotter. Returns list of dicts."""
    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(2.0)

    url = CERTSPOTTER_URL.format(domain=quote(domain))
    try:
        status, _headers, body, _ = await fetch(session, url, limiter,
                                                  timeout=60.0)
    except Exception as e:
        if verbose:
            warn(f"certspotter failed: {type(e).__name__}: {e}")
        status, body = None, None
    finally:
        if own_session:
            await session.close()

    if status != 200 or not body:
        if verbose:
            warn(f"certspotter returned status={status}")
        return []

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        warn("certspotter returned invalid JSON")
        return []

    if not isinstance(data, list):
        return []

    entries = []
    for row in data:
        # certspotter fields: id, dns_names[], not_before, not_after,
        # issuer.name, issuer.friendly_name
        issuer = row.get("issuer") or {}
        dns_names = row.get("dns_names") or []
        entries.append({
            "source": "certspotter",
            "id": row.get("id"),
            "issuer": issuer.get("name", "") or issuer.get("friendly_name", ""),
            "common_name": dns_names[0] if dns_names else "",
            "name_value": "\n".join(dns_names),
            "not_before": row.get("not_before", ""),
            "not_after": row.get("not_after", ""),
            "serial": "",
        })
    return entries


# ---------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------

def extract_names(entries: list[dict]) -> set[str]:
    """Return every unique DNS name across all cert entries."""
    names = set()
    for entry in entries:
        # name_value can be newline-separated
        for raw in (entry.get("name_value") or "").splitlines():
            name = raw.strip().lower()
            if not name or "*" in name:
                # Skip wildcards — we want concrete names
                if name and "*" not in name:
                    continue
                # Keep the wildcard itself as a name, but note it
                if name:
                    names.add(name)
                continue
            names.add(name)

        # Also grab common_name if present and not duplicate
        cn = (entry.get("common_name") or "").strip().lower()
        if cn and "*" not in cn:
            names.add(cn)
    return names


def extract_wildcards(entries: list[dict]) -> set[str]:
    """Return all wildcard patterns seen in certs."""
    wildcards = set()
    for entry in entries:
        for raw in (entry.get("name_value") or "").splitlines():
            name = raw.strip().lower()
            if name.startswith("*."):
                wildcards.add(name)
        cn = (entry.get("common_name") or "").strip().lower()
        if cn.startswith("*."):
            wildcards.add(cn)
    return wildcards


def extract_issuers(entries: list[dict]) -> dict:
    """Return {ca_name: count} for every cert issuer."""
    issuers = {}
    for entry in entries:
        raw = entry.get("issuer") or ""
        # Normalize: strip everything after the first newline or comma
        # e.g. "C=US, O=Let's Encrypt, CN=R3" -> "R3 (Let's Encrypt)"
        ca = _normalize_issuer(raw)
        issuers[ca] = issuers.get(ca, 0) + 1
    return issuers


def _normalize_issuer(raw: str) -> str:
    """Turn an X.500 DN into a short human name."""
    if not raw:
        return "unknown"

    cn = ""
    org = ""
    for part in re.split(r"[,/]\s*", raw):
        part = part.strip()
        if not part:
            continue
        key, _, val = part.partition("=")
        key = key.strip().upper()
        val = val.strip()
        if key == "CN":
            cn = val
        elif key == "O":
            org = val

    if cn and org:
        return f"{cn} ({org})"
    if cn:
        return cn
    if org:
        return org
    return raw[:80]


def extract_dates(entries: list[dict]) -> dict:
    """Return first-issued and last-issued timestamps."""
    dates = []
    for entry in entries:
        nb = entry.get("not_before") or ""
        if nb:
            dates.append(nb)
    if not dates:
        return {"first": None, "last": None, "count": 0}
    dates.sort()
    return {"first": dates[0], "last": dates[-1], "count": len(dates)}


def find_interesting(names: set[str], base_domain: str) -> list[str]:
    """Filter names to those that suggest infrastructure we should look at."""
    interesting = []
    for name in names:
        if name == base_domain:
            continue
        if not name.endswith(base_domain):
            continue
        # Get the label before the domain
        prefix = name[:-len(base_domain)].rstrip(".")
        if not prefix:
            continue
        # Skip boring prefixes like www., mail.
        if any(prefix.startswith(b) for b in BORING_PREFIXES):
            continue
        # Look for admin-ish, dev-ish, internal-ish keywords
        keywords = (
            "admin", "dev", "test", "staging", "stage", "prod",
            "internal", "intranet", "vpn", "owa", "exchange",
            "jenkins", "git", "gitlab", "svn", "ci", "build",
            "db", "sql", "backup", "archive", "old", "legacy",
            "api", "api-dev", "api-test", "internal-api",
            "portal", "dashboard", "monitor", "grafana", "kibana",
            "ftp", "sftp", "ssh",
        )
        if any(kw in prefix for kw in keywords):
            interesting.append(name)
    return sorted(interesting)


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def lookup(domain: str, session=None, verbose: bool = False,
                 use_fallback: bool = True) -> dict:
    """Full CT log analysis for a domain.

    Returns:
        {
          "domain": "example.com",
          "source": "crt.sh" | "certspotter" | "merged",
          "total_certs": int,
          "unique_names": [str, ...],
          "wildcards": [str, ...],
          "issuers": {name: count},
          "dates": {"first": ..., "last": ..., "count": ...},
          "interesting": [str, ...],
          "raw_entries": [...],   # not included if verbose=False
          "errors": [str, ...],
        }
    """
    info(f"querying CT logs for {domain}")

    entries = await fetch_crtsh(domain, session=session, verbose=verbose)
    source = "crt.sh"

    if not entries and use_fallback:
        warn("crt.sh returned nothing; falling back to certspotter")
        entries = await fetch_certspotter(domain, session=session,
                                            verbose=verbose)
        source = "certspotter"

    if not entries:
        return {
            "domain": domain,
            "source": None,
            "total_certs": 0,
            "unique_names": [],
            "wildcards": [],
            "issuers": {},
            "dates": {"first": None, "last": None, "count": 0},
            "interesting": [],
            "errors": ["no data from crt.sh or certspotter"],
        }

    names = extract_names(entries)
    wildcards = extract_wildcards(entries)
    issuers = extract_issuers(entries)
    dates = extract_dates(entries)
    interesting = find_interesting(names, domain)

    # Remove wildcards from the concrete names list
    concrete = sorted(n for n in names if not n.startswith("*."))

    return {
        "domain": domain,
        "source": source,
        "total_certs": len(entries),
        "unique_names": concrete,
        "wildcards": sorted(wildcards),
        "issuers": issuers,
        "dates": dates,
        "interesting": interesting,
        "raw_entries": entries if verbose else [],
        "errors": [],
    }


# ---------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False) -> dict:
    """CLI entry. Writes finding to store if provided."""
    # Strip scheme if present
    domain = target
    for prefix in ("http://", "https://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].split(":")[0]

    result = await lookup(domain, verbose=verbose)

    print()
    if not result["unique_names"] and not result["wildcards"]:
        warn(f"no certificate data found for {domain}")
    else:
        success(f"{result['total_certs']} certs, "
                f"{len(result['unique_names'])} unique names "
                f"(source: {result['source']})")

        if result["dates"]["first"]:
            info(f"  first cert: {result['dates']['first'][:19]}")
            info(f"  last cert:  {result['dates']['last'][:19]}")

        print()
        print("  Issuers:")
        for ca, count in sorted(result["issuers"].items(),
                                 key=lambda x: -x[1]):
            print(f"    {count:4d}  {ca}")

        if result["wildcards"]:
            print()
            print("  Wildcards:")
            for wc in result["wildcards"]:
                print(f"    {wc}")

        if result["interesting"]:
            print()
            success(f"  {len(result['interesting'])} interesting name(s):")
            for name in result["interesting"]:
                print(f"    {name}")

        if verbose:
            print()
            print(f"  All unique names ({len(result['unique_names'])}):")
            for name in result["unique_names"]:
                print(f"    {name}")

    if store is not None:
        store.add_finding({
            "module": "ct_logs",
            "type": "informational",
            "severity": "info",
            "target": domain,
            "evidence": (f"{result['total_certs']} CT cert(s), "
                         f"{len(result['unique_names'])} unique names, "
                         f"{len(result['wildcards'])} wildcard(s)"),
            "data": {
                "source": result["source"],
                "total_certs": result["total_certs"],
                "unique_names": result["unique_names"],
                "wildcards": result["wildcards"],
                "issuers": result["issuers"],
                "dates": result["dates"],
                "interesting": result["interesting"],
            },
        })
        success(f"finding written to store")

    return result


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    import asyncio
    p = argparse.ArgumentParser(
        prog="recon.ct_logs",
        description="Certificate Transparency log analysis.",
    )
    p.add_argument("target", help="domain or URL")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show all names and raw entries")
    p.add_argument("--store", action="store_true",
                   help="write finding to active workspace")
    p.add_argument("--no-fallback", action="store_true",
                   help="don't try certspotter if crt.sh fails")
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

    # If --no-fallback, temporarily disable the fallback
    if args.no_fallback:
        global CERTSPOTTER_URL
        CERTSPOTTER_URL = ""   # empty -> fetch_certspotter returns []

    asyncio.run(run(args.target, store=store, verbose=args.verbose))


if __name__ == "__main__":
    _cli()