"""
Reverse IP lookup: what domains point at this IP?

Sources, tried in order:
  1. HackerTarget   — free, no key, ~50/day
  2. ViewDNS.info   — free tier, HTML scrape
  3. Bing           — "ip:1.2.3.4" search
  4. Shodan         — if SHODAN_API_KEY is set (paid or free tier)

The result is a set of hostnames. Feed them straight into recon.investigate
to pivot from one IP into a whole network.

Design notes:
  - We don't trust any single source. If HackerTarget is rate-limited,
    we still get results from ViewDNS. If both are rate-limited, Bing
    usually has something.
  - We filter out obvious CDN noise (cloudflare.com, akamai.net, etc.).
    Sharing an IP with Cloudflare's edge means nothing.
  - We dedupe and sort before returning so the output is stable across
    runs.
"""

import asyncio
import os
import re
from urllib.parse import quote

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn
from core.target import parse


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

HACKERTARGET = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
VIEWDNS = "https://viewdns.info/reverseip/?host={ip}&t=1"
BING = "https://www.bing.com/search?q=ip%3A{ip}&count=50"
SHODAN = "https://api.shodan.io/shodan/host/{ip}?key={key}"


# Cheap domain shape. Deliberately permissive — we filter more
# aggressively after extraction.
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24})\b",
    re.IGNORECASE,
)


# CDN and shared-hosting apexes. Seeing these on an IP tells you nothing
# about the customers — every Cloudflare edge answers for millions of
# domains. Filter them out of reverse-IP results.
_CDN_NOISE = {
    "cloudflare.com", "cloudflare.net", "cloudflare-dns.com",
    "akamai.net", "akamaiedge.net", "akamaihd.net", "akamaitechnologies.com",
    "fastly.net", "fastlylb.net", "fastly-edge.com",
    "cloudfront.net",
    "amazonaws.com", "awsdns-00.org", "awsdns-00.com",
    "azureedge.net", "azurewebsites.net", "trafficmanager.net",
    "googleusercontent.com", "googleapis.com", "gstatic.com",
    "google.com", "youtube.com",
    "bing.com", "microsoft.com", "msn.com", "live.com",
    "facebook.com", "fbcdn.net", "twitter.com", "x.com",
    "linkedin.com", "instagram.com",
    "w3.org", "schema.org", "iana.org",
    "cloudflarestream.com", "cloudflareclient.com",
    "sucuri.net", "stackpathdns.com",
    "incapdns.net", "impervadns.net",
    "hwcdn.net", "llnwd.net",
    "edgekey.net", "edgesuite.net",
    "netlify.app", "netlify.com",
    "vercel.app", "vercel.com",
    "herokudns.com", "herokuapp.com",
    "github.io", "githubusercontent.com",
    "wpengine.com", "kinsta.cloud",
}


def _is_plausible_domain(d: str) -> bool:
    """Reject junk that looks like a domain but isn't useful."""
    if not d:
        return False
    d = d.lower()
    if len(d) > 253 or len(d) < 4:
        return False
    # Must have at least one dot and a TLD-shaped suffix
    if "." not in d:
        return False
    # Reject PTR-shaped garbage
    if d.startswith(("static.", "dynamic.", "pool.", "ip-", "ptr.")):
        return False
    if ".." in d:
        return False
    # Reject anything under a known CDN apex
    for noise in _CDN_NOISE:
        if d == noise or d.endswith("." + noise):
            return False
    # Reject pure-numeric labels (usually parsed from IPs)
    first_label = d.split(".", 1)[0]
    if first_label.isdigit():
        return False
    return True


# ---------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------

async def _hackertarget(ip: str, session, limiter,
                        verbose: bool = False) -> set[str]:
    """HackerTarget's free reverse-IP API. Returns a plaintext list."""
    try:
        r = await fetch(session, HACKERTARGET.format(ip=ip), limiter,
                        timeout=20.0)
    except Exception as e:
        if verbose:
            warn(f"reverse_ip: hackertarget failed: "
                 f"{type(e).__name__}: {e}")
        return set()
    if not r or r[0] != 200 or not r[2]:
        return set()
    body = r[2]
    # HackerTarget returns "error: ..." or "no records found" plaintext
    low = body.lower()[:200]
    if "error" in low or "no records" in low or "api count exceeded" in low:
        if verbose:
            warn(f"reverse_ip: hackertarget: {body[:120].strip()}")
        return set()
    out = set()
    for line in body.splitlines():
        line = line.strip().lower()
        if line and _DOMAIN_RE.fullmatch(line) and _is_plausible_domain(line):
            out.add(line)
    return out


async def _viewdns(ip: str, session, limiter,
                   verbose: bool = False) -> set[str]:
    """ViewDNS reverse-IP. HTML scrape, so fragile — but free."""
    try:
        r = await fetch(session, VIEWDNS.format(ip=ip), limiter,
                        timeout=25.0,
                        headers={"User-Agent":
                                 "Mozilla/5.0 (compatible; recon/0.1)"})
    except Exception as e:
        if verbose:
            warn(f"reverse_ip: viewdns failed: "
                 f"{type(e).__name__}: {e}")
        return set()
    if not r or r[0] != 200 or not r[2]:
        return set()

    # Rows look like: <tr><td>domain.com</td><td>...</td></tr>
    out = set()
    pattern = re.compile(
        r"<tr[^>]*>\s*<td[^>]*>\s*([a-z0-9][a-z0-9\-\.]*\.[a-z]{2,})\s*</td>",
        re.IGNORECASE,
    )
    for m in pattern.finditer(r[2]):
        d = m.group(1).strip().lower()
        if _is_plausible_domain(d):
            out.add(d)
    return out


async def _bing(ip: str, session, limiter,
                verbose: bool = False) -> set[str]:
    """Bing search for 'ip:1.2.3.4'. Very noisy; used as last resort."""
    try:
        r = await fetch(session, BING.format(ip=ip), limiter,
                        timeout=20.0,
                        headers={"User-Agent":
                                 "Mozilla/5.0 (compatible; recon/0.1)"})
    except Exception:
        return set()
    if not r or r[0] != 200 or not r[2]:
        return set()

    out = set()
    for m in _DOMAIN_RE.finditer(r[2]):
        d = m.group(1).lower()
        if _is_plausible_domain(d):
            out.add(d)
    return out


async def _shodan(ip: str, session, limiter,
                  verbose: bool = False) -> set[str]:
    """Shodan host lookup. Requires SHODAN_API_KEY in the environment."""
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return set()
    try:
        r = await fetch(session, SHODAN.format(ip=ip, key=key),
                        limiter, timeout=25.0)
    except Exception:
        return set()
    if not r or r[0] != 200 or not r[2]:
        return set()

    import json
    try:
        data = json.loads(r[2])
    except Exception:
        return set()

    out = set()
    for h in data.get("hostnames") or []:
        if _is_plausible_domain(h.lower()):
            out.add(h.lower())
    for d in data.get("domains") or []:
        if _is_plausible_domain(d.lower()):
            out.add(d.lower())
    return out


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def lookup(ip: str, session=None, verbose: bool = False,
                 sources: list[str] | None = None) -> dict:
    """Find every domain that has resolved to `ip`.

    Returns:
        {
          "ip": "1.2.3.4",
          "domains": ["example.com", ...],
          "by_source": {"hackertarget": [...], "viewdns": [...]},
          "sources_used": ["hackertarget", "viewdns"],
          "errors": [],
        }

    `sources` restricts which providers to query. Default: try all,
    stop early once one returns results, unless sources is explicit.
    """
    t = parse(ip)
    if not t.is_ip:
        raise ValueError(f"reverse_ip: not an IP: {ip!r}")
    ip = t.host
    
    try:
        from net.geo import _ip_special_category
        special = _ip_special_category(ip)
    except Exception:
        special = None

    if special:
        if verbose:
            info(f"reverse_ip: {ip} is {special}; skipping lookups")
        return {
            "ip": ip,
            "domains": [],
            "by_source": {},
            "sources_used": [],
            "errors": [],
            "special": special,
        }

    own = session is None
    if own:
        session = new_session()
    limiter = RateLimiter(2.0)

    valid = {"hackertarget", "viewdns", "bing", "shodan"}
    wanted = set(sources) if sources else valid
    results: dict[str, set[str]] = {}

    info(f"reverse_ip: querying {len(wanted)} source(s) for {ip}")

    try:
        # -- cheap sources first --
        if "hackertarget" in wanted:
            results["hackertarget"] = await _hackertarget(
                ip, session, limiter, verbose=verbose)
            if verbose:
                info(f"  hackertarget: "
                     f"{len(results['hackertarget'])} hit(s)")

        # If HT returned nothing and we weren't asked for a specific
        # source set, try ViewDNS.
        need_more = not any(results.values())
        if need_more and "viewdns" in wanted:
            results["viewdns"] = await _viewdns(
                ip, session, limiter, verbose=verbose)
            if verbose:
                info(f"  viewdns: {len(results['viewdns'])} hit(s)")

        # Shodan (only if key is set — otherwise returns silently)
        if "shodan" in wanted:
            results["shodan"] = await _shodan(
                ip, session, limiter, verbose=verbose)
            if verbose and results["shodan"]:
                info(f"  shodan: {len(results['shodan'])} hit(s)")

        # Bing as the last resort, only if everything else came up dry.
        # Bing is extremely noisy so we don't want it as a primary.
        need_more = not any(results.values())
        if need_more and "bing" in wanted:
            results["bing"] = await _bing(
                ip, session, limiter, verbose=verbose)
            if verbose:
                info(f"  bing: {len(results['bing'])} hit(s)")

        combined = set()
        for s in results.values():
            combined.update(s)

        out = sorted(combined)
        return {
            "ip": ip,
            "domains": out,
            "by_source": {k: sorted(v) for k, v in results.items() if v},
            "sources_used": sorted(k for k, v in results.items() if v),
            "errors": [],
        }
    finally:
        if own:
            await session.close()


async def run(target: str, store=None, verbose: bool = False,
              sources: list[str] | None = None) -> dict:
    """CLI entry. Writes finding to store if provided."""
    result = await lookup(target, verbose=verbose, sources=sources)

    print()
    if result["domains"]:
        success(f"reverse_ip: {len(result['domains'])} domain(s) "
                f"share {result['ip']}")
        for d in result["domains"][:40]:
            print(f"  {d}")
        if len(result["domains"]) > 40:
            print(f"  ... and {len(result['domains']) - 40} more")
    else:
        warn(f"reverse_ip: no domains found for {result['ip']}")

    if store is not None:
        store.add_finding({
            "module": "reverse_ip",
            "type": "informational",
            "severity": "info",
            "target": result["ip"],
            "evidence": (f"{len(result['domains'])} domain(s) on same IP "
                         f"(sources: {', '.join(result['sources_used']) or 'none'})"),
            "data": result,
        })
        success("finding written to store")

    return result


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.reverse_ip",
        description="Find domains that resolve to an IP.",
    )
    p.add_argument("target", help="IP address")
    p.add_argument("--source", action="append",
                   choices=["hackertarget", "viewdns", "bing", "shodan"],
                   help="restrict to specific source(s); repeatable")
    p.add_argument("--store", action="store_true",
                   help="write finding to active workspace")
    p.add_argument("-v", "--verbose", action="store_true")
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
        sources=args.source))


if __name__ == "__main__":
    _cli()