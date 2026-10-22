"""
Subdomain takeover detection.

Scans a set of hostnames for dangling DNS records pointing at
third-party services that no longer have a backend. When found, the
hostname is potentially claimable by an attacker.

How it works:

  1. Resolve each candidate hostname's CNAME chain.
  2. If the chain ends at a known takeoverable service (GitHub Pages,
     Heroku, S3, Azure, Netlify, Vercel, Fastly, ...), fetch the
     hostname.
  3. Match the response against a fingerprint database of "this
     backend is unclaimed" pages.
  4. Report hits with the CNAME chain, service, and fingerprint.

This module is read-only. It resolves DNS and fetches HTTP. It never
attempts to claim a hostname — that would be active exploitation.

Candidate filtering:

  Two important filters run before scanning:

    - Wildcards are dropped (*.example.com can't be claimed without
      brute-forcing the wildcard space, which is a different problem).
    - Hostnames under provider-owned zones are dropped. If the
      candidate ends with github.com, cloudfront.net, herokuapp.com,
      etc., the target doesn't control that DNS zone and no takeover
      is possible. Scanning them produces false positives because the
      provider's own "backend not found" pages match our fingerprints.

Input:

  Candidates come from:
    - ct_logs:     every name seen in CT logs
    - tls_cert:    every SAN on the target's cert

  If you pass a domain as the target, this module collects from both.
  If you pass --hosts-file, it uses those.

Usage:

    from recon.subdomain_takeover import scan

    findings = await scan(["blog.example.com", "shop.example.com"])

    # CLI
    python -m recon.subdomain_takeover example.com
    python -m recon.subdomain_takeover example.com -v
    python -m recon.subdomain_takeover --hosts-file hosts.txt

Findings written to the store:
    one row per vulnerable hostname.
"""

import asyncio
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn
from core.target import parse
from recon import dns_util


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

DEFAULT_TIMEOUT = 10.0
DEFAULT_CONCURRENCY = 12


# Parent domains owned by infrastructure providers. A candidate whose
# hostname ends with one of these is not the target's asset — the
# target doesn't control its DNS zone. Scanning them produces false
# positives because the provider's own "backend not found" pages match
# our fingerprints.
SKIP_PARENT_ZONES = {
    "github.com", "github.io", "githubusercontent.com", "githubassets.com",
    "amazonaws.com", "cloudfront.net", "aws.amazon.com",
    "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
    "blob.core.windows.net", "azurefd.net",
    "herokuapp.com", "herokudns.com", "herokussl.com",
    "netlify.app", "netlify.com",
    "vercel.app", "vercel.com", "now.sh",
    "fastly.net", "fastlylb.net", "fastly-edge.com",
    "cloudflare.com", "cloudflare.net",
    "googleapis.com", "googleusercontent.com", "gstatic.com",
    "akamaihd.net", "akamaiedge.net", "akamai.net",
    "myshopify.com", "shopify.com",
    "zendesk.com",
    "tumblr.com",
    "wordpress.com",
    "statuspage.io",
    "readthedocs.io",
    "surge.sh",
    "fly.dev", "fly.io",
    "onrender.com",
    "web.app", "firebaseapp.com", "firebaseio.com",
    "visualstudio.com", "azuredevops.com",
    "pantheonsite.io",
    "ghost.io",
    "cargocollective.com",
    "uservoice.com",
    "unbouncepages.com",
    "bitbucket.io", "bitbucket.org",
}


# ---------------------------------------------------------------------
# Takeover fingerprint database
# ---------------------------------------------------------------------
#
# Each entry:
#     service_name:    human-readable service name
#     cname_suffixes:  list of DNS suffixes that indicate the service
#     fingerprints:    list of (pattern, is_regex, note)
#                      If the response body matches ANY pattern, the
#                      hostname is vulnerable.
#     http_statuses:   optional set of statuses that are "normal" for
#                      the unclaimed state. If set, only statuses in
#                      this set are considered.
#
# This database is deliberately conservative — a false positive here
# wastes an hour of the operator's time.

TAKEOVER_DB = [
    {
        "service_name": "GitHub Pages",
        "cname_suffixes": ["github.io"],
        "fingerprints": [
            (r"There isn't a GitHub Pages site here", False,
             "GitHub Pages: site not found"),
            (r"Repository not found", False,
             "GitHub: repo not found"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Heroku",
        "cname_suffixes": ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "fingerprints": [
            (r"Heroku \| No such app", False, "Heroku: no such app"),
            (r"heroku\.com/404", False, "Heroku: 404 reference"),
            (r"no-such-app", False, "Heroku: no-such-app marker"),
        ],
        "http_statuses": {404},
    },
    {
        "service_name": "Netlify",
        "cname_suffixes": ["netlify.app", "netlify.com"],
        "fingerprints": [
            (r"Not Found - Request ID", False, "Netlify: not found"),
            (r"Looks like you've followed a broken link",
             False, "Netlify: broken link page"),
        ],
        "http_statuses": {404},
    },
    {
        "service_name": "Vercel",
        "cname_suffixes": ["vercel.app", "vercel-dns.com", "now.sh"],
        "fingerprints": [
            (r"The deployment could not be found", False,
             "Vercel: deployment not found"),
            (r"DEPLOYMENT_NOT_FOUND", False,
             "Vercel: DEPLOYMENT_NOT_FOUND"),
        ],
        "http_statuses": {404},
    },
    {
        "service_name": "AWS S3 (website)",
        "cname_suffixes": [
            "s3.amazonaws.com",
            "s3-website",
            ".s3.",
            ".amazonaws.com",
        ],
        "fingerprints": [
            (r"NoSuchBucket", False, "S3: NoSuchBucket"),
            (r"The specified bucket does not exist",
             False, "S3: bucket does not exist"),
        ],
        "http_statuses": {404, 403},
    },
    {
        "service_name": "Azure",
        "cname_suffixes": [
            "cloudapp.net", "cloudapp.azure.com",
            "azurewebsites.net", "blob.core.windows.net",
            "azurestaticapps.net", "trafficmanager.net",
            "azurefd.net",
        ],
        "fingerprints": [
            (r"Azure Blob Storage", False, "Azure: Blob error"),
            (r"The specified resource does not exist",
             False, "Azure: resource missing"),
            (r"404 Web Site not found", False,
             "Azure Websites: not found"),
            (r"Error 404 - Web app not found", False,
             "Azure App Service: not found"),
        ],
        "http_statuses": {404},
    },
    {
        "service_name": "Fastly",
        "cname_suffixes": [
            "fastly.net", "fastlylb.net", "fastly-edge.com",
        ],
        "fingerprints": [
            (r"Fastly error: unknown domain", False,
             "Fastly: unknown domain"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Shopify",
        "cname_suffixes": [
            "myshopify.com", "shopify.com",
        ],
        "fingerprints": [
            (r"Sorry, this shop is currently unavailable", False,
             "Shopify: shop unavailable"),
            (r"Only one step left", False,
             "Shopify: shop unclaimed"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Zendesk",
        "cname_suffixes": ["zendesk.com"],
        "fingerprints": [
            (r"Help Center Closed", False, "Zendesk: help center closed"),
            (r"this Zendesk is closed", False, "Zendesk: closed"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Tumblr",
        "cname_suffixes": ["tumblr.com"],
        "fingerprints": [
            (r"There's nothing here", False, "Tumblr: nothing here"),
            (r"Whatever you were looking for doesn't currently exist",
             False, "Tumblr: missing blog"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "WordPress.com",
        "cname_suffixes": ["wordpress.com"],
        "fingerprints": [
            (r"Do you want to register", False,
             "WordPress.com: register prompt"),
            (r"doesn't exist yet", False, "WordPress.com: not yet created"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Pantheon",
        "cname_suffixes": ["pantheonsite.io"],
        "fingerprints": [
            (r"The gods are wise, but do not know of the site which you seek",
             False, "Pantheon: site not found"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Ghost (ghost.io)",
        "cname_suffixes": ["ghost.io"],
        "fingerprints": [
            (r"Domain error", False, "Ghost: domain error"),
            (r"Failed to load site", False, "Ghost: site not found"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Surge.sh",
        "cname_suffixes": ["surge.sh"],
        "fingerprints": [
            (r"project not found", False, "Surge: project not found"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Bitbucket",
        "cname_suffixes": ["bitbucket.io", "bitbucket.org"],
        "fingerprints": [
            (r"Repository not found", False,
             "Bitbucket: repo not found"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Read the Docs",
        "cname_suffixes": ["readthedocs.io"],
        "fingerprints": [
            (r"404 - Read the Docs", False, "ReadTheDocs: 404"),
            (r"doesn't exist", False, "ReadTheDocs: project missing"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Cargo",
        "cname_suffixes": ["cargocollective.com"],
        "fingerprints": [
            (r"404 Not Found", False, "Cargo: 404"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Statuspage",
        "cname_suffixes": ["statuspage.io"],
        "fingerprints": [
            (r"Status page not found", False,
             "Statuspage: page missing"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Unbounce",
        "cname_suffixes": ["unbouncepages.com"],
        "fingerprints": [
            (r"The requested URL was not found on this server",
             False, "Unbounce: URL not found"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "UserVoice",
        "cname_suffixes": ["uservoice.com"],
        "fingerprints": [
            (r"This UserVoice subdomain is currently available",
             False, "UserVoice: subdomain available"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Fly.io",
        "cname_suffixes": ["fly.dev", "fly.io"],
        "fingerprints": [
            (r"404 Not Found", False, "Fly.io: 404"),
        ],
        "http_statuses": {404},
    },
    {
        "service_name": "Firebase Hosting",
        "cname_suffixes": ["web.app", "firebaseapp.com"],
        "fingerprints": [
            (r"Site Not Found", False, "Firebase: site not found"),
            (r"Firebase Hosting", False, "Firebase: hosting error page"),
        ],
        "http_statuses": None,
    },
    {
        "service_name": "Render",
        "cname_suffixes": ["onrender.com"],
        "fingerprints": [
            (r"Not Found", False, "Render: not found"),
        ],
        "http_statuses": {404},
    },
    {
        "service_name": "Azure DevOps",
        "cname_suffixes": ["visualstudio.com", "azuredevops.com"],
        "fingerprints": [
            (r"Azure DevOps Services \| Sign In", False,
             "Azure DevOps: sign in prompt"),
        ],
        "http_statuses": None,
    },
]


# ---------------------------------------------------------------------
# Candidate filtering
# ---------------------------------------------------------------------

def _is_provider_owned(host: str) -> bool:
    """Return True if `host` ends with a known provider's apex domain."""
    low = host.lower()
    for zone in SKIP_PARENT_ZONES:
        if low == zone or low.endswith("." + zone):
            return True
    return False


def _dedupe_and_filter(candidates: set[str], domain: str | None,
                        verbose: bool = False, skip_providers = True) -> list[str]:
    """Clean up candidates: strip wildcards, dedupe, filter by domain.

    Filters applied:
      - Wildcards (*.example.com) — can't be scanned without brute
        forcing the wildcard space.
      - Hostnames with bad characters.
      - Off-domain hostnames (if a domain filter is provided).
      - Provider-owned zones (github.com, cloudfront.net, etc.).

    In verbose mode, prints the reason for each skip.
    """
    out = set()
    skipped = {"wildcard": 0, "bad_chars": 0, "off_domain": 0,
               "provider_owned": 0, "duplicate": 0}

    for c in candidates:
        original = c
        c = c.strip().lower().rstrip(".")
        if not c:
            continue
        if c.startswith("*."):
            skipped["wildcard"] += 1
            if verbose:
                info(f"  skip {original:45s} wildcard")
            continue
        if " " in c or "/" in c:
            skipped["bad_chars"] += 1
            if verbose:
                info(f"  skip {original:45s} bad chars")
            continue
        if not re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", c):
            skipped["bad_chars"] += 1
            if verbose:
                info(f"  skip {original:45s} invalid hostname")
            continue
        if domain and not c.endswith(domain):
            skipped["off_domain"] += 1
            if verbose:
                info(f"  skip {original:45s} off-domain")
            continue
        if _is_provider_owned(c):
            skipped["provider_owned"] += 1
            if verbose:
                info(f"  skip {original:45s} provider-owned zone")
            continue
        if c in out:
            skipped["duplicate"] += 1
            continue
        out.add(c)

    if verbose and any(skipped.values()):
        info(f"  filter summary: "
             f"{skipped['wildcard']} wildcard, "
             f"{skipped['provider_owned']} provider-owned, "
             f"{skipped['off_domain']} off-domain, "
             f"{skipped['bad_chars']} invalid, "
             f"{skipped['duplicate']} dup")

    return sorted(out)


# ---------------------------------------------------------------------
# CNAME resolution
# ---------------------------------------------------------------------

async def _resolve_cname_chain(host: str, timeout: float = 5.0
                                ) -> list[str]:
    """Return the full CNAME chain starting from `host`."""
    chain = []
    current = host
    seen = set()
    for _ in range(10):
        if current in seen:
            break
        seen.add(current)
        try:
            cname = await dns_util.resolve_cname(current, timeout=timeout)
        except Exception:
            break
        if not cname:
            break
        chain.append(cname)
        current = cname
    return chain


# ---------------------------------------------------------------------
# Fingerprint matching
# ---------------------------------------------------------------------

def _match_fingerprint(body: str, status: int | None,
                       entry: dict) -> dict | None:
    """Return matched-fingerprint dict or None."""
    if body is None:
        return None
    body_low = body.lower()
    for pattern, is_regex, note in entry["fingerprints"]:
        if is_regex:
            if re.search(pattern, body, re.IGNORECASE):
                return {"note": note, "pattern": pattern}
        else:
            if pattern.lower() in body_low:
                return {"note": note, "pattern": pattern}
    return None


def _find_service_for_chain(chain: list[str]) -> dict | None:
    """Return the DB entry whose cname_suffixes matches the CNAME chain."""
    for cname in chain:
        low = cname.lower()
        for entry in TAKEOVER_DB:
            for suffix in entry["cname_suffixes"]:
                if low == suffix or low.endswith("." + suffix) \
                        or low.endswith(suffix):
                    return entry
    return None


# ---------------------------------------------------------------------
# Per-host scan
# ---------------------------------------------------------------------

async def _fetch_over_http(session, host: str, limiter,
                           timeout: float = DEFAULT_TIMEOUT
                           ) -> tuple[int | None, str, str]:
    """Fetch a host over HTTPS first, then HTTP."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = await fetch(session, url, limiter,
                            timeout=timeout, allow_redirects=True)
        except Exception:
            continue
        if r and r[0] is not None:
            return r[0], r[2] or "", r[3] or url
    return None, "", ""


async def _scan_one(session, host: str, limiter,
                    verbose: bool = False) -> dict:
    """Scan a single hostname. Returns a result dict."""
    result = {
        "host": host,
        "cname_chain": [],
        "service": None,
        "vulnerable": False,
        "evidence": None,
        "status": None,
        "final_url": None,
        "error": None,
    }

    # 1. Resolve CNAME chain
    chain = await _resolve_cname_chain(host)
    result["cname_chain"] = chain
    if not chain:
        if verbose:
            info(f"  {host:42s} no CNAME")
        return result

    # 2. Match chain against known services
    entry = _find_service_for_chain(chain)
    if not entry:
        if verbose:
            info(f"  {host:42s} CNAME → {chain[-1]} (not in DB)")
        return result

    result["service"] = entry["service_name"]

    # 3. Fetch and fingerprint
    status, body, final_url = await _fetch_over_http(
        session, host, limiter)
    result["status"] = status
    result["final_url"] = final_url

    if status is None:
        result["error"] = "fetch failed on both HTTPS and HTTP"
        return result

    # If the DB specifies valid statuses, filter
    if entry.get("http_statuses") and status not in entry["http_statuses"]:
        if verbose:
            info(f"  {host:42s} {entry['service_name']} "
                 f"HTTP {status} — status not in vulnerable set")
        return result

    # Fingerprint match
    match = _match_fingerprint(body, status, entry)
    if match:
        result["vulnerable"] = True
        result["evidence"] = {
            "note": match["note"],
            "pattern": match["pattern"],
            "service": entry["service_name"],
            "cname_chain": chain,
        }
    elif verbose:
        info(f"  {host:42s} {entry['service_name']} "
             f"HTTP {status} — no fingerprint match")

    return result


# ---------------------------------------------------------------------
# Candidate collection
# ---------------------------------------------------------------------

async def _collect_from_ct_logs(domain: str, verbose: bool) -> set[str]:
    """Get every hostname from CT logs for `domain`."""
    try:
        from recon import ct_logs
        result = await ct_logs.lookup(domain, verbose=verbose)
        names = set(result.get("unique_names") or [])
        names.add(domain)
        if verbose:
            info(f"  ct_logs: {len(names)} candidate(s)")
        return names
    except Exception as e:
        if verbose:
            warn(f"subdomain_takeover: ct_logs failed: "
                 f"{type(e).__name__}: {e}")
        return set()


async def _collect_from_tls(host: str, verbose: bool) -> set[str]:
    """Get every SAN from the target's TLS cert."""
    try:
        from recon import tls_cert
        result = await tls_cert.grab(host, verbose=verbose)
        sans = set()
        for san in result.get("sans") or []:
            if san.startswith("*"):
                sans.add(san)
            elif not re.match(r"^[\d.:]+$", san):
                sans.add(san)
        if verbose:
            info(f"  tls_cert: {len(sans)} candidate(s)")
        return sans
    except Exception as e:
        if verbose:
            warn(f"subdomain_takeover: tls_cert failed: "
                 f"{type(e).__name__}: {e}")
        return set()


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def scan(hosts: list[str] | None = None,
               domain: str | None = None,
               session=None,
               verbose: bool = False,
               concurrency: int = DEFAULT_CONCURRENCY,
               rate: float = 10.0,
               timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Scan for subdomain takeover.

    Either pass an explicit `hosts` list, or pass `domain` and let the
    module collect candidates itself from CT logs and the TLS cert.
    """
    start = time.time()

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(rate=rate)

    errors = []
    candidates: list[str] = []
    raw_count = 0

    try:
        # --- Candidate collection ---
        if hosts:
            raw_count = len(hosts)
            if verbose:
                info(f"subdomain_takeover: filtering "
                     f"{raw_count} explicit candidate(s)")
            candidates = _dedupe_and_filter(
                set(hosts), domain=None, verbose=verbose)
        elif domain:
            info(f"subdomain_takeover: collecting candidates for {domain}")
            from_ct = await _collect_from_ct_logs(domain, verbose)
            from_tls = await _collect_from_tls(domain, verbose)
            raw_count = len(from_ct | from_tls)
            candidates = _dedupe_and_filter(
                from_ct | from_tls, domain, verbose=verbose)
        else:
            return {
                "domain": None, "candidates": [], "scanned": 0,
                "vulnerable": [], "potential": [], "results": [],
                "elapsed": 0.0,
                "errors": ["no hosts and no domain provided"],
            }

        if not candidates:
            if raw_count > 0:
                warn(f"subdomain_takeover: all {raw_count} candidate(s) "
                     f"were filtered out (wildcards, provider-owned "
                     f"zones, or off-domain). Nothing to scan.")
            else:
                warn("subdomain_takeover: no candidates to scan")
            return {
                "domain": domain, "candidates": [], "scanned": 0,
                "vulnerable": [], "potential": [], "results": [],
                "elapsed": round(time.time() - start, 2),
                "errors": errors,
            }

        info(f"subdomain_takeover: scanning {len(candidates)} "
             f"hostname(s) for dangling CNAMEs")

        # --- Scan in parallel ---
        sem = asyncio.Semaphore(concurrency)

        async def _one(host):
            async with sem:
                return await _scan_one(session, host, limiter,
                                        verbose=verbose)

        results = await asyncio.gather(
            *[_one(h) for h in candidates],
            return_exceptions=True)

        clean_results = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                clean_results.append({
                    "host": candidates[i],
                    "cname_chain": [],
                    "service": None,
                    "vulnerable": False,
                    "evidence": None,
                    "status": None,
                    "final_url": None,
                    "error": f"{type(r).__name__}: {r}",
                })
            else:
                clean_results.append(r)

        vulnerable = [r for r in clean_results if r["vulnerable"]]
        potential = [
            r for r in clean_results
            if r["service"] and not r["vulnerable"]
        ]

        return {
            "domain": domain,
            "candidates": candidates,
            "scanned": len(candidates),
            "vulnerable": vulnerable,
            "potential": potential,
            "results": clean_results,
            "elapsed": round(time.time() - start, 2),
            "errors": errors,
        }
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# Store integration
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
              hosts: list[str] | None = None,
              rate: float = 10.0) -> dict:
    """CLI entry. Writes findings to store if provided."""
    domain = None
    if not hosts:
        try:
            t = parse(target)
            if t.is_ip or t.kind == "asn":
                warn(f"subdomain_takeover: {target} is not a domain; "
                     f"pass --hosts-file with explicit candidates")
                return {
                    "domain": None, "candidates": [], "scanned": 0,
                    "vulnerable": [], "potential": [], "results": [],
                    "elapsed": 0.0,
                    "errors": ["target is not a domain"],
                }
            domain = t.registrable or t.host
        except ValueError as e:
            warn(f"subdomain_takeover: could not parse {target!r}: {e}")
            return {
                "domain": None, "candidates": [], "scanned": 0,
                "vulnerable": [], "potential": [], "results": [],
                "elapsed": 0.0,
                "errors": [f"parse failed: {e}"],
            }

    result = await scan(
        hosts=hosts, domain=domain, verbose=verbose, rate=rate)

    print()
    if result["scanned"] == 0:
        return result

    if result["vulnerable"]:
        success(f"subdomain_takeover: {len(result['vulnerable'])} "
                f"VULNERABLE hostname(s) out of {result['scanned']} "
                f"scanned")
        for r in result["vulnerable"]:
            print()
            warn(f"  ⚠  {r['host']}")
            print(f"      service:    {r['service']}")
            print(f"      CNAME chain:")
            for c in r["cname_chain"]:
                print(f"        → {c}")
            ev = r.get("evidence") or {}
            print(f"      fingerprint: {ev.get('note')}")
            print(f"      matched:     {ev.get('pattern')}")
            if r.get("status"):
                print(f"      HTTP status: {r['status']}")
    else:
        info(f"subdomain_takeover: no takeover vulnerabilities found "
             f"({result['scanned']} scanned)")

    if result["potential"] and verbose:
        print()
        info(f"  {len(result['potential'])} hostname(s) point at "
             f"takeoverable services but did not match a fingerprint:")
        for r in result["potential"]:
            chain = " → ".join(r["cname_chain"])
            status = r.get("status")
            err = r.get("error")
            note = f"HTTP {status}" if status else (err or "no response")
            print(f"    {r['host']:42s} {r['service']:20s} {note}")

    if store is not None:
        for r in result["vulnerable"]:
            ev = r.get("evidence") or {}
            store.add_finding({
                "module": "subdomain_takeover",
                "type": "subdomain_takeover",
                "severity": "critical",
                "target": r["host"],
                "evidence": (f"{r['service']}: {ev.get('note', '')} "
                             f"(CNAME → {r['cname_chain'][-1] if r['cname_chain'] else '?'})"),
                "data": {
                    "host": r["host"],
                    "service": r["service"],
                    "cname_chain": r["cname_chain"],
                    "evidence": ev,
                    "http_status": r.get("status"),
                    "final_url": r.get("final_url"),
                },
            })
        if result["vulnerable"]:
            success(f"wrote {len(result['vulnerable'])} finding(s) "
                    f"to store")
        else:
            store.add_finding({
                "module": "subdomain_takeover",
                "type": "informational",
                "severity": "info",
                "target": target,
                "evidence": (f"{result['scanned']} hostname(s) scanned, "
                             f"no takeovers"),
                "data": {
                    "domain": result["domain"],
                    "scanned": result["scanned"],
                    "potential_count": len(result["potential"]),
                },
            })

    return result


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.subdomain_takeover",
        description="Scan hostnames for subdomain takeover.",
    )
    p.add_argument("target", nargs="?",
                   help="domain to collect candidates for "
                        "(CT logs + TLS cert)")
    p.add_argument("--hosts-file", default=None,
                   help="file with one hostname per line; overrides "
                        "the target-based candidate collection")
    p.add_argument("--rate", type=float, default=10.0,
                   help="requests per second (default 10)")
    p.add_argument("--store", action="store_true",
                   help="write findings to active workspace")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    hosts = None
    if args.hosts_file:
        path = Path(args.hosts_file)
        if not path.exists():
            warn(f"hosts file not found: {path}")
        else:
            hosts = [line.strip() for line in
                     path.read_text(encoding="utf-8").splitlines()
                     if line.strip() and not line.startswith("#")]
            info(f"loaded {len(hosts)} host(s) from {path}")

    if not hosts and not args.target:
        warn("either provide a target domain or --hosts-file")
        return

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

    target = args.target or ""
    asyncio.run(run(
        target, store=store, verbose=args.verbose,
        hosts=hosts, rate=args.rate))


if __name__ == "__main__":
    _cli()