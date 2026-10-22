"""
Host header injection detection.

The HTTP `Host` header tells the server which site the request is for.
When a client connects to a shared IP with multiple vhosts (or a
reverse proxy / CDN terminates traffic), the Host header is how the
server knows which app to serve.

If the app TRUSTS the Host header without validating it, an attacker
can abuse this:

  1. Password-reset poisoning
     The app emails "Click to reset: https://{Host}/reset?token=x".
     Attacker sends the reset request with `Host: attacker.test`.
     Victim clicks the link, attacker captures the token.

  2. Cache poisoning
     The app embeds the Host in a cached response. Attacker poisons
     the cache for a specific URL with a hostile Host value.

  3. Routing bypass / SSRF
     Apps behind a proxy sometimes route based on Host. Spoofing
     internal hostnames can reach internal services.

  4. Web cache deception
     CDN caches based on Host. Attacker forces the CDN to cache a
     sensitive page under their own Host.

Detection strategy:

  For a given URL, send the request with a modified Host header and
  observe whether the target:

    - Reflects the hostile Host anywhere in the response body
      (title, meta tags, absolute URLs, canonical links, og:url)

    - Redirects to the hostile Host
      (Location: https://attacker.test/...)

    - Sets cookies with Domain=attacker.test

  We test several Host header variants because filters often
  validate only the exact hostname:

    X-Forwarded-Host: attacker.test
    X-Forwarded-Server: attacker.test
    X-Host: attacker.test
    X-HTTP-Host-Override: attacker.test
    Forwarded: host=attacker.test
    Host: attacker.test                (may be blocked by the client)

  Note: on HTTPS, sending a raw Host header that doesn't match the
  SNI value can cause TLS issues. We use the same target hostname for
  the TCP connection but override the HTTP Host header — a normal
  capability of any HTTP client.

Severity:

  - Password reset reflects Host              → high
  - Any response reflects Host (title/meta)   → medium
  - Redirects to Host                          → medium
  - Cookie Domain=hostile                      → low
  - No reflection                              → info (not vulnerable)

Usage:

    from vuln.host_header import test_url

    findings = await test_url("https://example.com/", session, limiter)

    # CLI
    python -m vuln.host_header https://example.com/
    python -m vuln.host_header https://example.com/reset --cookie "session=x"

Findings written to the store:
    one row per vulnerable endpoint
"""

import asyncio
import secrets
import re
from urllib.parse import urlparse

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

RANDOM_TOKEN = secrets.token_hex(4)
HOSTILE_HOST = f"canary-{RANDOM_TOKEN}.tk-host-canary.test"

# Header names that various frameworks and proxies treat as "the Host"
HOST_HEADER_VARIANTS = [
    ("host_direct",          "Host"),
    ("x_forwarded_host",     "X-Forwarded-Host"),
    ("x_forwarded_server",   "X-Forwarded-Server"),
    ("x_host",               "X-Host"),
    ("x_http_host_override", "X-HTTP-Host-Override"),
    ("forwarded_host",       "Forwarded"),  # value is "host=..."
    ("x_original_host",      "X-Original-Host"),
    ("x_rewrite_url",        "X-Rewrite-URL"),  # some frameworks
]


# Markers we look for in the response body to detect reflection.
# These are places where absolute URLs are usually rendered.
REFLECTION_PATTERNS = [
    # Absolute URLs in href/src/action attributes
    (re.compile(r'(?:href|src|action)=["\']https?://[^"\']*'
                + re.escape(HOSTILE_HOST), re.IGNORECASE),
     "URL attribute"),
    # Canonical link
    (re.compile(r'<link[^>]*rel=["\']canonical["\'][^>]*href=["\']'
                r'[^"\']*' + re.escape(HOSTILE_HOST), re.IGNORECASE),
     "canonical link"),
    # og:url meta tag
    (re.compile(r'<meta[^>]*property=["\']og:url["\'][^>]*content=["\']'
                r'[^"\']*' + re.escape(HOSTILE_HOST), re.IGNORECASE),
     "og:url meta"),
    # Plain occurrence in body (last resort)
    (re.compile(re.escape(HOSTILE_HOST), re.IGNORECASE),
     "plain body text"),
]


# ---------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------

def _h(headers, name: str) -> str:
    """Case-insensitive header lookup."""
    if not headers:
        return ""
    name_lc = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lc:
            return str(v)
    return ""


def _find_reflection(body: str) -> tuple[str, str]:
    """Return (kind, snippet) if HOSTILE_HOST appears in the body."""
    if not body:
        return "", ""
    for pattern, kind in REFLECTION_PATTERNS:
        m = pattern.search(body)
        if m:
            # Grab a window of context
            start = max(0, m.start() - 40)
            end = min(len(body), m.end() + 40)
            snippet = body[start:end].replace("\n", " ").strip()
            return kind, snippet[:200]
    return "", ""


# ---------------------------------------------------------------------
# Single test
# ---------------------------------------------------------------------

async def _test_header(session, url: str, header_name: str,
                        header_value: str, limiter,
                        cookies=None, timeout: float = 10.0) -> dict | None:
    """Send one request with the given header. Return finding data or None."""
    headers = {header_name: header_value}

    try:
        status, resp_headers, body, _final = await fetch(
            session, url, limiter,
            method="GET",
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=False,
        )
    except Exception:
        return None

    if status is None:
        return None

    # --- Test 1: does the response redirect to our hostile host? ---
    location = _h(resp_headers, "location")
    if location and HOSTILE_HOST.lower() in location.lower():
        return {
            "kind": "redirect",
            "status": status,
            "location": location,
            "severity": "medium",
            "evidence": f"Redirected to hostile Host "
                        f"({header_name}: {header_value})",
        }

    # --- Test 2: does the body reflect the hostile host? ---
    reflection_kind, snippet = _find_reflection(body or "")
    if reflection_kind:
        # Slightly elevate if the reflection is in a URL attribute
        # or canonical link (these are usually what gets emailed)
        severity = "medium"
        if reflection_kind in ("canonical link", "og:url meta",
                                "URL attribute"):
            severity = "medium"
        return {
            "kind": "reflection",
            "reflection_kind": reflection_kind,
            "status": status,
            "snippet": snippet,
            "severity": severity,
            "evidence": (f"Hostile Host reflected in response "
                         f"({reflection_kind}) via "
                         f"{header_name}: {header_value}"),
        }

    # --- Test 3: does the server set a cookie with Domain=hostile? ---
    set_cookie = _h(resp_headers, "set-cookie")
    if set_cookie and HOSTILE_HOST.lower() in set_cookie.lower():
        return {
            "kind": "cookie",
            "status": status,
            "set_cookie": set_cookie[:300],
            "severity": "low",
            "evidence": (f"Cookie set with hostile Domain via "
                         f"{header_name}: {header_value}"),
        }

    return None


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def test_url(url: str, session=None, limiter=None,
                    cookies=None, verbose: bool = False,
                    timeout: float = 10.0) -> list[dict]:
    """Test a URL for Host header injection.

    Returns a list of findings. Uses class-dedup so we don't report
    the same bug once per header variant.
    """
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=10.0)

    info(f"host_header: testing {url}")

    findings: list[dict] = []
    seen_classes: set[str] = set()

    try:
        # Baseline request without modification
        try:
            base = await fetch(session, url, limiter,
                                cookies=cookies, timeout=timeout,
                                allow_redirects=False)
        except Exception as e:
            warn(f"host_header: baseline failed: "
                 f"{type(e).__name__}: {e}")
            return []
        if base is None or base[0] is None:
            warn("host_header: target did not respond")
            return []

        # Confirm the canary doesn't already appear in the baseline
        base_body = base[2] or ""
        if HOSTILE_HOST.lower() in base_body.lower():
            warn("host_header: canary collision in baseline — "
                 "unlikely but aborting")
            return []

        tested = 0
        for name, header_name in HOST_HEADER_VARIANTS:
            tested += 1
            # The "Forwarded" header has a special value format
            if header_name == "Forwarded":
                header_value = f"host={HOSTILE_HOST}"
            else:
                header_value = HOSTILE_HOST

            if verbose:
                info(f"  [{tested}/{len(HOST_HEADER_VARIANTS)}] "
                     f"{header_name}: {header_value}")

            r = await _test_header(
                session, url, header_name, header_value, limiter,
                cookies=cookies, timeout=timeout)
            if not r:
                if verbose:
                    info("       no reflection")
                continue

            # Dedup by kind of finding (not per-header)
            finding_class = f"{r['kind']}:{r.get('reflection_kind', '')}"
            if finding_class in seen_classes:
                if verbose:
                    info(f"       (duplicate class '{finding_class}' "
                         f"— skipped)")
                continue
            seen_classes.add(finding_class)

            finding = {
                "type": "host_header",
                "severity": r["severity"],
                "url": url,
                "parameter": header_name,
                "injection_kind": "header",
                "method": "GET",
                "payload": f"{header_name}: {header_value}",
                "http_status": r["status"],
                "evidence": r["evidence"],
                "data": {
                    "finding_class": finding_class,
                    "header_used": header_name,
                    "kind": r["kind"],
                    "location": r.get("location"),
                    "snippet": r.get("snippet"),
                    "set_cookie": r.get("set_cookie"),
                },
            }
            findings.append(finding)
            success(f"  [VULN] {header_name}: {r['evidence']}")

        return findings
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
               cookie: str | None = None) -> list[dict]:
    """CLI entry. Writes findings to store if provided."""
    cookies = parse_cookie_string(cookie) if cookie else None
    findings = await test_url(target, cookies=cookies, verbose=verbose)

    print()
    if not findings:
        info(f"no Host header injection detected on {target}")
    else:
        success(f"{len(findings)} Host header finding(s)")

    if store is not None:
        for f in findings:
            store.add_finding({
                "module": "host_header",
                "type": f["type"],
                "severity": f["severity"],
                "target": f["url"],
                "param": f["parameter"],
                "payload": f["payload"],
                "evidence": f["evidence"],
                "data": f["data"],
            })
        if findings:
            success(f"wrote {len(findings)} finding(s) to store")

    return findings


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="vuln.host_header",
        description="Detect Host header injection.",
    )
    p.add_argument("target", help="URL to test")
    p.add_argument("--cookie", default=None,
                   help="cookie string for authenticated testing")
    p.add_argument("--store", action="store_true",
                   help="write findings to active workspace")
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
        cookie=args.cookie))


if __name__ == "__main__":
    _cli()