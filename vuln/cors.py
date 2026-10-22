"""
CORS misconfiguration detection.

The browser's Same-Origin Policy blocks JavaScript on site A from
reading responses from site B. CORS (Cross-Origin Resource Sharing)
relaxes this via response headers. If the target:

  - reflects the Origin header back into Access-Control-Allow-Origin
    without validation, AND
  - sets Access-Control-Allow-Credentials: true

...then an attacker's site can read authenticated responses from the
victim's browser. That's typically a critical data-exfiltration bug.

Common misconfigurations detected:

  1. Reflects ANY Origin       — Origin: https://attacker.test → echoed
  2. Reflects with credentials — same as above + ACAC: true
  3. Null Origin accepted      — Origin: null (from sandboxed iframes,
                                 data: URLs, file://)
  4. Subdomain wildcard bypass — Origin: evil.example.com where
                                 *.example.com is reflected
  5. Prefix/suffix tricks      — Origin: https://example.com.attacker.test
                                 or https://attackerexample.com
  6. Wildcard + credentials    — ACAO: * + ACAC: true (invalid per spec
                                 but occasionally seen; browsers reject)

Severity:

  - Reflect ANY + ACAC:true              → critical
  - Reflect ANY, no credentials          → medium
  - Null origin accepted + ACAC:true     → high
  - Subdomain wildcard (internal only)   → high if attacker.test reflects
  - Suffix/prefix match only             → medium

Usage:

    from vuln.cors import test_url

    findings = await test_url("https://api.example.com/me", session, limiter)

    # CLI
    python -m vuln.cors https://api.example.com/me
    python -m vuln.cors https://api.example.com/me --cookie "session=x"

Findings written to the store:
    one row per vulnerable endpoint
"""

import asyncio
import secrets
from urllib.parse import urlparse

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Attacker-controlled-looking origins used as test values
RANDOM_TOKEN = secrets.token_hex(4)

TEST_ORIGINS = [
    # Direct reflection test — a completely different domain
    ("attacker_direct",  f"https://attacker-{RANDOM_TOKEN}.test"),
    ("http_attacker",    f"http://attacker-{RANDOM_TOKEN}.test"),

    # Null origin (sandboxed iframe, file://, data: URLs)
    ("null",             "null"),

    # Same-site subdomain abuse — if *.target.com is reflected
    # but the app trusts anything ending in .target.com, this catches it
    ("subdomain_evil",   None),    # filled in per-target

    # Prefix/suffix tricks (bypass naive regex)
    ("suffix_evil",      None),    # filled in per-target
    ("prefix_evil",      None),    # filled in per-target

    # Historical bypasses
    ("mixed_case",       None),    # filled in per-target
    ("backslash_dot",    None),    # filled in per-target
]


def _build_test_origins(target_host: str) -> list[tuple[str, str]]:
    """Build the full set of test origins for a given target host."""
    # Strip port from host
    host = target_host.split(":")[0]
    # Also strip any subdomain except the last two labels, so
    # api.example.com becomes example.com
    parts = host.split(".")
    if len(parts) >= 2:
        apex = ".".join(parts[-2:])
    else:
        apex = host

    origins = []
    for name, value in TEST_ORIGINS:
        if value is not None:
            origins.append((name, value))
            continue
        # Build the target-specific payload
        if name == "subdomain_evil":
            origins.append((name, f"https://evil.{apex}"))
        elif name == "suffix_evil":
            origins.append((name, f"https://{apex}.attacker-{RANDOM_TOKEN}.test"))
        elif name == "prefix_evil":
            origins.append((name, f"https://attacker-{RANDOM_TOKEN}{apex}"))
        elif name == "mixed_case":
            origins.append((name, f"https://{apex.upper()}.attacker.test"))
        elif name == "backslash_dot":
            origins.append((name, f"https://{apex}\\@attacker.test"))
    return origins


# ---------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------

def _h(headers, name: str) -> str:
    """Case-insensitive header lookup from a plain dict."""
    if not headers:
        return ""
    name_lc = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lc:
            return str(v)
    return ""


# ---------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------

async def _test_origin(session, url: str, origin: str, limiter,
                        cookies=None, timeout: float = 10.0) -> dict | None:
    """Send one request with `Origin: <value>`. Inspect the response."""
    try:
        status, headers, _body, _final = await fetch(
            session, url, limiter,
            method="GET",
            headers={"Origin": origin},
            cookies=cookies,
            timeout=timeout,
        )
    except Exception:
        return None

    if status is None:
        return None

    acao = _h(headers, "Access-Control-Allow-Origin")
    acac = _h(headers, "Access-Control-Allow-Credentials").lower()
    acam = _h(headers, "Access-Control-Allow-Methods")
    acah = _h(headers, "Access-Control-Allow-Headers")

    if not acao:
        return None

    return {
        "status": status,
        "acao": acao,
        "acac": acac,
        "acam": acam,
        "acah": acah,
        "credentials": acac == "true",
    }


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def test_url(url: str, session=None, limiter=None,
                    cookies=None, verbose: bool = False,
                    timeout: float = 10.0) -> list[dict]:
    """Test a URL for CORS misconfiguration.

    Sends requests with multiple attacker-controlled Origin values and
    inspects the ACAO/ACAC response headers. Returns a list of findings.
    """
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    parsed = urlparse(url)
    target_host = parsed.hostname or ""

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=10.0)

    info(f"cors: testing {url}")

    findings: list[dict] = []

    try:
        # Baseline: request without Origin to see if CORS is enabled at all
        try:
            base = await fetch(session, url, limiter,
                                cookies=cookies, timeout=timeout)
        except Exception as e:
            warn(f"cors: baseline failed: {type(e).__name__}: {e}")
            return []
        if base is None or base[0] is None:
            warn("cors: target did not respond")
            return []

        # Check baseline for CORS headers when no Origin was sent
        base_acao = _h(base[1], "Access-Control-Allow-Origin")
        if not base_acao:
            if verbose:
                info("  no CORS headers on baseline request (may still "
                     "reflect on specific origins)")

        # Build the origin list and test each. We dedupe findings by
        # a "class" key so we don't report the same underlying bug 8
        # times when ACAO: * applies to every origin we try.
        origins = _build_test_origins(target_host)
        seen_classes: set[str] = set()

        for name, origin in origins:
            r = await _test_origin(session, url, origin, limiter,
                                     cookies=cookies, timeout=timeout)
            if not r:
                continue

            acao = r["acao"]
            acac = r["acac"]

            reflected = (acao.strip() == origin.strip())
            substring_match = (origin in acao or acao in origin) and \
                              not reflected and acao not in ("*", "")
            wildcard = acao == "*"

            severity = None
            evidence = None
            # A "class" identifies the distinct bug shape. Two tests
            # that produce the same class → only reported once.
            finding_class = None

            if reflected and r["credentials"]:
                severity = "critical"
                finding_class = "reflected_with_credentials"
                evidence = (f"Origin '{origin}' reflected into ACAO "
                            f"with ACAC: true → any site can read "
                            f"authenticated responses")
            elif reflected:
                severity = "medium"
                finding_class = "reflected_no_credentials"
                evidence = (f"Origin '{origin}' reflected into ACAO "
                            f"(no credentials)")
            elif wildcard and r["credentials"]:
                severity = "high"
                finding_class = "wildcard_with_credentials"
                evidence = (f"ACAO: * with ACAC: true — invalid per "
                            f"spec, browser-dependent")
            elif substring_match and r["credentials"]:
                severity = "high"
                finding_class = "partial_match_with_credentials"
                evidence = (f"Partial-match ACAO '{acao}' for origin "
                            f"'{origin}' with credentials")
            elif substring_match:
                severity = "medium"
                finding_class = "partial_match_no_credentials"
                evidence = (f"Partial-match ACAO '{acao}' for origin "
                            f"'{origin}'")
            elif wildcard:
                severity = "low"
                finding_class = "wildcard_no_credentials"
                evidence = f"ACAO: * (wildcard, no credentials)"

            if not severity:
                if verbose:
                    info(f"  [{name}] OK (ACAO: {acao or 'absent'})")
                continue

            # Dedupe by class — only report each class once per URL
            if finding_class in seen_classes:
                if verbose:
                    info(f"  [{name}] (duplicate of "
                         f"'{finding_class}' class — skipped)")
                continue
            seen_classes.add(finding_class)

            finding = {
                "type": "cors",
                "severity": severity,
                "url": url,
                "parameter": "Origin",
                "injection_kind": "header",
                "method": "GET",
                "payload": origin,
                "http_status": r["status"],
                "evidence": evidence,
                "data": {
                    "finding_class": finding_class,
                    "test_name": name,
                    "acao": acao,
                    "acac": acac,
                    "acam": r["acam"],
                    "acah": r["acah"],
                    "credentials": r["credentials"],
                    "reflected": reflected,
                    "substring_match": substring_match,
                    "wildcard": wildcard,
                },
            }
            findings.append(finding)
            success(f"  [VULN] {name}: {evidence}")

            # If we already have a critical finding, we're done — no
            # reason to keep probing.
            if severity == "critical":
                break

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
        info(f"no CORS misconfiguration detected on {target}")
    else:
        success(f"{len(findings)} CORS finding(s)")

    if store is not None:
        for f in findings:
            store.add_finding({
                "module": "cors",
                "type": f["type"],
                "severity": f["severity"],
                "target": f["url"],
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
        prog="vuln.cors",
        description="Detect CORS misconfigurations.",
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