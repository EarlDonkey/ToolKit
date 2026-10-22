"""
CRLF injection detection.

HTTP response splitting and header injection. Occurs when an app
embeds user input into a response header (Location, Set-Cookie,
Custom-Header, etc.) without stripping CR (\\r) and LF (\\n). Result:

  1. Header injection: attacker adds arbitrary headers to the response.
       ?url=x%0d%0aSet-Cookie:admin=1

  2. Response splitting: attacker terminates the response early and
     starts a new one, enabling stored XSS and cache poisoning.
       ?url=x%0d%0a%0d%0a<script>alert(1)</script>

  3. Log injection: newlines in log lines forge entries.

Detection strategy:

  For each parameter, inject a canary header value via CRLF + a
  unique header name. Inspect the response:

    - If our canary header appears in the response headers →
      header injection confirmed.

    - If the response body starts with content that follows an
      injected blank line → response splitting confirmed (we look
      for our canary string as a standalone line).

  We test several encoding variants because filters often strip
  raw \\r\\n but miss encoded forms:

    %0d%0a        (URL-encoded)
    %0D%0A        (uppercase hex)
    \\r\\n         (raw)
    %E5%98%8A%E5%98%8D  (UTF-8 overlong CR/LF — bypasses naive decoders)
    %0a           (LF only — some frameworks normalize this)
    %23           (for fragment-based injection)
    %u000d%u000a  (IIS-style unicode escapes)

Usage:

    from vuln.crlf import test_url

    findings = await test_url(
        "https://example.com/redirect?url=x",
        session, limiter)

    # CLI
    python -m vuln.crlf "https://example.com/?url=x"
    python -m vuln.crlf "https://example.com/?url=x" --param url

Findings written to the store:
    one row per vulnerable parameter
"""

import asyncio
import secrets
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse,
)

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Unique canary header names/values so we can detect our injections
CANARY_HEADER = f"x-tk-canary-{secrets.token_hex(4)}"
CANARY_VALUE = secrets.token_hex(8)
CANARY_BODY_MARKER = f"tk-crlf-canary-{secrets.token_hex(4)}"

# Common parameter names that often end up in headers
COMMON_PARAMS = [
    # Redirect-ish
    "url", "uri", "redirect", "redirect_uri", "return", "next",
    "continue", "dest", "target", "goto", "callback",
    # Cookie-ish
    "cookie", "session", "token", "auth",
    # Header-ish
    "host", "referer", "referrer", "origin", "user-agent",
    "x-forwarded-for", "x-forwarded-host", "x-real-ip",
    # Generic
    "q", "query", "search", "name", "file", "path", "page",
    "lang", "locale", "country", "theme", "template",
    "ref", "referrer", "utm_source", "utm_medium", "utm_campaign",
]


# Encoding variants for CR + LF. The comment documents why we include each.
CRLF_VARIANTS = [
    ("url_encoded",       "%0d%0a"),
    ("url_encoded_upper", "%0D%0A"),
    ("lf_only",           "%0a"),
    ("cr_only",           "%0d"),
    ("unicode_iis",       "%u000d%u000a"),
    ("utf8_overlong",     "%E5%98%8A%E5%98%8D"),
]


# ---------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------

def _get_params(url: str) -> list[str]:
    parsed = urlparse(url)
    return list(parse_qs(parsed.query, keep_blank_values=True).keys())


def _set_param_raw(url: str, name: str, value: str) -> str:
    """Set a param value. Does NOT URL-encode the value — used when the
    payload is already pre-encoded."""
    parsed = urlparse(url)
    qp = parse_qs(parsed.query, keep_blank_values=True)
    qp[name] = [value]
    # We manually build the query string because urlencode() would
    # percent-encode the % signs we want to preserve
    pairs = []
    for k, vs in qp.items():
        for v in vs:
            pairs.append(f"{k}={v}")
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, "&".join(pairs), parsed.fragment,
    ))


# ---------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------

def _headers_to_dict(headers) -> dict:
    """Normalize a headers dict to lowercase keys."""
    if not headers:
        return {}
    return {k.lower(): v for k, v in headers.items()}


async def _test_variant(session, base_url: str, param: str,
                         crlf: str, limiter,
                         cookies=None, timeout: float = 10.0) -> dict | None:
    """Try one CRLF payload variant on one parameter."""
    # Two payloads per variant:
    #   1. Header injection: inject a Set-Cookie style header
    #   2. Response splitting: inject a blank line + a body marker
    payloads = [
        # Header injection
        (f"value{crlf}{CANARY_HEADER}: {CANARY_VALUE}",
         "header_injection"),
        # Response splitting
        (f"value{crlf}{crlf}{CANARY_BODY_MARKER}",
         "response_splitting"),
    ]

    for payload, kind in payloads:
        test_url = _set_param_raw(base_url, param, payload)
        try:
            status, headers, body, _final = await fetch(
                session, test_url, limiter,
                method="GET",
                allow_redirects=False,
                cookies=cookies,
                timeout=timeout,
            )
        except Exception:
            continue

        if status is None:
            continue

        headers_lc = _headers_to_dict(headers)

        # --- Check 1: header injection ---
        if kind == "header_injection":
            if CANARY_HEADER in headers_lc:
                return {
                    "kind": kind,
                    "status": status,
                    "header_name": CANARY_HEADER,
                    "header_value": headers_lc[CANARY_HEADER],
                    "payload_variant": crlf,
                }

        # --- Check 2: response splitting ---
        if kind == "response_splitting":
            # Our marker should appear in the body if the split
            # actually happened. It might also appear inside the body
            # as plain text (not a real split) — we accept either
            # as a "confirmed" injection but note the difference.
            if body and CANARY_BODY_MARKER in body:
                # Try to distinguish real split from reflection:
                # if the marker appears BEFORE the original page's
                # doctype/html tag, it's likely real response splitting
                body_lower = body.lower()
                marker_pos = body_lower.find(CANARY_BODY_MARKER.lower())
                html_pos = body_lower.find("<!doctype")
                if html_pos < 0:
                    html_pos = body_lower.find("<html")
                looks_like_split = (marker_pos >= 0 and
                                     (html_pos < 0 or marker_pos < html_pos))
                return {
                    "kind": kind,
                    "status": status,
                    "body_marker": CANARY_BODY_MARKER,
                    "looks_like_split": looks_like_split,
                    "payload_variant": crlf,
                }

    return None


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def test_url(url: str, session=None, limiter=None,
                    cookies=None, params: list[str] | None = None,
                    verbose: bool = False,
                    timeout: float = 10.0) -> list[dict]:
    """Test a URL for CRLF injection across all params (or a subset).

    Returns a list of findings. Empty means clean.
    """
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    parsed = urlparse(url)

    if params is None:
        in_url = _get_params(url)
        candidates = list(dict.fromkeys(in_url + COMMON_PARAMS))
    else:
        candidates = params

    if not candidates:
        return []

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=10.0)

    info(f"crlf: testing {len(candidates)} parameter(s) on {url}")

    findings: list[dict] = []

    try:
        # Baseline request so we don't misread the server's own behavior
        try:
            base = await fetch(session, url, limiter,
                                allow_redirects=False,
                                cookies=cookies, timeout=timeout)
        except Exception as e:
            warn(f"crlf: baseline failed: {type(e).__name__}: {e}")
            return []
        if base is None or base[0] is None:
            warn("crlf: target did not respond")
            return []

        tested = 0
        for param in candidates:
            tested += 1
            if verbose:
                info(f"  [{tested}/{len(candidates)}] '{param}'")

            for variant_name, crlf in CRLF_VARIANTS:
                r = await _test_variant(
                    session, url, param, crlf, limiter,
                    cookies=cookies, timeout=timeout)
                if not r:
                    continue

                kind = r["kind"]
                if kind == "header_injection":
                    severity = "medium"
                    evidence = (f"Injected header '{r['header_name']}: "
                                f"{r['header_value']}' appeared in the "
                                f"response (variant: {variant_name})")
                else:  # response_splitting
                    severity = "high" if r.get("looks_like_split") \
                               else "medium"
                    evidence = (f"Body marker '{r['body_marker']}' "
                                f"appeared "
                                f"{'before page content' if r.get('looks_like_split') else 'in response'}"
                                f" (variant: {variant_name})")

                finding = {
                    "type": "crlf",
                    "severity": severity,
                    "url": url,
                    "parameter": param,
                    "injection_kind": "query",
                    "method": "GET",
                    "payload": f"<value>{crlf}{CANARY_HEADER}: "
                               f"{CANARY_VALUE}",
                    "http_status": r["status"],
                    "evidence": evidence,
                    "data": {
                        "variant": variant_name,
                        "injection_kind": kind,
                        "looks_like_split": r.get("looks_like_split"),
                    },
                }
                findings.append(finding)
                success(f"  [VULN] {param} → {kind} ({variant_name})")
                if verbose:
                    info(f"      {evidence}")
                # One finding per parameter is enough
                break

        return findings
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
               cookie: str | None = None,
               params: list[str] | None = None) -> list[dict]:
    """CLI entry. Writes findings to store if provided."""
    cookies = parse_cookie_string(cookie) if cookie else None
    findings = await test_url(target, cookies=cookies,
                                params=params, verbose=verbose)

    print()
    if not findings:
        info(f"no CRLF injection detected on {target}")
    else:
        success(f"{len(findings)} CRLF finding(s)")

    if store is not None:
        for f in findings:
            store.add_finding({
                "module": "crlf",
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
        prog="vuln.crlf",
        description="Detect CRLF injection vulnerabilities.",
    )
    p.add_argument("target", help="URL to test")
    p.add_argument("--param", action="append",
                   help="test only this parameter name (repeatable)")
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
        cookie=args.cookie, params=args.param))


if __name__ == "__main__":
    _cli()