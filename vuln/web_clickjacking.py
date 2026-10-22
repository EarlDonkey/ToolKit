"""
Clickjacking detection.

An attacker embeds a target site in an invisible iframe, then overlays
fake UI on top of it. When the user clicks the "Play" button, they're
actually clicking the "Delete Account" button on the real site.

The defense is one of:

  - X-Frame-Options: DENY              (no embedding, ever)
  - X-Frame-Options: SAMEORIGIN        (only same-origin embedding)
  - CSP: frame-ancestors 'none'        (modern replacement)
  - CSP: frame-ancestors 'self'        (same-origin only)

Modern sites should use CSP frame-ancestors. X-Frame-Options is legacy
but still honored by all major browsers.

Detection strategy:

  For a given URL:

    1. Fetch the response headers.
    2. Look for X-Frame-Options and Content-Security-Policy.
    3. Classify:

       SAFE            XFO: DENY | SAMEORIGIN
                    OR CSP frame-ancestors 'none' | 'self'
       WEAK            XFO set to an invalid value (ignored by browsers)
                    OR only ALLOW-FROM (deprecated, mostly unimplemented)
       MISSING         neither header present → vulnerable
       CONTRADICTORY   XFO says DENY but CSP says frame-ancestors *
                       (CSP wins on modern browsers, so actually vulnerable)

  Severity:

    MISSING          medium (if the page has state-changing actions)
                     low    (if it's a static content page)
    WEAK             low
    CONTRADICTORY    medium

  We don't attempt to determine whether the page has "state-changing
  actions" — that requires crawling and heuristics. Instead, we rate
  MISSING as medium by default and let the report reader judge.

  --json-only flag skips the HTML/CSS/JS files that never matter for
  clickjacking (they're never the top-level document).

Usage:

    from vuln.web_clickjacking import test_url

    findings = await test_url("https://example.com/account", session, limiter)

    # CLI
    python -m vuln.web_clickjacking https://example.com/account
    python -m vuln.web_clickjacking https://example.com/account --json-only

Findings written to the store:
    one row per URL with the classification in `data`
"""

import asyncio
import re
from urllib.parse import urlparse

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error


# Extensions we skip when --json-only is off but we still want to
# avoid wasting requests on obvious static assets
ASSET_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".mp3", ".wav",
    ".pdf", ".zip", ".tar", ".gz",
}


# ---------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------

def _h(headers, name: str) -> str:
    if not headers:
        return ""
    name_lc = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lc:
            return str(v).strip()
    return ""


def _parse_frame_ancestors(csp: str) -> str | None:
    """Extract the frame-ancestors directive value from a CSP header."""
    if not csp:
        return None
    # Multiple policies can be comma-separated
    for policy in csp.split(","):
        for directive in policy.split(";"):
            directive = directive.strip()
            if directive.lower().startswith("frame-ancestors"):
                # Return everything after the directive name
                parts = directive.split(None, 1)
                return parts[1] if len(parts) > 1 else ""
    return None


def _classify(xfo: str, csp: str) -> tuple[str, str]:
    """Return (class, reason). Class ∈ safe | weak | missing | contradictory."""
    xfo_l = xfo.lower().strip()
    frame_ancestors = _parse_frame_ancestors(csp)

    # --- CSP frame-ancestors analysis ---
    csp_blocks = False
    csp_allows_all = False
    if frame_ancestors is not None:
        fa = frame_ancestors.lower().strip()
        if fa in ("'none'", "none"):
            csp_blocks = True
        elif fa in ("'self'", "self"):
            csp_blocks = True  # same-origin only
        elif fa in ("*",):
            csp_allows_all = True
        elif fa.startswith("http") or fa.startswith("'") or fa:
            # Some specific origin list — partial protection, treat
            # as weak unless '*' is present
            if "*" in fa:
                csp_allows_all = True
            else:
                csp_blocks = True  # restrictive allowlist

    # --- X-Frame-Options analysis ---
    xfo_blocks = False
    xfo_weak = False
    if xfo_l in ("deny", "sameorigin"):
        xfo_blocks = True
    elif xfo_l.startswith("allow-from"):
        # ALLOW-FROM is deprecated and ignored by modern browsers.
        xfo_weak = True
    elif xfo_l:
        # Anything else (typos like "SAMEORIGIN ", "deny, sameorigin",
        # or a value set on the wrong header) is ignored.
        xfo_weak = True

    # --- Decide ---
    if csp_allows_all and xfo_blocks:
        return ("contradictory",
                "X-Frame-Options set but CSP frame-ancestors allows *")
    if csp_blocks:
        return ("safe", f"CSP frame-ancestors restricts embedding")
    if xfo_blocks:
        return ("safe", f"X-Frame-Options: {xfo}")
    if csp_allows_all:
        return ("weak", "CSP frame-ancestors explicitly allows *")
    if xfo_weak:
        return ("weak", f"X-Frame-Options has invalid value: {xfo!r}")
    return ("missing", "neither X-Frame-Options nor CSP frame-ancestors")


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def test_url(url: str, session=None, limiter=None,
                    cookies=None, verbose: bool = False,
                    timeout: float = 10.0) -> dict:
    """Check a URL for clickjacking protection.

    Returns a single finding dict (not a list) — one URL, one verdict.
    """
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    # Skip obvious static assets unless the caller insists
    path = urlparse(url).path.lower()
    if any(path.endswith(ext) for ext in ASSET_EXTENSIONS):
        return {
            "type": "clickjacking",
            "severity": "info",
            "url": url,
            "evidence": "skipped: static asset",
            "data": {"classification": "skipped", "reason": "static asset"},
        }

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=10.0)

    info(f"clickjacking: testing {url}")

    try:
        try:
            status, headers, _body, final = await fetch(
                session, url, limiter,
                cookies=cookies, timeout=timeout)
        except Exception as e:
            warn(f"clickjacking: request failed: "
                 f"{type(e).__name__}: {e}")
            return {
                "type": "clickjacking",
                "severity": "info",
                "url": url,
                "evidence": f"request failed: {type(e).__name__}",
                "data": {"classification": "error"},
            }

        if status is None:
            return {
                "type": "clickjacking",
                "severity": "info",
                "url": url,
                "evidence": "no response",
                "data": {"classification": "error"},
            }

        xfo = _h(headers, "x-frame-options")
        csp = _h(headers, "content-security-policy")
        classification, reason = _classify(xfo, csp)

        # Map classification to severity
        severity_map = {
            "safe": "info",
            "weak": "low",
            "missing": "medium",
            "contradictory": "medium",
        }
        severity = severity_map.get(classification, "info")

        finding = {
            "type": "clickjacking",
            "severity": severity,
            "url": final or url,
            "evidence": f"{classification.upper()}: {reason}",
            "data": {
                "classification": classification,
                "reason": reason,
                "x_frame_options": xfo,
                "content_security_policy": csp[:300] if csp else "",
                "http_status": status,
            },
        }

        if verbose:
            success(f"  {classification}: {reason}")
            if xfo:
                info(f"    X-Frame-Options: {xfo}")
            if csp:
                # Only show the frame-ancestors portion of CSP
                fa = _parse_frame_ancestors(csp)
                if fa is not None:
                    info(f"    frame-ancestors: {fa}")

        return finding
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
               cookie: str | None = None,
               urls: list[str] | None = None) -> list[dict]:
    """CLI entry. Accepts a single URL or a list. Writes findings to store."""
    cookies = parse_cookie_string(cookie) if cookie else None

    # Combine target + urls into a single deduped list. The CLI passes
    # the first URL as `target` and the rest as `urls`; we need to
    # test all of them, not just one or the other.
    targets = [target] + list(urls or [])
    # Dedup while preserving order
    seen = set()
    targets = [u for u in targets if not (u in seen or seen.add(u))]

    findings = []
    for u in targets:
        f = await test_url(u, cookies=cookies, verbose=verbose)
        findings.append(f)

    print()
    # Summarize by classification
    by_class: dict[str, int] = {}
    for f in findings:
        c = f.get("data", {}).get("classification", "?")
        by_class[c] = by_class.get(c, 0) + 1

    if by_class:
        summary = ", ".join(f"{n} {c}" for c, n in by_class.items())
        info(f"clickjacking results: {summary}")

    vulnerable = [f for f in findings
                  if f.get("data", {}).get("classification")
                  in ("missing", "weak", "contradictory")]
    if vulnerable:
        success(f"{len(vulnerable)} URL(s) lack proper "
                f"clickjacking protection")

    if store is not None:
        for f in findings:
            store.add_finding({
                "module": "web_clickjacking",
                "type": f["type"],
                "severity": f["severity"],
                "target": f["url"],
                "evidence": f["evidence"],
                "data": f["data"],
            })
        success(f"wrote {len(findings)} finding(s) to store")

    return findings


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="vuln.web_clickjacking",
        description="Detect missing clickjacking protection.",
    )
    p.add_argument("target", nargs="+",
                   help="URL(s) to test (multiple allowed)")
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

    # Handle 1 URL (common) or N URLs (from shell globbing)
    first = args.target[0]
    rest = args.target[1:] if len(args.target) > 1 else None

    asyncio.run(run(
        first, store=store, verbose=args.verbose,
        cookie=args.cookie, urls=rest))


if __name__ == "__main__":
    _cli()