"""
Open redirect detection.

An open redirect vulnerability exists when an application accepts a URL
in a parameter and redirects the user to it without validating the
destination. Common parameter names: `next`, `url`, `redirect`,
`return`, `returnUrl`, `continue`, `dest`, `destination`, `r`, `u`,
`target`, `goto`, `out`, `view`, `login`, `logout`, `back`...

Impact:

  1. Phishing: send victim a link to the REAL company domain that
     forwards to attacker's site. Higher trust, lower suspicion.

  2. OAuth token theft: if the OAuth flow has an open redirect on its
     redirect_uri, the auth code can be exfiltrated.

  3. Password reset poisoning: if the reset link's host comes from a
     URL parameter, an attacker can poison it to their domain.

  4. SSRF chain: some open redirects can be chained to reach internal
     services from a trusted origin.

Detection strategy:

  For each parameter in the URL, replace its value with a canary URL
  pointing at a domain we control (default: a very unlikely name like
  `evil-canary-xyz.example`). Request with `allow_redirects=False`.
  Inspect the `Location:` header:

    - If it contains our canary host → VULNERABLE
    - If it points to the same host as the original → probably safe
    - If it points to a different host → SUSPICIOUS (report but low confidence)
    - If no redirect → not vulnerable (for this param)

  We also test a few obfuscated bypasses for weak filters:

    - //canary                    (protocol-relative)
    - https://canary              (absolute)
    - /\\canary                   (backslash trick)
    - \\\\canary                  (double backslash)
    - @canary                     (userinfo trick: real-site@canary)
    - canary%2f                   (encoded slash)
    - canary#@origin              (fragment trick)

Usage:

    from vuln.open_redirect import test_url

    findings = await test_url(
        "https://example.com/login?next=/dashboard",
        session, limiter)

    # CLI
    python -m vuln.open_redirect https://example.com/login?next=/dashboard
    python -m vuln.open_redirect https://example.com --include-cookies

Findings written to the store:
    one row per vulnerable parameter
"""

import asyncio
import secrets
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse, urljoin,
)

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# The domain we use as a canary. It doesn't need to actually resolve —
# we only look at the Location header the server sends back. Any
# server that puts this domain in Location is vulnerable regardless of
# whether the redirect would actually succeed in a browser.
CANARY_HOST = f"canary-{secrets.token_hex(6)}.tk-toolkit-canary.test"

# Canonical parameter names that commonly accept redirect URLs
COMMON_REDIRECT_PARAMS = [
    "url", "uri", "link", "redirect", "redirect_uri", "redirect_url",
    "return", "return_to", "returnurl", "return_url",
    "next", "continue", "dest", "destination", "target", "goto",
    "out", "view", "to", "from", "ref", "referer", "referrer",
    "back", "backurl", "back_url", "forward", "forward_url",
    "callback", "callback_url", "success", "failure", "cancel",
    "logout", "logout_url", "login", "login_url", "signin", "signout",
    "r", "u", "l", "d", "n", "t",
    "checkout_url", "checkouturl", "payment_url", "returnurl",
]


# Obfuscation payloads, in order of likely success
CANARY_PAYLOADS = [
    ("absolute",       f"https://{CANARY_HOST}"),
    ("protocol_rel",   f"//{CANARY_HOST}"),
    ("https_prefix",   f"https:{CANARY_HOST}"),
    ("backslash",      f"\\{CANARY_HOST}"),
    ("double_back",    f"\\\\{CANARY_HOST}"),
    ("userinfo",       f"@https://{CANARY_HOST}"),
    ("userinfo_swap",  f"https://real-site.test@{CANARY_HOST}"),
    ("encoded_slash",  f"https:%2F%2F{CANARY_HOST}"),
    ("encoded_hash",   f"https://{CANARY_HOST}%23@real-site.test"),
    ("triple_slash",   f"///{CANARY_HOST}"),
    ("at_direct",      f"@{CANARY_HOST}"),
    ("trailing_dot",   f"https://{CANARY_HOST}."),
]


# Statuses we treat as "a redirect happened"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


# ---------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------

def _get_params(url: str) -> list[str]:
    """Return every query-parameter name in the URL."""
    parsed = urlparse(url)
    return list(parse_qs(parsed.query, keep_blank_values=True).keys())


def _set_param(url: str, name: str, value: str) -> str:
    """Return a new URL with the named param set to `value`."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[name] = [value]
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlencode(qs, doseq=True), parsed.fragment,
    ))


def _is_same_host(location: str, original_host: str) -> bool:
    """Return True if `location` points to the same host as the original."""
    try:
        # Handle relative paths
        if location.startswith("/"):
            # A leading // means protocol-relative — NOT same-host
            if location.startswith("//"):
                return False
            return True
        parsed = urlparse(location)
        return parsed.hostname == original_host
    except Exception:
        return False


def _contains_canary(location: str) -> bool:
    """Return True if the canary host appears anywhere in Location."""
    if not location:
        return False
    # Look for either the bare canary or its variants
    return CANARY_HOST.lower() in location.lower()


# ---------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------

async def _test_payload(session, base_url: str, param: str,
                         payload: str, limiter,
                         cookies=None, timeout: float = 10.0) -> dict | None:
    """Try one payload on one parameter. Returns finding dict if vuln."""
    test_url = _set_param(base_url, param, payload)
    try:
        status, headers, _body, _final = await fetch(
            session, test_url, limiter,
            method="GET",
            allow_redirects=False,
            cookies=cookies,
            timeout=timeout,
        )
    except Exception:
        return None

    if status is None:
        return None

    # Look at the Location header on redirect responses
    if status not in REDIRECT_STATUSES:
        # Some servers do a "soft redirect" via JS or meta refresh.
        # For now we only check the Location header — clean and low-FP.
        return None

    location = ""
    for k, v in (headers or {}).items():
        if k.lower() == "location":
            location = v
            break

    if not _contains_canary(location):
        return None

    return {
        "status": status,
        "location": location,
    }


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def test_url(url: str, session=None, limiter=None,
                    cookies=None, params: list[str] | None = None,
                    verbose: bool = False,
                    timeout: float = 10.0) -> list[dict]:
    """Test a URL for open redirect on every parameter (or a subset).

    Returns a list of findings. Empty means no open redirect detected.
    """
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    parsed = urlparse(url)
    original_host = parsed.hostname or ""

    # Determine which params to test
    if params is None:
        # Test query-string params + a broad set of common names
        in_url = _get_params(url)
        candidates = list(dict.fromkeys(in_url + COMMON_REDIRECT_PARAMS))
    else:
        candidates = params

    if not candidates:
        return []

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=10.0)

    info(f"open_redirect: testing {len(candidates)} parameter(s) "
         f"on {url}")

    findings: list[dict] = []

    try:
        # First, baseline the target to see if it responds at all
        try:
            base = await fetch(session, url, limiter,
                                allow_redirects=False,
                                cookies=cookies, timeout=timeout)
        except Exception as e:
            warn(f"open_redirect: baseline failed: "
                 f"{type(e).__name__}: {e}")
            return []
        if base is None or base[0] is None:
            warn("open_redirect: target did not respond")
            return []

        tested = 0
        for param in candidates:
            tested += 1
            if verbose:
                info(f"  [{tested}/{len(candidates)}] testing "
                     f"'{param}'")

            for payload_name, payload in CANARY_PAYLOADS:
                r = await _test_payload(
                    session, url, param, payload, limiter,
                    cookies=cookies, timeout=timeout)
                if not r:
                    continue

                # Confirmed vulnerable
                location = r["location"]
                # Skip if the redirect points back to the same host
                # (some apps just echo the param into Location but
                # rewrite the host — not exploitable)
                if _is_same_host(location, original_host) and \
                        not _contains_canary(location):
                    continue

                finding = {
                    "type": "open_redirect",
                    "severity": "medium",
                    "url": url,
                    "parameter": param,
                    "injection_kind": "query",
                    "method": "GET",
                    "payload": payload,
                    "http_status": r["status"],
                    "evidence": (f"HTTP {r['status']} → "
                                 f"Location: {location[:200]}"),
                    "data": {
                        "payload_name": payload_name,
                        "location": location,
                        "canary": CANARY_HOST,
                    },
                }
                findings.append(finding)
                success(f"  [VULN] {param} → {payload_name} "
                        f"({r['status']})")
                if verbose:
                    info(f"      Location: {location[:200]}")
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
        info(f"no open redirect detected on {target}")
    else:
        success(f"{len(findings)} open redirect finding(s)")

    if store is not None:
        for f in findings:
            store.add_finding({
                "module": "open_redirect",
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
        prog="vuln.open_redirect",
        description="Detect open redirect vulnerabilities.",
    )
    p.add_argument("target", help="URL to test "
                                  "(including query string if you want "
                                  "specific params tested)")
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