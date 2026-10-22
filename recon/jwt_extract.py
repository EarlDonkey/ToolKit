"""
JWT extraction from live web responses.

Crawls a target and extracts JWTs found in:
  - Response headers (Authorization, Set-Cookie, X-*, custom)
  - Response cookies
  - Response bodies (HTML, JSON, XML)
  - Linked JavaScript files (bundles often contain JWTs in comments,
    test fixtures, or hardcoded sample tokens)

Why this matters:

  JWTs frequently leak because:
    - Debug pages embed them in HTML for developer convenience
    - Sample tokens are hardcoded in JS bundles
    - Error responses include the full request (headers + body)
    - Old tokens remain in cached HTML
    - Analytics / logging dashboards render them

  Once you have a live JWT, `vuln/jwt.py` can decode it, run offline
  attacks, and verify forged tokens against the source app.

Design:

  - Crawls the target's HTML pages for linked JS files, then scans
    every downloaded asset for JWT-shaped strings.
  - Deduplicates tokens by *payload* (the middle segment) so that
    if a JS bundle contains 16 copies of the same JWT with different
    signatures (as some bundlers do), you see it once with a count.
  - Classifies tokens:
      live       — has a signature, likely from a real request
      sample     — matches a known demo/example token
      jwt-shaped — a valid-looking JWT but likely unused (e.g. tests)
  - Records where each token was found (source URL, location).

Usage:

    from recon.jwt_extract import extract

    results = await extract(
        "https://example.com/",
        session, limiter, max_pages=50)

    # CLI
    python -m recon.jwt_extract https://example.com/
    python -m recon.jwt_extract https://example.com/ --max-pages 100 -v
    python -m recon.jwt_extract https://example.com/ --attack
    python -m recon.jwt_extract https://example.com/ --cookie "session=x"

Findings written to the store:
    one row per unique payload, with `data.locations[]` listing every
    place it was seen.
"""

import asyncio
import json as _json
import re
import time
from urllib.parse import urlparse, urljoin

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Broad JWT regex.
JWT_REGEX = re.compile(
    r"\b("
    r"eyJ[A-Za-z0-9_-]{2,}"       # header
    r"\."
    r"eyJ[A-Za-z0-9_-]{2,}"       # payload
    r"\."
    r"[A-Za-z0-9_-]{10,}={0,2}"   # signature (min 10 chars)
    r"(?:\.[A-Za-z0-9_-]+)?"      # optional 5th segment for JWE
    r")\b"
)

# JS file references in HTML
SCRIPT_SRC_RE = re.compile(
    r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

# Location labels
LOCATION_HEADER = "header"
LOCATION_COOKIE = "cookie"
LOCATION_BODY = "body"
LOCATION_JS = "js-file"

# Known sample / demo tokens. These are published in tutorials,
# are widely known, and are almost never used in production.
KNOWN_SAMPLE_SIGNATURES = {
    # jwt.io tutorial token (signed with "your-256-bit-secret")
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
}

DEFAULT_CONCURRENCY = 8
DEFAULT_MAX_PAGES = 50
DEFAULT_MAX_JS = 30


# ---------------------------------------------------------------------
# Token extraction
# ---------------------------------------------------------------------

def extract_jwts(text: str) -> set[str]:
    """Find every JWT-looking string in `text`."""
    if not text:
        return set()
    return set(JWT_REGEX.findall(text))


def _extract_from_headers(headers: dict) -> dict[str, list[str]]:
    out = {}
    if not headers:
        return out
    for name, value in headers.items():
        toks = extract_jwts(str(value))
        if toks:
            out[name] = sorted(toks)
    return out


# ---------------------------------------------------------------------
# Token classification
# ---------------------------------------------------------------------

def _decode_segment(b64: str) -> dict | None:
    """Best-effort base64url-decode a JWT segment to a dict."""
    import base64
    try:
        pad = "=" * (-len(b64) % 4)
        raw = base64.urlsafe_b64decode(b64 + pad)
        return _json.loads(raw)
    except Exception:
        return None


def classify_token(token: str) -> dict:
    """Return classification metadata for a JWT.

    Returns:
        {
          "header": dict | None,
          "payload": dict | None,
          "signature_b64": str,
          "alg": str | None,
          "class": "live" | "sample" | "jwt-shaped",
          "note": str,
        }
    """
    parts = token.split(".")
    meta = {
        "header": None,
        "payload": None,
        "signature_b64": "",
        "alg": None,
        "class": "jwt-shaped",
        "note": "",
    }
    if len(parts) < 3:
        return meta
    meta["header"] = _decode_segment(parts[0])
    meta["payload"] = _decode_segment(parts[1])
    meta["signature_b64"] = parts[2] if len(parts) > 2 else ""

    if meta["header"]:
        meta["alg"] = meta["header"].get("alg")

    # Sample classification
    if meta["signature_b64"] in KNOWN_SAMPLE_SIGNATURES:
        meta["class"] = "sample"
        meta["note"] = "known demo token (jwt.io tutorial)"
        return meta

    # jwt-shaped: alg=none or clearly a test
    if meta["header"] and (meta["header"].get("alg") or "").lower() == "none":
        meta["class"] = "jwt-shaped"
        meta["note"] = "alg=none (unsigned)"
        return meta

    # Heuristic: if the payload contains obvious test markers
    payload = meta["payload"] or {}
    test_markers = ("test", "demo", "example", "sample", "foo", "bar")
    name_field = str(payload.get("name", "")).lower()
    sub_field = str(payload.get("sub", "")).lower()
    if any(m in name_field or m in sub_field for m in test_markers):
        meta["class"] = "jwt-shaped"
        meta["note"] = "payload contains test markers"
        return meta

    # Otherwise, assume live
    if meta["signature_b64"]:
        meta["class"] = "live"
        meta["note"] = "has signature, not a known sample"
    return meta


# ---------------------------------------------------------------------
# Page fetching
# ---------------------------------------------------------------------

async def _fetch_text(session, url: str, limiter,
                       timeout: float = 15.0,
                       max_bytes: int = 2 * 1024 * 1024) -> dict | None:
    """Fetch a URL. Returns dict with status, headers, body, cookies."""
    try:
        status, headers, body, final = await fetch(
            session, url, limiter, timeout=timeout)
    except Exception:
        return None
    if status is None:
        return None
    body = (body or "")[:max_bytes]
    return {
        "url": url,
        "final_url": final or url,
        "status": status,
        "headers": headers or {},
        "body": body,
    }


def _extract_from_response(resp: dict) -> list[dict]:
    """Return list of {token, location, source_url, detail} for one response."""
    found = []
    src = resp["final_url"]

    # Headers
    for hname, toks in _extract_from_headers(resp["headers"]).items():
        for t in toks:
            found.append({
                "token": t,
                "location": LOCATION_HEADER,
                "source_url": src,
                "detail": hname,
            })

    # Cookies
    set_cookie = ""
    for k, v in resp["headers"].items():
        if k.lower() == "set-cookie":
            set_cookie = v
            break
    if set_cookie:
        for t in extract_jwts(set_cookie):
            found.append({
                "token": t,
                "location": LOCATION_COOKIE,
                "source_url": src,
                "detail": "Set-Cookie",
            })

    # Body
    for t in extract_jwts(resp["body"]):
        found.append({
            "token": t,
            "location": LOCATION_BODY,
            "source_url": src,
            "detail": "response body",
        })

    return found


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def extract(target: str, session=None, limiter=None,
                    cookies=None, max_pages: int = DEFAULT_MAX_PAGES,
                    max_js: int = DEFAULT_MAX_JS,
                    concurrency: int = DEFAULT_CONCURRENCY,
                    verbose: bool = False,
                    timeout: float = 15.0,
                    rate: float = 10.0) -> dict:
    """Crawl a target and extract JWTs from every response.

    Dedup: unique tokens are keyed by payload (segment 2). If the same
    payload appears in many places (e.g., a JS bundle with multiple
    copies), it's reported once with a list of locations.
    """
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=rate)

    start = time.time()

    info(f"jwt_extract: scanning {target} "
         f"(max_pages={max_pages}, max_js={max_js})")

    # Dedup by payload
    # payload_key -> {token, locations: [ {location, source_url, detail} ]}
    by_payload: dict[str, dict] = {}
    pages_scanned = 0
    js_scanned = 0

    to_visit: list[str] = [target]
    visited: set[str] = set()
    base_host = urlparse(target).hostname or ""

    try:
        while to_visit and pages_scanned < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            resp = await _fetch_text(session, url, limiter,
                                       timeout=timeout)
            pages_scanned += 1

            if resp is None:
                if verbose:
                    warn(f"  [{pages_scanned}] {url} — fetch failed")
                continue

            if verbose:
                info(f"  [{pages_scanned}] {url} — "
                     f"status={resp['status']} "
                     f"len={len(resp['body'])}")

            # Track any new payloads
            new_here = 0
            for item in _extract_from_response(resp):
                tok = item["token"]
                payload_key = tok.split(".")[1] if tok.count(".") >= 1 else tok
                if payload_key not in by_payload:
                    by_payload[payload_key] = {
                        "token": tok,
                        "locations": [],
                    }
                    new_here += 1
                by_payload[payload_key]["locations"].append({
                    "location": item["location"],
                    "source_url": item["source_url"],
                    "detail": item["detail"],
                })

            if new_here and not verbose:
                success(f"    +{new_here} new JWT(s) from {url[:60]}")

            # Scan linked JS files
            if "html" in (resp["headers"].get("Content-Type", "") or
                          resp["headers"].get("content-type", "")).lower():
                for src in SCRIPT_SRC_RE.findall(resp["body"]):
                    if js_scanned >= max_js:
                        break
                    js_url = urljoin(resp["final_url"], src)
                    if not js_url.startswith(("http://", "https://")):
                        continue
                    if base_host and base_host not in urlparse(js_url).hostname:
                        continue
                    if js_url in visited:
                        continue
                    visited.add(js_url)

                    js_resp = await _fetch_text(session, js_url, limiter,
                                                 timeout=timeout,
                                                 max_bytes=2 * 1024 * 1024)
                    js_scanned += 1
                    if js_resp is None:
                        continue

                    js_new = 0
                    for t in extract_jwts(js_resp["body"]):
                        payload_key = t.split(".")[1] if t.count(".") >= 1 else t
                        if payload_key not in by_payload:
                            by_payload[payload_key] = {
                                "token": t,
                                "locations": [],
                            }
                            js_new += 1
                        by_payload[payload_key]["locations"].append({
                            "location": LOCATION_JS,
                            "source_url": js_url,
                            "detail": "js file",
                        })
                    if js_new and not verbose:
                        success(f"    +{js_new} new JWT(s) from "
                                f"{js_url[-60:]}")

            if pages_scanned >= max_pages:
                break

    finally:
        if own_session:
            await session.close()

    elapsed = time.time() - start

    # Build the output list with classification and dedup'd locations
    tokens = []
    for payload_key, entry in by_payload.items():
        meta = classify_token(entry["token"])
        tokens.append({
            "token": entry["token"],
            "payload_key": payload_key,
            "locations": entry["locations"],
            "location_count": len(entry["locations"]),
            "class": meta["class"],
            "alg": meta["alg"],
            "note": meta["note"],
            "header": meta["header"],
            "payload": meta["payload"],
        })

    # Sort: live first, then jwt-shaped, then sample
    order = {"live": 0, "jwt-shaped": 1, "sample": 2}
    tokens.sort(key=lambda t: (order.get(t["class"], 9),
                                 t["payload_key"]))

    print()
    if tokens:
        by_class = {}
        for t in tokens:
            by_class[t["class"]] = by_class.get(t["class"], 0) + 1
        summary = ", ".join(f"{n} {c}" for c, n in by_class.items())
        success(f"jwt_extract: {len(tokens)} unique token(s) "
                f"({summary}) across {pages_scanned} page(s) + "
                f"{js_scanned} JS file(s) ({elapsed:.1f}s)")
    else:
        info(f"jwt_extract: no JWTs found "
             f"({pages_scanned} page(s), {js_scanned} JS file(s), "
             f"{elapsed:.1f}s)")

    return {
        "target": target,
        "tokens": tokens,
        "pages_scanned": pages_scanned,
        "js_files_scanned": js_scanned,
        "elapsed": round(elapsed, 2),
    }


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
               cookie: str | None = None,
               max_pages: int = DEFAULT_MAX_PAGES,
               max_js: int = DEFAULT_MAX_JS,
               rate: float = 10.0,
               attack: bool = False,
               verify_url: str | None = None) -> dict:
    """CLI entry. Optionally attacks tokens with vuln/jwt.py."""
    cookies = parse_cookie_string(cookie) if cookie else None

    result = await extract(
        target, cookies=cookies, max_pages=max_pages,
        max_js=max_js, verbose=verbose, rate=rate)

    # --- Display tokens ---
    if result["tokens"]:
        print()
        info("Discovered tokens:")
        for i, t in enumerate(result["tokens"], 1):
            locations_summary = ", ".join(
                sorted(set(f"{l['location']}" for l in t["locations"])))
            if t["location_count"] > 1:
                locations_summary += f" ×{t['location_count']}"
            alg = t["alg"] or "?"
            marker = {
                "live":       "[LIVE]",
                "jwt-shaped": "[JWT ]",
                "sample":     "[SAMP]",
            }.get(t["class"], "[?   ]")
            print(f"  {i:3d}. {marker} alg={alg:6s} "
                  f"sources={locations_summary}")
            if t["note"]:
                print(f"       note: {t['note']}")
            # Show subject/name from payload if present
            payload = t.get("payload") or {}
            interesting = []
            for k in ("sub", "name", "email", "user", "user_id",
                      "role", "iss", "aud", "exp"):
                if k in payload:
                    interesting.append(f"{k}={payload[k]!r}")
            if interesting:
                print(f"       {', '.join(interesting[:4])}")

    # --- Store findings ---
    if store is not None:
        for t in result["tokens"]:
            store.add_finding({
                "module": "jwt_extract",
                "type": "jwt_exposed",
                "severity": {
                    "live":       "high",
                    "jwt-shaped": "low",
                    "sample":     "info",
                }.get(t["class"], "info"),
                "target": t["locations"][0]["source_url"],
                "evidence": (f"{t['class']} JWT (alg={t['alg']}) "
                             f"seen in {t['location_count']} location(s)"),
                "data": {
                    "token": t["token"][:200],
                    "class": t["class"],
                    "alg": t["alg"],
                    "note": t["note"],
                    "locations": t["locations"],
                    "payload": t.get("payload"),
                    "header": t.get("header"),
                },
            })
        success(f"wrote {len(result['tokens'])} finding(s) to store")

    # --- Optional: attack each token ---
    if attack and result["tokens"]:
        from vuln import jwt as jwt_mod
        # Only attack live + jwt-shaped (skip samples)
        targets = [t for t in result["tokens"] if t["class"] != "sample"]
        if not targets:
            info("jwt_extract: all tokens are known samples — "
                 "nothing to attack")
            return result

        print()
        info(f"jwt_extract: attacking {len(targets)} non-sample "
             f"token(s)")

        for t in targets:
            tok = t["token"]
            print()
            info(f"  --- {t['class']} alg={t['alg']} ---")

            offline = jwt_mod.attack(tok, verbose=False)
            findings = offline.get("findings", [])
            if not findings:
                info("    no offline attacks succeeded")
                continue

            by_atk = {}
            for f in findings:
                by_atk.setdefault(f["attack"], []).append(f)

            for atk, items in by_atk.items():
                if atk == "weak_key":
                    success(f"    weak_key: FOUND {items[0]['key']!r}")
                elif atk == "alg_none":
                    info(f"    alg_none: {len(items)} forge variants")
                else:
                    info(f"    {atk}: {len(items)} variant(s)")

            # Optional verification
            if verify_url:
                priority = ["weak_key", "alg_none", "kid", "alg_confusion"]
                for atk in priority:
                    for f in by_atk.get(atk, []):
                        ft = f.get("forged_token")
                        if not ft or "<sign here>" in ft:
                            continue
                        r = await jwt_mod.verify_forgery(
                            verify_url, ft)
                        if r.get("accepted"):
                            success(f"    ✓ ACCEPTED ({atk}) — "
                                    f"HTTP {r['status_forged']} "
                                    f"(anon {r.get('status_anon')})")
                        else:
                            info(f"    ✗ rejected ({atk}) — "
                                 f"HTTP {r.get('status_forged')}")
                        break
                    else:
                        continue
                    break

    return result


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.jwt_extract",
        description="Crawl a target and extract JWTs from responses.",
    )
    p.add_argument("target", help="URL to crawl")
    p.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES,
                   help=f"max pages to crawl (default {DEFAULT_MAX_PAGES})")
    p.add_argument("--max-js", type=int, default=DEFAULT_MAX_JS,
                   help=f"max linked JS files to fetch "
                        f"(default {DEFAULT_MAX_JS})")
    p.add_argument("--rate", type=float, default=10.0,
                   help="requests per second (default 10)")
    p.add_argument("--cookie", default=None,
                   help="cookie string for authenticated crawling")
    p.add_argument("--attack", action="store_true",
                   help="automatically attack each found token with "
                        "vuln/jwt.py")
    p.add_argument("--verify", default=None,
                   help="URL to verify forged tokens against "
                        "(used with --attack)")
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
        cookie=args.cookie, max_pages=args.max_pages,
        max_js=args.max_js, rate=args.rate,
        attack=args.attack, verify_url=args.verify))


if __name__ == "__main__":
    _cli()