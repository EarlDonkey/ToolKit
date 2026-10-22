"""
Technology stack fingerprinting.

Sends one GET to the target, then matches the response (headers, HTML,
cookies, meta tags) against a signature database. Reports every
technology detected, with version numbers where possible.

Signature database lives at recon/signatures/tech.json. Format is
Wappalyzer-compatible enough that you can drop in their full DB if
you want more coverage.

Findings written to the store:
    one row per target with all detected technologies in `data`
"""

_TECH_FINGERPRINT_MARKER = "tech_fingerprint-v1"

import json
import re
from pathlib import Path

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


SIGNATURES_PATH = Path(__file__).parent / "signatures" / "tech.json"


def load_signatures(path=SIGNATURES_PATH) -> dict:
    """Load the tech signature DB. Returns {} on failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        warn(f"tech signatures not found at {path}; using embedded fallback")
        return _embedded_fallback()
    except Exception as e:
        warn(f"could not load tech signatures: {type(e).__name__}: {e}")
        return _embedded_fallback()


def _embedded_fallback() -> dict:
    """Minimal fallback DB if the JSON file is missing."""
    return {
        "categories": {},
        "signatures": [
            {"name": "nginx", "category": "web-server",
             "headers": {"server": "nginx(?:/([0-9.]+))?"},
             "version_group": 1},
            {"name": "apache", "category": "web-server",
             "headers": {"server": "apache(?:/([0-9.]+))?"},
             "version_group": 1},
            {"name": "iis", "category": "web-server",
             "headers": {"server": "microsoft-iis(?:/([0-9.]+))?"},
             "version_group": 1},
            {"name": "php", "category": "language",
             "headers": {"x-powered-by": "php(?:/([0-9.]+))?"},
             "version_group": 1},
            {"name": "cloudflare", "category": "cdn",
             "headers": {"server": "cloudflare", "cf-ray": ".*"}},
        ],
    }


def _match_headers(headers: dict, signature: dict) -> tuple[bool, str]:
    """Return (matched, version) for header rules."""
    version = ""
    for header_name, pattern in (signature.get("headers") or {}).items():
        value = ""
        for k, v in headers.items():
            if k.lower() == header_name.lower():
                value = str(v)
                break
        if not value:
            return False, ""
        m = re.search(pattern, value, re.IGNORECASE)
        if not m:
            return False, ""
        vg = signature.get("version_group")
        if vg and len(m.groups()) >= vg:
            version = m.group(vg) or ""
    return True, version


def _match_html(html: str, signature: dict) -> tuple[bool, str]:
    """Return (matched, version) for HTML body patterns."""
    patterns = signature.get("html") or []
    if not patterns:
        return False, ""
    version = ""
    matched_any = False
    for pattern in patterns:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            matched_any = True
            vg = signature.get("version_group")
            if vg and len(m.groups()) >= vg:
                version = m.group(vg) or version
    return matched_any, version


def _match_meta(html: str, signature: dict) -> tuple[bool, str]:
    """Return (matched, version) for meta tag rules."""
    metas = signature.get("meta") or {}
    if not metas:
        return False, ""
    version = ""
    for name, pattern in metas.items():
        rx = (
            r'<meta[^>]*\bname=["\']' + re.escape(name) +
            r'["\'][^>]*\bcontent=["\']([^"\']*)["\']'
        )
        rx_rev = (
            r'<meta[^>]*\bcontent=["\']([^"\']*)["\'][^>]*\bname=["\']' +
            re.escape(name) + r'["\']'
        )
        m = re.search(rx, html, re.IGNORECASE) or \
            re.search(rx_rev, html, re.IGNORECASE)
        if not m:
            return False, ""
        content = m.group(1)
        vm = re.search(pattern, content, re.IGNORECASE)
        if vm:
            vg = signature.get("version_group")
            if vg and len(vm.groups()) >= vg:
                version = vm.group(vg) or ""
    return True, version


def _match_cookies(cookies: dict, signature: dict) -> bool:
    """Return True if any cookie name matches the signature."""
    patterns = signature.get("cookies") or []
    if not patterns:
        return False
    for name in cookies.keys():
        for pattern in patterns:
            if re.search(pattern, name, re.IGNORECASE):
                return True
    return False


async def fingerprint(url: str, session=None, verbose: bool = False) -> dict:
    """Fingerprint one URL."""
    sig_db = load_signatures()
    signatures = sig_db.get("signatures", [])

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(5.0)

    try:
        r = await fetch(session, url, limiter)
    finally:
        if own_session:
            await session.close()

    if r is None or r[2] is None:
        return {"url": url, "status": None, "technologies": [],
                "categories": {}}

    status, headers, body, final_url = r
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    html = (body or "")[:200_000]

    cookies = {}
    for k, v in headers.items():
        if k == "set-cookie":
            for chunk in str(v).split(","):
                if "=" in chunk:
                    name = chunk.split("=", 1)[0].strip()
                    cookies[name] = True

    detected = []
    for sig in signatures:
        name = sig.get("name", "")
        category = sig.get("category", "")

        matched = False
        version = ""
        evidence = ""

        if sig.get("headers"):
            matched, version = _match_headers(headers, sig)
            if matched:
                evidence = "header"

        if not matched and sig.get("html"):
            matched, v2 = _match_html(html, sig)
            if matched:
                evidence = "html"
                version = v2 or version

        if not matched and sig.get("meta"):
            matched, v2 = _match_meta(html, sig)
            if matched:
                evidence = "meta"
                version = v2 or version

        if not matched and sig.get("cookies"):
            if _match_cookies(cookies, sig):
                matched = True
                evidence = "cookie"

        if matched:
            detected.append({
                "name": name,
                "version": version,
                "category": category,
                "evidence": evidence,
            })
            if verbose:
                vstr = f" {version}" if version else ""
                info(f"  detected: {name}{vstr} ({category})")

    by_cat: dict[str, list[str]] = {}
    for t in detected:
        by_cat.setdefault(t["category"], []).append(t["name"])

    return {
        "url": final_url,
        "status": status,
        "technologies": detected,
        "categories": by_cat,
    }


async def run(target: str, store=None, verbose: bool = False) -> dict:
    """Fingerprint a target and optionally write to store."""
    url = target
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    info(f"fingerprinting tech stack on {url}")
    result = await fingerprint(url, verbose=verbose)

    print()
    if not result["technologies"]:
        warn(f"no technologies detected on {url}")
    else:
        success(f"{len(result['technologies'])} technologies detected")
        for cat, names in sorted(result["categories"].items()):
            print(f"  [{cat}]")
            for name in sorted(names):
                ver = next((t["version"] for t in result["technologies"]
                            if t["name"] == name and t["version"]), "")
                vstr = f" {ver}" if ver else ""
                print(f"    {name}{vstr}")

    if store is not None:
        store.add_finding({
            "module": "tech_fingerprint",
            "type": "informational",
            "severity": "info",
            "target": target,
            "evidence": (f"{len(result['technologies'])} technologies "
                         f"detected"),
            "data": {
                "url": result["url"],
                "status": result["status"],
                "technologies": result["technologies"],
                "categories": result["categories"],
            },
        })
        success(f"finding written to store")

    return result


def _cli():
    import argparse
    import asyncio
    p = argparse.ArgumentParser(
        prog="recon.tech_fingerprint",
        description="Fingerprint the tech stack of a URL.",
    )
    p.add_argument("target", help="URL or hostname")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--store", action="store_true",
                   help="write finding to active workspace")
    args = p.parse_args()

    store = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; use `toolkit workspace switch`")
            return
        ws = get_workspace(active)
        store = open_store(ws.db_path, workspace_name=active)

    asyncio.run(run(args.target, store=store, verbose=args.verbose))


if __name__ == "__main__":
    _cli()