"""
Single-fetch web intelligence.

Fetches the root URL once and extracts everything cheap from that one
response: security headers, CSP domain whitelist, meta tags, cookies
with attributes, redirect chain.

Then, in parallel, fetches a small, fixed set of well-known paths:

    /robots.txt
    /sitemap.xml
    /.well-known/security.txt
    /.well-known/change-password
    /.well-known/openid-configuration
    /.well-known/oauth-authorization-server
    /.well-known/jwks.json
    /.well-known/assetlinks.json
    /.well-known/apple-app-site-association
    /.well-known/mta-sts.txt
    /.well-known/nodeinfo
    /.well-known/webfinger
    /.well-known/matrix/client
    /.well-known/matrix/server
    /favicon.ico

That's ~15 requests total. In exchange you get:

  - The CSP hostname whitelist (usually 20+ names, all related to the
    target's infrastructure).
  - Every cookie's attributes (Secure/HttpOnly/SameSite leaks).
  - All well-known discovery documents (OpenID Connect config is a
    goldmine: it lists every auth endpoint).
  - Favicon mmh3 hash for cross-referencing with Shodan and other
    passive fingerprinting.

This module is one HTTP client round-trip reused by multiple
extractors. It replaces the current pattern where tech_fingerprint,
cms_fingerprint, and js_analysis each re-fetch the root.

Verbose mode (-v) uncaps every display limit: full CSP hostname list,
every meta tag, every link element, every cookie with value, the full
robots.txt rule set, the full sitemap URL list, and a preview of every
well-known document body. Non-verbose shows curated summaries with
"... and N more" hints.
"""

import asyncio
import hashlib
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn
from core.target import parse


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "x-xss-protection",
    "x-permitted-cross-domain-policies",
    "expect-ct",
)


CSP_URL_DIRECTIVES = {
    "script-src", "script-src-elem", "script-src-attr",
    "style-src", "style-src-elem", "style-src-attr",
    "img-src", "font-src", "connect-src", "media-src",
    "frame-src", "child-src", "worker-src", "manifest-src",
    "prefetch-src", "form-action", "frame-ancestors",
    "report-uri", "report-to", "base-uri",
    "sandbox",
}


WELL_KNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/mta-sts.txt",
    "/.well-known/nodeinfo",
    "/.well-known/webfinger",
    "/.well-known/matrix/client",
    "/.well-known/matrix/server",
    "/.well-known/dnt-policy.txt",
    "/.well-known/humans.txt",
]


META_NAMES_OF_INTEREST = {
    "generator", "framework",
    "og:title", "og:description", "og:url", "og:image",
    "og:site_name", "og:type",
    "twitter:card", "twitter:site", "twitter:creator",
    "twitter:title",
    "robots", "googlebot", "msvalidate.01", "yandex-verification",
    "baidu-site-verification",
    "google-site-verification", "facebook-domain-verification",
    "apple-itunes-app", "google-play-app",
    "viewport", "theme-color", "application-name",
    "csrf-token", "csrf-param", "csrf_parameter",
    "openapi",
    "referrer", "description", "keywords", "author",
}


LINK_RELS_OF_INTEREST = {
    "canonical", "alternate", "manifest", "amphtml",
    "preconnect", "dns-prefetch", "prefetch", "prerender",
    "icon", "shortcut icon", "apple-touch-icon",
    "stylesheet", "preload", "modulepreload",
    "openid.server", "openid.delegate",
    "search", "help", "license", "author",
    "me",
    "webmention", "pingback",
    "hub",
    "pgpkey",
    "salvage",
    "indieauth", "indieauth-metadata",
    "micropub",
    "authorization_endpoint", "token_endpoint",
    "jwks_uri", "userinfo_endpoint",
    "registration_endpoint", "revocation_endpoint",
    "introspection_endpoint", "end_session_endpoint",
}


_META_RE = re.compile(
    r'<meta\s+([^>]+?)/?>',
    re.IGNORECASE | re.DOTALL,
)
_META_NAME_RE = re.compile(
    r'(?:name|property|itemprop)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_META_CONTENT_RE = re.compile(
    r'content\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE | re.DOTALL,
)

_LINK_RE = re.compile(
    r'<link\s+([^>]+?)/?>',
    re.IGNORECASE | re.DOTALL,
)
_LINK_REL_RE = re.compile(
    r'rel\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_LINK_HREF_RE = re.compile(
    r'href\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_LINK_TYPE_RE = re.compile(
    r'type\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_TITLE_RE = re.compile(
    r"<title[^>]*>(.*?)</title>",
    re.IGNORECASE | re.DOTALL,
)

_FAVICON_RE = re.compile(
    r'<link[^>]*\brel\s*=\s*["\'][^"\']*\bicon\b[^"\']*["\'][^>]*'
    r'\bhref\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_FAVICON_RE_REV = re.compile(
    r'<link[^>]*\bhref\s*=\s*["\']([^"\']+)["\'][^>]*'
    r'\brel\s*=\s*["\'][^"\']*\bicon\b[^"\']*["\']',
    re.IGNORECASE,
)

_ROBOTS_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z\-]*)\s*:\s*(.+?)\s*$")

_XML_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>",
                         re.IGNORECASE | re.DOTALL)


# ---------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------

def _norm_headers(headers: dict | None) -> dict:
    if not headers:
        return {}
    return {k.lower(): v for k, v in headers.items()}


def _security_headers(headers: dict) -> dict[str, str | None]:
    out = {}
    for h in SECURITY_HEADERS:
        out[h] = headers.get(h)
    return out


# ---------------------------------------------------------------------
# CSP parsing
# ---------------------------------------------------------------------

def _parse_csp_domains(headers: dict) -> dict:
    raw = headers.get("content-security-policy") or \
          headers.get("content-security-policy-report-only") or ""
    result = {"raw": raw, "directives": {}, "hosts": []}
    if not raw:
        return result

    hosts = set()
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        if not parts:
            continue
        name = parts[0].lower()
        values = parts[1:]
        if name not in CSP_URL_DIRECTIVES:
            result["directives"].setdefault(name, values)
            continue
        result["directives"][name] = values
        for token in values:
            token = token.strip().strip("'\"")
            if not token:
                continue
            if token in ("self", "none", "unsafe-inline",
                         "unsafe-eval", "strict-dynamic",
                         "unsafe-hashes", "report-sample"):
                continue
            if "://" in token:
                token = token.split("://", 1)[1]
            token = token.split("/", 1)[0]
            if token.startswith("["):
                pass
            elif ":" in token:
                token = token.split(":", 1)[0]
            if token.startswith("*."):
                token = token[2:]
            if token in ("data:", "blob:", "filesystem:", "mediastream:"):
                continue
            if "." in token and not token.startswith("."):
                hosts.add(token.lower())

    result["hosts"] = sorted(hosts)
    return result


# ---------------------------------------------------------------------
# Meta / link parsing
# ---------------------------------------------------------------------

def _parse_meta(html: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not html:
        return out
    for m in _META_RE.finditer(html):
        attrs = m.group(1)
        name_m = _META_NAME_RE.search(attrs)
        if not name_m:
            continue
        content_m = _META_CONTENT_RE.search(attrs)
        if not content_m:
            continue
        name = name_m.group(1).strip().lower()
        content = content_m.group(1).strip()
        if name and content and name not in out:
            out[name] = content
    return out


def _parse_links(html: str, base_url: str) -> list[dict]:
    out = []
    if not html:
        return out
    for m in _LINK_RE.finditer(html):
        attrs = m.group(1)
        rel_m = _LINK_REL_RE.search(attrs)
        href_m = _LINK_HREF_RE.search(attrs)
        if not (rel_m and href_m):
            continue
        rels = [r.strip().lower() for r in rel_m.group(1).split()]
        href = href_m.group(1).strip()
        type_m = _LINK_TYPE_RE.search(attrs)
        entry = {
            "rel": rels,
            "href": href,
            "absolute": urljoin(base_url, href),
        }
        if type_m:
            entry["type"] = type_m.group(1).strip()
        out.append(entry)
    return out


def _interesting_links(links: list[dict]) -> dict:
    out: dict[str, list[dict]] = {}
    for link in links:
        for rel in link["rel"]:
            if rel in LINK_RELS_OF_INTEREST:
                out.setdefault(rel, []).append({
                    "href": link["href"],
                    "absolute": link["absolute"],
                    "type": link.get("type"),
                })
    return out


def _extract_title(html: str) -> str:
    m = _TITLE_RE.search(html or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:300]


# ---------------------------------------------------------------------
# Cookie parsing
# ---------------------------------------------------------------------

_COOKIE_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_\-\.]+)\s*=\s*(.*)$")


def _parse_set_cookie(raw: str) -> list[dict]:
    if not raw:
        return []
    parts = re.split(r",\s*(?=[A-Za-z0-9_\-\.]+\s*=)", raw)
    out = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        segments = [s.strip() for s in part.split(";")]
        if not segments:
            continue
        name_val = segments[0]
        m = _COOKIE_NAME_RE.match(name_val)
        if not m:
            continue
        cookie = {
            "name": m.group(1),
            "value": m.group(2),
            "attributes": {},
        }
        for attr in segments[1:]:
            if "=" in attr:
                k, _, v = attr.partition("=")
                cookie["attributes"][k.strip().lower()] = v.strip()
            else:
                cookie["attributes"][attr.strip().lower()] = True
        out.append(cookie)
    return out


def _all_set_cookies(headers: dict) -> list[dict]:
    raw = headers.get("set-cookie") or ""
    return _parse_set_cookie(raw)


# ---------------------------------------------------------------------
# robots.txt parsing
# ---------------------------------------------------------------------

def _parse_robots(body: str) -> dict:
    result = {
        "raw": body or "",
        "user_agents": {},
        "sitemaps": [],
        "crawl_delays": {},
        "hosts": [],
    }
    current_ua = None
    if not body:
        return result

    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ROBOTS_LINE.match(line)
        if not m:
            continue
        key = m.group(1).lower()
        value = m.group(2).strip()

        if key == "user-agent":
            current_ua = value.lower()
            result["user_agents"].setdefault(
                current_ua, {"allow": [], "disallow": []})
        elif key == "disallow" and current_ua:
            result["user_agents"][current_ua]["disallow"].append(value)
        elif key == "allow" and current_ua:
            result["user_agents"][current_ua]["allow"].append(value)
        elif key == "sitemap":
            result["sitemaps"].append(value)
        elif key == "crawl-delay" and current_ua:
            result["crawl_delays"][current_ua] = value
        elif key == "host":
            result["hosts"].append(value)

    return result


# ---------------------------------------------------------------------
# Sitemap parsing
# ---------------------------------------------------------------------

def _parse_sitemap(body: str) -> list[str]:
    if not body:
        return []
    return [m.group(1).strip()
            for m in _XML_LOC_RE.finditer(body)
            if m.group(1).strip()]


# ---------------------------------------------------------------------
# Favicon hashing
# ---------------------------------------------------------------------

def _favicon_hash(data: bytes) -> str | None:
    if not data:
        return None
    try:
        import mmh3
        import base64
        b64 = base64.encodebytes(data)
        return str(mmh3.hash(b64))
    except ImportError:
        return "sha256:" + hashlib.sha256(data).hexdigest()[:32]


def _find_favicon_url(html: str, base_url: str) -> str:
    """Find the favicon URL, skipping data: URIs (which aren't fetchable)."""
    for rx in (_FAVICON_RE, _FAVICON_RE_REV):
        m = rx.search(html or "")
        if m:
            href = m.group(1).strip()
            # Skip data: URIs and other non-HTTP schemes
            if href.startswith(("data:", "javascript:", "#", "about:")):
                continue
            return urljoin(base_url, href)
    return urljoin(base_url, "/favicon.ico")


# ---------------------------------------------------------------------
# Well-known fetches
# ---------------------------------------------------------------------

async def _fetch_text(session, url: str, limiter, *,
                      timeout: float = 10.0,
                      max_bytes: int = 512 * 1024,
                      allow_redirects: bool = True) -> dict | None:
    try:
        status, headers, body, final = await fetch(
            session, url, limiter,
            timeout=timeout, allow_redirects=allow_redirects)
    except Exception:
        return None
    if status is None:
        return None
    return {
        "url": url,
        "final_url": final,
        "status": status,
        "headers": headers or {},
        "body": (body or "")[:max_bytes],
    }


async def _fetch_well_known(session, base_url: str, limiter,
                            verbose: bool) -> dict[str, dict]:
    out: dict[str, dict] = {}
    sem = asyncio.Semaphore(6)

    async def _one(path: str):
        url = urljoin(base_url, path)
        async with sem:
            r = await _fetch_text(session, url, limiter)
        return path, r

    results = await asyncio.gather(
        *[_one(p) for p in WELL_KNOWN_PATHS],
        return_exceptions=True)

    for item in results:
        if isinstance(item, Exception):
            continue
        path, r = item
        if r is None:
            continue
        if r["status"] in (200, 201, 202, 203, 204, 301, 302, 307, 308):
            out[path] = {
                "status": r["status"],
                "url": r["final_url"],
                "content_type": r["headers"].get("content-type", ""),
                "body": r["body"][:64 * 1024],
                "size": len(r["body"]),
            }
            if verbose:
                info(f"  well-known: {path} → {r['status']} "
                     f"({len(r['body'])} bytes)")
    return out


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def analyze(target: str, session=None, limiter=None,
                  verbose: bool = False,
                  rate: float = 10.0,
                  timeout: float = 15.0,
                  include_well_known: bool = True) -> dict:
    """Fetch a URL once, extract everything cheap, and return it."""
    t = parse(target)
    base_url = target if not t.is_ip else f"https://{t.host}"
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{t.host}"

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=rate)

    result: dict[str, Any] = {
        "target": base_url,
        "final_url": None,
        "status": None,
        "redirect_chain": [],
        "title": "",
        "headers": {},
        "security_headers": {},
        "csp": {},
        "meta": {},
        "meta_of_interest": {},
        "links": [],
        "interesting_links": {},
        "cookies": [],
        "favicon_hash": None,
        "favicon_url": None,
        "robots": {},
        "sitemap": {"url": None, "urls": []},
        "well_known": {},
        "errors": [],
    }

    info(f"web_intel: fetching {base_url}")

    try:
        root = await _fetch_text(session, base_url, limiter,
                                 timeout=timeout)
        if root is None:
            result["errors"].append("root fetch failed")
            warn(f"web_intel: root fetch failed for {base_url}")
            return result

        headers = _norm_headers(root["headers"])
        html = root["body"]

        result["final_url"] = root["final_url"]
        result["status"] = root["status"]
        result["headers"] = headers
        result["security_headers"] = _security_headers(headers)
        result["csp"] = _parse_csp_domains(headers)
        result["title"] = _extract_title(html)

        if root["final_url"] and root["final_url"] != base_url:
            result["redirect_chain"] = [base_url, root["final_url"]]

        result["meta"] = _parse_meta(html)
        result["meta_of_interest"] = {
            k: v for k, v in result["meta"].items()
            if k in META_NAMES_OF_INTEREST
        }

        result["links"] = _parse_links(html, root["final_url"])
        result["interesting_links"] = _interesting_links(result["links"])

        result["cookies"] = _all_set_cookies(root["headers"])

        # robots.txt
        robots_url = urljoin(root["final_url"], "/robots.txt")
        robots_resp = await _fetch_text(session, robots_url, limiter,
                                        timeout=timeout)
        if robots_resp and robots_resp["status"] == 200:
            result["robots"] = _parse_robots(robots_resp["body"])

        # sitemap
        sitemap_url = None
        if result["robots"].get("sitemaps"):
            sitemap_url = result["robots"]["sitemaps"][0]
        if not sitemap_url:
            sitemap_url = urljoin(root["final_url"], "/sitemap.xml")

        if sitemap_url:
            sm_resp = await _fetch_text(session, sitemap_url, limiter,
                                        timeout=timeout)
            if sm_resp and sm_resp["status"] == 200:
                urls = _parse_sitemap(sm_resp["body"])
                result["sitemap"] = {
                    "url": sm_resp["final_url"],
                    "urls": urls[:2000],
                    "total": len(urls),
                }

        # favicon
        fav_url = _find_favicon_url(html, root["final_url"])
        result["favicon_url"] = fav_url
        fav_resp = await _fetch_text(session, fav_url, limiter,
                                     timeout=timeout,
                                     max_bytes=512 * 1024)
        if fav_resp and fav_resp["status"] == 200:
            raw_bytes = fav_resp["body"].encode("utf-8", errors="replace")
            result["favicon_hash"] = _favicon_hash(raw_bytes)

        # well-known
        if include_well_known:
            if verbose:
                info("web_intel: fetching well-known paths")
            result["well_known"] = await _fetch_well_known(
                session, root["final_url"], limiter, verbose=verbose)

        return result
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# Store integration
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
              rate: float = 10.0,
              include_well_known: bool = True) -> dict:
    """CLI entry. Writes findings to store if provided."""
    result = await analyze(target, verbose=verbose, rate=rate,
                           include_well_known=include_well_known)

    print()
    if result["errors"] and not result["status"]:
        warn(f"web_intel: {target} — {'; '.join(result['errors'])}")
        return result

    success(f"web_intel: {result['final_url']} "
            f"(HTTP {result['status']})")

    # ---- Redirect chain ----
    if result["redirect_chain"]:
        info(f"  redirect chain:")
        for hop in result["redirect_chain"]:
            print(f"    {hop}")

    if result["title"]:
        info(f"  title: {result['title']}")

    # ---- Security headers ----
    present = {k: v for k, v in result["security_headers"].items() if v}
    missing = [k for k, v in result["security_headers"].items() if not v]

    if present:
        success(f"  {len(present)} security header(s) present:")
        for name, value in present.items():
            if verbose:
                print(f"    {name}: {value}")
            else:
                print(f"    {name}")
    if missing:
        warn(f"  {len(missing)} security header(s) missing:")
        if verbose:
            for name in missing:
                print(f"    {name}")
        else:
            print(f"    {', '.join(missing)}")

    # ---- CSP ----
    csp_hosts = result["csp"].get("hosts", [])
    csp_directives = result["csp"].get("directives", {})
    if csp_hosts:
        success(f"  CSP references {len(csp_hosts)} hostname(s):")
        limit = None if verbose else 30
        shown = csp_hosts if limit is None else csp_hosts[:limit]
        for h in shown:
            print(f"    {h}")
        if limit is not None and len(csp_hosts) > limit:
            info(f"    ... and {len(csp_hosts) - limit} more "
                 f"(use -v for all)")
    if verbose and csp_directives:
        info(f"  CSP directives ({len(csp_directives)}):")
        for name, values in csp_directives.items():
            print(f"    {name}: {' '.join(values)}")

    # ---- Meta tags ----
    if verbose:
        all_meta = result.get("meta", {})
        if all_meta:
            info(f"  meta tags ({len(all_meta)}):")
            for k, v in sorted(all_meta.items()):
                v_short = v if len(v) <= 200 else v[:197] + "..."
                print(f"    {k}: {v_short}")
    else:
        interesting = result.get("meta_of_interest", {})
        if interesting:
            success(f"  {len(interesting)} meta tag(s) of interest:")
            for k, v in interesting.items():
                v_short = v if len(v) <= 120 else v[:117] + "..."
                print(f"    {k}: {v_short}")

    # ---- Links ----
    if verbose:
        all_links = result.get("links", [])
        if all_links:
            info(f"  link elements ({len(all_links)}):")
            for link in all_links:
                rels = ",".join(link["rel"])
                href = link["href"]
                if len(href) > 120:
                    href = href[:117] + "..."
                print(f"    [{rels}] {href}")
    else:
        interesting_links = result.get("interesting_links", {})
        if interesting_links:
            success(f"  {sum(len(v) for v in interesting_links.values())} "
                    f"link(s) of interest:")
            for rel, entries in interesting_links.items():
                for e in entries[:5]:
                    href = e["href"]
                    if len(href) > 120:
                        href = href[:117] + "..."
                    print(f"    [{rel}] {href}")

    # ---- Cookies ----
    if result["cookies"]:
        success(f"  {len(result['cookies'])} cookie(s) set:")
        limit = None if verbose else 20
        shown = result["cookies"] if limit is None else result["cookies"][:limit]
        for c in shown:
            attrs = c["attributes"]
            flags = []
            if attrs.get("secure"):       flags.append("Secure")
            if attrs.get("httponly"):     flags.append("HttpOnly")
            if attrs.get("samesite"):     flags.append(f"SameSite={attrs['samesite']}")
            if attrs.get("domain"):       flags.append(f"Domain={attrs['domain']}")
            if attrs.get("path"):         flags.append(f"Path={attrs['path']}")
            if attrs.get("max-age"):      flags.append(f"Max-Age={attrs['max-age']}")
            if verbose:
                value = c["value"]
                if len(value) > 60:
                    value = value[:57] + "..."
                print(f"    {c['name']} = {value!r}  "
                      f"{' '.join(flags) or '(no flags)'}")
            else:
                print(f"    {c['name']}  {' '.join(flags) or '(no flags)'}")
        if limit is not None and len(result["cookies"]) > limit:
            info(f"    ... and {len(result['cookies']) - limit} more "
                 f"(use -v for all)")

    # ---- robots.txt ----
    robots = result.get("robots") or {}
    if robots.get("sitemaps") or robots.get("user_agents"):
        success(f"  robots.txt parsed:")
        if robots.get("sitemaps"):
            for s in robots["sitemaps"]:
                print(f"    Sitemap: {s}")
        if verbose:
            for ua, rules in robots.get("user_agents", {}).items():
                info(f"    User-Agent: {ua}")
                for a in rules.get("allow", []):
                    print(f"      Allow: {a}")
                for d in rules.get("disallow", []):
                    print(f"      Disallow: {d}")
        else:
            total_disallow = sum(
                len(v.get("disallow", []))
                for v in robots.get("user_agents", {}).values())
            total_allow = sum(
                len(v.get("allow", []))
                for v in robots.get("user_agents", {}).values())
            if total_disallow:
                info(f"    {total_disallow} Disallow entries")
            if total_allow:
                info(f"    {total_allow} Allow entries")

    # ---- Sitemap ----
    sitemap = result.get("sitemap") or {}
    if sitemap.get("urls"):
        total = sitemap.get("total", len(sitemap["urls"]))
        success(f"  sitemap: {total} URL(s) from {sitemap['url']}")
        if verbose:
            for u in sitemap["urls"]:
                print(f"    {u}")
        else:
            for u in sitemap["urls"][:10]:
                print(f"    {u}")
            if total > 10:
                info(f"    ... and {total - 10} more (use -v for all)")

    # ---- well-known ----
    if result["well_known"]:
        success(f"  {len(result['well_known'])} well-known file(s) present:")
        for path, entry in result["well_known"].items():
            print(f"    {path} → {entry['status']} "
                  f"({entry['size']} bytes)")
            if verbose and entry.get("body"):
                body = entry["body"]
                lines = body.splitlines()[:5]
                for line in lines:
                    line = line.rstrip()
                    if len(line) > 140:
                        line = line[:137] + "..."
                    print(f"      | {line}")
                remaining = len(body.splitlines()) - 5
                if remaining > 0:
                    print(f"      | ... ({remaining} more line(s))")

    # ---- Favicon ----
    if result["favicon_hash"]:
        info(f"  favicon: {result['favicon_url']}")
        info(f"  favicon hash: {result['favicon_hash']}")

    # ---- Store ----
    if store is not None:
        store.add_finding({
            "module": "web_intel",
            "type": "informational",
            "severity": "info",
            "target": result["final_url"] or target,
            "evidence": (f"HTTP {result['status']}, "
                         f"{len(result['security_headers'])} security "
                         f"headers, {len(csp_hosts)} CSP hosts, "
                         f"{len(result['cookies'])} cookies"),
            "data": result,
        })
        success("finding written to store")

        try:
            for h in csp_hosts:
                store.upsert_host(
                    ip=h,
                    hostname=h,
                    discovery=f"csp ({result['final_url']})",
                    tags=["csp"],
                )
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.web_intel",
        description="Single-fetch web intelligence extractor.",
    )
    p.add_argument("target", help="URL, hostname, or IP")
    p.add_argument("--no-well-known", action="store_true",
                   help="skip .well-known/* fetches")
    p.add_argument("--rate", type=float, default=10.0,
                   help="requests per second (default 10)")
    p.add_argument("--store", action="store_true",
                   help="write finding to active workspace")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="uncap all display limits: full CSP hostname "
                        "list, every meta tag, every link element, "
                        "every cookie with value, full robots rules, "
                        "full sitemap, and body previews of every "
                        "well-known file")
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
        rate=args.rate,
        include_well_known=not args.no_well_known))


if __name__ == "__main__":
    _cli()