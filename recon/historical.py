"""
Historical reconnaissance: Wayback Machine, Common Crawl, URLScan.io,
public code search, and dead-path detection.

Finds information that used to be public but isn't linked anymore:

  - Wayback Machine: every archived URL for the target domain
      → old admin panels, retired API endpoints, old file names

  - Common Crawl: every URL the CC crawler has ever indexed
      → different coverage than Wayback; sometimes finds things
        Wayback missed, especially behind CDNs and bot protections

  - grep.app: public code files (mostly GitHub) that reference
    the target domain
      → hardcoded URLs, deploy scripts, config files, retired
        infrastructure referenced by third parties and former
        employees

  - URLScan.io: public scans of the target
      → query-only by default; --urlscan-key enables submitting
        new scans (free API key at urlscan.io/register)

  - Dead-path detection: for the top-N interesting Wayback URLs,
    one probe each to see if they're alive now
      → dead paths are the highest-signal findings

Retry behaviour:

  Every third-party source is retried on 429 (rate limit) and 5xx
  (server error). The retry profile controls how patient we are:

    fast (default)   2 retries, 2s then 4s. Per-source max wait ~6s.
    moderate         3 retries, 3s then 6s then 12s. Max wait ~21s.
    aggressive       3 retries, 5s then 15s then 30s. Max wait ~50s.

  Fast catches transient blips. Moderate and aggressive give
  sustained rate limits a chance to clear, but rarely convert a
  persistent 429 into a success within a single run.

  Common Crawl gets one extra fallback step before retries: if the
  wildcard query 504s (which it does on huge domains like
  github.com), we retry immediately with an apex-only query, which
  is smaller and faster. Only if that fails too do we enter the
  normal retry loop.

Findings written to the store:
    one row per target with URLs, historical hosts, and interesting
    paths in `data`
"""

import asyncio
import json
import re
from urllib.parse import quote, urlparse

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/?q={query}&size=100"
URLSCAN_SUBMIT = "https://urlscan.io/api/v1/scan/"
COMMONCRAWL_COLLINFO = "https://index.commoncrawl.org/collinfo.json"
GREP_APP = "https://grep.app/api/search?q={query}"

DEFAULT_DEAD_PROBE_COUNT = 40


# ── SESSION H1.1 ── Retry profiles ──────────────────────────────────

RETRY_PROFILES = {
    "fast":       {"retries": 2, "backoff": [2.0, 4.0]},
    "moderate":   {"retries": 3, "backoff": [3.0, 6.0, 12.0]},
    "aggressive": {"retries": 3, "backoff": [5.0, 15.0, 30.0]},
}
DEFAULT_RETRY_PROFILE = "fast"

# HTTP status codes we treat as retryable.
RETRYABLE_STATUS = {429, 503, 504, 502, 500, 520, 521, 522}

# Status codes we report as "rate_limited" in the per-source summary.
RATE_LIMIT_STATUS = {429}


async def _fetch_with_retry(session, url, limiter, profile="fast",
                              timeout=30.0, quiet=True,
                              headers=None, verbose=False,
                              label="fetch"):
    """Fetch a URL, retrying on rate-limit and server errors.

    Returns (status, body, error_kind) where error_kind is one of:
        None            success (status may be 200 or a real 4xx we
                        didn't retry)
        "rate_limited"  final attempt returned 429
        "timeout"       final attempt returned a 5xx server error
        "error"         transport failure or other non-retryable error

    If successful, status is the HTTP status and body is the response
    text. If exhausted, status is the last-seen status (or None) and
    body is None.
    """
    prof = RETRY_PROFILES.get(profile, RETRY_PROFILES[DEFAULT_RETRY_PROFILE])
    backoffs = prof["backoff"]
    attempts = prof["retries"] + 1  # initial + retries

    last_status = None
    last_kind = None

    for attempt in range(attempts):
        try:
            status, _h, body, _ = await fetch(
                session, url, limiter, timeout=timeout, quiet=quiet,
                headers=headers)
        except Exception as e:
            if verbose:
                warn(f"  {label}: attempt {attempt + 1} raised "
                     f"{type(e).__name__}: {e}")
            status, body = None, None

        if status is not None and status not in RETRYABLE_STATUS:
            return status, body, None

        last_status = status
        if status in RATE_LIMIT_STATUS:
            last_kind = "rate_limited"
        elif status is not None and 500 <= status < 600:
            last_kind = "timeout"
        else:
            last_kind = "error"

        if attempt >= attempts - 1:
            break
        wait = backoffs[attempt] if attempt < len(backoffs) else backoffs[-1]
        if verbose:
            warn(f"  {label}: attempt {attempt + 1} returned "
                 f"status={status}, retrying in {wait}s")
        await asyncio.sleep(wait)

    return last_status, None, last_kind

# ── END SESSION H1.1 retry profiles ─────────────────────────────────


INTERESTING_PATH_PATTERNS = [
    r"/admin", r"/administrator", r"/wp-admin", r"/cpanel",
    r"/login", r"/signin", r"/auth",
    r"/api/", r"/api/v\d", r"/rest/", r"/graphql", r"/swagger",
    r"/config", r"/\.env", r"/\.git",
    r"/backup", r"/\.bak", r"/\.old", r"/\.sql", r"/dump",
    r"/old", r"/legacy", r"/archive",
    r"/dev", r"/test", r"/staging", r"/uat",
    r"/internal", r"/private",
    r"\.php", r"\.asp", r"\.aspx", r"\.jsp", r"\.cgi",
    r"\.zip", r"\.tar", r"\.gz", r"\.rar",
    r"\.sql", r"\.bak", r"\.old", r"\.orig", r"\.save",
    r"\.log", r"\.conf", r"\.config",
    r"\.json", r"\.xml", r"\.yml", r"\.yaml",
    r"/phpinfo", r"/info\.php", r"/server-status",
    r"/actuator", r"/metrics", r"/debug",
]

_INTERESTING_RE = re.compile(
    "|".join(f"(?:{p})" for p in INTERESTING_PATH_PATTERNS),
    re.IGNORECASE,
)


# ---------------------------------------------------------------------
# Wayback Machine
# ---------------------------------------------------------------------

async def fetch_wayback_urls(domain: str, session=None,
                              limit: int = 10_000,
                              retry_profile: str = DEFAULT_RETRY_PROFILE,
                              verbose: bool = False) -> tuple[list[dict], str]:
    """Return (archived_urls, status) from the Wayback CDX API.

    status is "ok", "rate_limited", "timeout", or "error".
    """
    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(5.0)

    params = (
        f"?url=*.{quote(domain)}/*"
        f"&output=json"
        f"&fl=timestamp,original,statuscode,mimetype,digest"
        f"&collapse=digest"
        f"&filter=statuscode:200"
        f"&limit={limit}"
    )
    url = WAYBACK_CDX + params

    try:
        status, body, err_kind = await _fetch_with_retry(
            session, url, limiter, profile=retry_profile,
            timeout=60.0, verbose=verbose, label="wayback")
    finally:
        if own_session:
            await session.close()

    if err_kind:
        if verbose:
            warn(f"Wayback CDX: {err_kind} (last status={status})")
        return [], err_kind

    if status != 200 or not body:
        if verbose:
            warn(f"Wayback CDX returned status={status}")
        return [], "error"

    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        warn("Wayback CDX returned invalid JSON")
        return [], "error"

    if not rows or len(rows) < 2:
        return [], "ok"

    entries = []
    for row in rows[1:]:
        if len(row) < 5:
            continue
        entries.append({
            "timestamp": row[0],
            "url": row[1],
            "status": row[2],
            "mime": row[3],
            "digest": row[4],
        })
    return entries, "ok"


# ---------------------------------------------------------------------
# Common Crawl
# ---------------------------------------------------------------------

async def _commoncrawl_most_recent_index(session, limiter,
                                          retry_profile="fast",
                                          verbose=False) -> str | None:
    """Fetch the most recent Common Crawl index URL."""
    status, body, err_kind = await _fetch_with_retry(
        session, COMMONCRAWL_COLLINFO, limiter,
        profile=retry_profile, timeout=30.0,
        verbose=verbose, label="commoncrawl collinfo")

    if err_kind or status != 200 or not body:
        return None

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None

    if not data or not isinstance(data, list):
        return None

    try:
        data.sort(key=lambda x: x.get("id", ""), reverse=True)
    except Exception:
        pass

    first = data[0]
    index_url = first.get("cdx-api") or first.get("cdx_api")
    if not index_url:
        return None
    return index_url.rstrip("/")


async def fetch_commoncrawl_urls(domain: str, session=None,
                                   limit: int = 5000,
                                   retry_profile: str = DEFAULT_RETRY_PROFILE,
                                   verbose: bool = False
                                   ) -> tuple[list[dict], str]:
    """Query the most recent Common Crawl index for a domain.

    Returns (urls, status). status is "ok", "rate_limited",
    "timeout", or "error".

    On wildcard-query timeout (504), retries immediately with an
    apex-only query, which is smaller and usually succeeds where the
    wildcard fails.
    """
    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(3.0)

    try:
        index_url = await _commoncrawl_most_recent_index(
            session, limiter, retry_profile=retry_profile,
            verbose=verbose)
        if index_url is None:
            if verbose:
                warn("Common Crawl: could not resolve index URL")
            return [], "error"

        if verbose:
            info(f"  commoncrawl: using index {index_url}")

        # Attempt 1: wildcard query
        wildcard_url = (
            index_url
            + f"?url=*.{quote(domain)}/*"
            + f"&output=json"
            + f"&limit={limit}"
        )
        status, body, err_kind = await _fetch_with_retry(
            session, wildcard_url, limiter,
            profile=retry_profile, timeout=60.0,
            verbose=verbose, label="commoncrawl wildcard")

        # If wildcard failed with a server error, try apex-only as a
        # smaller fallback before giving up.
        if err_kind in ("timeout", "rate_limited"):
            apex_url = (
                index_url
                + f"?url={quote(domain)}"
                + f"&output=json"
                + f"&limit={min(limit, 1000)}"
            )
            if verbose:
                info(f"  commoncrawl: wildcard query failed "
                     f"({err_kind}); trying apex-only query")
            status, body, err_kind = await _fetch_with_retry(
                session, apex_url, limiter,
                profile=retry_profile, timeout=60.0,
                verbose=verbose, label="commoncrawl apex")

        if err_kind:
            if verbose:
                warn(f"Common Crawl: {err_kind}")
            return [], err_kind

        if status != 200 or not body:
            if verbose:
                warn(f"Common Crawl returned status={status}")
            return [], "error"

        entries = []
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            entries.append({
                "url": row.get("url", ""),
                "status": row.get("status", ""),
                "mime": row.get("mime", ""),
                "timestamp": row.get("timestamp", ""),
            })
        return entries, "ok"
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# grep.app code search
# ---------------------------------------------------------------------

async def search_grep_app(domain: str, session=None,
                            limit: int = 50,
                            retry_profile: str = DEFAULT_RETRY_PROFILE,
                            verbose: bool = False
                            ) -> tuple[list[dict], str]:
    """Search grep.app for public code files referencing the domain.

    Returns (hits, status).
    """
    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(2.0)

    try:
        url = GREP_APP.format(query=quote(domain))
        status, body, err_kind = await _fetch_with_retry(
            session, url, limiter,
            profile=retry_profile, timeout=30.0, quiet=True,
            headers={"Accept": "application/json"},
            verbose=verbose, label="grep.app")

        if err_kind:
            if verbose:
                warn(f"grep.app: {err_kind}")
            return [], err_kind

        if status != 200 or not body:
            if verbose:
                warn(f"grep.app returned status={status}")
            return [], "error"

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return [], "error"

        hits_root = data.get("hits") or {}
        hits = hits_root.get("hits") or []
        total = hits_root.get("total")

        out = []
        for h in hits[:limit]:
            repo = h.get("repo") or h.get("repo_raw") or ""
            path = h.get("path") or ""
            content = h.get("content") or {}
            snippet = content.get("snippet") or ""
            snippet = re.sub(r"<[^>]+>", "", snippet).strip()[:300]

            out.append({
                "repo": repo,
                "path": path,
                "snippet": snippet,
                "url": (f"https://github.com/{repo}/blob/HEAD/{path}"
                        if repo and path else None),
            })

        if verbose:
            info(f"  grep.app: {len(out)} hit(s) "
                 f"(total reported: {total})")
        return out, "ok"
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# URLScan.io
# ---------------------------------------------------------------------

async def urlscan_search(domain: str, session=None,
                          retry_profile: str = DEFAULT_RETRY_PROFILE,
                          verbose: bool = False
                          ) -> tuple[list[dict], str]:
    """Query URLScan.io for public scans of a domain."""
    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(3.0)

    query = f"domain:{domain}"
    url = URLSCAN_SEARCH.format(query=quote(query))

    try:
        status, body, err_kind = await _fetch_with_retry(
            session, url, limiter,
            profile=retry_profile, timeout=30.0,
            headers={"Accept": "application/json"},
            verbose=verbose, label="urlscan search")

        if err_kind:
            return [], err_kind

        if status != 200 or not body:
            if verbose:
                warn(f"URLScan returned status={status}")
            return [], "error"

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return [], "error"

        results = []
        for row in data.get("results", []):
            page = row.get("page") or {}
            task = row.get("task") or {}
            results.append({
                "url": page.get("url"),
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "asn": page.get("asn"),
                "asnname": page.get("asnname"),
                "country": page.get("country"),
                "server": page.get("server"),
                "status": page.get("status"),
                "mime": page.get("mimeType"),
                "scan_time": task.get("time"),
                "scan_url": row.get("result"),
                "screenshot": row.get("screenshot"),
            })
        return results, "ok"
    finally:
        if own_session:
            await session.close()


async def urlscan_submit(url: str, api_key: str, session=None,
                          verbose: bool = False) -> dict:
    """Submit a new scan to URLScan.io. Requires API key."""
    if not api_key:
        return {"error": "no API key provided"}

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(1.0)

    payload = json.dumps({"url": url, "visibility": "public"})
    try:
        status, _headers, body, _ = await fetch(
            session, URLSCAN_SUBMIT, limiter,
            method="POST",
            headers={
                "API-Key": api_key,
                "Content-Type": "application/json",
            },
            data=payload.encode("utf-8"),
            timeout=30.0,
        )
    except Exception as e:
        if verbose:
            warn(f"URLScan submit failed: {type(e).__name__}: {e}")
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        if own_session:
            await session.close()

    if status not in (200, 201) or not body:
        return {"error": f"HTTP {status}"}

    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"error": "invalid JSON response"}


# ---------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------

def extract_historical_hosts(urls: list[dict], domain: str) -> list[str]:
    """Return unique hosts (subdomains) seen in archived URLs."""
    hosts = set()
    for entry in urls:
        try:
            parsed = urlparse(entry["url"])
            host = (parsed.hostname or "").lower()
        except Exception:
            continue
        if not host:
            continue
        if not host.endswith(domain):
            continue
        hosts.add(host)
    return sorted(hosts)


def find_interesting_paths(urls: list[dict]) -> dict[str, list[dict]]:
    """Group archived URLs by interesting pattern."""
    groups: dict[str, list[dict]] = {}

    patterns_named = [
        ("admin",       r"/admin|/administrator|/wp-admin|/cpanel"),
        ("login",       r"/login|/signin|/auth"),
        ("api",         r"/api/|/api/v\d|/rest/|/graphql|/swagger"),
        ("config",      r"/config|/\.env|/\.git"),
        ("backup",      r"/backup|\.bak$|\.old$|\.sql$|/dump"),
        ("old",         r"/old|/legacy|/archive"),
        ("dev",         r"/dev|/test|/staging|/uat"),
        ("internal",    r"/internal|/private"),
        ("dynamic",     r"\.php|\.asp|\.aspx|\.jsp|\.cgi"),
        ("archives",    r"\.zip$|\.tar$|\.gz$|\.rar$"),
        ("databases",   r"\.sql$|\.db$"),
        ("logs",        r"\.log$"),
        ("configs",     r"\.conf$|\.config$"),
        ("data",        r"\.json$|\.xml$|\.yml$|\.yaml$"),
        ("server-info", r"/phpinfo|/info\.php|/server-status"),
        ("debug",       r"/actuator|/metrics|/debug"),
    ]

    for name, pattern in patterns_named:
        rx = re.compile(pattern, re.IGNORECASE)
        matches = []
        for entry in urls:
            if rx.search(entry["url"]):
                matches.append({
                    "url": entry["url"],
                    "timestamp": entry["timestamp"],
                })
        if matches:
            groups[name] = matches[:50]

    return groups


# ---------------------------------------------------------------------
# Dead-path detection
# ---------------------------------------------------------------------

async def probe_dead_paths(interesting_paths: dict[str, list[dict]],
                             limit: int = DEFAULT_DEAD_PROBE_COUNT,
                             session=None, verbose: bool = False
                             ) -> list[dict]:
    """Probe the top-N interesting paths to see which are dead now."""
    if limit <= 0:
        return []

    priority = ["admin", "config", "backup", "api", "internal",
                "old", "dev", "login", "dynamic", "databases",
                "archives", "logs", "configs", "data",
                "server-info", "debug"]

    candidates = []
    seen_urls = set()
    for group in priority:
        entries = interesting_paths.get(group, [])
        entries = sorted(entries, key=lambda e: e.get("timestamp", ""),
                          reverse=True)
        for e in entries:
            if e["url"] in seen_urls:
                continue
            seen_urls.add(e["url"])
            candidates.append({
                "url": e["url"],
                "group": group,
                "timestamp": e.get("timestamp", ""),
            })
            if len(candidates) >= limit:
                break
        if len(candidates) >= limit:
            break

    if not candidates:
        return []

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(5.0)

    if verbose:
        info(f"  probing {len(candidates)} interesting URL(s) "
             f"for dead paths")

    dead = []
    try:
        sem = asyncio.Semaphore(5)

        async def _probe(cand):
            async with sem:
                try:
                    status, _h, _body, _ = await fetch(
                        session, cand["url"], limiter, timeout=10.0,
                        allow_redirects=False, quiet=True)
                except Exception:
                    return None
                if status in (404, 410):
                    return {
                        "url": cand["url"],
                        "status": status,
                        "group": cand["group"],
                        "last_archived": _format_ts(cand["timestamp"]),
                    }
                return None

        results = await asyncio.gather(
            *[_probe(c) for c in candidates],
            return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                dead.append(r)
    finally:
        if own_session:
            await session.close()

    return dead


def _format_ts(ts: str) -> str:
    """Turn '20190412031245' into '2019-04-12'."""
    if not ts or len(ts) < 8:
        return ts
    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def lookup(domain: str, session=None, verbose: bool = False,
                 urlscan_key: str | None = None,
                 wayback_limit: int = 10_000,
                 commoncrawl_limit: int = 5000,
                 enable_commoncrawl: bool = True,
                 enable_grep: bool = True,
                 dead_probe_count: int = DEFAULT_DEAD_PROBE_COUNT,
                 retry_profile: str = DEFAULT_RETRY_PROFILE) -> dict:
    """Historical recon for a domain."""
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0].split(":")[0].lower()

    result = {
        "domain": domain,
        "retry_profile": retry_profile,
        "wayback_urls": 0,
        "wayback_total_returned": 0,
        "commoncrawl_urls": 0,
        "historical_hosts": [],
        "interesting_paths": {},
        "dead_paths": [],
        "urlscan_results": [],
        "urlscan_submitted": None,
        "grep_results": [],
        "source_status": {
            "wayback": None,
            "commoncrawl": None,
            "grep": None,
            "urlscan": None,
        },
        "errors": [],
    }

    # --- Wayback ---
    info(f"querying Wayback Machine for {domain}")
    urls, wb_status = await fetch_wayback_urls(
        domain, session=session, limit=wayback_limit,
        retry_profile=retry_profile, verbose=verbose)
    result["source_status"]["wayback"] = wb_status
    result["wayback_total_returned"] = len(urls)

    if urls:
        result["wayback_urls"] = len(urls)
        result["historical_hosts"] = extract_historical_hosts(urls, domain)
        result["interesting_paths"] = find_interesting_paths(urls)
    elif wb_status != "ok":
        result["errors"].append(f"wayback: {wb_status}")

    # --- Common Crawl ---
    if enable_commoncrawl:
        info(f"querying Common Crawl for {domain}")
        cc_urls, cc_status = await fetch_commoncrawl_urls(
            domain, session=session, limit=commoncrawl_limit,
            retry_profile=retry_profile, verbose=verbose)
        result["source_status"]["commoncrawl"] = cc_status
        result["commoncrawl_urls"] = len(cc_urls)

        if cc_urls:
            merged = []
            for e in cc_urls:
                merged.append({
                    "url": e.get("url", ""),
                    "timestamp": e.get("timestamp", ""),
                })
            existing = set()
            for group in result["interesting_paths"].values():
                for item in group:
                    existing.add(item["url"])
            cc_new = [m for m in merged
                       if m["url"] and m["url"] not in existing]
            if cc_new:
                cc_groups = find_interesting_paths(cc_new)
                for name, entries in cc_groups.items():
                    result["interesting_paths"].setdefault(
                        name, []).extend(entries)

            cc_host_set = set(result["historical_hosts"])
            for m in merged:
                try:
                    host = (urlparse(m["url"]).hostname or "").lower()
                except Exception:
                    continue
                if host and host.endswith(domain):
                    cc_host_set.add(host)
            result["historical_hosts"] = sorted(cc_host_set)
        elif cc_status != "ok":
            result["errors"].append(f"commoncrawl: {cc_status}")
    else:
        result["source_status"]["commoncrawl"] = "disabled"

    # --- grep.app ---
    if enable_grep:
        info(f"querying grep.app for {domain}")
        grep_hits, grep_status = await search_grep_app(
            domain, session=session,
            retry_profile=retry_profile, verbose=verbose)
        result["source_status"]["grep"] = grep_status
        result["grep_results"] = grep_hits
        if grep_status != "ok":
            result["errors"].append(f"grep.app: {grep_status}")
    else:
        result["source_status"]["grep"] = "disabled"

    # --- URLScan ---
    info(f"querying URLScan.io for {domain}")
    scans, us_status = await urlscan_search(
        domain, session=session,
        retry_profile=retry_profile, verbose=verbose)
    result["source_status"]["urlscan"] = us_status
    result["urlscan_results"] = scans
    if us_status != "ok":
        result["errors"].append(f"urlscan: {us_status}")

    if urlscan_key:
        info(f"submitting new scan to URLScan.io for {domain}")
        submit_result = await urlscan_submit(
            f"https://{domain}", urlscan_key, session=session,
            verbose=verbose)
        if "error" in submit_result:
            result["errors"].append(
                f"urlscan submit failed: {submit_result['error']}")
        else:
            result["urlscan_submitted"] = submit_result.get("api") or \
                                            submit_result.get("message")

    # --- Dead-path probing ---
    if dead_probe_count > 0 and result["interesting_paths"]:
        dead = await probe_dead_paths(
            result["interesting_paths"],
            limit=dead_probe_count,
            session=session, verbose=verbose)
        result["dead_paths"] = dead

    return result


# ---------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------

def _fmt_status(s: str | None) -> str:
    """Render a source status for the summary line."""
    if s is None:
        return "?"
    if s == "ok":
        return "ok"
    if s == "disabled":
        return "disabled"
    if s == "rate_limited":
        return "RATE LIMITED"
    if s == "timeout":
        return "TIMEOUT"
    if s == "error":
        return "error"
    return s


async def run(target: str, store=None, verbose: bool = False,
              urlscan_key: str | None = None,
              enable_commoncrawl: bool = True,
              enable_grep: bool = True,
              dead_probe_count: int = DEFAULT_DEAD_PROBE_COUNT,
              retry_profile: str = DEFAULT_RETRY_PROFILE) -> dict:
    """CLI entry. Writes finding to store if provided."""
    result = await lookup(target, verbose=verbose,
                          urlscan_key=urlscan_key,
                          enable_commoncrawl=enable_commoncrawl,
                          enable_grep=enable_grep,
                          dead_probe_count=dead_probe_count,
                          retry_profile=retry_profile)

    print()
    success(f"Historical recon for {result['domain']} "
            f"(retry profile: {retry_profile})")

    ss = result["source_status"]
    print(f"    Wayback:       {_fmt_status(ss['wayback'])}"
          + (f" — {result['wayback_urls']} URL(s)"
             if result["wayback_urls"] else ""))
    print(f"    Common Crawl:  {_fmt_status(ss['commoncrawl'])}"
          + (f" — {result['commoncrawl_urls']} URL(s)"
             if result["commoncrawl_urls"] else ""))
    print(f"    grep.app:      {_fmt_status(ss['grep'])}"
          + (f" — {len(result['grep_results'])} hit(s)"
             if result["grep_results"] else ""))
    print(f"    URLScan:       {_fmt_status(ss['urlscan'])}"
          + (f" — {len(result['urlscan_results'])} scan(s)"
             if result["urlscan_results"] else ""))
    if result["historical_hosts"]:
        print(f"    Hosts:         {len(result['historical_hosts'])} "
              f"unique hostname(s)")
    if result["dead_paths"]:
        print(f"    Dead paths:    {len(result['dead_paths'])}")

    # If every source failed, print a clear message and stop.
    healthy = [k for k, v in ss.items() if v in ("ok", "disabled")]
    if not healthy:
        print()
        warn("all sources failed; nothing useful to report")
        for e in result["errors"]:
            warn(f"  {e}")
        if retry_profile != "aggressive":
            info(f"  try --retry-profile aggressive for more patience")
        return result

    # Per-source error recap
    if result["errors"]:
        print()
        for e in result["errors"]:
            warn(f"  {e}")
        if any("rate_limited" in e or "timeout" in e
               for e in result["errors"]):
            if retry_profile == "fast":
                info(f"  try --retry-profile moderate or aggressive "
                     f"for more patience")

    # Findings sections only if we got results.
    if result["historical_hosts"]:
        print()
        print("  Historical hosts:")
        for h in result["historical_hosts"][:30]:
            print(f"    {h}")
        if len(result["historical_hosts"]) > 30:
            print(f"    ... and "
                  f"{len(result['historical_hosts']) - 30} more")

    if result["interesting_paths"]:
        print()
        print("  Interesting paths (grouped):")
        for group, entries in sorted(
                result["interesting_paths"].items(),
                key=lambda x: -len(x[1])):
            print(f"    [{group}] {len(entries)} URL(s)")
            for e in entries[:3]:
                print(f"      {e['url']}")
            if len(entries) > 3:
                print(f"      ... and {len(entries) - 3} more")

    if result["dead_paths"]:
        print()
        success(f"  Dead paths ({len(result['dead_paths'])}): "
                f"were live, now 404")
        for d in result["dead_paths"][:30]:
            print(f"    HTTP {d['status']} {d['url']}")
            print(f"      last archived: {d['last_archived']} "
                  f"({d['group']})")
        if len(result["dead_paths"]) > 30:
            print(f"    ... and {len(result['dead_paths']) - 30} more")

    if result["grep_results"]:
        print()
        success(f"  Code files referencing {result['domain']}:")
        for g in result["grep_results"][:20]:
            loc = g.get("url") or f"{g.get('repo')}/{g.get('path')}"
            print(f"    {loc}")
            if g.get("snippet"):
                snippet = g["snippet"][:120].replace("\n", " ")
                print(f"      {snippet}")
        if len(result["grep_results"]) > 20:
            print(f"    ... and {len(result['grep_results']) - 20} more")

    if result["urlscan_results"]:
        print()
        print("  Recent URLScan results:")
        for scan in result["urlscan_results"][:5]:
            url = scan.get("url") or "?"
            ip = scan.get("ip") or "?"
            server = scan.get("server") or "?"
            print(f"    {url}")
            print(f"      IP={ip} server={server}")

    if result.get("urlscan_submitted"):
        success(f"  New scan submitted: "
                f"{result['urlscan_submitted']}")

    if store is not None:
        store.add_finding({
            "module": "historical",
            "type": "informational",
            "severity": "info",
            "target": result["domain"],
            "evidence": (f"{result['wayback_urls']} wayback URL(s), "
                         f"{result['commoncrawl_urls']} CC URL(s), "
                         f"{len(result['grep_results'])} grep.app hit(s), "
                         f"{len(result['dead_paths'])} dead path(s), "
                         f"{len(result['historical_hosts'])} hostname(s)"),
            "data": {
                "retry_profile": retry_profile,
                "source_status": result["source_status"],
                "wayback_urls": result["wayback_urls"],
                "commoncrawl_urls": result["commoncrawl_urls"],
                "historical_hosts": result["historical_hosts"],
                "interesting_paths": result["interesting_paths"],
                "dead_paths": result["dead_paths"],
                "grep_results": result["grep_results"],
                "urlscan_results": result["urlscan_results"],
            },
        })
        success(f"finding written to store")

    return result


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.historical",
        description="Wayback + Common Crawl + grep.app + URLScan "
                    "historical recon.",
    )
    p.add_argument("target", help="domain")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--urlscan-key", default=None,
                   help="URLScan.io API key (enables submitting "
                        "new scans)")
    p.add_argument("--wayback-limit", type=int, default=10000,
                   help="max Wayback URLs to fetch (default 10000)")
    p.add_argument("--commoncrawl-limit", type=int, default=5000,
                   help="max Common Crawl URLs to fetch (default 5000)")
    p.add_argument("--no-commoncrawl", action="store_true",
                   help="skip Common Crawl query")
    p.add_argument("--no-grep", action="store_true",
                   help="skip grep.app code search")
    p.add_argument("--probe-dead", type=int, default=DEFAULT_DEAD_PROBE_COUNT,
                   help=f"number of interesting URLs to probe for "
                        f"dead paths (default "
                        f"{DEFAULT_DEAD_PROBE_COUNT}, 0 to disable)")
    p.add_argument("--retry-profile",
                   choices=["fast", "moderate", "aggressive"],
                   default=DEFAULT_RETRY_PROFILE,
                   help=f"retry patience for third-party APIs "
                        f"(default {DEFAULT_RETRY_PROFILE})")
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

    asyncio.run(run(args.target, store=store, verbose=args.verbose,
                    urlscan_key=args.urlscan_key,
                    enable_commoncrawl=not args.no_commoncrawl,
                    enable_grep=not args.no_grep,
                    dead_probe_count=args.probe_dead,
                    retry_profile=args.retry_profile))


if __name__ == "__main__":
    _cli()