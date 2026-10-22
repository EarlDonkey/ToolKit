"""
JavaScript / manifest / inline-script analysis.

Downloads every piece of client-side code from a target and extracts:

  - API endpoints      (/api/v1/users, /graphql, /rest/orders)
  - Hardcoded secrets  (AWS, Google Maps, Stripe, JWT, private keys)
  - High-entropy strings (fallback for secrets the regexes miss)
  - Internal hosts     (internal-api.corp.local, staging.example.com)
  - Source map refs    (foo.js.map — recovered into original source)
  - Recovered source   (sourcesContent from .map files, when present)
  - Debug flags        (DEBUG=true, verbose logging)
  - Dev comments       (TODO, FIXME, XXX, HACK — often reveal structure)
  - Email addresses    (dev emails in comments)
  - Every HTTP(S) URL  (references to other services)
  - Recursive JS       (webpack/Vite/ESBuild chunks loaded at runtime)

Also fetches:
  - <link rel="manifest">  PWA manifest (app name, version, icons)
  - Inline <script> tags    embedded configs, sometimes with secrets

Caps:
  - 50 JS files by default (--max-js to raise)
  - 30 additional recursive chunks discovered from those files
  - 500 KB per file
  - Total budget ~10 MB

Findings written to the store:
    one row per target with all extracted intelligence in `data`

D4 additions:
  - Source map recovery — .map files often contain the original
    uncompiled source, which can reveal comments, internal API
    endpoints, and test data stripped from the minified bundle.
  - Secret classification — each match gets a severity based on
    type; format-checked where cheap.
  - High-entropy fallback — quoted strings ≥ 20 chars with Shannon
    entropy ≥ 4.5 bits/char, excluding ones already matched by
    named regexes.
  - Endpoint clustering — api_paths grouped by first two segments.
  - Recursive chunk discovery — webpack/Vite/ESBuild dynamic chunk
    references followed up to an extra 30 files.
"""

import asyncio
import json
import math
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.http import new_session, fetch, RateLimiter, resolve_root
from core.output import info, success, warn, error


DEFAULT_MAX_JS = 50
DEFAULT_MAX_TOTAL_JS = 80
MAX_FILE_BYTES = 500 * 1024
TOTAL_BUDGET_BYTES = 10 * 1024 * 1024

# High-entropy fallback thresholds
ENTROPY_MIN_LEN = 20
ENTROPY_MIN_BITS = 4.5

# ---------------------------------------------------------------------
# Regex patterns for extraction
# ---------------------------------------------------------------------

API_PATTERN = re.compile(
    r"""["'`]                                # open quote
        (                                     # capture group 1
            /(?:api|rest|graphql|v\d|internal)
            (?:/[a-zA-Z0-9_\-\.{}$]+)+
        )
        ["'`]                                 # close quote
    """,
    re.VERBOSE,
)

URL_PATTERN = re.compile(
    r"""https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]+""",
)

SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("aws_secret",     re.compile(
        r"(?i)aws(.{0,20})?(secret|sk)[^a-z0-9]"
        r"([0-9a-zA-Z/+]{40})")),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("google_oauth",   re.compile(
        r"\b([0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com)\b")),
    ("stripe_live",    re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b")),
    ("stripe_test",    re.compile(r"\b(sk_test_[0-9a-zA-Z]{24,})\b")),
    ("stripe_pk",      re.compile(
        r"\b(pk_(?:live|test)_[0-9a-zA-Z]{24,})\b")),
    ("github_pat",     re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b")),
    ("github_oauth",   re.compile(r"\b(gho_[0-9a-zA-Z]{36})\b")),
    ("gitlab_pat",     re.compile(r"\b(glpat-[0-9a-zA-Z\-_]{20,})\b")),
    ("slack_token",    re.compile(
        r"\b(xox[bpoa]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24})\b")),
    ("slack_webhook",  re.compile(
        r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+")),
    ("twilio_sid",     re.compile(r"\b(AC[a-f0-9]{32})\b")),
    ("sendgrid",       re.compile(
        r"\b(SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43})\b")),
    ("mailgun",        re.compile(r"\b(key-[0-9a-f]{32})\b")),
    ("firebase_url",   re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("private_key",    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt",            re.compile(
        r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b")),
]

# ---------------------------------------------------------------------
# D4: secret classification table
# ---------------------------------------------------------------------
#
# Maps a secret type to (severity, note). Format validation happens
# where cheap; most entries are just "this pattern implies this
# severity".
SECRET_SEVERITY = {
    "aws_access_key": "critical",
    "aws_secret":     "critical",
    "private_key":    "critical",
    "stripe_live":    "critical",
    "stripe_test":    "low",
    "stripe_pk":      "info",
    "github_pat":     "high",
    "github_oauth":   "high",
    "gitlab_pat":     "high",
    "slack_token":    "high",
    "slack_webhook":  "high",
    "twilio_sid":     "high",
    "sendgrid":       "high",
    "mailgun":        "high",
    "google_api_key": "medium",
    "google_oauth":   "medium",
    "jwt":            "medium",
    "firebase_url":   "low",
    "high_entropy":   "low",
}

# Extra check for "obviously a demo/example key" patterns
_DEMO_KEY_RE = re.compile(
    r"(?i)(example|test|demo|placeholder|xxxx|1234567890|"
    r"abcdefg|0000000000|your[_\-]?key)",
)

# Internal hostnames
INTERNAL_HOST_PATTERN = re.compile(
    r"""["'\s>]                              # boundary
        (                                     # capture group 1
            (?:[a-zA-Z][a-zA-Z0-9\-]{1,62}\.)+   # one or more labels
            (?:
                local|internal|corp|lan|home|intranet|localdomain
            )
        )
        (?:["'\s<.,;:]|$)                     # boundary
    """,
    re.VERBOSE,
)

SOURCEMAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")
SOURCEMAP_COMMENT_PATTERN = re.compile(
    r"/\*[#@]\s*sourceMappingURL=([^\s\*]+)\s*\*/")

DEV_COMMENT_PATTERN = re.compile(
    r"(?://|#)\s*(TODO|FIXME|XXX|HACK|BUG|NOTE|WARNING|SECURITY)[: ](.*?)$",
    re.MULTILINE | re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

SCRIPT_SRC_PATTERN = re.compile(
    r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
INLINE_SCRIPT_PATTERN = re.compile(
    r"<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
MANIFEST_PATTERN = re.compile(
    r'<link[^>]*\brel\s*=\s*["\']manifest["\'][^>]*\bhref\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
MANIFEST_PATTERN_REV = re.compile(
    r'<link[^>]*\bhref\s*=\s*["\']([^"\']+)["\'][^>]*\brel\s*=\s*["\']manifest["\']',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------
# D4: chunk reference patterns
# ---------------------------------------------------------------------
#
# Webpack: __webpack_require__.e(/* require.ensure */ "chunk-name")
#          __webpack_require__.u = id => "chunk-" + id + ".js"
#          __webpack_require__.p = "/static/js/"
# Vite:    import("./chunk-abc123.js")
# ESBuild: import("./chunk-abc123.js")
# SWC/Next: __webpack_require__.u
CHUNK_PATTERNS = [
    # Static path strings that look like chunk files
    re.compile(r"""["']\.?/?([a-zA-Z0-9_\-/]+\.chunk\.js)["']"""),
    re.compile(r"""["']\.?/?([a-zA-Z0-9_\-/]+-[0-9a-f]{8,}\.js)["']"""),
    re.compile(r"""["']\.?/?([a-zA-Z0-9_\-/]+\.[0-9a-f]{8,}\.js)["']"""),
    # import("./xyz.js")
    re.compile(r"""import\s*\(\s*["'](\.?/[^"']+\.js)["']\s*\)"""),
    # Vite: new URL("./xyz.js", import.meta.url)
    re.compile(r"""new\s+URL\s*\(\s*["'](\.?/[^"']+\.js)["']"""),
]


# ---------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------

async def _fetch_text(session, url, limiter, max_bytes=MAX_FILE_BYTES,
                      timeout=15.0):
    """Fetch a URL as text, capped at max_bytes. Returns '' on failure."""
    try:
        status, headers, body, final_url = await fetch(
            session, url, limiter, timeout=timeout)
    except Exception:
        return ""
    if status != 200 or not body:
        return ""
    ct = (headers or {}).get("content-type", "") if headers else ""
    if ct and not any(t in ct.lower() for t in
                      ("javascript", "json", "text", "xml", "html",
                       "ecmascript")):
        return ""
    return body[:max_bytes]

# ── D4.1 ── Root resolution ──────────────────────────────────────────

async def _resolve_root(target, session, limiter, verbose=False):
    """Pick a working base URL for a target that may or may not
    include a scheme or a www prefix.

    Tries https://{host}, https://www.{host}, http://{host},
    http://www.{host}. Returns the first that responds with any
    HTTP status, or None if all fail.
    """
    from urllib.parse import urlparse as _urlparse

    if target.startswith(("http://", "https://")):
        parsed = _urlparse(target)
        host = parsed.hostname or ""
    else:
        host = target.split("/")[0].split(":")[0]

    if not host:
        return None

    bare_host = host[4:] if host.startswith("www.") else host

    candidates = [
        f"https://{bare_host}",
        f"https://www.{bare_host}",
        f"http://{bare_host}",
        f"http://www.{bare_host}",
    ]

    for base in candidates:
        try:
            status, _h, _body, _ = await fetch(
                session, base, limiter, timeout=10.0, quiet=True)
        except Exception:
            continue
        if status is not None:
            if verbose:
                info(f"    resolved root: {base}")
            return base
    return None

# ── END D4.1 ──


# ---------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------

def extract_api_paths(text):
    return {m.group(1) for m in API_PATTERN.finditer(text)}


def extract_urls(text):
    return set(URL_PATTERN.findall(text))


def extract_secrets(text):
    """Return list of dicts, sorted by severity."""
    out = []
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            match_text = m.group(0)
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 30)
            snippet = text[start:end].replace("\n", " ")[:100]
            severity = SECRET_SEVERITY.get(name, "low")
            note = ""
            # Demote obvious demo keys
            if _DEMO_KEY_RE.search(match_text):
                if severity in ("critical", "high"):
                    severity = "low"
                note = "looks like a demo/placeholder value"
            out.append({
                "type": name,
                "match": match_text[:200],
                "snippet": snippet,
                "severity": severity,
                "note": note,
            })
    # Sort: critical first, then high, medium, low, info
    order = {"critical": 0, "high": 1, "medium": 2,
             "low": 3, "info": 4}
    out.sort(key=lambda s: order.get(s["severity"], 9))
    return out


def extract_internal_hosts(text):
    return {m.group(1).lower() for m in INTERNAL_HOST_PATTERN.finditer(text)}


def extract_sourcemaps(text):
    maps = set()
    for m in SOURCEMAP_PATTERN.finditer(text):
        maps.add(m.group(1))
    for m in SOURCEMAP_COMMENT_PATTERN.finditer(text):
        maps.add(m.group(1))
    return maps


def extract_dev_comments(text):
    out = []
    for m in DEV_COMMENT_PATTERN.finditer(text):
        marker = m.group(1).upper()
        content = m.group(2).strip()[:200]
        if content:
            out.append({"marker": marker, "content": content})
    return out


_EMAIL_PLACEHOLDERS = {
    "you@domain.com", "user@domain.com", "email@domain.com",
    "name@domain.com", "your@email.com", "user@example.com",
    "name@example.com", "someone@example.com",
    "noreply@example.com", "test@test.com", "foo@bar.com",
}


def extract_emails(text):
    emails = set(EMAIL_PATTERN.findall(text))
    out = set()
    for e in emails:
        low = e.lower()
        if low in _EMAIL_PLACEHOLDERS:
            continue
        if low.endswith((".png", ".jpg", ".gif", ".webp", ".svg")):
            continue
        if "@example." in low or "@test." in low:
            continue
        out.add(e)
    return out


# ---------------------------------------------------------------------
# D4: high-entropy fallback
# ---------------------------------------------------------------------

def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    ent = 0.0
    for c, k in counts.items():
        p = k / n
        ent -= p * math.log2(p)
    return ent


# Match quoted strings we might care about. Catches "..." and '...'
_QUOTED_RE = re.compile(r"""["']([A-Za-z0-9_\-+/=.]{20,200})["']""")


def _find_high_entropy(text, exclude_matches):
    """Return list of {match, entropy, length} for quoted strings
    that look like secrets by entropy but weren't caught by a
    named regex.
    """
    exclude = set()
    for m in exclude_matches:
        exclude.add(m)

    out = []
    seen = set()
    for m in _QUOTED_RE.finditer(text):
        s = m.group(1)
        if s in seen:
            continue
        seen.add(s)
        if any(s in ex or ex in s for ex in exclude):
            continue
        # Skip obvious paths/URLs
        if s.startswith(("/", "http", "./", "../")):
            continue
        if "." in s and "/" in s:
            continue
        # Skip if it's just a base64 blob of only letters (likely a
        # minified identifier)
        if all(c.isalpha() for c in s):
            continue
        ent = _shannon_entropy(s)
        if ent < ENTROPY_MIN_BITS:
            continue
        out.append({
            "match": s[:200],
            "entropy": round(ent, 2),
            "length": len(s),
        })
    # Dedupe by match text
    seen2 = set()
    uniq = []
    for h in out:
        if h["match"] in seen2:
            continue
        seen2.add(h["match"])
        uniq.append(h)
    return uniq


# ---------------------------------------------------------------------
# D4: chunk reference extraction
# ---------------------------------------------------------------------

def _find_chunk_refs(text, base_url):
    """Return a set of absolute chunk URLs referenced by the text.

    This is heuristic — we don't run the JS, so we can't execute
    webpack's runtime. We scan for quoted strings that look like
    chunk files and resolve them against base_url.
    """
    refs = set()
    for rx in CHUNK_PATTERNS:
        for m in rx.finditer(text):
            raw = m.group(1).strip()
            if not raw or len(raw) > 200:
                continue
            full = urljoin(base_url, raw)
            if not full.startswith(("http://", "https://")):
                continue
            refs.add(full)
    return refs


# ---------------------------------------------------------------------
# D4: source map recovery
# ---------------------------------------------------------------------

def _decode_sourcemap(map_json):
    """Given a parsed sourcemap JSON, return {source_path: text}.

    Only sources with non-empty sourcesContent entries are returned;
    many sourcemaps omit sourcesContent, in which case we can't
    recover anything useful without fetching each source separately.
    """
    out = {}
    sources = map_json.get("sources") or []
    contents = map_json.get("sourcesContent") or []
    for i, src in enumerate(sources):
        if i >= len(contents):
            break
        content = contents[i]
        if not content:
            continue
        out[str(src)] = str(content)
    return out


async def _fetch_sourcemap(map_url, session, limiter):
    """Fetch and parse a .map file. Returns (raw_text, parsed_json)."""
    text = await _fetch_text(session, map_url, limiter,
                              max_bytes=5 * 1024 * 1024)
    if not text:
        return "", None
    try:
        return text, json.loads(text)
    except json.JSONDecodeError:
        return text, None


def _write_sources(sources_dict, js_url, workspace):
    """Write recovered sources to disk under workspace/loot/js/.

    Returns {source_path: written_file_path} or {}.
    """
    if workspace is None or not sources_dict:
        return {}
    try:
        base = workspace.loot_dir / "js"
        base.mkdir(parents=True, exist_ok=True)
        # Build a directory from the JS URL
        parsed = urlparse(js_url)
        host = parsed.hostname or "unknown"
        # Use the last path segment without extension
        last = parsed.path.rsplit("/", 1)[-1]
        if last.endswith(".js"):
            last = last[:-3]
        last = re.sub(r"[^A-Za-z0-9_\-]", "_", last)[:40] or "bundle"
        subdir = base / host / last
        subdir.mkdir(parents=True, exist_ok=True)

        written = {}
        for src_path, src_text in sources_dict.items():
            safe = src_path.replace("\\", "/").lstrip("/")
            safe = re.sub(r"\.\.", "_", safe)
            safe = re.sub(r"[^A-Za-z0-9_\-/.]", "_", safe)
            if not safe:
                safe = "source.js"
            out_path = subdir / safe
            try:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(src_text, encoding="utf-8",
                                     errors="replace")
                written[src_path] = str(out_path)
            except Exception:
                continue
        return written
    except Exception:
        return {}


async def _recover_sources(js_url, js_text, session, limiter,
                             workspace=None, verbose=False):
    """Full source map recovery for one JS file.

    Returns:
        {
          "map_url": str | None,
          "sources": {source_path: text},
          "written": {source_path: file_path},
          "errors": [str],
        }
    """
    result = {
        "map_url": None,
        "sources": {},
        "written": {},
        "errors": [],
    }
    refs = extract_sourcemaps(js_text)
    if not refs:
        return result

    # The ref is usually relative to the JS file's directory
    # or an absolute URL or a data: URI (rare).
    ref = sorted(refs)[0]
    if ref.startswith("data:"):
        # Base64-encoded inline sourcemap
        try:
            import base64
            _, _, b64 = ref.partition(",")
            decoded = base64.b64decode(b64)
            data = json.loads(decoded)
            result["map_url"] = "data:inline"
            result["sources"] = _decode_sourcemap(data)
        except Exception as e:
            result["errors"].append(f"inline map decode: {e}")
            return result
    else:
        map_url = urljoin(js_url, ref)
        result["map_url"] = map_url
        raw, data = await _fetch_sourcemap(map_url, session, limiter)
        if data is None:
            if raw:
                result["errors"].append("map file present but invalid JSON")
            else:
                result["errors"].append("map file fetch failed")
            return result
        result["sources"] = _decode_sourcemap(data)

    if result["sources"] and workspace is not None:
        result["written"] = _write_sources(result["sources"], js_url,
                                            workspace)

    if verbose and result["sources"]:
        info(f"    sourcemap: recovered {len(result['sources'])} "
             f"source file(s) from {js_url.rsplit('/', 1)[-1]}")

    return result


# ---------------------------------------------------------------------
# D4: path clustering
# ---------------------------------------------------------------------

def _cluster_paths(paths):
    """Group a flat list of API paths by their first two segments.

    /api/v1/users          → "/api/v1"
    /api/v1/users/1        → "/api/v1"
    /admin/login           → "/admin"
    /graphql               → "/graphql"
    """
    clusters = {}
    for p in paths:
        if not p:
            continue
        parts = [x for x in p.split("/") if x]
        if not parts:
            continue
        if len(parts) >= 2:
            key = "/" + "/".join(parts[:2])
        else:
            key = "/" + parts[0]
        clusters.setdefault(key, []).append(p)
    return clusters


# ---------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------

async def analyze_file(session, url, limiter, verbose=False):
    """Fetch and analyze one JS file. Returns findings dict."""
    text = await _fetch_text(session, url, limiter)
    if not text:
        return {"url": url, "size": 0, "error": "fetch failed"}

    secrets = extract_secrets(text)
    entropy = _find_high_entropy(text, [s["match"] for s in secrets])

    return {
        "url": url,
        "size": len(text),
        "api_paths": sorted(extract_api_paths(text)),
        "urls": sorted(extract_urls(text)),
        "secrets": secrets,
        "high_entropy": entropy,
        "internal_hosts": sorted(extract_internal_hosts(text)),
        "sourcemaps": sorted(extract_sourcemaps(text)),
        "dev_comments": extract_dev_comments(text)[:20],
        "emails": sorted(extract_emails(text)),
        "chunk_refs": sorted(_find_chunk_refs(text, url)),
    }


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


async def _probe_scheme(session, host, limiter,
                         verbose=False) -> str:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            status, _headers, _body, final_url = await fetch(
                session, url, limiter, timeout=10.0)
            if status and status < 500:
                if verbose:
                    info(f"  scheme probe: {url} → {status}")
                return final_url or url
        except Exception:
            continue
    return f"http://{host}"


async def analyze(target, session=None, verbose=False,
                   max_js=DEFAULT_MAX_JS, workspace=None):
    """Full JS + manifest + inline-script analysis for a target URL.

    D4 additions:
      - Recursive chunk discovery (up to DEFAULT_MAX_TOTAL_JS total)
      - Source map recovery (writes to workspace/loot/js/ when a
        workspace is provided)
      - Secret severity classification
      - High-entropy string detection
      - API path clustering
    """
    base_url = target
    if not base_url.startswith(("http://", "https://")):
        pass

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(5.0)

    # ── D4.1 ── Resolve root once; handles the www fallback ──
    resolved = await _resolve_root(target, session, limiter,
                                    verbose=verbose)
    if resolved is None:
        # Couldn't resolve any candidate — return a clean error
        # rather than trying to fetch a host that doesn't exist.
        if own_session:
            await session.close()
        return {
            "target": target,
            "error": "target does not resolve",
            "files_analyzed": 0,
            "inline_scripts": 0,
            "manifest": None,
            "api_paths": [],
            "api_clusters": {},
            "urls": [],
            "secrets": [],
            "high_entropy": [],
            "internal_hosts": [],
            "sourcemaps": [],
            "source_map_recoveries": [],
            "dev_comments": [],
            "emails": [],
            "chunk_refs": [],
        }
    base_url = resolved
    # ── END D4.1 ──

    try:
        info(f"fetching {base_url}")
        html = await _fetch_text(session, base_url, limiter, timeout=20.0)
        if not html:
            return {
                "target": base_url,
                "error": "could not fetch base page",
                "files_analyzed": 0,
                "inline_scripts": 0,
                "manifest": None,
                "api_paths": [],
                "api_clusters": {},
                "urls": [],
                "secrets": [],
                "high_entropy": [],
                "internal_hosts": [],
                "sourcemaps": [],
                "source_map_recoveries": [],
                "dev_comments": [],
                "emails": [],
                "chunk_refs": [],
            }

        script_srcs = set(SCRIPT_SRC_PATTERN.findall(html))
        resolved = set()
        for src in script_srcs:
            resolved.add(urljoin(base_url, src))
        script_urls = sorted(resolved)

        if len(script_urls) > max_js:
            warn(f"found {len(script_urls)} JS files; capping at {max_js}")
            script_urls = script_urls[:max_js]

        info(f"analyzing {len(script_urls)} initial JS file(s)")

        # --- 1. Fetch initial JS files ---
        sem = asyncio.Semaphore(6)
        results = []

        async def _one(url):
            async with sem:
                return await analyze_file(session, url, limiter,
                                            verbose=verbose)

        file_results = await asyncio.gather(
            *[_one(u) for u in script_urls], return_exceptions=True)

        for r in file_results:
            if isinstance(r, Exception):
                continue
            results.append(r)

        # --- 2. Recursive chunk discovery ---
        # Collect all chunk refs from the initial files, dedupe,
        # and fetch up to (max_total_js - already_fetched) of them.
        initial_urls = {r["url"] for r in results}
        all_chunk_refs = set()
        for r in results:
            for ref in r.get("chunk_refs", []):
                if ref not in initial_urls:
                    all_chunk_refs.add(ref)

        max_total = DEFAULT_MAX_TOTAL_JS
        remaining_slots = max_total - len(results)
        if all_chunk_refs and remaining_slots > 0:
            to_fetch = sorted(all_chunk_refs)[:remaining_slots]
            info(f"following {len(to_fetch)} recursive chunk(s) "
                 f"(had {len(all_chunk_refs)})")
            chunk_results = await asyncio.gather(
                *[_one(u) for u in to_fetch], return_exceptions=True)
            for r in chunk_results:
                if isinstance(r, Exception):
                    continue
                results.append(r)
        elif all_chunk_refs and verbose:
            info(f"  ({len(all_chunk_refs)} more chunk(s) available "
                 f"but max_total_js={max_total} reached)")

        # --- 3. Source map recovery ---
        recoveries = []
        for r in results:
            if r.get("error"):
                continue
            js_text = await _fetch_text(session, r["url"], limiter)
            if not js_text:
                continue
            rec = await _recover_sources(
                r["url"], js_text, session, limiter,
                workspace=workspace, verbose=verbose)
            if rec.get("map_url"):
                recoveries.append({
                    "js_url": r["url"],
                    "map_url": rec.get("map_url"),
                    "source_count": len(rec.get("sources", {})),
                    "written": rec.get("written", {}),
                    "errors": rec.get("errors", []),
                })

        # --- 4. Inline scripts ---
        inline_scripts = INLINE_SCRIPT_PATTERN.findall(html)
        inline_text = "\n".join(inline_scripts)
        if verbose:
            info(f"  {len(inline_scripts)} inline script(s), "
                 f"{len(inline_text)} bytes total")

        # --- 5. Manifest ---
        manifest_url = None
        m = MANIFEST_PATTERN.search(html) or MANIFEST_PATTERN_REV.search(html)
        if m:
            manifest_url = urljoin(base_url, m.group(1))
            if verbose:
                info(f"  PWA manifest: {manifest_url}")
        manifest_data = None
        if manifest_url:
            manifest_text = await _fetch_text(session, manifest_url, limiter)
            if manifest_text:
                try:
                    manifest_data = json.loads(manifest_text)
                except json.JSONDecodeError:
                    manifest_data = {"raw": manifest_text[:1000]}

        # --- 6. Aggregate everything ---
        all_api = set()
        all_urls = set()
        all_secrets = []
        all_entropy = []
        all_hosts = set()
        all_maps = set()
        all_comments = []
        all_emails = set()
        all_chunk_refs = set()

        for r in results:
            all_api.update(r.get("api_paths", []))
            all_urls.update(r.get("urls", []))
            for s in r.get("secrets", []):
                s["_source"] = r["url"]
                all_secrets.append(s)
            for h in r.get("high_entropy", []):
                h["_source"] = r["url"]
                all_entropy.append(h)
            all_hosts.update(r.get("internal_hosts", []))
            all_maps.update(r.get("sourcemaps", []))
            for c in r.get("dev_comments", []):
                c["_source"] = r["url"]
                all_comments.append(c)
            all_emails.update(r.get("emails", []))
            all_chunk_refs.update(r.get("chunk_refs", []))

        if inline_text:
            all_api.update(extract_api_paths(inline_text))
            all_urls.update(extract_urls(inline_text))
            for s in extract_secrets(inline_text):
                s["_source"] = "inline"
                all_secrets.append(s)
            for h in _find_high_entropy(
                    inline_text,
                    [s["match"] for s in extract_secrets(inline_text)]):
                h["_source"] = "inline"
                all_entropy.append(h)
            all_hosts.update(extract_internal_hosts(inline_text))
            for c in extract_dev_comments(inline_text):
                c["_source"] = "inline"
                all_comments.append(c)
            all_emails.update(extract_emails(inline_text))

        # Dedupe secrets by (type, match) — keep highest severity
        seen_secrets = {}
        for s in all_secrets:
            key = (s["type"], s["match"])
            if key in seen_secrets:
                continue
            seen_secrets[key] = s
        unique_secrets = list(seen_secrets.values())
        order = {"critical": 0, "high": 1, "medium": 2,
                 "low": 3, "info": 4}
        unique_secrets.sort(key=lambda s: order.get(s["severity"], 9))

        # Dedupe entropy hits
        seen_ent = set()
        unique_entropy = []
        for h in all_entropy:
            if h["match"] in seen_ent:
                continue
            seen_ent.add(h["match"])
            unique_entropy.append(h)
        unique_entropy.sort(key=lambda h: -h["entropy"])
        unique_entropy = unique_entropy[:50]

        # Cluster the API paths
        api_clusters = _cluster_paths(sorted(all_api))

        return {
            "target": base_url,
            "files_analyzed": len([r for r in results if r.get("size")]),
            "total_js_bytes": sum(r.get("size", 0) for r in results),
            "inline_scripts": len(inline_scripts),
            "inline_bytes": len(inline_text),
            "manifest": manifest_data,
            "manifest_url": manifest_url,
            "api_paths": sorted(all_api),
            "api_clusters": api_clusters,
            "urls": sorted(all_urls),
            "secrets": unique_secrets,
            "high_entropy": unique_entropy,
            "internal_hosts": sorted(all_hosts),
            "sourcemaps": sorted(all_maps),
            "source_map_recoveries": recoveries,
            "dev_comments": all_comments[:50],
            "emails": sorted(all_emails),
            "chunk_refs": sorted(all_chunk_refs),
        }
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------

async def run(target, store=None, verbose=False,
              max_js=DEFAULT_MAX_JS, workspace=None):
    result = await analyze(target, verbose=verbose, max_js=max_js,
                            workspace=workspace)

    print()
    if result.get("error"):
        error(f"  {result['error']}")
        return result

    success(f"JS analysis for {result['target']}")
    print(f"  Files analyzed:  {result['files_analyzed']}")
    print(f"  Total JS bytes:  {result['total_js_bytes']:,}")
    print(f"  Inline scripts:  {result['inline_scripts']} "
          f"({result['inline_bytes']:,} bytes)")
    if result.get("manifest"):
        print(f"  PWA manifest:    yes")

    if result["api_clusters"]:
        print()
        success(f"  API endpoints ({len(result['api_paths'])}, "
                f"{len(result['api_clusters'])} cluster(s)):")
        for prefix, entries in sorted(result["api_clusters"].items(),
                                       key=lambda x: -len(x[1])):
            print(f"    {prefix:30s} ({len(entries)})")
            for p in entries[:3]:
                print(f"      {p}")
            if len(entries) > 3:
                print(f"      ... and {len(entries) - 3} more")

    if result["secrets"]:
        print()
        by_sev = {}
        for s in result["secrets"]:
            by_sev.setdefault(s["severity"], []).append(s)
        total = len(result["secrets"])
        parts = ", ".join(f"{len(v)} {k}" for k, v in sorted(
            by_sev.items(),
            key=lambda x: {"critical": 0, "high": 1, "medium": 2,
                            "low": 3, "info": 4}.get(x[0], 9)))
        error(f"  Secrets ({total}: {parts}):")
        for s in result["secrets"][:15]:
            tag = f"[{s['severity']:8s}]"
            print(f"    {tag} {s['type']:20s} {s['match'][:60]}")
            if s.get("note"):
                print(f"               note: {s['note']}")
            print(f"               src:  {s['_source']}")
        if total > 15:
            print(f"    ... and {total - 15} more")

    if result["high_entropy"]:
        print()
        warn(f"  High-entropy strings ({len(result['high_entropy'])}):")
        for h in result["high_entropy"][:10]:
            print(f"    entropy={h['entropy']:5.2f} "
                  f"len={h['length']:3d} {h['match'][:60]}")
            print(f"               src: {h['_source']}")
        if len(result["high_entropy"]) > 10:
            print(f"    ... and {len(result['high_entropy']) - 10} more")

    if result["source_map_recoveries"]:
        print()
        success(f"  Source map recoveries "
                f"({len(result['source_map_recoveries'])}):")
        for rec in result["source_map_recoveries"]:
            js = rec["js_url"].rsplit("/", 1)[-1]
            print(f"    {js} → {rec['source_count']} source file(s)")
            if rec.get("written"):
                for src, path in list(rec["written"].items())[:3]:
                    print(f"      {src}")
                    print(f"        → {path}")
            if rec.get("errors"):
                for e in rec["errors"]:
                    print(f"      err: {e}")

    if result["internal_hosts"]:
        print()
        warn(f"  Internal hosts ({len(result['internal_hosts'])}):")
        for h in result["internal_hosts"][:15]:
            print(f"    {h}")

    if result["sourcemaps"]:
        print()
        info(f"  Source map references "
             f"({len(result['sourcemaps'])}):")
        for m in result["sourcemaps"][:10]:
            print(f"    {m}")

    if result["chunk_refs"]:
        print()
        info(f"  Recursive chunk references "
             f"({len(result['chunk_refs'])}):")
        for c in result["chunk_refs"][:10]:
            print(f"    {c}")
        if len(result["chunk_refs"]) > 10:
            print(f"    ... and {len(result['chunk_refs']) - 10} more")

    if result["dev_comments"]:
        print()
        info(f"  Dev comments ({len(result['dev_comments'])}):")
        for c in result["dev_comments"][:10]:
            print(f"    [{c['marker']}] {c['content'][:100]}")

    if result["emails"]:
        print()
        info(f"  Emails ({len(result['emails'])}):")
        for e in result["emails"][:10]:
            print(f"    {e}")

    if result.get("manifest"):
        print()
        info("  PWA manifest:")
        m = result["manifest"]
        for key in ("name", "short_name", "version", "start_url",
                    "display", "scope"):
            if isinstance(m, dict) and m.get(key):
                print(f"    {key:12s} {m[key]}")

    if store is not None:
        severity = ("critical" if any(
                        s["severity"] == "critical"
                        for s in result["secrets"])
                    else "high" if any(
                        s["severity"] == "high"
                        for s in result["secrets"])
                    else "medium" if result["secrets"] else (
                        "medium" if result["api_paths"]
                        or result["internal_hosts"] else "info"))
        store.add_finding({
            "module": "js_analysis",
            "type": ("secret_exposed" if result["secrets"]
                     else "informational"),
            "severity": severity,
            "target": target,
            "evidence": (f"{len(result['secrets'])} secrets, "
                         f"{len(result['api_paths'])} API paths "
                         f"in {len(result['api_clusters'])} cluster(s), "
                         f"{len(result['source_map_recoveries'])} "
                         f"source map recoveries, "
                         f"{len(result['internal_hosts'])} internal hosts "
                         f"in {result['files_analyzed']} JS files"),
            "data": result,
        })
        success("finding written to store")

    return result


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.js_analysis",
        description="Analyze JS files, inline scripts, and PWA manifest.",
    )
    p.add_argument("target", help="URL or hostname")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--max-js", type=int, default=DEFAULT_MAX_JS,
                   help=f"max initial JS files to analyze "
                        f"(default {DEFAULT_MAX_JS})")
    p.add_argument("--store", action="store_true")
    args = p.parse_args()

    store = None
    workspace = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; use `toolkit workspace switch`")
            return
        workspace = get_workspace(active)
        store = open_store(workspace.db_path, workspace_name=active)

    asyncio.run(run(args.target, store=store, verbose=args.verbose,
                    max_js=args.max_js, workspace=workspace))


if __name__ == "__main__":
    _cli()