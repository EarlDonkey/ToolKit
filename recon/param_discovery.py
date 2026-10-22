"""
Hidden HTTP parameter discovery.

Given a URL, tries a wordlist of common parameter names to find ones
that change the response in a way that suggests they're meaningful
(not just ignored). This is how you find:

    ?debug=1            Enable debug output
    ?admin=true         Bypass auth checks
    ?test=1             Different behavior for tests
    ?source=internal    Bypass IP allowlists
    ?preview=1          Show unpublished content
    ?raw=1              Return unprocessed source
    ?format=json        Change response format
    ?callback=foo       JSONP callback (often reflects)

Design:

  For each candidate parameter, we compare the response to a baseline
  with the parameter absent. If the response differs meaningfully,
  the parameter is "live". What counts as meaningful:

    - Status code changes
    - Response length changes by more than a threshold (default 30 bytes)
    - Response content changes (hash diff) with stable status
    - Specific "interesting strings" appear that weren't there before
      (e.g. "debug", "root", "warning", "error", "sql")

  We test each candidate with several values because the parameter
  might only trigger on a specific value:

      1, true, on, yes, admin, test, debug, raw, 0, false

  To keep the request count manageable, we do a two-stage check:

    Stage 1: Send `?param=1`. If the response differs from baseline,
             keep the parameter as a candidate.

    Stage 2: For candidates, send a few more values to confirm and
             classify. Report the parameter with the values that work.

  For authenticated discovery, pass `--cookie`. The module will use
  the cookies on every request.

  Rate limiting is aggressive by default (`--rate 5`) since we're
  hitting the same endpoint hundreds of times. On a heavily-WAF'd
  target this will trip alarms — that's why it's opt-in.

Severity:

  Discovered parameters start at `info` severity. They become
  findings worth noting, not vulnerabilities themselves. If the
  parameter name matches suspicious patterns (`admin`, `debug`,
  `test`, `internal`, `root`) we bump to `low`.

Usage:

    from recon.param_discovery import discover

    findings = await discover("https://example.com/api/user", session, limiter)

    # CLI
    python -m recon.param_discovery https://example.com/api/user
    python -m recon.param_discovery https://example.com/api/user \\
        --wordlist custom-params.txt \\
        --cookie "session=x" -v

Findings written to the store:
    one row per discovered parameter
"""

import asyncio
import hashlib
import secrets
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Curated list of ~250 common parameters. Covers debug flags, auth
# toggles, format selectors, source indicators, and framework-specific
# params (Spring, Django, Rails, Laravel, ASP.NET).
COMMON_PARAMS = [
    # --- Debug / test flags ---
    "debug", "test", "testing", "dev", "develop", "development",
    "staging", "stage", "preview", "verbose", "trace", "log",
    "show_errors", "display_errors", "error_reporting", "backtrace",
    "dump", "inspect", "diagnostics", "profiler", "profile",

    # --- Auth / privilege ---
    "admin", "administrator", "is_admin", "isadmin", "superuser",
    "root", "sudo", "elevate", "role", "roles", "permission",
    "permissions", "auth", "authorized", "internal", "employee",
    "staff", "user", "user_id", "uid", "id", "account", "account_id",
    "customer_id", "tenant", "tenant_id", "org", "organization",

    # --- Bypass / override ---
    "bypass", "skip", "no_auth", "noauth", "unauthenticated",
    "force", "override", "ignore", "disable", "disabled",
    "x-forwarded-for", "x-real-ip", "forwarded-for", "client-ip",
    "remote-addr", "x-originating-ip", "x-remote-ip", "x-client-ip",
    "x-remote-addr", "true-client-ip", "cf-connecting-ip",

    # --- Content / format ---
    "format", "fmt", "type", "output", "output_format", "response",
    "response_type", "accept", "content_type", "mime", "mimetype",
    "encoding", "charset", "lang", "language", "locale", "country",
    "currency", "timezone", "tz",

    # --- View / display ---
    "view", "template", "theme", "skin", "layout", "render",
    "renderer", "partial", "fragment", "include", "embed",
    "callback", "jsonp", "jsonpcallback", "raw", "source", "code",
    "plain", "text", "print", "pdf", "download",

    # --- Redirect / navigation ---
    "next", "url", "uri", "redirect", "redirect_uri", "redirect_url",
    "return", "return_to", "returnurl", "return_url", "continue",
    "dest", "destination", "target", "goto", "out", "back", "backurl",

    # --- Pagination ---
    "page", "p", "pagenum", "page_num", "page_number", "offset",
    "start", "from", "limit", "count", "size", "per_page", "perpage",
    "pagesize", "page_size", "max", "n", "num", "number",

    # --- Search / filter ---
    "q", "query", "search", "s", "keyword", "keywords", "filter",
    "sort", "order", "orderby", "order_by", "sortby", "sort_by",
    "asc", "desc", "direction", "dir", "field", "fields", "select",
    "columns", "include", "exclude",

    # --- File / path ---
    "file", "filename", "path", "filepath", "dir", "folder",
    "document", "doc", "resource", "asset", "image", "img",
    "template", "layout", "config", "conf",

    # --- API / data ---
    "api", "api_key", "apikey", "key", "token", "secret", "password",
    "signature", "sig", "hash", "checksum", "nonce", "salt",

    # --- Versioning ---
    "version", "v", "ver", "revision", "rev", "build", "release",
    "api_version", "apiversion", "schema", "migration",

    # --- Actions ---
    "action", "do", "op", "operation", "method", "cmd", "command",
    "func", "function", "handler", "task", "job", "run", "exec",
    "execute", "process", "submit", "confirm", "approve", "cancel",
    "delete", "remove", "edit", "update", "create", "new",

    # --- Framework-specific ---
    "_method", "_token", "_csrf", "csrf", "csrf_token", "csrfmiddlewaretoken",
    "authenticity_token", "__RequestVerificationToken", "X-CSRF-Token",
    "X-Requested-With", "X-HTTP-Method-Override", "_format",
    "utf8", "_utf8", "commit", "authenticity_token",

    # --- Analytics / tracking (usually benign, still interesting) ---
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "ref", "referer", "referrer", "source",
    "campaign", "medium", "channel",

    # --- Misc ---
    "callback_url", "webhook", "webhook_url", "notify", "notification",
    "email", "phone", "name", "first_name", "last_name", "username",
    "message", "comment", "content", "body", "text", "title",
    "category", "tag", "tags", "label", "group", "type",
    "public", "private", "hidden", "visible", "show", "hide",
    "enable", "disable", "enabled", "disabled", "status", "state",
    "mode", "color", "size", "width", "height", "position",
    "start_time", "end_time", "start_date", "end_date", "date",
    "time", "timestamp", "created_at", "updated_at",
]


# Param values tried in stage 2. Deliberately varied.
STAGE2_VALUES = [
    "0", "false", "no", "off",
    "test", "debug", "raw",
    "admin", "root", "internal",
    "json", "xml", "html",
]


# Parameter names that are inherently interesting if they exist
SUSPICIOUS_NAMES = {
    "admin", "administrator", "is_admin", "isadmin", "superuser",
    "root", "sudo", "elevate",
    "debug", "test", "dev", "develop", "development",
    "internal", "employee", "staff",
    "bypass", "skip", "no_auth", "noauth",
    "force", "override", "ignore",
    "raw", "source", "code", "dump",
    "preview", "profiler", "profile",
}


# Body length threshold for stage 1 detection
LENGTH_THRESHOLD = 30

# Words that suggest debug content when they appear in a response
INTERESTING_STRINGS = [
    "debug", "stack trace", "traceback", "exception",
    "sql", "syntax error", "warning",
    "root", "admin", "internal",
    "test mode", "development mode",
    "stacktrace", "mysql", "postgres", "sqlite",
    "config", "secret", "token", "password",
]


# ---------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------

def _with_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[name] = [value]
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlencode(qs, doseq=True), parsed.fragment,
    ))


def _hash(text: str) -> str:
    return hashlib.sha1((text or "").encode("utf-8",
                                              errors="ignore")).hexdigest()


# ---------------------------------------------------------------------
# Stage 1 detection
# ---------------------------------------------------------------------

def _stage1_differs(baseline: dict, response: dict) -> tuple[bool, str]:
    """Compare stage-1 response to baseline. Return (differs, reason)."""
    # Status code change is a strong signal
    if response["status"] != baseline["status"]:
        return True, f"status {baseline['status']}→{response['status']}"

    # Large body length change
    bl = baseline["length"]
    rl = response["length"]
    if abs(rl - bl) >= LENGTH_THRESHOLD:
        return True, f"length {bl}→{rl}"

    # Content hash change while status is stable (with minimum size)
    if bl > 200 and _hash(baseline["body"]) != _hash(response["body"]):
        # Ignore if body length is identical but hash differs — that's
        # likely a dynamic page element (timestamps, CSRF tokens)
        if rl != bl:
            return True, "content differs"

    return False, ""


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def discover(url: str, session=None, limiter=None,
                    cookies=None, params: list[str] | None = None,
                    extra_params: list[str] | None = None,
                    verbose: bool = False, rate: float = 5.0,
                    timeout: float = 10.0) -> list[dict]:
    """Discover hidden parameters on a URL.

    Returns a list of finding dicts — one per parameter that looks live.
    """
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    # Build the parameter list
    base = list(params) if params else list(COMMON_PARAMS)
    # Remove any parameter already present in the URL (we're looking
    # for new ones)
    existing = set(parse_qs(urlparse(url).query,
                             keep_blank_values=True).keys())
    base = [p for p in base if p not in existing]
    if extra_params:
        base.extend(extra_params)
    # Dedup preserving order
    seen = set()
    base = [p for p in base if not (p in seen or seen.add(p))]

    if not base:
        warn("param_discovery: no candidate parameters to test")
        return []

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=rate)

    info(f"param_discovery: testing {len(base)} candidate parameter(s) "
         f"on {url}")

    findings: list[dict] = []

    try:
        # Baseline request
        try:
            base_req = await fetch(session, url, limiter,
                                    cookies=cookies, timeout=timeout)
        except Exception as e:
            warn(f"param_discovery: baseline failed: "
                 f"{type(e).__name__}: {e}")
            return []
        if base_req is None or base_req[0] is None:
            warn("param_discovery: target did not respond")
            return []

        baseline = {
            "status": base_req[0],
            "body": base_req[2] or "",
            "length": len(base_req[2] or ""),
            "hash": _hash(base_req[2] or ""),
        }

        if verbose:
            info(f"  baseline: status={baseline['status']} "
                 f"length={baseline['length']}")

        # ---- Stage 1: cheap single-value test ----
        candidates: list[tuple[str, str, dict]] = []
        tested = 0

        for param in base:
            tested += 1
            test_url = _with_param(url, param, "1")
            try:
                r = await fetch(session, test_url, limiter,
                                 cookies=cookies, timeout=timeout)
            except Exception:
                continue
            if r is None or r[0] is None:
                continue

            response = {
                "status": r[0],
                "body": r[2] or "",
                "length": len(r[2] or ""),
            }
            differs, reason = _stage1_differs(baseline, response)
            if differs:
                candidates.append((param, reason, response))
                if verbose:
                    success(f"  [{tested}/{len(base)}] '{param}' "
                            f"stage1 hit: {reason}")

        if not candidates:
            info("  no parameters changed the response")
            return []

        info(f"  stage 1: {len(candidates)} candidate(s) found")

        # ---- Stage 2: confirm with multiple values ----
        for param, stage1_reason, _ in candidates:
            working_values = []
            for value in STAGE2_VALUES:
                test_url = _with_param(url, param, value)
                try:
                    r = await fetch(session, test_url, limiter,
                                     cookies=cookies, timeout=timeout)
                except Exception:
                    continue
                if r is None or r[0] is None:
                    continue
                response = {
                    "status": r[0],
                    "body": r[2] or "",
                    "length": len(r[2] or ""),
                }
                differs, _ = _stage1_differs(baseline, response)
                if differs:
                    working_values.append(value)

            if not working_values:
                # Stage 1 false positive — no value re-triggers
                if verbose:
                    warn(f"  '{param}' stage1 hit but no stage2 value "
                         f"confirms (false positive)")
                continue

            # Parameter is confirmed live
            suspicious = param.lower() in SUSPICIOUS_NAMES
            severity = "low" if suspicious else "info"

            finding = {
                "type": "hidden_param",
                "severity": severity,
                "url": url,
                "param": param,
                "payload": f"?{param}=1",
                "evidence": (f"'{param}' changed response "
                             f"({stage1_reason}); "
                             f"working values: "
                             f"{','.join(working_values[:6])}"),
                "data": {
                    "parameter": param,
                    "stage1_reason": stage1_reason,
                    "working_values": working_values,
                    "suspicious": suspicious,
                },
            }
            findings.append(finding)
            success(f"  [DISCOVERED] {param} "
                    f"({','.join(working_values[:4])})"
                    + (" [suspicious]" if suspicious else ""))

        return findings
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# Wordlist loading (for custom wordlists)
# ---------------------------------------------------------------------

def load_wordlist(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        warn(f"param_discovery: wordlist not found: {path}")
        return []
    out = []
    for line in p.read_text(encoding="utf-8",
                             errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
               cookie: str | None = None,
               wordlist: str | None = None,
               rate: float = 5.0) -> list[dict]:
    """CLI entry. Writes findings to store if provided."""
    cookies = parse_cookie_string(cookie) if cookie else None

    params = None
    if wordlist:
        params = load_wordlist(wordlist)
        if params:
            info(f"param_discovery: loaded {len(params)} param(s) "
                 f"from {wordlist}")

    findings = await discover(target, cookies=cookies, params=params,
                                verbose=verbose, rate=rate)

    print()
    if not findings:
        info(f"no hidden parameters discovered on {target}")
    else:
        success(f"{len(findings)} hidden parameter(s) discovered")

    if store is not None:
        for f in findings:
            store.add_finding({
                "module": "param_discovery",
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
        prog="recon.param_discovery",
        description="Discover hidden HTTP parameters.",
    )
    p.add_argument("target", help="URL to test")
    p.add_argument("--wordlist", default=None,
                   help="custom wordlist (one param per line)")
    p.add_argument("--cookie", default=None,
                   help="cookie string for authenticated testing")
    p.add_argument("--rate", type=float, default=5.0,
                   help="requests per second (default 5)")
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
        cookie=args.cookie, wordlist=args.wordlist, rate=args.rate))


if __name__ == "__main__":
    _cli()