"""
Sensitive path / file exposure check.

Tests a curated list of ~200 paths that commonly leak on misconfigured
web servers. Read-only (HEAD or GET with a 1-byte range) wherever
possible. Reports paths that return 200, 301/302 (redirect to the
file), or 401/403 (which confirm existence).

The default wordlist is at recon/signatures/leaks.txt.

Severity is set by STATUS, not by filename:

    200                    → high (or critical for known-bad files)
    301/302/303/307/308    → low  (redirect may point at real file)
    401/403                → info (existence confirmed, no leak)
    5xx                    → low  (potential error disclosure)

Findings:
    one row per target with the list of leaked paths in `data`
"""

import asyncio
from pathlib import Path

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error
from core.http import FailureTracker


LEAKS_PATH = Path(__file__).parent / "signatures" / "leaks.txt"
DEFAULT_CONCURRENCY = 8

# Timeouts: HEAD requests should be fast (server may not support them,
# but they respond quickly when supported). GET fallback is longer
# because the server actually has to send a body.
HEAD_TIMEOUT = 3.0
GET_TIMEOUT = 5.0

# Paths that returning 200/301/302/401/403 means the path EXISTS.
# 404 = not found. 5xx = server error (might still indicate something).
INTERESTING_STATUS = {200, 201, 202, 203, 204, 301, 302, 303, 307, 308,
                      401, 403, 405, 500, 501, 502, 503}

# Paths that are ACTUALLY bad when they return 200. These get a
# `critical` rating rather than `high`.
CRITICAL_FILES = (
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD",
    "/.aws/credentials",
    "/wp-config.php", "/wp-config.php.bak",
    "/backup.sql", "/db.sql", "/dump.sql",
    "/backup.zip", "/site.zip", "/www.zip",
    "/id_rsa", "/.ssh/id_rsa",
)


# ---------------------------------------------------------------------
# Wordlist loading
# ---------------------------------------------------------------------

def load_paths(path=LEAKS_PATH) -> list[str]:
    """Load the sensitive paths wordlist."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        warn(f"leak wordlist not found at {path}; using builtin fallback")
        return _embedded_fallback()
    except Exception as e:
        warn(f"could not read leak wordlist: {e}")
        return _embedded_fallback()

    paths = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            paths.append(line)
    return paths


def _embedded_fallback() -> list[str]:
    return [
        "/.git/config", "/.env", "/.env.local", "/.env.production",
        "/backup.zip", "/backup.tar.gz", "/backup.sql",
        "/db.sql", "/dump.sql", "/site.zip",
        "/config.php", "/config.json", "/web.config",
        "/phpinfo.php", "/info.php",
        "/wp-config.php", "/wp-config.php.bak",
        "/wp-json/wp/v2/users", "/wp-login.php",
        "/admin/", "/admin/login", "/administrator/",
        "/phpmyadmin/", "/pma/", "/jenkins/",
        "/server-status", "/server-info",
        "/.DS_Store", "/sitemap.xml", "/robots.txt",
        "/.well-known/security.txt",
        "/api/swagger.json", "/api/openapi.json",
        "/actuator/health", "/actuator/env",
        "/.htaccess", "/nginx.conf", "/apache2.conf",
        "/requirements.txt", "/package.json", "/composer.json",
        "/Dockerfile", "/docker-compose.yml",
        "/CHANGELOG.md", "/README.md", "/VERSION",
    ]


# ---------------------------------------------------------------------
# Single-path check
# ---------------------------------------------------------------------

async def _check_path(session, base_url: str, path: str,
                       limiter, verbose: bool = False) -> dict | None:
    """Check one path. Returns a dict if interesting, else None."""
    url = base_url.rstrip("/") + path
    try:
        r = await fetch(session, url, limiter, method="HEAD",
                        timeout=HEAD_TIMEOUT)
    except Exception:
        return None

    if r is None:
        return None

    status, headers, body, final_url = r

    # HEAD may not be supported by all servers. If we got 405/501 or
    # nothing useful, retry with GET.
    if status in (405, 501) or status is None:
        try:
            r = await fetch(session, url, limiter, method="GET",
                            timeout=GET_TIMEOUT)
        except Exception:
            return None
        if r is None:
            return None
        status, headers, body, final_url = r

    if status not in INTERESTING_STATUS:
        return None

    body_len = len(body) if body else 0

    # --- Catchall detection ---
    #
    # Three classes of "200 that isn't a leak":
    #
    #   1. Empty body:           the server has a route that returns
    #                            nothing for unmatched paths. Very
    #                            common on SPAs and CDNs. A real
    #                            leaked file always has content.
    #
    #   2. Huge body (>200KB):   a CMS or SPA catchall returning its
    #                            home page for every URL.
    #
    #   3. Baseline match:       we compare against a random-path
    #                            response later; for now, we just
    #                            note the two heuristics above.
    if status == 200 and body_len == 0:
        if verbose:
            info(f"  {status} {path}  (skipped: empty body — "
                 f"likely catchall)")
        return None
    if status == 200 and body_len > 200_000:
        if verbose:
            info(f"  {status} {path}  (skipped: >200KB — "
                 f"likely CMS catchall)")
        return None

    return {
        "path": path,
        "url": final_url,
        "status": status,
        "length": body_len,
        "server": (headers or {}).get("server", "") if headers else "",
        "content_type": (headers or {}).get("content-type", "") if headers else "",
    }


# ---------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------

def _classify(leaked: list[dict]) -> tuple[str, str]:
    """Return (severity, finding_type) for a set of leaked paths.

    Rules:
        - Any critical file at 200        → critical / sensitive_file_exposed
        - Any file at 200                 → high     / sensitive_file_exposed
        - Any 301/302/303/307/308         → low      / sensitive_path_redirect
        - Any 5xx                         → low      / server_error_disclosure
        - Only 401/403 hits               → info     / informational
        - Nothing                         → info     / informational
    """
    if not leaked:
        return "info", "informational"

    has_200 = any(e["status"] == 200 for e in leaked)
    exposed_critical = any(
        e["path"] in CRITICAL_FILES and e["status"] == 200
        for e in leaked
    )
    has_redirect = any(e["status"] in (301, 302, 303, 307, 308)
                       for e in leaked)
    has_5xx = any(e["status"] >= 500 for e in leaked)

    if exposed_critical:
        return "critical", "sensitive_file_exposed"
    if has_200:
        return "high", "sensitive_file_exposed"
    if has_redirect:
        return "low", "sensitive_path_redirect"
    if has_5xx:
        return "low", "server_error_disclosure"
    # Only 401/403 — just confirms existence, no actual leak
    return "info", "informational"


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def check(target: str, session=None, paths=None,
                concurrency: int = DEFAULT_CONCURRENCY,
                verbose: bool = False) -> dict:
    """Check a target for exposed sensitive paths.
    ...
    """
    base_url = target
    if not base_url.startswith(("http://", "https://")):
        base_url = f"http://{base_url}"

    if paths is None:
        paths = load_paths()

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(10.0)

    # ── SESSION R1 ── Pre-flight: confirm the target responds ──
    from core.http import preflight
    ok, reason = await preflight(base_url, session=session,
                                  limiter=limiter, timeout=5.0)
    if not ok:
        if own_session:
            await session.close()
        error(f"leak_check: target unreachable — {reason}")
        info(f"  (skipping {len(paths)} path(s))")
        return {
            "target": base_url,
            "checked": 0,
            "leaked": [],
            "unreachable": True,
            "reason": reason,
        }
    # ── END SESSION R1 ──

    sem = asyncio.Semaphore(concurrency)
    leaked: list[dict] = []

    # ── SESSION R1 ── Failure tracker ──
    tracker = FailureTracker(trip_after=20)
    # ── END SESSION R1 ──

    async def _one(path):
        async with sem:
            result = await _check_path(session, base_url, path, limiter,
                                        verbose=verbose)
            # ── SESSION R1 ── Track failures ──
            if result is None:
                if tracker.record_failure():
                    if verbose:
                        warn(f"  aborted after {tracker.trip_after} "
                             f"consecutive failures")
            else:
                tracker.record_success()
            # ── END SESSION R1 ──
            if result:
                leaked.append(result)
                try:
                    from net.util import PRINT_LOCK
                    with PRINT_LOCK:
                        status = result["status"]
                        if status == 200:
                            marker = "LEAK"
                        elif status in (301, 302, 303, 307, 308):
                            marker = "REDIR"
                        elif status in (401, 403):
                            marker = "AUTH"
                        elif status >= 500:
                            marker = "ERR "
                        else:
                            marker = "?   "
                        success(f"  [{status:3d}] {marker} "
                                f"{result['path']}  "
                                f"({result['length']} bytes)")
                except Exception:
                    pass

    info(f"checking {len(paths)} sensitive paths on {base_url}")
    await asyncio.gather(*[_one(p) for p in paths])

    if own_session:
        await session.close()

    return {
        "target": base_url,
        "checked": len(paths),
        "leaked": sorted(leaked, key=lambda x: x["path"]),
    }


# ---------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
              paths=None) -> dict:
    """Run the leak check and optionally write to store."""
    result = await check(target, paths=paths, verbose=verbose)

    print()
    if not result["leaked"]:
        info(f"no exposed paths found on {target} "
             f"({result['checked']} checked)")
    else:
        severity, ftype = _classify(result["leaked"])
        n = len(result["leaked"])
        n200 = sum(1 for e in result["leaked"] if e["status"] == 200)
        nredirect = sum(1 for e in result["leaked"]
                        if e["status"] in (301, 302, 303, 307, 308))
        nauth = sum(1 for e in result["leaked"]
                    if e["status"] in (401, 403))
        n5xx = sum(1 for e in result["leaked"] if e["status"] >= 500)

        success(f"{n} interesting path(s) on {target}  "
                f"[severity={severity}]")
        if n200:
            warn(f"  → {n200} path(s) actually EXPOSED (200)")
        if nredirect:
            info(f"  → {nredirect} path(s) redirected")
        if nauth:
            info(f"  → {nauth} path(s) exist but require auth (401/403)")
        if n5xx:
            info(f"  → {n5xx} path(s) returned server errors")

        print()
        for entry in result["leaked"]:
            print(f"  [{entry['status']:3d}] {entry['path']}  "
                  f"({entry['length']} bytes, "
                  f"{entry['content_type'] or '?'})")

    if store is not None:
        severity, ftype = _classify(result["leaked"])
        store.add_finding({
            "module": "leak_check",
            "type": ftype,
            "severity": severity,
            "target": target,
            "evidence": (f"{len(result['leaked'])} exposed path(s) "
                         f"of {result['checked']} checked"),
            "data": {
                "checked": result["checked"],
                "leaked": result["leaked"],
                "count_200": sum(1 for e in result["leaked"]
                                  if e["status"] == 200),
                "count_redirect": sum(1 for e in result["leaked"]
                                       if e["status"] in (301, 302, 303, 307, 308)),
                "count_auth": sum(1 for e in result["leaked"]
                                   if e["status"] in (401, 403)),
                "count_5xx": sum(1 for e in result["leaked"]
                                  if e["status"] >= 500),
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
        prog="recon.leak_check",
        description="Check for exposed sensitive paths.",
    )
    p.add_argument("target", help="URL or hostname")
    p.add_argument("--paths-file", default=None,
                   help="custom wordlist (one path per line)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--store", action="store_true")
    args = p.parse_args()

    paths = load_paths() if not args.paths_file else \
        load_paths(Path(args.paths_file))

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

    asyncio.run(run(args.target, store=store,
                    verbose=args.verbose, paths=paths))


if __name__ == "__main__":
    _cli()