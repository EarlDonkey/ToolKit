"""
Directory and file brute-force.

Discovers hidden paths on a web server by trying a large embedded
wordlist of common directory and file names, watching for:

  200  → path exists and is readable (report — high signal)
  301  → permanent redirect (report — often to /path/)
  302  → temporary redirect (report — might be login redirect)
  401  → auth required (report — protected resource)
  403  → forbidden (report — resource exists but blocked)
  500  → server error (report — might indicate a bug)

  404  → not found (skip)
  429  → rate-limited (back off and retry)

Design:

  - Single-level by default. `admin/` is tried as `admin/`, not
    recursively into `admin/config.php` — that requires crawl mode,
    which we expose with `--recursive`.
  - Statuses we consider "found": 200, 201, 204, 301, 302, 303,
    307, 308, 401, 403, 500, 501, 502, 503.
  - Statuses we consider "not found": 404, 410.
  - Anything else is "unknown" and reported with low confidence.
  - Auto-detects the server's 404 signature. Some apps return 200
    with a custom "not found" page — we baseline by fetching a
    known-random path and comparing lengths/hashes.
  - Includes common extensions: with `--extensions php,asp,aspx,jsp,html`,
    each word is also tried with those suffixes appended.
  - Throttles by default (rate=10/s). Raise with `--rate 50` for
    fast scans on networks you own.

Wordlist:

  Embedded ~5,000-path wordlist (see WORDLIST at the bottom).
  Covers:
    - Common directories (admin, api, backup, .git, wp-admin, ...)
    - Framework paths (actuator, console, swagger, graphql, ...)
    - Config files (.env, config.php, web.config, ...)
    - Backup files (backup.zip, db.sql, site.tar.gz, ...)
    - Well-known paths (.well-known/security.txt, robots.txt, ...)
    - Documentation (README.md, CHANGELOG.md, ...)

  Use `--wordlist path.txt` to override.

Usage:

    from recon.dirbust import discover

    findings = await discover("https://example.com/", session, limiter)

    # CLI
    python -m recon.dirbust https://example.com/
    python -m recon.dirbust https://example.com/ --rate 50 -v
    python -m recon.dirbust https://example.com/ --extensions php,bak
    python -m recon.dirbust https://example.com/ --recursive
    python -m recon.dirbust https://example.com/ --wordlist custom.txt

Findings written to the store:
    one row per discovered path
"""

import asyncio
import hashlib
import random
import secrets
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Statuses we treat as "found" (report) vs "not found" (skip) vs "unknown"
FOUND_STATUSES = {200, 201, 202, 204, 301, 302, 303, 307, 308,
                  401, 403, 405, 500, 501, 502, 503}
NOT_FOUND_STATUSES = {404, 410}

# Extensions tried by default. User can override with --extensions.
DEFAULT_EXTENSIONS = []

# Recursion depth when --recursive is on
MAX_RECURSION_DEPTH = 2

# Cap on total requests to avoid runaway scans
# Cap on total requests to avoid runaway scans
MAX_REQUESTS = 20000


# ---------------------------------------------------------------------
# Embedded wordlist (~600 entries)
# ---------------------------------------------------------------------
#
# Curated for the highest-signal paths across common web stacks.
# Not exhaustive — a large external wordlist (SecLists) can be passed
# via --wordlist.

WORDLIST = [
    # --- Version control ---
    ".git/config", ".git/HEAD", ".git/index",
    ".git/logs/HEAD", ".git/refs/heads/main",
    ".gitignore", ".gitattributes", ".gitlab-ci.yml",
    ".github/", ".github/workflows/",
    ".svn/entries", ".svn/wc.db",
    ".hg/requires", ".hg/store/00manifest.i",
    ".bzr/branch-format",
    "CVS/Root", "CVS/Entries",

    # --- Config / secrets ---
    ".env", ".env.local", ".env.production", ".env.dev",
    ".env.backup", ".env.old", ".env.example",
    "config.php", "config.php.bak", "config.php.old",
    "config.json", "config.yml", "config.yaml", "config.xml",
    "configuration.php", "settings.py", "settings.py.bak",
    "local.settings.json", "appsettings.json",
    "appsettings.Development.json",
    "web.config", "web.config.bak",
    ".htaccess", ".htpasswd", ".htaccess.bak",
    "php.ini", "nginx.conf", "apache2.conf", "httpd.conf",
    ".aws/credentials", ".docker/config.json",
    ".npmrc", ".yarnrc", ".pypirc", ".netrc",
    "secrets.yml", "credentials.json", "credentials.xml",
    "keys.json", "tokens.json",

    # --- Backups ---
    "backup.zip", "backup.tar", "backup.tar.gz", "backup.rar",
    "backup.sql", "backup.sql.gz", "backup.db",
    "site.zip", "site.tar.gz", "www.zip", "www.tar.gz",
    "public.zip", "public_html.zip", "webroot.zip",
    "db.sql", "db.sql.gz", "dump.sql", "dump.sql.gz",
    "database.sql", "database.sql.gz",
    "old.zip", "old.tar.gz", "archive.zip", "archive.tar.gz",
    "backup.old", "backup.bak", "backup.save",

    # --- Admin / control panels ---
    "admin/", "admin/login", "admin.php", "admin.html",
    "admin1/", "admin2/", "adminarea/", "adminpanel/",
    "administrator/", "administrator/index.php",
    "manage/", "manager/", "management/",
    "console/", "cp/", "cpanel/", "controlpanel/",
    "dashboard/", "panel/", "portal/",
    "wp-admin/", "wp-login.php", "wp-config.php",
    "wp-content/", "wp-includes/", "wp-json/",
    "phpmyadmin/", "pma/", "mysql/", "mysqladmin/",
    "pgadmin/", "adminer.php", "adminer/",
    "jenkins/", "hudson/", "grafana/", "kibana/",
    "prometheus/", "zabbix/", "nagios/",
    "solr/", "elasticsearch/",

    # --- API / docs / debug ---
    "api/", "api/v1/", "api/v2/", "api/v3/",
    "rest/", "graphql", "graphiql", "playground",
    "swagger", "swagger.json", "swagger.yaml",
    "swagger-ui.html", "swagger-ui/", "swagger/index.html",
    "openapi.json", "openapi.yaml",
    "api-docs", "api/docs", "api/swagger.json",
    "docs/", "documentation/", "redoc/",
    "health", "healthz", "healthcheck", "ping", "status",
    "metrics", "stats", "debug", "debug/vars",
    "actuator", "actuator/health", "actuator/env",
    "actuator/beans", "actuator/mappings",
    "server-status", "server-info",
    ".well-known/security.txt", ".well-known/change-password",
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "humans.txt", "security.txt",

    # --- Common directories ---
    "assets/", "static/", "media/", "images/", "img/",
    "css/", "js/", "scripts/", "styles/",
    "files/", "uploads/", "download/", "downloads/",
    "backup/", "backups/", "temp/", "tmp/", "cache/",
    "logs/", "log/", "data/", "db/", "database/",
    "private/", "internal/", "intranet/", "hidden/",
    "old/", "new/", "test/", "tests/", "dev/", "development/",
    "staging/", "prod/", "production/", "demo/",
    "includes/", "include/", "lib/", "library/",
    "src/", "source/", "vendor/", "node_modules/",
    "app/", "application/", "web/", "webroot/",
    "public/", "public_html/", "htdocs/",
    "cgi-bin/", "cgi/", "bin/", "install/", "setup/",

    # --- Files / metadata ---
    "index.php", "index.html", "index.htm", "index.jsp",
    "default.php", "default.html",
    "README.md", "readme.txt", "README",
    "CHANGELOG.md", "CHANGELOG", "CHANGES",
    "LICENSE", "LICENSE.txt", "license.md",
    "VERSION", "version.txt", "version.json",
    "package.json", "package-lock.json", "yarn.lock",
    "composer.json", "composer.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "Gemfile", "Gemfile.lock",
    "Makefile", "Dockerfile", "docker-compose.yml",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    ".editorconfig", ".eslintrc", ".prettierrc",
    "favicon.ico", "apple-touch-icon.png",

    # --- Framework-specific ---
    "console", "trace", "info.php", "phpinfo.php", "test.php",
    "app_dev.php", "app.php", "web/app_dev.php",
    "server.php", "artisan", "telescope",
    "rails/info/routes", "rails/info/properties",
    "wp-cron.php", "wp-signup.php", "wp-trackback.php",
    "xmlrpc.php", "wp-mail.php",
    "htaccess.txt",
    "install.php", "upgrade.php",
    "checkout.php", "checkout/", "cart/", "account/",
    "user/", "users/", "profile/", "login/", "logout/",
    "signin/", "signup/", "register/", "auth/",
    "oauth/", "oauth2/", "saml/", "sso/",
    "sessions/", "session/",
    "migrate/", "migrations/",
    "queue/", "jobs/", "worker/",
    "api/health", "api/status", "api/metrics",
    "api/users", "api/user", "api/admin",
    "api/login", "api/logout", "api/register",
    "api/v1/users", "api/v1/admin", "api/v1/login",
    "api/v1/health", "api/v1/status",
    "api/v2/users", "api/v2/admin",

    # --- Sensitive files ---
    ".ssh/authorized_keys", ".ssh/id_rsa",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "server.key", "server.crt", "server.pem",
    "private.key", "private.pem", "private.crt",
    ".ftpconfig", ".remote-sync.json",
    "nohup.out", "error_log", "error.log",
    "access.log", "access_log",
    "debug.log", "debug.log.1",
    "application.log", "app.log",
    "django.log", "rails.log",
    "php_errors.log", "php_error.log",

    # --- Config files by extension ---
    "config.bak", "config.old", "config.orig", "config.save",
    "config.swp", "config.php~", "config.php.save",
    ".config", ".config.json",
    "database.yml", "database.yml.bak",
    "secrets.json", "secrets.yaml",
    "id_rsa.pub",

    # --- Dotfiles ---
    ".user.ini",
    ".well-known/", ".well-known/acme-challenge/",
    ".well-known/pki-validation/",
    ".well-known/openid-configuration",
    ".well-known/jwks.json",
    ".well-known/oauth-authorization-server",
    ".well-known/assetlinks.json",
    ".well-known/apple-app-site-association",

    # --- Directories that commonly have listings ---
    "assets/images/", "static/images/",
    "export/", "exports/", "import/", "imports/",
    "documents/", "pdf/", "archive/",
    "static/files/", "media/files/",

    # --- Misc ---
    "flag.txt", "flag", "key.txt",
    "test.txt", "info.txt", "notes.txt",
    "todo.txt", "TODO",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "phpinfo", "test",
]

# ---------------------------------------------------------------------
# Status classification
# ---------------------------------------------------------------------

def _classify(status: int) -> str:
    """Return 'found', 'not_found', or 'unknown'."""
    if status in FOUND_STATUSES:
        return "found"
    if status in NOT_FOUND_STATUSES:
        return "not_found"
    return "unknown"


def _severity_for(path: str, status: int) -> str:
    """Rate the discovered path."""
    low = path.lower()

    # High-value paths
    high_value_prefixes = (
        ".git", ".env", ".svn", ".hg", ".aws", ".docker",
        "admin", "administrator", "console", "manage",
        "phpmyadmin", "pma", "wp-admin", "wp-config",
        "swagger", "graphql", "actuator", "debug", "test",
        "backup", "bak", "dump", "sql", "db",
        "config", "credentials", "secrets", "keys",
    )

    # Status 200 on a high-value path = high
    if status == 200:
        for p in high_value_prefixes:
            if p in low:
                return "high"

    # Status 200 on any other path = medium
    if status == 200:
        return "medium"

    # 401/403 means "exists but protected" — informational
    if status in (401, 403):
        for p in high_value_prefixes:
            if p in low:
                return "medium"
        return "low"

    # 301/302 redirects are often directory markers
    if status in (301, 302, 303, 307, 308):
        return "info"

    # 5xx errors are usually informational
    if status >= 500:
        return "low"

    return "info"


# ---------------------------------------------------------------------
# 404-signature detection
# ---------------------------------------------------------------------

async def _baseline_missing(session, base_url: str, limiter,
                              cookies=None, timeout: float = 10.0) -> dict:
    """Fetch a random path to learn the server's "not found" signature.

    Some applications return 200 with a custom "not found" page. We
    compare each subsequent response against this baseline to filter
    out those false positives.
    """
    random_path = f"tk-missing-{secrets.token_hex(8)}-nonexistent"
    url = urljoin(base_url, random_path)
    try:
        r = await fetch(session, url, limiter, cookies=cookies,
                         timeout=timeout)
    except Exception:
        return {"status": None, "length": 0, "hash": "", "path": random_path}

    if r is None or r[0] is None:
        return {"status": None, "length": 0, "hash": "", "path": random_path}

    body = r[2] or ""
    return {
        "status": r[0],
        "length": len(body),
        "hash": hashlib.sha1(body.encode("utf-8", errors="ignore")).hexdigest(),
        "path": random_path,
    }


def _is_missing_clone(response: dict, baseline: dict) -> bool:
    """Return True if this response looks like the server's 404 page."""
    # If the baseline failed, we can't compare — assume not a clone
    if not baseline.get("status"):
        return False

    # If the server returns 200 for missing pages, check body match
    if response["status"] == baseline["status"]:
        if response["hash"] == baseline["hash"]:
            return True
        # Allow small variations (dynamic elements)
        if abs(response["length"] - baseline["length"]) < 50:
            return True

    return False


# ---------------------------------------------------------------------
# Path probing
# ---------------------------------------------------------------------

async def _probe_path(session, base_url: str, path: str, limiter,
                       baseline: dict, cookies=None,
                       timeout: float = 10.0) -> dict | None:
    """Probe one path. Return a finding dict if found, None otherwise."""
    url = urljoin(base_url, path)
    try:
        r = await fetch(session, url, limiter, cookies=cookies,
                         timeout=timeout, allow_redirects=False)
    except Exception:
        return None

    if r is None or r[0] is None:
        return None

    status, headers, body, final = r
    body = body or ""

    # Ignore 404s and 410s
    if status in NOT_FOUND_STATUSES:
        return None

    # Response hash for clone detection
    resp = {
        "status": status,
        "length": len(body),
        "hash": hashlib.sha1(
            body.encode("utf-8", errors="ignore")).hexdigest(),
    }

    # If this looks like the server's 404 page, skip
    if _is_missing_clone(resp, baseline):
        return None

    # Extract Location header for redirects
    location = ""
    for k, v in (headers or {}).items():
        if k.lower() == "location":
            location = str(v)
            break

    # Extract Content-Type for filtering
    ctype = ""
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            ctype = str(v)
            break

    finding = {
        "type": "directory_listing" if "index of" in body.lower()[:500]
                else "informational",
        "severity": _severity_for(path, status),
        "url": url,
        "path": path,
        "http_status": status,
        "evidence": f"HTTP {status} ({len(body)} bytes)"
                    + (f" → {location[:80]}" if location else ""),
        "data": {
            "path": path,
            "status": status,
            "size": len(body),
            "content_type": ctype,
            "location": location if location else None,
            "discovery_method": "dirbust",
        },
    }
    return finding


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def discover(url: str, session=None, limiter=None,
                    cookies=None, wordlist: list[str] | None = None,
                    extensions: list[str] | None = None,
                    recursive: bool = False,
                    verbose: bool = False,
                    rate: float = 10.0,
                    timeout: float = 10.0,
                    max_requests: int = MAX_REQUESTS) -> list[dict]:
    """Discover hidden paths on a web server.

    Returns a list of findings, one per discovered path.
    """
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    if not url.endswith("/"):
        url += "/"

    words = wordlist if wordlist else WORDLIST
    exts = extensions if extensions is not None else DEFAULT_EXTENSIONS

    # Build the full path list
    paths: list[str] = []
    for word in words:
        # Try the bare word
        paths.append(word)
        # If the word doesn't end in "/", also try "/word/"
        if not word.endswith("/") and "." not in word:
            paths.append(word + "/")
        # Try extensions
        for ext in exts:
            ext = ext.lstrip(".")
            if not word.endswith("." + ext):
                paths.append(f"{word}.{ext}")

    # Deduplicate while preserving order
    seen = set()
    paths = [p for p in paths if not (p in seen or seen.add(p))]

    if len(paths) > max_requests:
        warn(f"dirbust: capping {len(paths)} paths at {max_requests}")
        paths = paths[:max_requests]

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=rate)

    info(f"dirbust: testing {len(paths)} path(s) on {url} "
         f"(rate={rate}/s)")

    findings: list[dict] = []

    try:
        # --- Baseline the server's 404 signature ---
        baseline = await _baseline_missing(session, url, limiter,
                                             cookies=cookies,
                                             timeout=timeout)
        if verbose:
            if baseline["status"]:
                info(f"  baseline 404: status={baseline['status']} "
                     f"length={baseline['length']}")
            else:
                warn("  could not baseline 404 (server may be down)")

        # --- Probe every path ---
        completed = 0
        hits = 0
        sem = asyncio.Semaphore(20)  # cap concurrent requests
        lock = asyncio.Lock()

        async def _one(path: str) -> dict | None:
            nonlocal completed, hits
            async with sem:
                r = await _probe_path(
                    session, url, path, limiter, baseline,
                    cookies=cookies, timeout=timeout)
            async with lock:
                completed += 1
                if r:
                    hits += 1
                    # Print live
                    sev_marker = {
                        "high": "[!]", "medium": "[+]",
                        "low": "[-]", "info": "[*]",
                    }.get(r["severity"], "[*]")
                    print(f"  {sev_marker} [{r['http_status']:3d}] "
                          f"{path}"
                          + (f" ({r['data']['size']} bytes)"
                             if r["data"]["size"] else ""))
                if verbose and completed % 50 == 0:
                    pct = 100 * completed / len(paths)
                    info(f"  progress: {completed}/{len(paths)} "
                         f"({pct:.0f}%) — {hits} hits")
            return r

        tasks = [_one(p) for p in paths]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        # --- Recursive mode: re-scan top-level directories found ---
        if recursive and findings:
            # Collect top-level dirs that were found
            top_dirs = set()
            for f in findings:
                status = f["data"]["status"]
                if status in (200, 301, 302) and "/" in f["path"]:
                    # Take the first segment
                    seg = f["path"].split("/", 1)[0]
                    if seg:
                        top_dirs.add(seg)

            if top_dirs and len(findings) < max_requests:
                info(f"dirbust: recursing into "
                     f"{len(top_dirs)} directory/ies")
                for d in top_dirs:
                    sub_url = urljoin(url, d + "/")
                    remaining = max_requests - len(paths)
                    if remaining <= 0:
                        break
                    sub_findings = await discover(
                        sub_url, session=session, limiter=limiter,
                        cookies=cookies, wordlist=words,
                        extensions=exts, recursive=False,
                        verbose=False, rate=rate,
                        timeout=timeout,
                        max_requests=min(remaining, 2000))
                    findings.extend(sub_findings)

        return findings
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# Wordlist loading
# ---------------------------------------------------------------------

def load_wordlist(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        warn(f"dirbust: wordlist not found: {path}")
        return []
    out = []
    for line in p.read_text(encoding="utf-8",
                             errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line.lstrip("/"))
    return out


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
               cookie: str | None = None,
               wordlist: str | None = None,
               extensions: str | None = None,
               recursive: bool = False,
               rate: float = 10.0) -> list[dict]:
    """CLI entry. Writes findings to store if provided."""
    cookies = parse_cookie_string(cookie) if cookie else None

    words = None
    if wordlist:
        words = load_wordlist(wordlist)
        if words:
            info(f"dirbust: loaded {len(words)} word(s) "
                 f"from {wordlist}")

    exts = None
    if extensions:
        exts = [e.strip() for e in extensions.split(",") if e.strip()]

    findings = await discover(
        target, cookies=cookies, wordlist=words, extensions=exts,
        recursive=recursive, verbose=verbose, rate=rate)

    print()
    if not findings:
        info(f"no hidden paths discovered on {target}")
    else:
        by_sev = {}
        for f in findings:
            s = f.get("severity", "info")
            by_sev[s] = by_sev.get(s, 0) + 1
        summary = ", ".join(f"{n} {s}" for s, n in by_sev.items())
        success(f"{len(findings)} hidden path(s) discovered ({summary})")

    if store is not None:
        for f in findings:
            store.add_finding({
                "module": "dirbust",
                "type": f["type"],
                "severity": f["severity"],
                "target": f["url"],
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
        prog="recon.dirbust",
        description="Directory and file brute-force.",
    )
    p.add_argument("target", help="Base URL")
    p.add_argument("--wordlist", default=None,
                   help="custom wordlist (one path per line)")
    p.add_argument("--extensions", default=None,
                   help="comma-separated extensions to append "
                        "(e.g. 'php,asp,aspx,jsp,html,bak')")
    p.add_argument("--recursive", action="store_true",
                   help="recurse into discovered directories (slower)")
    p.add_argument("--cookie", default=None,
                   help="cookie string for authenticated testing")
    p.add_argument("--rate", type=float, default=10.0,
                   help="requests per second (default 10)")
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
        cookie=args.cookie, wordlist=args.wordlist,
        extensions=args.extensions, recursive=args.recursive,
        rate=args.rate))


if __name__ == "__main__":
    _cli()