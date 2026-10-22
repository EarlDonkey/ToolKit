"""
Full-target reconnaissance orchestrator.

Runs every applicable recon module against a single target and produces
a combined dossier (HTML + Markdown, optionally raw JSON).

Target-kind dispatch:

  - IP target (1.2.3.4)      → ip_intel, asn, whois, tls_cert,
                               reverse_ip
  - Domain (example.com)     → tech_fingerprint, web_intel,
                               cms_fingerprint, leak_check, ct_logs,
                               tls_cert, whois, asn, historical,
                               js_analysis, emails, cloud_enum,
                               social
  - URL (https://x/y)        → web_intel, tech_fingerprint,
                               cms_fingerprint, leak_check, js_analysis,
                               tls_cert, whois, asn, historical
  - ASN (AS15169)            → asn + prefix expansion

This means `investigate 1.2.3.4` no longer wastes time on CT logs, and
`investigate https://example.com/foo` no longer re-queries WHOIS through
a URL-shaped target.

Optional `--scan` mode:

  Passing --scan also runs the vuln/ modules (sqli, xss, nosqli, lfi,
  ssrf, xxe, crlf, open_redirect, host_header, cors, web_clickjacking)
  against the URL target. This is off by default because it's slower
  and noisier. It is what you want when you're actively pentesting; it
  is not what you want for pure reconnaissance.

Behavior on module failure:

  Failures are isolated. If a module raises, we record the error in
  the report and continue with the next module. One broken scanner
  never kills the whole investigation.

Execution modes:

  Sequential (default)  — modules run one at a time. Predictable,
                          low risk of triggering rate limits.
  Parallel (--parallel) — modules run concurrently where safe. Faster
                          but riskier against WAF-protected targets.

Output:

  By default, HTML and Markdown dossiers are written to the target
  workspace's report/ directory, or a path given with -o.

  --json dumps the raw per-module data to a sibling .json file.

Usage:

    py -m recon.investigate example.com
    py -m recon.investigate 1.2.3.4
    py -m recon.investigate https://example.com/foo --scan
    py -m recon.investigate example.com --parallel
    py -m recon.investigate example.com --skip cloud_enum,social
    py -m recon.investigate example.com --only tech_fingerprint,leak_check
    py -m recon.investigate example.com -o ~/Desktop/example-dossier
    py -m recon.investigate example.com --store
"""

import asyncio
import html as _html
import json
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from core.output import info, success, warn, error
from core.target import parse


# ---------------------------------------------------------------------
# Module registries — one per target kind
# ---------------------------------------------------------------------
#
# Each entry is a tuple:
#     (key, description, module_path)
#
# `key` is what --skip / --only match against.
# `module_path` is imported lazily so a broken module doesn't break the
# whole orchestrator import.

# --- IP targets ---
IP_MODULES = [
    ("ip_intel",    "IP intelligence (ASN, geo, RDAP, reverse IP, ports)",
     "recon.ip_intel"),
    ("asn",         "ASN / netblocks",           "recon.asn"),
    ("whois",       "IP RDAP",                    "recon.whois"),
    ("tls_cert",    "TLS certificate",            "recon.tls_cert"),
    ("reverse_ip",  "Reverse IP",                 "recon.reverse_ip"),
]

# --- Domain targets ---
DOMAIN_MODULES = [
    ("tech_fingerprint", "Technology stack",
     "recon.tech_fingerprint"),
    ("web_intel",        "Web intelligence (headers, CSP, robots, "
                          "well-known)", "recon.web_intel"),
    ("cms_fingerprint",  "CMS detection",
     "recon.cms_fingerprint"),
    ("leak_check",       "Exposed sensitive paths",
     "recon.leak_check"),
    ("ct_logs",          "Certificate transparency",
     "recon.ct_logs"),
    ("tls_cert",         "TLS certificate",           "recon.tls_cert"),
    ("whois",            "Domain WHOIS + IP RDAP",     "recon.whois"),
    ("asn",              "ASN / netblocks",            "recon.asn"),
    ("historical",       "Wayback + URLScan",          "recon.historical"),
    ("js_analysis",      "JS files + API endpoints",   "recon.js_analysis"),
    ("emails",           "Email addresses",            "recon.emails"),
    ("cloud_enum",       "Public cloud buckets",       "recon.cloud_enum"),
    ("social",           "Social profiles",            "recon.social"),
    # Modules below will be added in later steps; the orchestrator
    # catches ImportError and records them as failed gracefully.
    ("subdomain_takeover", "Subdomain takeover scan",
     "recon.subdomain_takeover"),
    ("openapi",          "OpenAPI / Swagger discovery",
     "recon.openapi"),
    ("cors",             "CORS misconfiguration",      "recon.cors"),
]

# --- URL targets ---
URL_MODULES = [
    ("web_intel",        "Web intelligence",
     "recon.web_intel"),
    ("tech_fingerprint", "Technology stack",
     "recon.tech_fingerprint"),
    ("cms_fingerprint",  "CMS detection",
     "recon.cms_fingerprint"),
    ("leak_check",       "Exposed sensitive paths",
     "recon.leak_check"),
    ("js_analysis",      "JS files + API endpoints",
     "recon.js_analysis"),
    ("tls_cert",         "TLS certificate",           "recon.tls_cert"),
    ("whois",            "Domain WHOIS + IP RDAP",     "recon.whois"),
    ("asn",              "ASN / netblocks",            "recon.asn"),
    ("historical",       "Wayback + URLScan",          "recon.historical"),
    ("openapi",          "OpenAPI / Swagger discovery",
     "recon.openapi"),
    ("cors",             "CORS misconfiguration",      "recon.cors"),
    ("web_clickjacking", "Clickjacking protection",
     "vuln.web_clickjacking"),
]

# --- Extra modules only in --scan mode (URL targets) ---
SCAN_MODULES = [
    ("sqli",             "SQL injection",              "vuln.sqli"),
    ("xss",              "Reflected XSS",              "vuln.xss"),
    ("nosqli",           "NoSQL injection",            "vuln.nosqli"),
    ("lfi",              "Local file inclusion",       "vuln.lfi"),
    ("ssrf",             "SSRF",                       "vuln.ssrf"),
    ("xxe",              "XXE",                        "vuln.xxe"),
    ("crlf",             "CRLF injection",             "vuln.crlf"),
    ("open_redirect",    "Open redirect",              "vuln.open_redirect"),
    ("host_header",      "Host header injection",      "vuln.host_header"),
]

# --- ASN targets ---
ASN_MODULES = [
    ("asn",         "ASN / netblocks",            "recon.asn"),
]


# Every key we know about, regardless of target kind. Used by
# --list-modules and for validating --skip / --only.
ALL_MODULES = (
    IP_MODULES + DOMAIN_MODULES + URL_MODULES + SCAN_MODULES + ASN_MODULES
)
ALL_KEYS = sorted({m[0] for m in ALL_MODULES})


# ---------------------------------------------------------------------
# Module execution
# ---------------------------------------------------------------------

async def _load_and_run(module_path: str, target: str, verbose: bool,
                        scan: bool = False):
    """Import and run one module. Returns (ok, result_or_error)."""
    try:
        mod = __import__(module_path, fromlist=["run"])
    except ImportError as e:
        return False, {
            "error": f"module not installed: {e}",
            "traceback": traceback.format_exc(),
        }
    except Exception as e:
        return False, {
            "error": f"import failed: {type(e).__name__}: {e}",
            "traceback": traceback.format_exc(),
        }

    run_fn = getattr(mod, "run", None)
    if run_fn is None:
        return False, {"error": f"{module_path} has no run() function"}

    try:
        # Most modules accept (target, verbose=...). Try that first
        # and fall back to (target) if the signature differs.
        try:
            result = await run_fn(target, verbose=verbose)
        except TypeError:
            result = await run_fn(target)
        return True, result
    except Exception as e:
        return False, {
            "error": f"{type(e).__name__}: {e}",
            "traceback": traceback.format_exc(),
        }


async def _run_module(key: str, description: str, module_path: str,
                       target: str, verbose: bool,
                       scan: bool = False) -> dict:
    """Run a single module and return a normalized result dict."""
    info(f"▶  {key}: {description}")
    start = time.time()
    ok, result = await _load_and_run(module_path, target, verbose,
                                     scan=scan)
    elapsed = time.time() - start

    if ok:
        success(f"   ✓ {key} ({elapsed:.1f}s)")
        return {
            "key": key,
            "description": description,
            "ok": True,
            "elapsed": round(elapsed, 2),
            "result": result,
        }
    else:
        error(f"   ✗ {key} ({elapsed:.1f}s) — {result.get('error', '?')}")
        return {
            "key": key,
            "description": description,
            "ok": False,
            "elapsed": round(elapsed, 2),
            "error": result.get("error", "unknown error"),
            "traceback": result.get("traceback", ""),
        }


# ---------------------------------------------------------------------
# Target-kind dispatcher
# ---------------------------------------------------------------------

def _pick_modules(target: str, scan: bool) -> tuple[list, str]:
    """Parse the target and return (module_list, kind_string).

    kind_string is one of: "ip", "domain", "url", "asn".
    Raises ValueError if the target can't be parsed.
    """
    t = parse(target)

    if t.kind == "asn":
        return list(ASN_MODULES), "asn"
    if t.is_ip:
        return list(IP_MODULES), "ip"
    if t.kind == "url":
        mods = list(URL_MODULES)
        if scan:
            mods.extend(SCAN_MODULES)
        return mods, "url"
    # Default: domain
    return list(DOMAIN_MODULES), "domain"


# ---------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------

async def investigate(target: str, skip: list[str] | None = None,
                       only: list[str] | None = None,
                       parallel: bool = False,
                       verbose: bool = False,
                       scan: bool = False) -> dict:
    """Run every applicable recon module against the target.

    Returns a dossier dict suitable for rendering and storage.
    """
    skip_set = set(skip or [])
    only_set = set(only) if only else None

    # Pick module set based on target kind
    try:
        modules_for_kind, kind = _pick_modules(target, scan=scan)
    except ValueError as e:
        error(f"investigate: cannot parse target {target!r}: {e}")
        return {
            "target": target, "kind": "unknown", "modules": [],
            "elapsed": 0.0,
            "error": f"parse failed: {e}",
        }

    # Filter by --skip / --only
    active = []
    for key, description, module_path in modules_for_kind:
        if only_set is not None and key not in only_set:
            continue
        if key in skip_set:
            continue
        active.append((key, description, module_path))

    if not active:
        warn(f"no modules selected — nothing to do "
             f"(target kind: {kind})")
        return {"target": target, "kind": kind, "modules": [],
                "elapsed": 0.0}

    started_at = datetime.now(timezone.utc)
    t0 = time.time()

    info(f"starting investigation of {target} "
         f"(kind={kind}, {len(active)} module(s), "
         f"mode={'parallel' if parallel else 'sequential'}"
         + (", scan=on" if scan else "")
         + ")")
    print()

    if parallel:
        coros = [
            _run_module(k, d, m, target, verbose, scan=scan)
            for k, d, m in active
        ]
        modules = await asyncio.gather(*coros,
                                       return_exceptions=False)
    else:
        modules = []
        for k, d, m in active:
            result = await _run_module(k, d, m, target, verbose, scan=scan)
            modules.append(result)

    elapsed = time.time() - t0
    finished_at = datetime.now(timezone.utc)

    ok_count = sum(1 for m in modules if m["ok"])
    fail_count = len(modules) - ok_count

    print()
    if fail_count == 0:
        success(f"investigation complete: {ok_count} module(s) OK "
                f"in {elapsed:.1f}s")
    else:
        warn(f"investigation complete: {ok_count} OK, "
             f"{fail_count} failed in {elapsed:.1f}s")

    return {
        "target": target,
        "kind": kind,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "elapsed": round(elapsed, 2),
        "mode": "parallel" if parallel else "sequential",
        "scan": scan,
        "modules": modules,
    }


# ---------------------------------------------------------------------
# Dossier rendering — summary
# ---------------------------------------------------------------------

def _esc(v) -> str:
    if v is None:
        return ""
    return _html.escape(str(v))


def _summarize_module(m: dict) -> dict:
    """Extract summary numbers for the header row."""
    if not m["ok"]:
        return {"key": m["key"], "status": "failed",
                "summary": m.get("error", "?")}
    r = m["result"] or {}
    key = m["key"]

    if key == "ip_intel":
        summary = r.get("summary") or ""
        return {"key": key, "status": "ok", "summary": summary}

    if key == "tech_fingerprint":
        n = len(r.get("technologies", []))
        return {"key": key, "status": "ok",
                "summary": f"{n} technologies detected"}

    if key == "web_intel":
        csp = len((r.get("csp") or {}).get("hosts") or [])
        wk = len(r.get("well_known") or {})
        return {"key": key, "status": "ok",
                "summary": f"{csp} CSP host(s), {wk} well-known file(s)"}

    if key == "cms_fingerprint":
        cms = r.get("cms") or "none"
        ver = r.get("version") or ""
        return {"key": key, "status": "ok",
                "summary": f"{cms} {ver}".strip() or "no CMS detected"}

    if key == "leak_check":
        leaked = r.get("leaked", [])
        n200 = sum(1 for e in leaked if e.get("status") == 200)
        return {"key": key, "status": "ok",
                "summary": f"{len(leaked)} path(s), {n200} public"}

    if key == "ct_logs":
        return {"key": key, "status": "ok",
                "summary": f"{r.get('total_certs', 0)} cert(s), "
                           f"{len(r.get('unique_names', []))} names"}

    if key == "tls_cert":
        cn = r.get("subject_cn") or "?"
        sans = len(r.get("sans") or [])
        return {"key": key, "status": "ok",
                "summary": f"CN={cn}, {sans} SAN(s)"}

    if key == "whois":
        w = r.get("whois") or {}
        if r.get("type") == "ip":
            return {"key": key, "status": "ok",
                    "summary": w.get("org") or "no RDAP data"}
        return {"key": key, "status": "ok",
                "summary": w.get("registrar") or "no WHOIS data"}

    if key == "asn":
        a = (r.get("asn_info") or {})
        ip = (r.get("ip_info") or {})
        asn = a.get("asn") or ip.get("asn")
        return {"key": key, "status": "ok",
                "summary": f"AS{asn}" if asn else "no ASN data"}

    if key == "historical":
        return {"key": key, "status": "ok",
                "summary": f"{r.get('wayback_urls', 0)} archived URL(s), "
                           f"{len(r.get('historical_hosts', []))} host(s)"}

    if key == "js_analysis":
        return {"key": key, "status": "ok",
                "summary": f"{r.get('files_analyzed', 0)} JS file(s), "
                           f"{len(r.get('api_paths', []))} API path(s), "
                           f"{len(r.get('secrets', []))} secret(s)"}

    if key == "emails":
        return {"key": key, "status": "ok",
                "summary": f"{len(r.get('emails', []))} email(s)"}

    if key == "cloud_enum":
        buckets = r.get("buckets", [])
        public = [b for b in buckets if b.get("status") == 200]
        return {"key": key, "status": "ok",
                "summary": f"{len(public)} public, "
                           f"{len(buckets) - len(public)} other"}

    if key == "social":
        return {"key": key, "status": "ok",
                "summary": f"{sum(r.get('counts', {}).values())} profile(s)"}

    if key == "reverse_ip":
        n = len(r.get("domains") or [])
        return {"key": key, "status": "ok",
                "summary": f"{n} domain(s) on same IP"}

    if key == "web_clickjacking":
        # run() returns a list
        if isinstance(r, list) and r:
            c = r[0].get("data", {}).get("classification", "?")
            return {"key": key, "status": "ok",
                    "summary": f"classification: {c}"}
        return {"key": key, "status": "ok", "summary": "no URLs tested"}

    return {"key": key, "status": "ok", "summary": ""}


# ---------------------------------------------------------------------
# Dossier rendering — HTML
# ---------------------------------------------------------------------

def _render_html(dossier: dict) -> str:
    target = dossier["target"]
    kind = dossier.get("kind", "domain")
    started = dossier.get("started_at", "")[:19]
    elapsed = dossier["elapsed"]
    modules = dossier["modules"]
    mode = dossier.get("mode", "sequential")
    scan = dossier.get("scan", False)

    summaries = [_summarize_module(m) for m in modules]
    summary_rows = "".join(
        f"<div class='sum-row sum-{s['status']}'>"
        f"<span class='sum-key'>{_esc(s['key'])}</span>"
        f"<span class='sum-val'>{_esc(s['summary'])}</span>"
        f"</div>"
        for s in summaries
    )

    sections = ""
    for m in modules:
        sections += _render_module_section(m)

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Dossier — {_esc(target)}</title>
<style>
    * {{ box-sizing: border-box; }}
    body {{
        font-family: 'Segoe UI', system-ui, sans-serif;
        background: #0b0f19; color: #e2e8f0;
        margin: 0; padding: 30px; line-height: 1.5;
    }}
    .wrap {{ max-width: 1300px; margin: 0 auto; }}
    header {{
        background: linear-gradient(135deg, #1e293b, #0f172a);
        border: 1px solid #334155; border-radius: 12px;
        padding: 30px; margin-bottom: 30px;
    }}
    h1 {{ margin: 0 0 10px 0; color: #38bdf8; font-size: 2.1em; }}
    .kind-badge {{
        display: inline-block; padding: 2px 10px; border-radius: 4px;
        background: #0369a1; color: #e0f2fe; font-size: 0.6em;
        vertical-align: middle; margin-left: 12px; text-transform:
        uppercase; letter-spacing: 1px;
    }}
    .meta {{ color: #94a3b8; font-size: 0.95em; }}
    .meta span {{ margin-right: 20px; }}
    .meta strong {{ color: #cbd5e1; }}

    section.summary {{
        background: #1e293b; border: 1px solid #334155;
        border-radius: 12px; padding: 25px; margin-bottom: 30px;
    }}
    section.summary h2 {{ margin-top: 0; }}

    .sum-row {{
        display: grid; grid-template-columns: 220px 1fr;
        gap: 15px; padding: 8px 12px;
        border-bottom: 1px solid #334155; font-size: 0.95em;
    }}
    .sum-row:last-child {{ border-bottom: none; }}
    .sum-key {{ color: #94a3b8; font-family: monospace; font-size: 0.9em; }}
    .sum-val {{ color: #cbd5e1; }}
    .sum-failed .sum-val {{ color: #fca5a5; }}

    section.module {{
        background: #1e293b; border: 1px solid #334155;
        border-radius: 12px; padding: 25px; margin-bottom: 20px;
    }}
    section.module h2 {{
        margin: 0 0 15px 0; font-size: 1.4em; color: #f1f5f9;
        display: flex; align-items: center; gap: 12px;
    }}
    section.module h2 .status {{
        font-size: 0.7em; padding: 3px 10px; border-radius: 4px;
        font-family: monospace; font-weight: 700;
    }}
    section.module h2 .status-ok {{ background: #065f46; color: #d1fae5; }}
    section.module h2 .status-fail {{ background: #7f1d1d; color: #fecaca; }}

    pre, .code {{
        background: #0f172a; border: 1px solid #1e293b;
        padding: 12px; border-radius: 6px; overflow-x: auto;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.85em; color: #cbd5e1;
        white-space: pre-wrap; word-break: break-word;
        max-height: 500px; overflow-y: auto;
    }}
    .kv-grid {{
        display: grid; grid-template-columns: 200px 1fr;
        gap: 6px 15px; font-size: 0.9em; margin-bottom: 12px;
    }}
    .kv-grid .k {{ color: #94a3b8; }}
    .kv-grid .v {{ color: #cbd5e1; word-break: break-all; }}

    .section-title {{
        color: #94a3b8; font-size: 0.82em; text-transform: uppercase;
        letter-spacing: 1px; margin: 20px 0 8px 0; font-weight: 700;
    }}
    .chip {{
        display: inline-block;
        background: #0f172a; border: 1px solid #334155;
        padding: 4px 10px; border-radius: 999px;
        font-size: 0.85em; color: #cbd5e1;
        font-family: monospace; margin: 3px 3px 3px 0;
    }}
    .chip.sev-critical {{ background: #450a0a; border-color: #dc2626; }}
    .chip.sev-high     {{ background: #431407; border-color: #ea580c; }}
    .chip.sev-medium   {{ background: #422006; border-color: #eab308; }}
    .chip.sev-low      {{ background: #082f49; border-color: #0284c7; }}

    footer {{
        text-align: center; color: #475569; font-size: 0.85em;
        margin-top: 40px; padding-top: 20px;
        border-top: 1px solid #334155;
    }}
</style>
</head>
<body>
<div class="wrap">

<header>
    <h1>Recon Dossier<span class="kind-badge">{_esc(kind)}</span></h1>
    <div class="meta">
        <span><strong>Target:</strong> {_esc(target)}</span>
        <span><strong>Started:</strong> {_esc(started)} UTC</span>
        <span><strong>Elapsed:</strong> {elapsed}s</span>
        <span><strong>Mode:</strong> {_esc(mode)}</span>
        {f"<span><strong>Scan:</strong> on</span>" if scan else ""}
    </div>
</header>

<section class="summary">
    <h2>Module Summary</h2>
    {summary_rows}
</section>

{sections}

<footer>
    Generated by toolkit recon · {_esc(datetime.now(timezone.utc).isoformat()[:19])} UTC
</footer>

</div>
</body>
</html>
"""
    return doc


def _render_module_section(m: dict) -> str:
    key = m["key"]
    desc = m["description"]
    if not m["ok"]:
        tb = m.get("traceback", "")
        tb_html = f"<pre>{_esc(tb)}</pre>" if tb else ""
        return f"""
        <section class="module">
            <h2>
                {_esc(key)} — {_esc(desc)}
                <span class="status status-fail">FAILED</span>
            </h2>
            <div class="kv-grid">
                <div class="k">Error:</div>
                <div class="v">{_esc(m.get('error', '?'))}</div>
            </div>
            {tb_html}
        </section>
        """

    r = m["result"] or {}
    body = _render_module_body(key, r)

    return f"""
    <section class="module">
        <h2>
            {_esc(key)} — {_esc(desc)}
            <span class="status status-ok">OK ({m['elapsed']}s)</span>
        </h2>
        {body}
    </section>
    """


def _chips(items, limit=60, cls=""):
    """Render a list of strings as chips, with a +N more trailer."""
    if not items:
        return ""
    shown = items[:limit]
    out = "".join(f"<span class='chip {cls}'>{_esc(x)}</span>"
                  for x in shown)
    if len(items) > limit:
        out += f"<span class='chip'>... +{len(items) - limit} more</span>"
    return out


def _render_module_body(key: str, r) -> str:
    """Render module-specific output.

    `r` can be a dict (most modules) or a list (web_clickjacking).
    """

    # -------- ip_intel --------
    if key == "ip_intel":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        summary = r.get("summary") or ""
        sections = r.get("sections") or {}
        html = f"<div class='kv-grid'>"
        html += f"<div class='k'>Summary:</div><div class='v'>{_esc(summary)}</div>"
        html += "</div>"

        rdap = (sections.get("rdap_asn") or {}).get("rdap") or {}
        if rdap:
            html += "<div class='section-title'>RDAP</div><div class='kv-grid'>"
            for k in ("handle", "name", "org", "country", "type"):
                if rdap.get(k):
                    html += (f"<div class='k'>{k}</div>"
                             f"<div class='v'>{_esc(rdap[k])}</div>")
            for email in (rdap.get("emails") or [])[:5]:
                html += (f"<div class='k'>email</div>"
                         f"<div class='v'>{_esc(email)}</div>")
            html += "</div>"

        asn_block = (sections.get("rdap_asn") or {}).get("asn") or {}
        ip_info = asn_block.get("ip_info") or {}
        asn_info = asn_block.get("asn_info") or {}
        asn = asn_info.get("asn") or ip_info.get("asn")
        if asn:
            name = asn_info.get("name") or ip_info.get("asn_name") or ""
            html += "<div class='section-title'>ASN</div><div class='kv-grid'>"
            html += f"<div class='k'>ASN</div><div class='v'>AS{asn}</div>"
            if name:
                html += f"<div class='k'>Name</div><div class='v'>{_esc(name)}</div>"
            if ip_info.get("prefix"):
                html += (f"<div class='k'>Prefix</div>"
                         f"<div class='v'>{_esc(ip_info['prefix'])}</div>")
            html += "</div>"

        cdn = sections.get("cdn_classification")
        if cdn:
            html += (f"<div class='section-title'>CDN classification</div>"
                     f"<div class='kv-grid'>"
                     f"<div class='k'>Provider</div>"
                     f"<div class='v'>{_esc(cdn['provider'])} "
                     f"(AS{cdn['asn']})</div>"
                     f"<div class='k'>Note</div>"
                     f"<div class='v'>{_esc(cdn['note'])}</div>"
                     f"</div>")

        ptr = sections.get("ptr") or {}
        if ptr.get("hostnames"):
            html += ("<div class='section-title'>Reverse DNS</div>"
                     + _chips(ptr["hostnames"]))

        ports = (sections.get("ports") or {}).get("open_ports") or []
        if ports:
            html += ("<div class='section-title'>Open ports</div>"
                     + _chips([str(p) for p in ports]))

        services = (sections.get("services") or {}).get("services") or []
        if services:
            html += "<div class='section-title'>Services</div>"
            rows = "".join(
                f"<div class='k'>{svc.get('port')}</div>"
                f"<div class='v'>{_esc(svc.get('service'))} "
                f"{_esc(svc.get('version') or '')}</div>"
                for svc in services[:30]
            )
            html += f"<div class='kv-grid'>{rows}</div>"

        rev = sections.get("reverse_ip") or {}
        domains = rev.get("domains") or []
        if domains:
            html += ("<div class='section-title'>Reverse IP "
                     f"({len(domains)})</div>" + _chips(domains, limit=60))

        pdns = sections.get("passive_dns") or {}
        hosts = pdns.get("historical_hostnames") or []
        if hosts:
            html += ("<div class='section-title'>Passive DNS "
                     f"({len(hosts)})</div>" + _chips(hosts, limit=60))

        return html

    # -------- web_intel --------
    if key == "web_intel":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        html = "<div class='kv-grid'>"
        html += f"<div class='k'>Final URL:</div><div class='v'>{_esc(r.get('final_url'))}</div>"
        html += f"<div class='k'>Status:</div><div class='v'>{_esc(r.get('status'))}</div>"
        if r.get("title"):
            html += f"<div class='k'>Title:</div><div class='v'>{_esc(r['title'])}</div>"
        html += "</div>"

        sh = r.get("security_headers") or {}
        present = {k: v for k, v in sh.items() if v}
        missing = [k for k, v in sh.items() if not v]
        if present or missing:
            html += "<div class='section-title'>Security headers</div>"
            html += "<div class='kv-grid'>"
            for k, v in present.items():
                html += f"<div class='k'>{_esc(k)}</div><div class='v'>{_esc(v)}</div>"
            for k in missing:
                html += (f"<div class='k'>missing</div>"
                         f"<div class='v'>{_esc(k)}</div>")
            html += "</div>"

        csp = r.get("csp") or {}
        hosts = csp.get("hosts") or []
        if hosts:
            html += ("<div class='section-title'>CSP hosts "
                     f"({len(hosts)})</div>" + _chips(hosts))

        cookies = r.get("cookies") or []
        if cookies:
            html += f"<div class='section-title'>Cookies ({len(cookies)})</div>"
            rows = ""
            for c in cookies[:30]:
                attrs = c.get("attributes") or {}
                flags = []
                if attrs.get("secure"):     flags.append("Secure")
                if attrs.get("httponly"):   flags.append("HttpOnly")
                if attrs.get("samesite"):   flags.append(f"SameSite={attrs['samesite']}")
                rows += (f"<div class='k'>{_esc(c['name'])}</div>"
                         f"<div class='v'>{_esc(' '.join(flags) or '(no flags)')}</div>")
            html += f"<div class='kv-grid'>{rows}</div>"

        wk = r.get("well_known") or {}
        if wk:
            html += (f"<div class='section-title'>Well-known "
                     f"({len(wk)})</div>")
            html += _chips([f"{p} [{v.get('status')}]"
                            for p, v in wk.items()])

        robots = r.get("robots") or {}
        if robots.get("sitemaps") or robots.get("user_agents"):
            html += "<div class='section-title'>robots.txt</div>"
            for s in robots.get("sitemaps") or []:
                html += f"<div class='code'>Sitemap: {_esc(s)}</div>"

        sm = r.get("sitemap") or {}
        if sm.get("urls"):
            html += (f"<div class='section-title'>Sitemap "
                     f"({sm.get('total', len(sm['urls']))} URL(s))</div>")
            html += _chips(sm["urls"][:40])
            if len(sm["urls"]) > 40:
                html += f"<span class='chip'>... +{len(sm['urls']) - 40} more</span>"

        if r.get("favicon_hash"):
            html += (f"<div class='section-title'>Favicon</div>"
                     f"<div class='kv-grid'>"
                     f"<div class='k'>URL</div>"
                     f"<div class='v'>{_esc(r.get('favicon_url'))}</div>"
                     f"<div class='k'>Hash</div>"
                     f"<div class='v'>{_esc(r['favicon_hash'])}</div>"
                     f"</div>")

        return html

    # -------- tls_cert --------
    if key == "tls_cert":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        html = "<div class='kv-grid'>"
        for k, label in (
            ("subject_cn", "Subject CN"),
            ("issuer_cn", "Issuer CN"),
            ("serial", "Serial"),
            ("not_before", "Not before"),
            ("not_after", "Not after"),
            ("protocol", "TLS version"),
            ("key_alg", "Key alg"),
            ("key_size", "Key size"),
            ("sig_alg", "Signature alg"),
        ):
            if r.get(k):
                html += (f"<div class='k'>{label}</div>"
                         f"<div class='v'>{_esc(r[k])}</div>")
        if r.get("expired"):
            html += ("<div class='k'>Status</div>"
                     "<div class='v' style='color:#fca5a5'>EXPIRED</div>")
        if r.get("self_signed"):
            html += ("<div class='k'>Self-signed</div>"
                     "<div class='v' style='color:#fca5a5'>yes</div>")
        html += "</div>"

        sans = r.get("sans") or []
        if sans:
            html += (f"<div class='section-title'>SANs "
                     f"({len(sans)})</div>" + _chips(sans))
        return html

    # -------- reverse_ip --------
    if key == "reverse_ip":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        domains = r.get("domains") or []
        if not domains:
            return "<div class='kv-grid'><div class='k'>Result:</div><div class='v'>no domains found</div></div>"
        html = (f"<div class='section-title'>{len(domains)} domain(s) "
                f"on same IP</div>")
        html += _chips(domains, limit=80)
        return html

    # -------- tech_fingerprint --------
    if key == "tech_fingerprint":
        techs = r.get("technologies", []) if isinstance(r, dict) else []
        if not techs:
            return "<div class='kv-grid'><div class='k'>Result:</div><div class='v'>no technologies detected</div></div>"
        rows = "".join(
            f"<div class='k'>{_esc(t.get('category'))}</div>"
            f"<div class='v'>{_esc(t.get('name'))} {_esc(t.get('version', ''))}</div>"
            for t in techs
        )
        return f"<div class='kv-grid'>{rows}</div>"

    # -------- cms_fingerprint --------
    if key == "cms_fingerprint":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        if not r.get("cms"):
            return ("<div class='kv-grid'><div class='k'>Result:</div>"
                    "<div class='v'>no CMS identified</div></div>")
        html = "<div class='kv-grid'>"
        html += f"<div class='k'>CMS:</div><div class='v'>{_esc(r['cms'])}</div>"
        html += (f"<div class='k'>Confidence:</div>"
                 f"<div class='v'>{_esc(r.get('confidence'))}</div>")
        if r.get("version"):
            html += f"<div class='k'>Version:</div><div class='v'>{_esc(r['version'])}</div>"
        html += "</div>"
        evidence = r.get("evidence") or []
        if evidence:
            html += ("<div class='section-title'>Evidence</div>"
                     + _chips(evidence))
        return html

    # -------- leak_check --------
    if key == "leak_check":
        leaked = r.get("leaked", []) if isinstance(r, dict) else []
        if not leaked:
            return "<div class='kv-grid'><div class='k'>Result:</div><div class='v'>no exposed paths</div></div>"
        rows = "".join(
            f"<div class='k'>HTTP {e['status']}</div>"
            f"<div class='v'>{_esc(e['path'])} ({e.get('length', 0)} bytes)</div>"
            for e in leaked[:60]
        )
        return f"<div class='kv-grid'>{rows}</div>"

    # -------- ct_logs --------
    if key == "ct_logs":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        names = r.get("unique_names", []) or []
        wildcards = r.get("wildcards", []) or []
        html = "<div class='kv-grid'>"
        html += f"<div class='k'>Total certs:</div><div class='v'>{r.get('total_certs', 0)}</div>"
        html += f"<div class='k'>Unique names:</div><div class='v'>{len(names)}</div>"
        html += f"<div class='k'>Wildcards:</div><div class='v'>{_esc(', '.join(wildcards)) or '—'}</div>"
        html += "</div>"
        if names:
            html += ("<div class='section-title'>Names</div>"
                     + _chips(names, limit=80))
        return html

    # -------- whois --------
    if key == "whois":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        w = r.get("whois") or {}
        html = "<div class='kv-grid'>"
        for field in ("registrar", "created", "updated", "expires",
                      "handle", "name", "org", "country", "type"):
            if w.get(field):
                html += f"<div class='k'>{field}:</div><div class='v'>{_esc(w[field])}</div>"
        if w.get("nameservers"):
            html += (f"<div class='k'>Nameservers:</div>"
                     f"<div class='v'>{_esc(', '.join(w['nameservers']))}</div>")
        for email in (w.get("emails") or [])[:5]:
            html += f"<div class='k'>email:</div><div class='v'>{_esc(email)}</div>"
        html += "</div>"
        return html

    # -------- asn --------
    if key == "asn":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        a = r.get("asn_info") or {}
        ip = r.get("ip_info") or {}
        html = "<div class='kv-grid'>"
        asn = a.get("asn") or ip.get("asn")
        if asn:
            html += f"<div class='k'>ASN:</div><div class='v'>AS{asn}</div>"
        if a.get("name") or ip.get("asn_name"):
            html += (f"<div class='k'>Name:</div>"
                     f"<div class='v'>{_esc(a.get('name') or ip.get('asn_name'))}</div>")
        if ip.get("prefix"):
            html += f"<div class='k'>Prefix:</div><div class='v'>{_esc(ip['prefix'])}</div>"
        if a.get("country") or ip.get("asn_country"):
            html += (f"<div class='k'>Country:</div>"
                     f"<div class='v'>{_esc(a.get('country') or ip.get('asn_country'))}</div>")
        html += "</div>"
        if a.get("prefixes_v4"):
            html += ("<div class='section-title'>IPv4 prefixes</div>"
                     + _chips([p["prefix"] for p in a["prefixes_v4"][:40]]))
        return html

    # -------- historical --------
    if key == "historical":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        html = "<div class='kv-grid'>"
        html += f"<div class='k'>Wayback URLs:</div><div class='v'>{r.get('wayback_urls', 0)}</div>"
        html += (f"<div class='k'>URLScan results:</div>"
                 f"<div class='v'>{len(r.get('urlscan_results', []))}</div>")
        html += "</div>"
        hosts = r.get("historical_hosts", [])
        if hosts:
            html += ("<div class='section-title'>Historical hosts</div>"
                     + _chips(hosts))
        return html

    # -------- js_analysis --------
    if key == "js_analysis":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        html = "<div class='kv-grid'>"
        html += f"<div class='k'>Files analyzed:</div><div class='v'>{r.get('files_analyzed', 0)}</div>"
        html += f"<div class='k'>API paths:</div><div class='v'>{len(r.get('api_paths', []))}</div>"
        html += f"<div class='k'>Secrets:</div><div class='v'>{len(r.get('secrets', []))}</div>"
        html += "</div>"
        if r.get("api_paths"):
            html += ("<div class='section-title'>API paths</div>"
                     + _chips(r["api_paths"][:40]))
        if r.get("secrets"):
            html += "<div class='section-title'>Secrets</div>"
            html += _chips(
                [f"[{s['type']}] {s['match'][:60]}" for s in r["secrets"][:15]],
                cls="sev-high",
            )
        return html

    # -------- emails --------
    if key == "emails":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        emails = r.get("emails", [])
        if not emails:
            return "<div class='kv-grid'><div class='k'>Result:</div><div class='v'>no emails</div></div>"
        html = "<div class='kv-grid'>"
        html += f"<div class='k'>Total:</div><div class='v'>{len(emails)}</div>"
        html += f"<div class='k'>MX:</div><div class='v'>{_esc(', '.join((r.get('mx') or [])[:3]) or 'none')}</div>"
        html += "</div>"
        html += ("<div class='section-title'>Addresses</div>"
                 + _chips([f"{e['email']} [{e['confidence']}]"
                           for e in emails[:60]]))
        return html

    # -------- cloud_enum --------
    if key == "cloud_enum":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        buckets = r.get("buckets", [])
        if not buckets:
            return "<div class='kv-grid'><div class='k'>Result:</div><div class='v'>no buckets found</div></div>"
        html = "<div class='kv-grid'>"
        html += f"<div class='k'>Total:</div><div class='v'>{len(buckets)}</div>"
        html += (f"<div class='k'>Public:</div>"
                 f"<div class='v'>{sum(1 for b in buckets if b.get('status') == 200)}</div>")
        html += "</div>"
        html += "<div class='section-title'>Buckets</div>"
        for b in buckets[:40]:
            cls = "sev-high" if b.get("status") == 200 else ""
            count = ""
            if b.get("object_count") is not None:
                n = b["object_count"]
                count = f" ({n:,} obj)" if n else " (empty)"
            html += (f"<span class='chip {cls}'>"
                     f"{_esc(b.get('provider'))}: {_esc(b.get('name'))}"
                     f"{count}</span>")
        return html

    # -------- social --------
    if key == "social":
        if not isinstance(r, dict):
            return f"<pre>{_esc(r)}</pre>"
        profiles = r.get("profiles", {})
        if not profiles:
            return "<div class='kv-grid'><div class='k'>Result:</div><div class='v'>no social profiles</div></div>"
        html = ""
        for platform, entries in profiles.items():
            html += f"<div class='section-title'>{_esc(platform)}</div>"
            for e in entries[:15]:
                marker = " ✓" if e.get("verified") else ""
                html += (f"<span class='chip'>{_esc(e.get('url'))}"
                         f"{marker}</span>")
        if r.get("dns_verifications"):
            html += "<div class='section-title'>DNS verification tokens</div>"
            for name, value in r["dns_verifications"].items():
                html += (f"<span class='chip'>{_esc(name)}="
                         f"{_esc(value)}</span>")
        return html

    # -------- web_clickjacking (list result) --------
    if key == "web_clickjacking":
        if isinstance(r, list):
            rows = ""
            for f in r:
                url = f.get("url", "?")
                sev = f.get("severity", "info")
                ev = f.get("evidence", "")
                rows += (f"<div class='k'>[{_esc(sev)}]</div>"
                         f"<div class='v'>{_esc(url)} — {_esc(ev)}</div>")
            return f"<div class='kv-grid'>{rows}</div>"
        return f"<pre>{_esc(r)}</pre>"

    # -------- Scan mode modules (sqli, xss, lfi, ...) --------
    if key in {k for k, _, _ in SCAN_MODULES}:
        findings = r if isinstance(r, list) else (
            r.get("findings") if isinstance(r, dict) else [])
        if not findings:
            return "<div class='kv-grid'><div class='k'>Result:</div><div class='v'>no findings</div></div>"
        rows = ""
        for f in findings[:60]:
            sev = f.get("severity", "?")
            typ = f.get("type", key)
            param = f.get("param") or f.get("parameter") or ""
            ev = f.get("evidence", "")
            rows += (f"<div class='k'>[{_esc(sev)}] {_esc(typ)}"
                     f"{(' ' + _esc(param)) if param else ''}</div>"
                     f"<div class='v'>{_esc(ev)}</div>")
        return f"<div class='kv-grid'>{rows}</div>"

    # -------- Fallback: raw JSON --------
    if isinstance(r, (dict, list)):
        return f"<pre>{_esc(json.dumps(r, indent=2, default=str)[:8000])}</pre>"
    return f"<pre>{_esc(r)}</pre>"


# ---------------------------------------------------------------------
# Dossier rendering — Markdown
# ---------------------------------------------------------------------

def _render_markdown(dossier: dict) -> str:
    target = dossier["target"]
    kind = dossier.get("kind", "domain")
    started = dossier.get("started_at", "")[:19]
    elapsed = dossier["elapsed"]
    modules = dossier["modules"]

    lines = [
        f"# Recon Dossier — {target}",
        "",
        f"**Kind:** {kind}  ",
        f"**Started:** {started} UTC  ",
        f"**Elapsed:** {elapsed}s  ",
        f"**Mode:** {dossier.get('mode', 'sequential')}  ",
    ]
    if dossier.get("scan"):
        lines.append(f"**Scan mode:** on  ")
    lines += [
        "",
        "---",
        "",
        "## Module Summary",
        "",
        "| Module | Status | Summary |",
        "|--------|--------|---------|",
    ]

    for m in modules:
        s = _summarize_module(m)
        status = "OK" if m["ok"] else "FAILED"
        summary = (s.get("summary", "") or "").replace("|", "\\|")
        lines.append(f"| `{m['key']}` | {status} | {summary} |")

    lines += ["", "---", ""]

    for m in modules:
        lines.append(f"## {m['key']} — {m['description']}")
        lines.append("")
        if not m["ok"]:
            lines.append(f"**FAILED:** {m.get('error', '?')}")
            lines.append("")
            continue
        r = m["result"] or {}
        lines.extend(_render_markdown_module(m["key"], r))
        lines.append("")

    lines += [
        "---",
        "",
        f"*Generated {datetime.now(timezone.utc).isoformat()[:19]} UTC*",
    ]
    return "\n".join(lines)


def _render_markdown_module(key: str, r) -> list[str]:
    """Render module output as a list of Markdown lines."""
    lines = []

    if key == "ip_intel" and isinstance(r, dict):
        lines.append(f"**Summary:** {r.get('summary', '')}")
        lines.append("")
        sections = r.get("sections") or {}
        rdap = (sections.get("rdap_asn") or {}).get("rdap") or {}
        if rdap:
            lines.append("**RDAP:**")
            lines.append("")
            for k in ("handle", "name", "org", "country", "type"):
                if rdap.get(k):
                    lines.append(f"- `{k}`: {rdap[k]}")
            lines.append("")
        asn_block = (sections.get("rdap_asn") or {}).get("asn") or {}
        a = asn_block.get("asn_info") or {}
        ip = asn_block.get("ip_info") or {}
        asn = a.get("asn") or ip.get("asn")
        if asn:
            lines.append(f"**ASN:** AS{asn} "
                         f"{a.get('name') or ip.get('asn_name') or ''}")
            lines.append("")
        cdn = sections.get("cdn_classification")
        if cdn:
            lines.append(f"**CDN/cloud:** {cdn['provider']} "
                         f"(AS{cdn['asn']}) — {cdn['note']}")
            lines.append("")
        ptr = sections.get("ptr") or {}
        if ptr.get("hostnames"):
            lines.append(f"**Reverse DNS:** "
                         f"{', '.join(ptr['hostnames'])}")
            lines.append("")
        ports = (sections.get("ports") or {}).get("open_ports") or []
        if ports:
            lines.append(f"**Open ports:** "
                         f"{', '.join(str(p) for p in ports)}")
            lines.append("")
        services = (sections.get("services") or {}).get("services") or []
        if services:
            lines.append("**Services:**")
            lines.append("")
            for svc in services[:30]:
                v = f" {svc.get('version')}" if svc.get("version") else ""
                lines.append(f"- `{svc.get('port')}` {svc.get('service')}{v}")
            lines.append("")
        rev = sections.get("reverse_ip") or {}
        domains = rev.get("domains") or []
        if domains:
            lines.append(f"**Reverse IP ({len(domains)}):**")
            lines.append("")
            for d in domains[:80]:
                lines.append(f"- `{d}`")
            lines.append("")
        pdns = sections.get("passive_dns") or {}
        hosts = pdns.get("historical_hostnames") or []
        if hosts:
            lines.append(f"**Passive DNS ({len(hosts)}):**")
            lines.append("")
            for h in hosts[:80]:
                lines.append(f"- `{h}`")
            lines.append("")

    elif key == "web_intel" and isinstance(r, dict):
        lines.append(f"**URL:** {r.get('final_url')}")
        lines.append(f"**Status:** HTTP {r.get('status')}")
        if r.get("title"):
            lines.append(f"**Title:** {r['title']}")
        lines.append("")
        sh = r.get("security_headers") or {}
        present = {k: v for k, v in sh.items() if v}
        missing = [k for k, v in sh.items() if not v]
        if present:
            lines.append("**Security headers present:**")
            lines.append("")
            for k, v in present.items():
                lines.append(f"- `{k}`: {v}")
            lines.append("")
        if missing:
            lines.append(f"**Security headers missing:** "
                         f"{', '.join(missing)}")
            lines.append("")
        csp_hosts = (r.get("csp") or {}).get("hosts") or []
        if csp_hosts:
            lines.append(f"**CSP hosts ({len(csp_hosts)}):**")
            lines.append("")
            for h in csp_hosts:
                lines.append(f"- `{h}`")
            lines.append("")
        wk = r.get("well_known") or {}
        if wk:
            lines.append(f"**Well-known ({len(wk)}):**")
            lines.append("")
            for path, entry in wk.items():
                lines.append(f"- `{path}` → HTTP {entry.get('status')}")
            lines.append("")
        sm = r.get("sitemap") or {}
        if sm.get("urls"):
            lines.append(f"**Sitemap: {sm.get('total', len(sm['urls']))} URL(s)**")
            lines.append("")
            for u in sm["urls"][:60]:
                lines.append(f"- `{u}`")
            lines.append("")

    elif key == "tls_cert" and isinstance(r, dict):
        for k in ("subject_cn", "issuer_cn", "serial", "not_before",
                  "not_after", "protocol", "key_alg", "key_size",
                  "sig_alg"):
            if r.get(k):
                lines.append(f"- **{k}:** {r[k]}")
        if r.get("expired"):
            lines.append("- **Status:** EXPIRED")
        if r.get("self_signed"):
            lines.append("- **Self-signed:** yes")
        sans = r.get("sans") or []
        if sans:
            lines.append("")
            lines.append(f"**SANs ({len(sans)}):**")
            lines.append("")
            for s in sans:
                lines.append(f"- `{s}`")

    elif key == "reverse_ip" and isinstance(r, dict):
        domains = r.get("domains") or []
        if domains:
            lines.append(f"**{len(domains)} domain(s) on same IP:**")
            lines.append("")
            for d in domains[:80]:
                lines.append(f"- `{d}`")

    elif key == "tech_fingerprint" and isinstance(r, dict):
        for t in r.get("technologies", []):
            v = f" {t.get('version')}" if t.get("version") else ""
            lines.append(f"- **{t.get('category')}**: {t.get('name')}{v}")

    elif key == "cms_fingerprint" and isinstance(r, dict):
        if r.get("cms"):
            lines.append(f"- **CMS:** {r['cms']}")
            lines.append(f"- **Confidence:** {r.get('confidence')}")
            if r.get("version"):
                lines.append(f"- **Version:** {r['version']}")
            for e in r.get("evidence", []):
                lines.append(f"  - {e}")
        else:
            lines.append("_No CMS identified._")

    elif key == "leak_check" and isinstance(r, dict):
        leaked = r.get("leaked", [])
        if not leaked:
            lines.append("_No exposed paths._")
        else:
            for e in leaked[:60]:
                lines.append(f"- HTTP {e['status']} `{e['path']}` "
                             f"({e.get('length', 0)} bytes)")

    elif key == "ct_logs" and isinstance(r, dict):
        lines.append(f"- Total certificates: {r.get('total_certs', 0)}")
        lines.append(f"- Unique names: {len(r.get('unique_names', []))}")
        lines.append(f"- Wildcards: {', '.join(r.get('wildcards', [])) or '—'}")
        if r.get("unique_names"):
            lines.append("")
            for n in r["unique_names"][:80]:
                lines.append(f"- `{n}`")

    elif key == "whois" and isinstance(r, dict):
        w = r.get("whois") or {}
        for f in ("registrar", "created", "updated", "expires",
                  "handle", "name", "org", "country", "type"):
            if w.get(f):
                lines.append(f"- **{f}:** {w[f]}")
        if w.get("nameservers"):
            lines.append(f"- **nameservers:** "
                         f"{', '.join(w['nameservers'])}")
        for email in (w.get("emails") or [])[:5]:
            lines.append(f"- **email:** {email}")

    elif key == "asn" and isinstance(r, dict):
        a = r.get("asn_info") or {}
        ip = r.get("ip_info") or {}
        asn = a.get("asn") or ip.get("asn")
        if asn:
            lines.append(f"- **ASN:** AS{asn}")
        if a.get("name") or ip.get("asn_name"):
            lines.append(f"- **Name:** {a.get('name') or ip.get('asn_name')}")
        if ip.get("prefix"):
            lines.append(f"- **Prefix:** {ip['prefix']}")
        if a.get("prefixes_v4"):
            lines.append("")
            lines.append(f"**IPv4 prefixes ({len(a['prefixes_v4'])}):**")
            lines.append("")
            for p in a["prefixes_v4"][:40]:
                lines.append(f"- `{p['prefix']}`")

    elif key == "historical" and isinstance(r, dict):
        lines.append(f"- Wayback URLs: {r.get('wayback_urls', 0)}")
        lines.append(f"- URLScan results: "
                     f"{len(r.get('urlscan_results', []))}")
        if r.get("historical_hosts"):
            lines.append("")
            for h in r["historical_hosts"]:
                lines.append(f"- `{h}`")

    elif key == "js_analysis" and isinstance(r, dict):
        lines.append(f"- Files analyzed: {r.get('files_analyzed', 0)}")
        lines.append(f"- API paths: {len(r.get('api_paths', []))}")
        lines.append(f"- Secrets: {len(r.get('secrets', []))}")
        if r.get("api_paths"):
            lines.append("")
            for p in r["api_paths"][:50]:
                lines.append(f"- `{p}`")
        if r.get("secrets"):
            lines.append("")
            for s in r["secrets"][:20]:
                lines.append(f"- `[{s.get('type')}]` "
                             f"{s.get('match', '')[:100]}")

    elif key == "emails" and isinstance(r, dict):
        for e in r.get("emails", [])[:80]:
            lines.append(f"- `{e['email']}` ({e.get('confidence')})")

    elif key == "cloud_enum" and isinstance(r, dict):
        buckets = r.get("buckets", [])
        if not buckets:
            lines.append("_No buckets found._")
        else:
            for b in buckets[:50]:
                marker = " **[PUBLIC]**" if b.get("status") == 200 else ""
                lines.append(f"- `{b.get('provider')}` `{b.get('name')}` "
                             f"(HTTP {b.get('status')}){marker}")

    elif key == "social" and isinstance(r, dict):
        for platform, entries in (r.get("profiles") or {}).items():
            lines.append(f"### {platform}")
            lines.append("")
            for e in entries[:15]:
                marker = " ✓" if e.get("verified") else ""
                lines.append(f"- {e.get('url')}{marker}")
            lines.append("")

    elif key == "web_clickjacking" and isinstance(r, list):
        for f in r:
            lines.append(f"- [{f.get('severity', 'info')}] "
                         f"{f.get('url', '?')} — {f.get('evidence', '')}")

    elif key in {k for k, _, _ in SCAN_MODULES}:
        findings = r if isinstance(r, list) else (
            r.get("findings") if isinstance(r, dict) else [])
        if not findings:
            lines.append("_No findings._")
        else:
            for f in findings[:60]:
                sev = f.get("severity", "?")
                typ = f.get("type", key)
                param = f.get("param") or f.get("parameter") or ""
                lines.append(f"- [{sev}] {typ} {param} — "
                             f"{f.get('evidence', '')}")

    else:
        lines.append("```json")
        lines.append(json.dumps(r, indent=2, default=str)[:5000])
        lines.append("```")

    return lines


# ---------------------------------------------------------------------
# Dossier writing
# ---------------------------------------------------------------------

def write_dossiers(dossier: dict, base_path: Path,
                    want_json: bool = False) -> dict:
    base_path = Path(base_path)
    base_path.parent.mkdir(parents=True, exist_ok=True)

    if base_path.suffix in (".html", ".htm", ".md", ".json"):
        base = base_path.with_suffix("")
    else:
        base = base_path

    written = {}

    html_path = base.with_suffix(".html")
    html_path.write_text(_render_html(dossier), encoding="utf-8")
    written["html"] = html_path

    md_path = base.with_suffix(".md")
    md_path.write_text(_render_markdown(dossier), encoding="utf-8")
    written["markdown"] = md_path

    if want_json:
        json_path = base.with_suffix(".json")
        json_path.write_text(
            json.dumps(dossier, indent=2, default=str),
            encoding="utf-8")
        written["json"] = json_path

    return written


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target: str, output: str | None = None,
              skip: list[str] | None = None,
              only: list[str] | None = None,
              parallel: bool = False,
              verbose: bool = False,
              want_json: bool = False,
              scan: bool = False,
              store=None,
              workspace=None) -> dict:
    """Full investigation. Writes dossier(s) and returns the raw data."""
    dossier = await investigate(target, skip=skip, only=only,
                                 parallel=parallel, verbose=verbose,
                                 scan=scan)

    # Determine output path
    if output:
        base_path = Path(output)
    elif workspace is not None:
        base_path = workspace.report_dir / "dossier"
    else:
        base_path = Path("dossier")

    print()
    info(f"writing dossiers to {base_path}.*")
    written = write_dossiers(dossier, base_path, want_json=want_json)
    for fmt, path in written.items():
        success(f"  {fmt}: {path}")

    if store is not None:
        modules_ok = sum(1 for m in dossier["modules"] if m["ok"])
        modules_failed = len(dossier["modules"]) - modules_ok
        store.add_finding({
            "module": "investigate",
            "type": "informational",
            "severity": "info",
            "target": target,
            "evidence": (f"kind={dossier.get('kind', '?')}, "
                         f"{modules_ok} module(s) OK, "
                         f"{modules_failed} failed "
                         f"in {dossier['elapsed']}s"),
            "data": {
                "target": target,
                "kind": dossier.get("kind"),
                "elapsed": dossier["elapsed"],
                "mode": dossier.get("mode", "sequential"),
                "scan": dossier.get("scan", False),
                "summary": [_summarize_module(m)
                            for m in dossier["modules"]],
            },
        })
        success("investigation summary written to store")

    return dossier


def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.investigate",
        description="Run all applicable recon modules and produce a "
                    "combined dossier. The module set is chosen based "
                    "on whether the target is an IP, a domain, or a URL.",
    )
    p.add_argument("target", help="domain, URL, or IP")
    p.add_argument("-o", "--output", default=None,
                   help="output base path (extensions added automatically)")
    p.add_argument("--skip", default=None,
                   help="comma-separated module keys to skip")
    p.add_argument("--only", default=None,
                   help="comma-separated module keys to run exclusively")
    p.add_argument("--parallel", action="store_true",
                   help="run modules concurrently (faster but riskier)")
    p.add_argument("--scan", action="store_true",
                   help="also run vuln/ modules (sqli, xss, nosqli, lfi, "
                        "ssrf, xxe, crlf, open_redirect, host_header) "
                        "against a URL target. Off by default.")
    p.add_argument("--json", dest="want_json", action="store_true",
                   help="also write a raw JSON dump")
    p.add_argument("--store", action="store_true",
                   help="write summary to active workspace")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--list-modules", action="store_true",
                   help="list available module keys and exit")
    args = p.parse_args()

    if args.list_modules:
        print("Modules by target kind:")
        print()
        print("IP targets:")
        for k, d, _ in IP_MODULES:
            print(f"  {k:22s} {d}")
        print()
        print("Domain targets:")
        for k, d, _ in DOMAIN_MODULES:
            print(f"  {k:22s} {d}")
        print()
        print("URL targets:")
        for k, d, _ in URL_MODULES:
            print(f"  {k:22s} {d}")
        print()
        print("URL targets, --scan mode only:")
        for k, d, _ in SCAN_MODULES:
            print(f"  {k:22s} {d}")
        print()
        print("ASN targets:")
        for k, d, _ in ASN_MODULES:
            print(f"  {k:22s} {d}")
        return

    skip = [s.strip() for s in args.skip.split(",")] if args.skip else None
    only = [s.strip() for s in args.only.split(",")] if args.only else None

    store = None
    workspace = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; use `toolkit workspace switch`")
        else:
            workspace = get_workspace(active)
            store = open_store(workspace.db_path, workspace_name=active)

    asyncio.run(run(
        args.target,
        output=args.output,
        skip=skip, only=only,
        parallel=args.parallel,
        verbose=args.verbose,
        want_json=args.want_json,
        scan=args.scan,
        store=store,
        workspace=workspace,
    ))


if __name__ == "__main__":
    _cli()