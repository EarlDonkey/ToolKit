"""
Unified HTML report.

Reads everything from a Store and produces one self-contained HTML
file. No external CSS, no CDN, no JavaScript framework. Everything is
inlined so the report opens offline, from a USB stick, or in an email.

Structure:

    HEADER              engagement metadata (name, operator, targets)
    EXECUTIVE SUMMARY   severity counts + module counts + asset counts
    CRITICAL FINDINGS   cards, sorted by severity
    HIGH FINDINGS
    MEDIUM FINDINGS
    LOW FINDINGS
    INFO FINDINGS
    HOSTS               table of every discovered host
    SERVICES            table of every open service
    CREDENTIALS         table of captured credentials
    ARTIFACTS           screenshots / saved responses / loot files

Features:

  - Severity-first layout, with a module filter dropdown at the top.
  - Per-finding justification from report.severity (why is this high?).
  - Search box that filters cards by any visible text.
  - Collapsible severity sections.
  - Optional image embedding (--embed-images): base64-inlines every
    screenshot/artifact referenced by a finding, so the HTML is fully
    portable. Default off because it bloats the file.

Usage:

    from report.unified import generate
    generate(store, output_path, workspace=ws, embed_images=False)

    # CLI:
    python -m report.unified --workspace acme-corp -o report.html
    python -m report.unified --workspace acme-corp -o report.html \\
        --embed-images
"""

import base64
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Informational",
}
SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#eab308",
    "low":      "#0284c7",
    "info":     "#64748b",
}


# ---------------------------------------------------------------------
# Escaping helpers
# ---------------------------------------------------------------------

def _e(v) -> str:
    """HTML-escape a value, tolerating None and non-strings."""
    if v is None:
        return ""
    return html.escape(str(v))


def _short(v, n=200) -> str:
    """Truncate a string for display."""
    if v is None:
        return ""
    s = str(v)
    return s if len(s) <= n else s[:n - 1] + "…"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------

def _rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index((sev or "info").lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def _group_findings(findings: list) -> dict:
    """Return {severity: [findings]} sorted within each group."""
    out = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev not in out:
            out[sev] = []
        out[sev].append(f)
    for s in out:
        out[s].sort(key=lambda x: (
            x.get("module") or "",
            x.get("target") or "",
            x.get("port") or 0,
        ))
    return out


# ---------------------------------------------------------------------
# Finding card
# ---------------------------------------------------------------------

def _render_finding_card(f: dict, embed_images: bool = False,
                         base_path: Path | None = None) -> str:
    """Render one finding as an HTML card."""
    fid = f.get("id", "?")
    module = f.get("module") or "unknown"
    ftype = f.get("type") or "unknown"
    severity = (f.get("severity") or "info").lower()
    target = f.get("target") or ""
    port = f.get("port")
    param = f.get("param")
    payload = f.get("payload")
    evidence = f.get("evidence")
    ts = f.get("ts") or ""
    justification = f.get("severity_justification")
    score = f.get("severity_score")

    # Data blob (extracted tables, creds, cves, etc.)
    data = f.get("data")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {"raw": data}

    # --- Metadata block ---
    meta_rows = []
    if target:
        meta_rows.append(("Target", _e(target) +
                          (f":{port}" if port else "")))
    if param:
        meta_rows.append(("Parameter", f"<code>{_e(param)}</code>"))
    if ts:
        meta_rows.append(("Found", _e(ts)))
    if score is not None and justification:
        meta_rows.append(("Severity basis",
                          f"{_e(justification)} <span class='dim'>"
                          f"(score {_e(score)})</span>"))
    meta_html = "".join(
        f"<div class='meta-row'><span class='meta-k'>{k}:</span> "
        f"<span class='meta-v'>{v}</span></div>"
        for k, v in meta_rows
    )

    # --- Payload block ---
    payload_html = ""
    if payload:
        payload_html = (
            f"<div class='block'>"
            f"<div class='block-title'>Payload</div>"
            f"<pre class='code'>{_e(_short(payload, 500))}</pre>"
            f"</div>"
        )

    # --- Evidence block ---
    evidence_html = ""
    if evidence:
        evidence_html = (
            f"<div class='block'>"
            f"<div class='block-title'>Evidence</div>"
            f"<div class='evidence'>{_e(_short(evidence, 800))}</div>"
            f"</div>"
        )

    # --- Extracted data block (if any) ---
    extracted_html = ""
    if isinstance(data, dict) and data:
        # Filter out noisy keys we already render elsewhere
        skip = {"raw"}
        keys = [k for k in data.keys() if k not in skip]
        if keys:
            rows = []
            for k in keys:
                v = data[k]
                # Long lists: show count + first few items
                if isinstance(v, list):
                    if len(v) > 8:
                        preview = ", ".join(_e(x) for x in v[:8])
                        rows.append(
                            f"<div class='meta-row'>"
                            f"<span class='meta-k'>{_e(k)}:</span> "
                            f"<span class='meta-v'>{len(v)} item(s) — "
                            f"{preview}, …</span></div>"
                        )
                    else:
                        preview = ", ".join(_e(x) for x in v)
                        rows.append(
                            f"<div class='meta-row'>"
                            f"<span class='meta-k'>{_e(k)}:</span> "
                            f"<span class='meta-v'>{preview}</span></div>"
                        )
                elif isinstance(v, (dict,)):
                    pretty = json.dumps(v, indent=2, default=str)
                    rows.append(
                        f"<div class='block'>"
                        f"<div class='block-title'>{_e(k)}</div>"
                        f"<pre class='code'>{_e(_short(pretty, 800))}</pre>"
                        f"</div>"
                    )
                else:
                    rows.append(
                        f"<div class='meta-row'>"
                        f"<span class='meta-k'>{_e(k)}:</span> "
                        f"<span class='meta-v'>{_e(_short(v, 300))}</span>"
                        f"</div>"
                    )
            extracted_html = (
                "<div class='block'>"
                "<div class='block-title'>Extracted Data</div>"
                + "".join(rows) +
                "</div>"
            )

    # --- Optional embedded image ---
    image_html = ""
    if embed_images and isinstance(data, dict):
        img_rel = data.get("screenshot_path") or data.get("image_path")
        if img_rel and base_path:
            img_abs = (base_path / img_rel
                       if not Path(img_rel).is_absolute()
                       else Path(img_rel))
            image_html = _embed_image(img_abs)

    # --- Wrap ---
    return f"""
    <div class="card sev-{severity}" data-module="{_e(module)}"
         data-severity="{severity}" id="finding-{fid}">
        <div class="card-header">
            <span class="pill pill-{severity}">{_e(severity.upper())}</span>
            <span class="card-title">{_e(module)} / {_e(ftype)}</span>
            <a class="anchor" href="#finding-{fid}">#{fid}</a>
        </div>
        {meta_html}
        {payload_html}
        {evidence_html}
        {extracted_html}
        {image_html}
    </div>
    """


def _embed_image(path: Path) -> str:
    """Read an image and return an <img> tag with base64 inline data."""
    if not path.exists():
        return ""
    try:
        raw = path.read_bytes()
    except Exception:
        return ""
    ext = path.suffix.lower().lstrip(".")
    mime = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "webp": "image/webp",
        "svg": "image/svg+xml",
    }.get(ext, "application/octet-stream")
    b64 = base64.b64encode(raw).decode("ascii")
    size_kb = len(raw) / 1024
    return (
        f"<div class='block'>"
        f"<div class='block-title'>Screenshot "
        f"<span class='dim'>({path.name}, {size_kb:.0f} KB)</span></div>"
        f"<img class='shot' src='data:{mime};base64,{b64}' "
        f"alt='{_e(path.name)}'>"
        f"</div>"
    )


# ---------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------

def _render_summary(store, findings: list) -> str:
    """Executive summary block."""
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        if s not in sev_counts:
            sev_counts[s] = 0
        sev_counts[s] += 1

    mod_counts = {}
    for f in findings:
        m = f.get("module") or "unknown"
        mod_counts[m] = mod_counts.get(m, 0) + 1

    summary = store.summary() if store else {}

    sev_cards = "".join(
        f"<div class='stat sev-{s}'>"
        f"<div class='stat-num'>{sev_counts.get(s, 0)}</div>"
        f"<div class='stat-lab'>{SEVERITY_LABEL[s]}</div>"
        f"</div>"
        for s in SEVERITY_ORDER
    )

    mod_cards = "".join(
        f"<div class='chip'>{_e(m)} <span class='chip-n'>"
        f"{c}</span></div>"
        for m, c in sorted(mod_counts.items(),
                            key=lambda x: -x[1])
    )

    asset_cards = "".join(
        f"<div class='asset'>"
        f"<span class='asset-n'>{summary.get(k, 0)}</span> "
        f"<span class='asset-l'>{lab}</span>"
        f"</div>"
        for k, lab in [
            ("hosts", "hosts"),
            ("services", "services"),
            ("credentials", "credentials"),
            ("sessions", "sessions"),
            ("artifacts", "artifacts"),
        ]
    )

    return f"""
    <section class="summary">
        <h2>Executive Summary</h2>
        <div class="stat-grid">{sev_cards}</div>
        <h3>By Module</h3>
        <div class="chip-row">{mod_cards or '<span class="dim">no findings</span>'}</div>
        <h3>Assets</h3>
        <div class="asset-grid">{asset_cards}</div>
    </section>
    """


def _render_findings_section(severity: str, findings: list,
                             embed_images: bool = False,
                             base_path: Path | None = None) -> str:
    if not findings:
        return ""
    label = SEVERITY_LABEL.get(severity, severity.title())
    cards = "".join(
        _render_finding_card(f, embed_images=embed_images,
                             base_path=base_path)
        for f in findings
    )
    return f"""
    <section class="severity-section" data-severity="{severity}">
        <h2 class="sev-header sev-h-{severity}">
            <button class="toggle" data-target="grp-{severity}">
                <span class="chev">▾</span>
            </button>
            {_e(label)} Findings
            <span class="count">{len(findings)}</span>
        </h2>
        <div class="card-grid" id="grp-{severity}">{cards}</div>
    </section>
    """


def _render_hosts_table(hosts: list) -> str:
    if not hosts:
        return ""
    rows = []
    for h in hosts:
        tags = h.get("tags") or []
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except Exception:
                tags = []
        vendor = next((t[7:] for t in tags if str(t).startswith("vendor:")),
                      "")
        rows.append(
            f"<tr>"
            f"<td><code>{_e(h.get('ip'))}</code></td>"
            f"<td><code class='dim'>{_e(h.get('mac'))}</code></td>"
            f"<td>{_e(h.get('hostname'))}</td>"
            f"<td>{_e(vendor)}</td>"
            f"<td>{_e(h.get('os_guess'))}</td>"
            f"<td>{_e(h.get('discovery'))}</td>"
            f"<td class='dim'>{_e(h.get('first_seen','')[:19])}</td>"
            f"</tr>"
        )
    return f"""
    <section class="appendix">
        <h2>Appendix: Hosts <span class="count">{len(hosts)}</span></h2>
        <table class="data-table">
            <thead><tr>
                <th>IP</th><th>MAC</th><th>Hostname</th>
                <th>Vendor</th><th>OS guess</th><th>Discovery</th>
                <th>First seen</th>
            </tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </section>
    """


def _render_services_table(services: list) -> str:
    if not services:
        return ""
    rows = []
    for s in services:
        rows.append(
            f"<tr>"
            f"<td><code>{_e(s.get('host_ip'))}:{_e(s.get('port'))}</code></td>"
            f"<td>{_e(s.get('proto'))}</td>"
            f"<td>{_e(s.get('service'))}</td>"
            f"<td>{_e(s.get('version'))}</td>"
            f"<td class='dim mono'>{_e(_short(s.get('banner'), 100))}</td>"
            f"</tr>"
        )
    return f"""
    <section class="appendix">
        <h2>Appendix: Services <span class="count">{len(services)}</span></h2>
        <table class="data-table">
            <thead><tr>
                <th>Host:Port</th><th>Proto</th><th>Service</th>
                <th>Version</th><th>Banner</th>
            </tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </section>
    """


def _render_credentials_table(creds: list) -> str:
    if not creds:
        return ""
    rows = []
    for c in creds:
        rows.append(
            f"<tr>"
            f"<td class='dim'>{_e(c.get('ts','')[:19])}</td>"
            f"<td>{_e(c.get('target'))}</td>"
            f"<td><code>{_e(c.get('username'))}</code></td>"
            f"<td><code class='secret'>{_e(c.get('password'))}</code></td>"
            f"<td class='dim mono'>{_e(c.get('hash'))}</td>"
            f"<td>{_e(c.get('source'))}</td>"
            f"</tr>"
        )
    return f"""
    <section class="appendix">
        <h2>Appendix: Credentials <span class="count">{len(creds)}</span></h2>
        <table class="data-table">
            <thead><tr>
                <th>Found</th><th>Target</th><th>Username</th>
                <th>Password</th><th>Hash</th><th>Source</th>
            </tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </section>
    """


def _render_artifacts_table(artifacts: list) -> str:
    if not artifacts:
        return ""
    rows = []
    for a in artifacts:
        rows.append(
            f"<tr>"
            f"<td class='dim'>{_e(a.get('ts','')[:19])}</td>"
            f"<td>{_e(a.get('kind'))}</td>"
            f"<td class='mono'>{_e(a.get('path'))}</td>"
            f"<td class='dim'>{_e(a.get('size'))}</td>"
            f"<td class='dim mono'>{_e(_short(a.get('sha256'), 16))}…</td>"
            f"<td>{_e(a.get('notes'))}</td>"
            f"</tr>"
        )
    return f"""
    <section class="appendix">
        <h2>Appendix: Artifacts <span class="count">{len(artifacts)}</span></h2>
        <table class="data-table">
            <thead><tr>
                <th>Captured</th><th>Kind</th><th>Path</th>
                <th>Size</th><th>SHA256</th><th>Notes</th>
            </tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </section>
    """


# ---------------------------------------------------------------------
# CSS + JS (inline)
# ---------------------------------------------------------------------

_CSS = """
* { box-sizing: border-box; }
body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0b0f19; color: #e2e8f0; margin: 0; padding: 0;
    line-height: 1.5;
}
.wrap { max-width: 1400px; margin: 0 auto; padding: 30px; }

/* Header */
header.report-head {
    background: linear-gradient(135deg, #1e293b, #0f172a);
    border: 1px solid #334155; border-radius: 12px;
    padding: 30px; margin-bottom: 30px;
}
header.report-head h1 {
    margin: 0 0 10px 0; color: #38bdf8; font-size: 2.1em;
    letter-spacing: -0.5px;
}
header.report-head .head-meta {
    color: #94a3b8; font-size: 0.95em;
}
header.report-head .head-meta span { margin-right: 20px; }
header.report-head .head-meta strong { color: #cbd5e1; }

/* Summary */
section.summary {
    background: #1e293b; border: 1px solid #334155;
    border-radius: 12px; padding: 25px; margin-bottom: 30px;
}
section h2 {
    margin: 0 0 15px 0; font-size: 1.4em; color: #f1f5f9;
    display: flex; align-items: center; gap: 12px;
}
section h3 {
    margin: 25px 0 10px 0; font-size: 1.05em; color: #94a3b8;
    text-transform: uppercase; letter-spacing: 1px;
}
.stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
}
.stat {
    background: #0f172a; padding: 18px 12px; border-radius: 8px;
    text-align: center; border: 1px solid #334155;
}
.stat.sev-critical { border-color: #dc2626; background: #450a0a; }
.stat.sev-high     { border-color: #ea580c; background: #431407; }
.stat.sev-medium   { border-color: #eab308; background: #422006; }
.stat.sev-low      { border-color: #0284c7; background: #082f49; }
.stat.sev-info     { border-color: #64748b; }
.stat-num {
    font-size: 2.2em; font-weight: 700; color: #f1f5f9;
    font-family: monospace;
}
.stat-lab {
    color: #94a3b8; font-size: 0.82em; text-transform: uppercase;
    letter-spacing: 1px; margin-top: 4px;
}
.chip-row { display: flex; flex-wrap: wrap; gap: 8px; }
.chip {
    background: #0f172a; border: 1px solid #334155;
    padding: 5px 12px; border-radius: 999px; font-size: 0.9em;
    color: #cbd5e1; font-family: monospace;
}
.chip-n {
    background: #1e293b; padding: 1px 8px; border-radius: 999px;
    margin-left: 6px; font-weight: 700;
}
.asset-grid { display: flex; flex-wrap: wrap; gap: 20px; }
.asset {
    display: flex; align-items: baseline; gap: 8px;
    color: #94a3b8;
}
.asset-n { color: #f1f5f9; font-size: 1.4em; font-weight: 700;
           font-family: monospace; }
.asset-l { font-size: 0.9em; text-transform: lowercase; }

/* Filter bar */
.filter-bar {
    position: sticky; top: 0; z-index: 10;
    background: #0b0f19; padding: 15px 0;
    border-bottom: 1px solid #334155; margin-bottom: 20px;
    display: flex; gap: 12px; flex-wrap: wrap;
    align-items: center;
}
.filter-bar input, .filter-bar select {
    background: #1e293b; border: 1px solid #334155;
    color: #e2e8f0; padding: 8px 14px; border-radius: 6px;
    font-size: 0.95em; font-family: inherit;
}
.filter-bar input { flex: 1; min-width: 250px; }
.filter-bar input:focus, .filter-bar select:focus {
    outline: none; border-color: #38bdf8;
}
.filter-bar .pill-count {
    color: #94a3b8; font-size: 0.9em; font-family: monospace;
}

/* Severity sections */
.severity-section { margin-bottom: 30px; }
.sev-header {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 18px; border-radius: 8px; cursor: pointer;
    user-select: none; border: 1px solid #334155;
}
.sev-h-critical { background: #450a0a; border-color: #dc2626; }
.sev-h-high     { background: #431407; border-color: #ea580c; }
.sev-h-medium   { background: #422006; border-color: #eab308; }
.sev-h-low      { background: #082f49; border-color: #0284c7; }
.sev-h-info     { background: #1e293b; border-color: #64748b; }
.sev-header .toggle {
    background: none; border: none; color: #cbd5e1;
    font-size: 1.2em; cursor: pointer; padding: 0 6px;
    font-family: inherit;
}
.sev-header .chev {
    display: inline-block; transition: transform 0.15s;
}
.sev-header.collapsed .chev { transform: rotate(-90deg); }
.sev-header .count {
    background: #0f172a; padding: 2px 10px; border-radius: 999px;
    font-size: 0.8em; color: #94a3b8; font-family: monospace;
    margin-left: auto;
}

/* Cards */
.card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(440px, 1fr));
    gap: 16px; margin-top: 15px;
}
.card {
    background: #1e293b; border: 1px solid #334155;
    border-left-width: 4px; border-radius: 8px; padding: 18px;
    transition: border-color 0.15s;
}
.card:hover { border-color: #38bdf8; }
.card.sev-critical { border-left-color: #dc2626; }
.card.sev-high     { border-left-color: #ea580c; }
.card.sev-medium   { border-left-color: #eab308; }
.card.sev-low      { border-left-color: #0284c7; }
.card.sev-info     { border-left-color: #64748b; }
.card-header {
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 12px; padding-bottom: 10px;
    border-bottom: 1px solid #334155;
}
.pill {
    font-size: 0.72em; padding: 3px 10px; border-radius: 4px;
    font-weight: 700; letter-spacing: 0.5px; font-family: monospace;
}
.pill-critical { background: #dc2626; color: white; }
.pill-high     { background: #ea580c; color: white; }
.pill-medium   { background: #eab308; color: #1e293b; }
.pill-low      { background: #0284c7; color: white; }
.pill-info     { background: #64748b; color: white; }
.card-title {
    flex: 1; font-weight: 600; color: #f1f5f9;
    font-family: monospace; font-size: 0.95em;
}
.anchor {
    color: #475569; text-decoration: none; font-size: 0.85em;
    font-family: monospace;
}
.anchor:hover { color: #38bdf8; }

.meta-row { font-size: 0.9em; margin-bottom: 6px; }
.meta-k {
    color: #94a3b8; font-weight: 600; margin-right: 6px;
    text-transform: lowercase; letter-spacing: 0.3px;
}
.meta-v { color: #cbd5e1; }
.meta-v code { background: #0f172a; padding: 1px 6px; border-radius: 3px;
               color: #38bdf8; font-size: 0.9em; }

.block { margin-top: 12px; }
.block-title {
    color: #94a3b8; font-size: 0.78em; text-transform: uppercase;
    letter-spacing: 1px; margin-bottom: 6px; font-weight: 700;
}
.block-title .dim { text-transform: none; letter-spacing: 0;
                    font-weight: 400; }
.code, .evidence {
    background: #0f172a; border: 1px solid #1e293b; padding: 10px;
    border-radius: 6px; font-family: 'Consolas', 'Monaco', monospace;
    font-size: 0.85em; color: #cbd5e1; overflow-x: auto;
    white-space: pre-wrap; word-break: break-word;
    max-height: 250px; overflow-y: auto;
}
.evidence { color: #94a3b8; font-style: italic; }

.shot {
    max-width: 100%; border-radius: 6px; border: 1px solid #334155;
    margin-top: 6px;
}

/* Appendix tables */
section.appendix {
    margin-top: 40px;
}
.data-table {
    width: 100%; border-collapse: collapse;
    background: #1e293b; border-radius: 8px; overflow: hidden;
    border: 1px solid #334155; font-size: 0.88em;
}
.data-table th {
    background: #0f172a; color: #94a3b8; text-align: left;
    padding: 10px 12px; font-weight: 600; font-size: 0.82em;
    text-transform: uppercase; letter-spacing: 0.5px;
    border-bottom: 1px solid #334155;
}
.data-table td {
    padding: 8px 12px; border-bottom: 1px solid #0f172a;
    color: #cbd5e1; vertical-align: top;
}
.data-table tr:last-child td { border-bottom: none; }
.data-table tr:hover td { background: #0f172a; }
.data-table code {
    background: #0f172a; padding: 1px 6px; border-radius: 3px;
    font-size: 0.92em;
}
.data-table .secret { color: #fca5a5; }

.dim { color: #64748b; }
.mono { font-family: 'Consolas', 'Monaco', monospace; }

.hidden { display: none !important; }

footer {
    text-align: center; color: #475569; font-size: 0.85em;
    margin-top: 40px; padding-top: 20px;
    border-top: 1px solid #334155;
}
"""

_JS = """
// Module filter
const moduleFilter = document.getElementById('module-filter');
const searchInput = document.getElementById('search-input');
const countEl = document.getElementById('visible-count');
const allCards = () => document.querySelectorAll('.card');

function applyFilters() {
    const mod = moduleFilter.value;
    const q = searchInput.value.toLowerCase().trim();
    let visible = 0;
    allCards().forEach(card => {
        const matchesMod = !mod || card.dataset.module === mod;
        const text = card.textContent.toLowerCase();
        const matchesSearch = !q || text.includes(q);
        const show = matchesMod && matchesSearch;
        card.classList.toggle('hidden', !show);
        if (show) visible++;
    });
    // Hide severity sections that have no visible cards
    document.querySelectorAll('.severity-section').forEach(sec => {
        const anyVisible = sec.querySelectorAll('.card:not(.hidden)').length > 0;
        sec.classList.toggle('hidden', !anyVisible);
    });
    countEl.textContent = `${visible} / ${allCards().length}`;
}

if (moduleFilter) moduleFilter.addEventListener('change', applyFilters);
if (searchInput)  searchInput.addEventListener('input', applyFilters);

// Collapsible severity headers
document.querySelectorAll('.sev-header').forEach(h => {
    h.addEventListener('click', (e) => {
        if (e.target.tagName === 'BUTTON') return;
        const btn = h.querySelector('.toggle');
        const target = document.getElementById(btn.dataset.target);
        if (target) {
            target.classList.toggle('hidden');
            h.classList.toggle('collapsed');
        }
    });
});
document.querySelectorAll('.sev-header .toggle').forEach(b => {
    b.addEventListener('click', (e) => {
        e.stopPropagation();
        const h = b.closest('.sev-header');
        const target = document.getElementById(b.dataset.target);
        if (target) {
            target.classList.toggle('hidden');
            h.classList.toggle('collapsed');
        }
    });
});

// Keyboard shortcut: / focuses search
document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
        e.preventDefault();
        searchInput.focus();
    }
});

applyFilters();
"""


# ---------------------------------------------------------------------
# Top-level generator
# ---------------------------------------------------------------------

def generate(store, output_path, workspace=None, embed_images: bool = False,
             title: str = "Security Assessment Report") -> Path:
    """Produce the unified HTML report.

    Args:
        store:          core.store.Store instance (or db path string)
        output_path:    path to write the HTML file to
        workspace:      optional core.workspace.Workspace, used for
                        metadata and to resolve relative image paths
        embed_images:   if True, base64-inline every referenced image
        title:          report title shown at the top

    Returns the output path.
    """
    from core.store import Store

    if not hasattr(store, "query_findings"):
        store = Store.open(store)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    findings = store.query_findings()
    hosts = store.query_hosts()
    services = store.query_services()
    credentials = store.query_credentials()
    artifacts = store.query_artifacts()

    # Attach severity justification if the finding has it stored
    for f in findings:
        data = f.get("data") or {}
        if isinstance(data, dict):
            if "severity_justification" in data:
                f["severity_justification"] = data["severity_justification"]
            if "severity_score" in data:
                f["severity_score"] = data["severity_score"]
            if "severity" in data and not f.get("severity"):
                f["severity"] = data["severity"]

    grouped = _group_findings(findings)

    # Workspace metadata (optional)
    ws_name = ws_operator = ""
    ws_scope = []
    ws_created = ""
    if workspace is not None:
        m = workspace.meta
        ws_name = m.name
        ws_operator = m.operator
        ws_created = m.created_at
        ws_scope = m.target_scope or []

    base_path = workspace.path if workspace is not None else None

    # Modules list for the filter dropdown
    modules = sorted({(f.get("module") or "unknown") for f in findings})
    module_options = "".join(
        f'<option value="{_e(m)}">{_e(m)}</option>' for m in modules
    )

    # Severity sections (in priority order)
    sev_sections = "".join(
        _render_findings_section(s, grouped.get(s, []),
                                 embed_images=embed_images,
                                 base_path=base_path)
        for s in SEVERITY_ORDER
    )

    header_meta = []
    if ws_name:
        header_meta.append(f"<span><strong>Engagement:</strong> "
                           f"{_e(ws_name)}</span>")
    if ws_operator:
        header_meta.append(f"<span><strong>Operator:</strong> "
                           f"{_e(ws_operator)}</span>")
    if ws_scope:
        header_meta.append(f"<span><strong>Scope:</strong> "
                           f"{_e(', '.join(ws_scope))}</span>")
    header_meta.append(f"<span><strong>Generated:</strong> {_e(_ts())}</span>")
    if ws_created:
        header_meta.append(f"<span><strong>Workspace created:</strong> "
                           f"{_e(ws_created[:19])}</span>")

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">

<header class="report-head">
    <h1>{_e(title)}</h1>
    <div class="head-meta">{''.join(header_meta)}</div>
</header>

{_render_summary(store, findings)}

<div class="filter-bar">
    <input id="search-input" type="text"
           placeholder="Search findings…  (press / to focus)">
    <select id="module-filter">
        <option value="">All modules</option>
        {module_options}
    </select>
    <span class="pill-count">
        <span id="visible-count"></span> visible
    </span>
</div>

{sev_sections}

{_render_hosts_table(hosts)}
{_render_services_table(services)}
{_render_credentials_table(credentials)}
{_render_artifacts_table(artifacts)}

<footer>
    Generated by toolkit &middot; {_e(_ts())}
</footer>

</div>
<script>{_JS}</script>
</body>
</html>
"""

    output_path.write_text(doc, encoding="utf-8")
    size_kb = output_path.stat().st_size / 1024
    success(f"report written to {output_path} ({size_kb:.1f} KB, "
            f"{len(findings)} finding(s))")
    return output_path


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="report.unified",
        description="Generate a unified HTML report from a workspace.",
    )
    p.add_argument("--workspace", "-w", default=None,
                   help="workspace name (defaults to active)")
    p.add_argument("--output", "-o", default=None,
                   help="output path (default: <workspace>/report/report.html)")
    p.add_argument("--embed-images", action="store_true",
                   help="base64-inline every referenced image")
    p.add_argument("--title", default="Security Assessment Report")
    args = p.parse_args()

    from core.workspace import get_active, get_workspace, list_workspaces
    from core.store import open_store

    name = args.workspace or get_active()
    if not name:
        if list_workspaces():
            warn("no workspace specified and no active workspace; "
                 "use --workspace <name> or `toolkit workspace switch`")
        else:
            warn("no workspaces found; create one with "
                 "`toolkit workspace new <name>`")
        return

    try:
        ws = get_workspace(name)
    except FileNotFoundError as e:
        error(str(e))
        return

    store = open_store(ws.db_path, workspace_name=name)

    output = Path(args.output) if args.output else (
        ws.report_dir / "report.html")
    output.parent.mkdir(parents=True, exist_ok=True)

    info(f"generating report for workspace '{name}' -> {output}")
    generate(store, output, workspace=ws, embed_images=args.embed_images,
             title=args.title)


if __name__ == "__main__":
    _cli()