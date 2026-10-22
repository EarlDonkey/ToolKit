"""
Markdown report generator.

Same data as report.unified, different format. Produces a single
Markdown file suitable for pasting into Notion, Obsidian, Confluence,
Jira, GitHub issues, or a plain-text email.

Why both formats exist:

  HTML is for delivery  — self-contained, styled, offline-openable.
  Markdown is for review — diffable, works with git, pastes cleanly
                          into ticket systems and wikis.

Structure mirrors report.unified:

    # Title
    metadata block
    ## Executive Summary
    ## Findings by severity (critical → info)
    ## Appendix: Hosts
    ## Appendix: Services
    ## Appendix: Credentials
    ## Appendix: Artifacts

Features:

  - Emoji severity markers so it reads at a glance.
  - Table cells escape '|' so payloads with pipes don't break tables.
  - Payload and evidence wrapped in fenced code blocks.
  - Numbered findings within each severity section, so you can say
    "see High finding #2" in a ticket.

Usage:

    from report.markdown import generate
    generate(store, output_path, workspace=ws)

    # CLI:
    python -m report.markdown --workspace acme-corp
    python -m report.markdown -w acme-corp -o report.md
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from core.output import info, success, warn, error


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}
SEVERITY_LABEL = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Informational",
}


# ---------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------

def _md_escape(value) -> str:
    """Escape a value for inclusion in Markdown table cells and text.

    We escape:
      |  → \\|   (breaks tables)
      \\  → \\\\  (would otherwise consume the next char in some contexts)
      newline → space (single-line cells)
    """
    if value is None:
        return ""
    s = str(value)
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    s = s.replace("\r", "").replace("\n", " ")
    return s


def _fence(value, lang="text") -> str:
    """Wrap a value in a fenced code block, escaping embedded fences."""
    if value is None:
        return ""
    s = str(value)
    # If the content contains ``` we switch to a longer fence
    if "```" in s:
        fence = "````"
    else:
        fence = "```"
    return f"{fence}{lang}\n{s}\n{fence}"


def _ts_short(v) -> str:
    """Trim an ISO timestamp to 19 chars: '2026-09-23T12:34:56'."""
    if not v:
        return ""
    s = str(v)
    return s[:19] if len(s) >= 19 else s


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------
# Grouping (same logic as unified)
# ---------------------------------------------------------------------

def _rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index((sev or "info").lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def _group_findings(findings: list) -> dict:
    out = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev not in out:
            out[sev] = []
        out[sev].append(f)
    # Sort within each bucket by module, then target, then port
    for s in out:
        out[s].sort(key=lambda x: (
            x.get("module") or "",
            x.get("target") or "",
            x.get("port") or 0,
        ))
    return out


# ---------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------

def _render_header(title: str, workspace) -> str:
    lines = [f"# {title}", ""]
    if workspace is not None:
        m = workspace.meta
        if m.name:
            lines.append(f"**Engagement:** {_md_escape(m.name)}  ")
        if m.operator:
            lines.append(f"**Operator:** {_md_escape(m.operator)}  ")
        if m.target_scope:
            scope = ", ".join(m.target_scope)
            lines.append(f"**Scope:** `{_md_escape(scope)}`  ")
        if m.created_at:
            lines.append(f"**Workspace created:** {_ts_short(m.created_at)}  ")
    lines.append(f"**Generated:** {_now()}  ")
    lines.append("")
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _render_summary(store, findings: list) -> str:
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    mod_counts = {}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        if s not in sev_counts:
            sev_counts[s] = 0
        sev_counts[s] += 1
        m = f.get("module") or "unknown"
        mod_counts[m] = mod_counts.get(m, 0) + 1

    summary = store.summary() if store else {}

    lines = ["## Executive Summary", ""]
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for s in SEVERITY_ORDER:
        icon = SEVERITY_ICON[s]
        label = SEVERITY_LABEL[s]
        count = sev_counts.get(s, 0)
        lines.append(f"| {icon} {label} | {count} |")
    lines.append("")

    if summary:
        lines.append(
            f"**Assets:** "
            f"{summary.get('hosts', 0)} hosts, "
            f"{summary.get('services', 0)} services, "
            f"{summary.get('credentials', 0)} credentials, "
            f"{summary.get('artifacts', 0)} artifacts"
        )
        lines.append("")

    if mod_counts:
        mods = ", ".join(
            f"`{_md_escape(m)}` ({c})"
            for m, c in sorted(mod_counts.items(), key=lambda x: -x[1])
        )
        lines.append(f"**Findings by module:** {mods}")
        lines.append("")

    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _render_finding(f: dict, index: int, section_label: str) -> str:
    """Render one finding as a Markdown subsection."""
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

    # Heading: numbered within the severity section
    heading = f"### {index}. `{_md_escape(module)}` / `{_md_escape(ftype)}`"
    if target:
        target_disp = f"{target}:{port}" if port else target
        heading += f" — `{_md_escape(target_disp)}`"

    lines = [heading, ""]

    # Metadata bullets
    if target:
        tgt = f"`{target}:{port}`" if port else f"`{target}`"
        lines.append(f"- **Target:** {tgt}")
    if param:
        lines.append(f"- **Parameter:** `{_md_escape(param)}`")
    if ts:
        lines.append(f"- **Found:** `{_ts_short(ts)}`")
    if justification and score is not None:
        lines.append(
            f"- **Severity basis:** {_md_escape(justification)} "
            f"*(score {_md_escape(score)})*"
        )
    lines.append(f"- **Store ID:** `{_md_escape(fid)}`")
    lines.append("")

    # Payload block
    if payload:
        lines.append("**Payload:**")
        lines.append("")
        lines.append(_fence(payload, "text"))
        lines.append("")

    # Evidence block — blockquote
    if evidence:
        lines.append("**Evidence:**")
        lines.append("")
        # Split long evidence into lines, prefix each with '> '
        for line in str(evidence).splitlines() or [""]:
            lines.append(f"> {_md_escape(line)}")
        lines.append("")

    # Extracted data block
    data = f.get("data")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {"raw": data}
    if isinstance(data, dict) and data:
        skip = {"screenshot_path", "image_path"}
        keys = [k for k in data.keys() if k not in skip]
        if keys:
            lines.append("**Extracted data:**")
            lines.append("")
            for k in keys:
                v = data[k]
                if isinstance(v, list):
                    if len(v) > 8:
                        preview = ", ".join(_md_escape(x) for x in v[:8])
                        lines.append(f"- `{_md_escape(k)}`: {len(v)} item(s) "
                                     f"— {preview}, …")
                    else:
                        preview = ", ".join(_md_escape(x) for x in v)
                        lines.append(f"- `{_md_escape(k)}`: {preview}")
                elif isinstance(v, dict):
                    pretty = json.dumps(v, indent=2, default=str)
                    lines.append(f"- `{_md_escape(k)}`:")
                    lines.append("")
                    lines.append(_fence(pretty, "json"))
                    lines.append("")
                else:
                    lines.append(f"- `{_md_escape(k)}`: {_md_escape(v)}")
            lines.append("")

    # Optional screenshot reference (path only — Markdown reports
    # reference images by relative path so they can be rendered if
    # the images are shipped alongside)
    if isinstance(data, dict):
        img = data.get("screenshot_path") or data.get("image_path")
        if img:
            lines.append(f"**Screenshot:** `{_md_escape(img)}`")
            lines.append("")

    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _render_severity_section(severity: str, findings: list) -> str:
    if not findings:
        return ""
    icon = SEVERITY_ICON.get(severity, "•")
    label = SEVERITY_LABEL.get(severity, severity.title())
    lines = [f"## {icon} {label} Findings ({len(findings)})", ""]
    for i, f in enumerate(findings, 1):
        lines.append(_render_finding(f, i, label))
    return "\n".join(lines)


def _render_hosts_table(hosts: list) -> str:
    if not hosts:
        return ""
    lines = [f"## Appendix: Hosts ({len(hosts)})", ""]
    lines.append("| IP | MAC | Hostname | Vendor | OS guess | Discovery | First seen |")
    lines.append("|----|-----|----------|--------|----------|-----------|------------|")
    for h in hosts:
        tags = h.get("tags") or []
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except Exception:
                tags = []
        vendor = next((str(t)[7:] for t in tags
                       if str(t).startswith("vendor:")), "")
        lines.append(
            f"| `{_md_escape(h.get('ip'))}` "
            f"| `{_md_escape(h.get('mac'))}` "
            f"| {_md_escape(h.get('hostname'))} "
            f"| {_md_escape(vendor)} "
            f"| {_md_escape(h.get('os_guess'))} "
            f"| {_md_escape(h.get('discovery'))} "
            f"| {_ts_short(h.get('first_seen'))} |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _render_services_table(services: list) -> str:
    if not services:
        return ""
    lines = [f"## Appendix: Services ({len(services)})", ""]
    lines.append("| Host:Port | Proto | Service | Version | Banner |")
    lines.append("|-----------|-------|---------|---------|--------|")
    for s in services:
        banner = s.get("banner") or ""
        if len(str(banner)) > 100:
            banner = str(banner)[:99] + "…"
        lines.append(
            f"| `{_md_escape(s.get('host_ip'))}:{_md_escape(s.get('port'))}` "
            f"| {_md_escape(s.get('proto'))} "
            f"| {_md_escape(s.get('service'))} "
            f"| {_md_escape(s.get('version'))} "
            f"| {_md_escape(banner)} |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _render_credentials_table(creds: list) -> str:
    if not creds:
        return ""
    lines = [f"## Appendix: Credentials ({len(creds)})", ""]
    lines.append("| Found | Target | Username | Password | Source |")
    lines.append("|-------|--------|----------|----------|--------|")
    for c in creds:
        lines.append(
            f"| {_ts_short(c.get('ts'))} "
            f"| {_md_escape(c.get('target'))} "
            f"| `{_md_escape(c.get('username'))}` "
            f"| `{_md_escape(c.get('password'))}` "
            f"| {_md_escape(c.get('source'))} |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _render_artifacts_table(artifacts: list) -> str:
    if not artifacts:
        return ""
    lines = [f"## Appendix: Artifacts ({len(artifacts)})", ""]
    lines.append("| Captured | Kind | Path | Size | Notes |")
    lines.append("|----------|------|------|------|-------|")
    for a in artifacts:
        lines.append(
            f"| {_ts_short(a.get('ts'))} "
            f"| {_md_escape(a.get('kind'))} "
            f"| `{_md_escape(a.get('path'))}` "
            f"| {_md_escape(a.get('size'))} "
            f"| {_md_escape(a.get('notes'))} |"
        )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------
# Top-level generator
# ---------------------------------------------------------------------

def generate(store, output_path, workspace=None,
             title: str = "Security Assessment Report") -> Path:
    """Write a Markdown report.

    Args:
        store:        core.store.Store instance (or db path string)
        output_path:  path to write the .md file to
        workspace:    optional core.workspace.Workspace for metadata
        title:        heading shown at the top
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

    # Attach severity justification from data blob if present
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

    parts = []
    parts.append(_render_header(title, workspace))
    parts.append(_render_summary(store, findings))
    for sev in SEVERITY_ORDER:
        parts.append(_render_severity_section(sev, grouped.get(sev, [])))
    parts.append(_render_hosts_table(hosts))
    parts.append(_render_services_table(services))
    parts.append(_render_credentials_table(credentials))
    parts.append(_render_artifacts_table(artifacts))

    doc = "\n".join(p for p in parts if p)

    # Trim excessive blank lines (3+ in a row → 2)
    while "\n\n\n\n" in doc:
        doc = doc.replace("\n\n\n\n", "\n\n\n")

    output_path.write_text(doc, encoding="utf-8")
    size_kb = output_path.stat().st_size / 1024
    line_count = doc.count("\n") + 1
    success(f"markdown report written to {output_path} "
            f"({size_kb:.1f} KB, {line_count} lines, "
            f"{len(findings)} finding(s))")
    return output_path


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="report.markdown",
        description="Generate a Markdown report from a workspace.",
    )
    p.add_argument("--workspace", "-w", default=None,
                   help="workspace name (defaults to active)")
    p.add_argument("--output", "-o", default=None,
                   help="output path (default: <workspace>/report/report.md)")
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
        ws.report_dir / "report.md")
    output.parent.mkdir(parents=True, exist_ok=True)

    info(f"generating markdown report for workspace '{name}' -> {output}")
    generate(store, output, workspace=ws, title=args.title)


if __name__ == "__main__":
    _cli()