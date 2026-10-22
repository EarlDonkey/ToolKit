"""
Output exporters for network scan results: CSV, JSON, and HTML.

The HTML uses the same dark-mode dashboard style as nm+.py for
consistency.
"""

import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from core.output import success


def export_json(inventory, path, extra=None):
    """Write a JSON report."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inventory": inventory,
    }
    if extra:
        report.update(extra)
    Path(path).write_text(json.dumps(report, indent=2, default=str),
                          encoding="utf-8")
    success(f"JSON report saved to {path}")


def export_csv(inventory, path):
    """Write a flat CSV of every discovered host + service."""
    rows = []
    for ip, host in inventory.items():
        services = host.get("services") or []
        if not services:
            rows.append({
                "ip": ip,
                "mac": host.get("mac", ""),
                "hostname": host.get("hostname", ""),
                "discovery": host.get("discovery", ""),
                "os_guess": host.get("os_guess", ""),
                "port": "",
                "service": "",
                "version": "",
            })
            continue
        for svc in services:
            rows.append({
                "ip": ip,
                "mac": host.get("mac", ""),
                "hostname": host.get("hostname", ""),
                "discovery": host.get("discovery", ""),
                "os_guess": host.get("os_guess", ""),
                "port": svc.get("port", ""),
                "service": svc.get("service", ""),
                "version": svc.get("version", ""),
            })

    fields = ["ip", "mac", "hostname", "discovery", "os_guess",
              "port", "service", "version"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    success(f"CSV report saved to {path} ({len(rows)} rows)")


def export_html(inventory, path, title="Network Reconnaissance Report"):
    """Dark-mode HTML dashboard."""
    cards = ""
    for ip, host in sorted(inventory.items()):
        services = host.get("services") or []
        svc_html = ""
        for svc in services:
            version = html.escape(svc.get("version", "") or "")
            label = f"{svc.get('port')}/{svc.get('service', '?')}"
            if version:
                label += f" — {version}"
            svc_html += f'<span class="badge port">{html.escape(label)}</span>'
        if not svc_html:
            svc_html = '<span class="badge none">no open ports</span>'

        cves = host.get("cves") or []
        cve_html = ""
        for cve in cves:
            cve_html += (f'<div class="cve">'
                         f'<strong>[{html.escape(cve.get("severity", "?"))}]</strong> '
                         f'{html.escape(cve.get("id", ""))} — '
                         f'{html.escape(cve.get("summary", ""))}'
                         f'</div>')
        if not cve_html:
            cve_html = '<span class="badge none">no CVEs matched</span>'

        cards += f"""
        <div class="node-card">
            <div class="card-header">
                <span class="status-indicator"></span>
                <span class="ip-addr">{html.escape(ip)}</span>
            </div>
            <div class="metadata"><strong>MAC:</strong> <span class="mono">{html.escape(str(host.get('mac', '')))}</span></div>
            <div class="metadata"><strong>Hostname:</strong> {html.escape(str(host.get('hostname', '')))}</div>
            <div class="metadata"><strong>Discovery:</strong> {html.escape(str(host.get('discovery', '')))}</div>
            <div class="metadata"><strong>OS guess:</strong> {html.escape(str(host.get('os_guess', '')))}</div>
            <div class="systems-title">Services:</div>
            <div class="badge-container">{svc_html}</div>
            <div class="systems-title">CVE Matches:</div>
            <div class="cve-container">{cve_html}</div>
        </div>
        """

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 30px; }}
  header {{ background: linear-gradient(135deg, #1e293b, #0f172a); padding: 25px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #334155; }}
  h1 {{ margin: 0; color: #38bdf8; font-size: 2em; }}
  .summary {{ color: #94a3b8; font-size: 0.95em; margin-top: 8px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 25px; }}
  .node-card {{ background-color: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; }}
  .node-card:hover {{ border-color: #38bdf8; }}
  .card-header {{ display: flex; align-items: center; margin-bottom: 15px; border-bottom: 1px solid #334155; padding-bottom: 10px; }}
  .status-indicator {{ width: 12px; height: 12px; background-color: #10b981; border-radius: 50%; margin-right: 12px; box-shadow: 0 0 8px #10b981; }}
  .ip-addr {{ font-size: 1.3em; font-weight: 700; color: #fff; font-family: monospace; }}
  .metadata {{ font-size: 0.9em; margin-bottom: 6px; color: #cbd5e1; }}
  .mono {{ font-family: monospace; color: #94a3b8; }}
  .systems-title {{ font-size: 0.85em; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #94a3b8; margin: 15px 0 8px 0; }}
  .badge-container {{ display: flex; flex-wrap: wrap; gap: 6px; }}
  .badge {{ font-size: 0.78em; padding: 4px 8px; border-radius: 4px; font-weight: 600; font-family: monospace; }}
  .badge.port {{ background-color: #0369a1; color: #e0f2fe; border: 1px solid #0284c7; }}
  .badge.none {{ background-color: #1e293b; color: #64748b; border: 1px solid #475569; }}
  .cve-container {{ display: flex; flex-direction: column; gap: 6px; }}
  .cve {{ background-color: #450a0a; border: 1px solid #991b1b; padding: 6px 8px; border-radius: 4px; font-size: 0.82em; }}
</style>
</head>
<body>
  <header>
    <h1>{html.escape(title)}</h1>
    <div class="summary">
      Generated {datetime.now(timezone.utc).isoformat()} &nbsp;|&nbsp;
      Hosts: {len(inventory)} &nbsp;|&nbsp;
      Open ports: {sum(len(h.get('services') or []) for h in inventory.values())} &nbsp;|&nbsp;
      CVE matches: {sum(len(h.get('cves') or []) for h in inventory.values())}
    </div>
  </header>
  <div class="grid">{cards}</div>
</body>
</html>
"""
    Path(path).write_text(doc, encoding="utf-8")
    success(f"HTML report saved to {path}")