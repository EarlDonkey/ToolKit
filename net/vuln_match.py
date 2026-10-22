"""
CVE correlation from service banners.
"""

import json
import re
from pathlib import Path

from core.output import info, success, warn

try:
    from packaging.version import InvalidVersion, Version
    _HAS_PACKAGING = True
except ImportError:
    _HAS_PACKAGING = False


DB_PATH = Path(__file__).parent / "cve_db.json"


def load_db(path=DB_PATH):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        warn(f"could not load CVE db ({path}): {type(e).__name__}: {e}")
        return {}


SERVICE_ALIASES = {
    "openssh": "openssh", "ssh": "openssh",
    "apache": "apache", "httpd": "apache", "apache2": "apache",
    "nginx": "nginx",
    "mysql": "mysql", "mariadb": "mysql",
    "postgres": "postgres", "postgresql": "postgres",
    "redis": "redis",
    "vsftpd": "vsftpd", "proftpd": "proftpd", "pure-ftpd": "vsftpd",
    "exim": "exim", "sendmail": "exim",
    "iis": "iis", "microsoft-iis": "iis",
}


_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def _clean_version(raw):
    """Extract a clean X.Y[.Z] from a messy banner string.
    Handles: '2.4.52 (Ubuntu)', 'OpenSSH_8.9p1', 'nginx/1.18.0'."""
    if not raw:
        return None
    m = _VERSION_RE.search(str(raw))
    if not m:
        return None
    return ".".join(p for p in m.groups() if p is not None)


def _parse_version(s):
    """Return a comparable tuple, or None on failure."""
    if not s:
        return None
    if _HAS_PACKAGING:
        try:
            return Version(s)
        except InvalidVersion:
            return None
    # Fallback: tuple comparison
    try:
        return tuple(int(x) for x in s.split("."))
    except Exception:
        return None


def _normalize_service(name):
    low = (name or "").lower()
    for alias, key in SERVICE_ALIASES.items():
        if alias in low:
            return key
    return None


def match_service(service_dict, db=None):
    if db is None:
        db = load_db()

    candidates = [
        service_dict.get("service", ""),
        service_dict.get("version", ""),
        service_dict.get("banner", ""),
    ]
    candidates += list(service_dict.get("headers", {}).values()) if \
        service_dict.get("headers") else []

    service_key = None
    for c in candidates:
        key = _normalize_service(c)
        if key and key in db:
            service_key = key
            break

    if service_key is None:
        return []

    raw = service_dict.get("version") or service_dict.get("banner") or ""
    version_str = _clean_version(raw)
    if version_str is None:
        return []

    observed = _parse_version(version_str)
    if observed is None:
        return []

    hits = []
    for entry in db[service_key]:
        threshold = _parse_version(entry.get("before"))
        if threshold is None:
            continue
        try:
            if observed < threshold:
                for cve in entry.get("cves", []):
                    hits.append({
                        "id": cve.get("id"),
                        "severity": cve.get("severity", "unknown"),
                        "summary": cve.get("summary", ""),
                        "affects": f"{service_key} < {entry['before']}",
                        "observed": version_str,
                    })
        except TypeError:
            # Mixing Version and tuple can't happen, but just in case
            continue

    return hits


def scan_services(service_results, db=None):
    if db is None:
        db = load_db()
    findings = {}
    for ip, services in service_results.items():
        ip_hits = []
        for svc in services:
            hits = match_service(svc, db=db)
            for h in hits:
                hit = dict(h)
                hit["port"] = svc.get("port")
                hit["service"] = svc.get("service")
                ip_hits.append(hit)
        if ip_hits:
            findings[ip] = ip_hits
    return findings


async def run(target, ports_arg=None, top=100, verbose=False):
    from net.service_fingerprint import run as fp_run

    services = await fp_run(target, ports_arg=ports_arg, top=top,
                            verbose=verbose)
    if not services:
        warn("nothing to match")
        return {}

    info("matching banners against CVE database")
    findings = scan_services(services)

    print()
    if not findings:
        success("no CVE matches from observed banners")
        return {}

    total = sum(len(v) for v in findings.values())
    warn(f"{total} candidate CVE(s) across {len(findings)} host(s)")
    for ip, hits in sorted(findings.items()):
        print(f"  {ip}:")
        for h in hits:
            print(f"    [{h['severity']}] {h['id']} "
                  f"(port {h['port']}, {h['service']})")
            print(f"        {h['summary']}")

    return findings