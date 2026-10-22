"""
Deep subdomain enumeration.

Combines passive sources, DNS record mining, target-derived wordlist
generation, curated brute force, and permutation extrapolation into
one module. Works on any domain; nothing is hardcoded to a specific
target.

Scope:

  When the input target is a proper subdomain (e.g. tyas.tyc.edu.tw),
  the default scope is that subdomain — the module enumerates only
  hosts under it. When the input is already an apex (example.com),
  the scope is the apex.

  This means `--target tyas.tyc.edu.tw` returns TYAS-only findings,
  not the whole tyc.edu.tw school district. Pass --apex to widen
  the scope deliberately.

Design:

  1. Passive sources (default ON):
       - crt.sh, certspotter (CT logs)
       - AlienVault OTX passive DNS
       - RapidDNS, Anubis, HackerTarget
       - URLScan, Wayback, Common Crawl

  2. DNS record mining (default ON):
       - NS, MX, SPF, DMARC
       - DKIM selectors (common ones)

  3. Target-derived wordlist (part of --brute):
       - Splits the scope into labels
       - Generates mechanical permutations per label
       - Optionally mixes in operator-supplied --aliases
       - Public-suffix aware (strips edu.tw, co.uk, etc.)

  4. Curated wordlist (part of --brute):
       - ~400 high-signal entries embedded in this file

  5. Permutation extrapolation (after brute):
       - If lab3 and lab4 resolve, try lab1..lab99
       - Strips trailing digits and generates a numeric range

  6. Full wordlist (--full-brute):
       - Loads wordlists/subdomains.txt (~3,400 entries)

  7. Resolution + CNAME capture:
       - Each unique candidate resolved once via core.dns
       - CNAME chains recorded for D2 (subdomain takeover detection)

Output structure:

    result["live"]       — resolves to A/AAAA records
    result["historical"] — never resolved in this run, but was
                           reported by a passive source
    result["dangling"]   — CNAME exists, A record doesn't; D2 input
    result["by_source"]  — raw per-source counts
    result["sources"]    — source status (ok / rate_limited / error)

Usage:

    from recon.subdomains_deep import enumerate_subdomains

    result = await enumerate_subdomains("example.com")

    # CLI
    py toolkit.py recon --target example.com --subdeep
    py toolkit.py recon --target tyas.tyc.edu.tw --subdeep --brute -v
    py toolkit.py recon --target tyas.tyc.edu.tw --subdeep --apex
    py toolkit.py recon --target example.com --subdeep --full-brute

Findings written to the store:
    one host record per resolved subdomain; a summary finding with
    the full result.
"""

import asyncio
import json
import re
from pathlib import Path
from urllib.parse import quote, urlparse

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

CURATED_WORDLIST = [
    # --- Admin / control panels ---
    "admin", "administrator", "admin1", "admin2", "adminpanel",
    "manage", "manager", "management", "console", "control",
    "cp", "cpanel", "whm", "plesk", "webmin", "directadmin",
    "panel", "dashboard", "portal", "backend",

    # --- Mail / MX / comms ---
    "mail", "mail1", "mail2", "mail3", "mail4", "mail5",
    "smtp", "smtp1", "smtp2", "smtp-relay", "mx", "mx1", "mx2",
    "imap", "pop", "pop3", "webmail", "roundcube", "squirrelmail",
    "exchange", "owa", "outlook", "autodiscover", "autoconfig",
    "zimbra", "postfix", "mailserver", "mailhost", "mailgate",
    "mta", "mta1", "mailrelay", "mailgw",

    # --- DNS / infrastructure ---
    "ns", "ns0", "ns1", "ns2", "ns3", "ns4", "ns5", "ns6",
    "ns7", "ns8", "ns9", "ns01", "ns02", "ns03",
    "dns", "dns1", "dns2", "dns3", "dns4", "dns5",
    "resolver", "rdns", "pdns",

    # --- Web / frontend ---
    "www", "www1", "www2", "www3", "www4", "www5",
    "web", "web1", "web2", "web3", "web4",
    "static", "static1", "static2", "cdn", "cdn1", "cdn2", "cdn3",
    "assets", "media", "images", "img", "img1", "img2",
    "css", "js", "fonts", "files", "docs", "download",
    "downloads", "uploads", "files",

    # --- API / backend ---
    "api", "api1", "api2", "api3", "api-dev", "api-test", "api-staging",
    "api-prod", "apigw", "apim", "rest", "graphql", "grpc",
    "ws", "websocket", "socket", "gateway", "backend",

    # --- Auth / SSO / identity ---
    "auth", "auth1", "sso", "idp", "login", "signin", "accounts",
    "account", "oauth", "oauth2", "openid", "saml", "cas",
    "keycloak", "ldap", "ldap1", "ldap2", "adfs", "ad",
    "radius", "radius1", "radius2",

    # --- Dev / staging / test ---
    "dev", "dev1", "dev2", "dev3", "development", "devel",
    "staging", "stage", "stg", "test", "test1", "test2", "test3",
    "testing", "qa", "uat", "preprod", "demo", "demo1", "demo2",
    "sandbox", "lab", "lab1", "lab2", "lab3",
    "beta", "alpha", "canary", "edge",
    "new", "old", "legacy", "v1", "v2", "v3",

    # --- Internal / corporate ---
    "internal", "intranet", "intra", "corp", "extranet",
    "private", "partner", "partners", "vendor", "suppliers",
    "directory", "people", "staff", "team", "teams",
    "hr", "hrm", "finance", "sales", "marketing", "support",
    "helpdesk", "help", "kb", "wiki", "docs",
    "service", "services", "it", "itsupport",

    # --- Monitoring / ops ---
    "monitor", "monitoring", "nagios", "zabbix", "grafana",
    "kibana", "prometheus", "graylog", "sentry", "metrics",
    "status", "stats", "analytics", "logs", "log",
    "nms", "netmon", "checkmk", "icinga", "observium",
    "smokeping", "cacti", "munin", "collectd",

    # --- CI / CD / version control ---
    "git", "gitlab", "github", "bitbucket", "gitea", "gogs",
    "svn", "hg", "repo", "repos", "code",
    "jenkins", "ci", "build", "builds", "drone",
    "nexus", "artifactory", "harbor", "registry",

    # --- Databases ---
    "db", "db1", "db2", "mysql", "mysql1", "postgres", "postgresql",
    "mssql", "oracle", "mongodb", "mongo", "redis", "cassandra",
    "elasticsearch", "elastic", "opensearch", "influxdb",
    "sql", "pgsql", "phpmyadmin", "pma", "pgadmin", "adminer",

    # --- File / storage ---
    "storage", "nas", "nfs", "smb", "samba", "cifs",
    "fileshare", "fileserver", "share", "ftp", "sftp", "ftps",
    "s3", "minio", "nextcloud", "owncloud", "seafile",
    "backup", "backups", "backup1", "backup2", "archive",

    # --- Communication ---
    "chat", "chat1", "matrix", "mattermost", "rocket", "rocketchat",
    "slack", "jabber", "xmpp", "irc",
    "meet", "meeting", "conference", "zoom", "webex", "jitsi",

    # --- VPN / remote access ---
    "vpn", "vpn1", "vpn2", "vpn3", "openvpn", "wireguard", "wg",
    "pptp", "l2tp", "ipsec", "sslvpn", "remote", "rdp",
    "gateway", "gate", "ras", "bastion", "jump",

    # --- Mobile / apps ---
    "mobile", "m", "apps", "app", "app1", "app2", "ios", "android",

    # --- Search / catalog ---
    "search", "solr", "elastic", "catalog", "catalogue",
    "opac", "library", "lib", "bib", "repository", "dspace",

    # --- Misc / catch-all ---
    "assets1", "assets2", "content", "cms", "wp", "wordpress",
    "shop", "store", "ecommerce", "payment", "pay", "billing",
    "news", "blog", "blogs", "forum", "forums", "community",
    "events", "campus", "school", "students", "student",
    "staff", "faculty", "alumni", "giving", "donate",

    # --- Bare / infra names ---
    "cloud", "aws", "gcp", "azure", "do", "vps", "server",
    "server1", "server2", "host", "host1", "host2", "node",
    "node1", "node2", "cluster", "k8s", "kube",
    "docker", "container", "vm", "vm1", "vm2", "esxi",
    "proxmox", "pve", "xen", "hyperv", "vcenter",
]


FULL_WORDLIST_PATH = Path("wordlists") / "subdomains.txt"


DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "k2", "mail", "dkim", "s1", "s2",
    "mandrill", "sendgrid", "amazonses", "mta",
]


RETRY_PROFILES = {
    "fast":       {"retries": 2, "backoff": [2.0, 4.0]},
    "moderate":   {"retries": 3, "backoff": [3.0, 6.0, 12.0]},
    "aggressive": {"retries": 3, "backoff": [5.0, 15.0, 30.0]},
}
DEFAULT_RETRY_PROFILE = "fast"
RETRYABLE_STATUS = {429, 503, 504, 502, 500, 520, 521, 522}
RATE_LIMIT_STATUS = {429}


PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "edu.tw", "com.tw", "org.tw", "net.tw", "gov.tw", "idv.tw",
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "re.kr",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in",
    "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk", "idv.hk",
    "com.sg", "org.sg", "net.sg", "edu.sg", "gov.sg",
    "com.mx", "org.mx", "net.mx", "edu.mx", "gob.mx",
    "co.za", "org.za", "net.za", "gov.za", "ac.za",
    "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr",
    "co.il", "org.il", "net.il", "gov.il", "ac.il",
}


_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24})\b",
    re.IGNORECASE,
)
_TRAILING_DIGITS_RE = re.compile(r"^(.*?)(\d+)$")


# ---------------------------------------------------------------------
# Retry helper
# ---------------------------------------------------------------------

async def _fetch_with_retry(session, url, limiter, profile="fast",
                              timeout=30.0, headers=None,
                              verbose=False, label="fetch"):
    """Fetch with retries on rate-limit and 5xx. Returns
    (status, body, error_kind)."""
    prof = RETRY_PROFILES.get(profile, RETRY_PROFILES[DEFAULT_RETRY_PROFILE])
    backoffs = prof["backoff"]
    attempts = prof["retries"] + 1

    last_status = None
    last_kind = None
    for attempt in range(attempts):
        try:
            status, _h, body, _ = await fetch(
                session, url, limiter, timeout=timeout, quiet=True,
                headers=headers)
        except Exception as e:
            if verbose:
                warn(f"  {label}: attempt {attempt + 1} raised "
                     f"{type(e).__name__}")
            status, body = None, None

        if status is not None and status not in RETRYABLE_STATUS:
            return status, body, None

        last_status = status
        if status in RATE_LIMIT_STATUS:
            last_kind = "rate_limited"
        elif status is not None and 500 <= status < 600:
            last_kind = "timeout"
        else:
            last_kind = "error"

        if attempt >= attempts - 1:
            break
        wait = backoffs[attempt] if attempt < len(backoffs) else backoffs[-1]
        if verbose:
            warn(f"  {label}: attempt {attempt + 1} status={status}, "
                 f"retrying in {wait}s")
        await asyncio.sleep(wait)

    return last_status, None, last_kind


# ---------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------

def _normalize_input(target):
    """Turn any target form into (host, apex_domain)."""
    if target.startswith(("http://", "https://")):
        target = target.split("://", 1)[1]
    host = target.split("/")[0].split(":")[0].lower().strip(".")
    if not host:
        return "", ""

    labels = host.split(".")
    if len(labels) < 2:
        return host, host

    tail2 = ".".join(labels[-2:])
    if tail2 in PUBLIC_SUFFIXES and len(labels) >= 3:
        apex = ".".join(labels[-3:])
    else:
        apex = tail2
    return host, apex


def _compute_scope(host, apex, force_apex=False):
    """Return the scope string for source queries and brute.

    Default: scope is the input host if it's a proper subdomain of
    the apex (tyas.tyc.edu.tw), otherwise the apex itself (tyc.edu.tw).

    force_apex=True: always use the apex.
    """
    if force_apex:
        return apex
    if host and apex and host != apex and host.endswith("." + apex):
        return host
    return apex


def _apex_label(apex_domain):
    """Return the main brand label of an apex domain."""
    if not apex_domain:
        return ""
    labels = apex_domain.split(".")
    for i in range(len(labels)):
        tail = ".".join(labels[i:])
        if tail in PUBLIC_SUFFIXES:
            return labels[i - 1] if i >= 1 else labels[0]
    return labels[-2] if len(labels) >= 2 else labels[0]


def _is_valid_label(label):
    return bool(label) and bool(_LABEL_RE.match(label))


def _in_scope(name, scope):
    """Return True if `name` is inside `scope`.

    A name is in scope if it equals `scope` or is a subdomain of it.
    Rejects anything with '@' (email address captured by mistake).
    """
    if not name or not scope:
        return False
    if "@" in name:
        return False
    name = name.lower().rstrip(".")
    if name == scope:
        return True
    return name.endswith("." + scope)


# ---------------------------------------------------------------------
# Passive sources
# ---------------------------------------------------------------------

async def _from_crtsh(scope, session, limiter, profile, verbose):
    """crt.sh via JSON API. Query scoped to `scope`."""
    url = f"https://crt.sh/?q=%25.{quote(scope)}&output=json"
    status, body, kind = await _fetch_with_retry(
        session, url, limiter, profile=profile, timeout=60.0,
        verbose=verbose, label="crt.sh")
    if kind or status != 200 or not body:
        return set(), kind or "error"

    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        return set(), "error"

    out = set()
    for row in rows:
        for name in (row.get("name_value") or "").split("\n"):
            name = name.strip().lower()
            if not name or name.startswith("*"):
                continue
            if _in_scope(name, scope):
                out.add(name)
    return out, "ok"


async def _from_certspotter(scope, session, limiter, profile, verbose):
    url = (f"https://api.certspotter.com/v1/issuances"
           f"?domain={quote(scope)}&include_subdomains=true"
           f"&expand=dns_names")
    status, body, kind = await _fetch_with_retry(
        session, url, limiter, profile=profile, timeout=60.0,
        verbose=verbose, label="certspotter")
    if kind or status != 200 or not body:
        return set(), kind or "error"

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return set(), "error"

    out = set()
    for row in data if isinstance(data, list) else []:
        for name in row.get("dns_names") or []:
            name = name.strip().lower()
            if not name or name.startswith("*"):
                continue
            if _in_scope(name, scope):
                out.add(name)
    return out, "ok"


async def _from_otx(scope, session, limiter, profile, verbose):
    url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
           f"{quote(scope)}/passive_dns")
    status, body, kind = await _fetch_with_retry(
        session, url, limiter, profile=profile, timeout=45.0,
        verbose=verbose, label="otx")
    if kind or status != 200 or not body:
        return set(), kind or "error"

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return set(), "error"

    out = set()
    for row in data.get("passive_dns") or []:
        hostname = (row.get("hostname") or "").strip().lower()
        if hostname and _in_scope(hostname, scope):
            out.add(hostname)
    return out, "ok"


async def _from_rapiddns(scope, session, limiter, profile, verbose):
    url = f"https://rapiddns.io/subdomain/{quote(scope)}?full=1"
    status, body, kind = await _fetch_with_retry(
        session, url, limiter, profile=profile, timeout=45.0,
        headers={"User-Agent": "Mozilla/5.0 (compatible; recon/0.1)"},
        verbose=verbose, label="rapiddns")
    if kind or status != 200 or not body:
        return set(), kind or "error"

    out = set()
    for m in _DOMAIN_RE.finditer(body):
        name = m.group(1).lower()
        if _in_scope(name, scope):
            out.add(name)
    return out, "ok"


async def _from_anubis(scope, session, limiter, profile, verbose):
    url = f"https://jldc.me/anubis/subdomains/{quote(scope)}"
    status, body, kind = await _fetch_with_retry(
        session, url, limiter, profile=profile, timeout=30.0,
        verbose=verbose, label="anubis")
    if kind or status != 200 or not body:
        return set(), kind or "error"

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return set(), "error"

    out = set()
    for name in data if isinstance(data, list) else []:
        name = str(name).strip().lower()
        if name and _in_scope(name, scope):
            out.add(name)
    return out, "ok"


async def _from_hackertarget(scope, session, limiter, profile, verbose):
    url = f"https://api.hackertarget.com/hostsearch/?q={quote(scope)}"
    status, body, kind = await _fetch_with_retry(
        session, url, limiter, profile=profile, timeout=30.0,
        verbose=verbose, label="hackertarget")
    if kind or status != 200 or not body:
        return set(), kind or "error"

    low = body.lower()[:200]
    if "error" in low or "no records" in low or "api count" in low:
        return set(), "ok"

    out = set()
    for line in body.splitlines():
        if "," in line:
            name = line.split(",", 1)[0].strip().lower()
            if _in_scope(name, scope):
                out.add(name)
    return out, "ok"


async def _from_urlscan(scope, session, limiter, profile, verbose):
    url = (f"https://urlscan.io/api/v1/search/"
           f"?q=domain:{quote(scope)}&size=100")
    status, body, kind = await _fetch_with_retry(
        session, url, limiter, profile=profile, timeout=30.0,
        headers={"Accept": "application/json"},
        verbose=verbose, label="urlscan")
    if kind or status != 200 or not body:
        return set(), kind or "error"

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return set(), "error"

    out = set()
    for row in data.get("results", []):
        page = row.get("page") or {}
        host = (page.get("domain") or "").lower()
        if host and _in_scope(host, scope):
            out.add(host)
    return out, "ok"


async def _from_wayback(scope, session, limiter, profile, verbose):
    url = (f"https://web.archive.org/cdx/search/cdx"
           f"?url=*.{quote(scope)}/*"
           f"&output=json&fl=original&collapse=urlkey&limit=10000")
    status, body, kind = await _fetch_with_retry(
        session, url, limiter, profile=profile, timeout=60.0,
        verbose=verbose, label="wayback")
    if kind or status != 200 or not body:
        return set(), kind or "error"

    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        return set(), "error"

    out = set()
    for row in rows[1:] if isinstance(rows, list) else []:
        if not row:
            continue
        try:
            host = urlparse(row[0]).hostname or ""
        except Exception:
            continue
        host = host.lower()
        if host and _in_scope(host, scope):
            out.add(host)
    return out, "ok"


async def _from_commoncrawl(scope, session, limiter, profile, verbose):
    status, body, kind = await _fetch_with_retry(
        session, "https://index.commoncrawl.org/collinfo.json",
        limiter, profile=profile, timeout=30.0,
        verbose=verbose, label="commoncrawl collinfo")
    if kind or status != 200 or not body:
        return set(), kind or "error"
    try:
        data = json.loads(body)
        data.sort(key=lambda x: x.get("id", ""), reverse=True)
        index_url = data[0].get("cdx-api") or data[0].get("cdx_api")
    except Exception:
        return set(), "error"
    if not index_url:
        return set(), "error"

    url = index_url + f"?url=*.{quote(scope)}/*&output=json&limit=5000"
    status, body, kind = await _fetch_with_retry(
        session, url, limiter, profile=profile, timeout=60.0,
        verbose=verbose, label="commoncrawl")
    if kind or status != 200 or not body:
        return set(), kind or "error"

    out = set()
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            host = urlparse(row.get("url", "")).hostname or ""
        except Exception:
            continue
        host = host.lower()
        if host and _in_scope(host, scope):
            out.add(host)
    return out, "ok"


PASSIVE_SOURCES = [
    ("crtsh",          _from_crtsh),
    ("certspotter",    _from_certspotter),
    ("otx",            _from_otx),
    ("rapiddns",       _from_rapiddns),
    ("anubis",         _from_anubis),
    ("hackertarget",   _from_hackertarget),
    ("urlscan",        _from_urlscan),
    ("wayback",        _from_wayback),
    ("commoncrawl",    _from_commoncrawl),
]


# ---------------------------------------------------------------------
# DNS record mining
# ---------------------------------------------------------------------

async def _dns_record_mining(apex, scope=None, verbose=False):
    """Mine NS, MX, SPF, DMARC, DKIM for hostnames.

    NS and MX are queried against the apex (they're apex-level
    records). SPF/DMARC/DKIM are queried against the scope so they
    reflect the target's own mail config, not the district's.
    """
    import subprocess

    loop = asyncio.get_event_loop()
    mail_scope = scope or apex

    def _nslookup(qtype, name):
        try:
            out = subprocess.run(
                ["nslookup", f"-type={qtype}", name],
                capture_output=True, text=True, timeout=8.0)
            return out.stdout
        except Exception:
            return ""

    async def _q(qtype, name):
        return await loop.run_in_executor(None, _nslookup, qtype, name)

    hosts = set()
    details = {"ns": [], "mx": [], "spf": [], "dmarc": [], "dkim": []}

    # --- NS (apex-level) ---
    text = await _q("NS", apex)
    for m in re.finditer(r"(?:nameserver|Name Server)\s*=\s*(\S+)",
                          text, re.IGNORECASE):
        host = m.group(1).rstrip(".").lower()
        if host and host != apex:
            details["ns"].append(host)
            if _in_scope(host, scope or apex):
                hosts.add(host)

    # --- MX (apex-level) ---
    text = await _q("MX", apex)
    for m in re.finditer(r"mail exchanger\s*=\s*\d+\s+(\S+)",
                          text, re.IGNORECASE):
        host = m.group(1).rstrip(".").lower()
        if host:
            details["mx"].append(host)
            if _in_scope(host, scope or apex):
                hosts.add(host)

    # --- SPF (scope-level) ---
    text = await _q("TXT", mail_scope)
    for m in re.finditer(r'"(v=spf1[^"]+)"', text):
        spf = m.group(1)
        details["spf"].append(spf)
        for tok in spf.split():
            if tok.startswith(("include:", "redirect=")):
                val = tok.split(":", 1)[1] if ":" in tok else \
                      tok.split("=", 1)[1]
                val = val.rstrip(".")
                if "." in val and _in_scope(val, scope or apex):
                    hosts.add(val.lower())

    # --- DMARC (scope-level) ---
    text = await _q("TXT", "_dmarc." + mail_scope)
    for m in re.finditer(r'"(v=DMARC1[^"]+)"', text):
        dmarc = m.group(1)
        details["dmarc"].append(dmarc)
        for tok in dmarc.split(";"):
            tok = tok.strip()
            if tok.startswith(("rua=", "ruf=")):
                _, _, val = tok.partition("=")
                for addr in val.split(","):
                    addr = addr.strip()
                    if "@" in addr:
                        _, _, mail_dom = addr.partition("@")
                        mail_dom = mail_dom.rstrip(".")
                        if mail_dom and "." in mail_dom \
                                and _in_scope(mail_dom, scope or apex):
                            hosts.add(mail_dom.lower())

    # --- DKIM (scope-level) ---
    for sel in DKIM_SELECTORS:
        text = await _q("TXT", f"{sel}._domainkey.{mail_scope}")
        if "v=DKIM1" in text or "p=" in text:
            details["dkim"].append(sel)
            hosts.add(f"{sel}._domainkey.{mail_scope}")

    if verbose:
        info(f"  dns records: ns={len(details['ns'])} "
             f"mx={len(details['mx'])} spf={len(details['spf'])} "
             f"dmarc={len(details['dmarc'])} dkim={len(details['dkim'])}")

    return hosts, details


# ---------------------------------------------------------------------
# Target-derived wordlist generation
# ---------------------------------------------------------------------

def _generate_target_derived(scope, aliases=None, verbose=False):
    """Produce candidate subdomain labels for the scope.

    The scope is the domain whose immediate children we're
    enumerating. For `tyas.tyc.edu.tw`, the labels we generate are
    prepended to `.tyas.tyc.edu.tw`. `tyas` and `tyc` are both
    sources of interesting candidate labels.
    """
    labels = set()
    alias_labels = []
    if aliases:
        for a in aliases:
            a = a.strip().lower()
            if a:
                alias_labels.append(a)
                labels.add(a)
                labels.add(a.replace("-", ""))
                labels.add(a.replace(" ", "-"))
                labels.add(a.replace(" ", ""))

    # Every label of the scope
    for lab in (scope.split(".") if scope else []):
        if lab and lab not in ("www",):
            labels.add(lab)

    # Mechanical variants
    variants = set()
    for lab in labels:
        if not lab:
            continue
        variants.add(lab)
        variants.add(lab.replace("-", ""))
        variants.add(lab.replace(".", "-"))
        if len(lab) > 3:
            variants.add(lab[:3])
            variants.add(lab[:4])
        if lab.endswith("s") and len(lab) > 3:
            variants.add(lab[:-1])
        else:
            variants.add(lab + "s")
        for i in range(1, 4):
            variants.add(f"{lab}{i}")

    cleaned = set()
    for v in variants:
        if not v:
            continue
        if len(v) > 40:
            continue
        if _is_valid_label(v):
            cleaned.add(v)

    if verbose:
        info(f"  target-derived: {len(cleaned)} candidate(s) "
             f"from scope={scope!r}"
             + (f" + {len(alias_labels)} alias(es)"
                if alias_labels else ""))

    return cleaned


# ---------------------------------------------------------------------
# Permutation extrapolation
# ---------------------------------------------------------------------

def _extrapolate_permutations(found_hosts, scope, verbose=False):
    """Given resolved hosts, extrapolate numeric permutations.

    Only looks at hosts that are immediate children of `scope` and
    have trailing digits in the leftmost label.
    """
    base_map = {}
    for host in found_hosts:
        if not host.endswith("." + scope):
            continue
        # Leftmost label of the host, relative to scope
        prefix_part = host[:-len("." + scope)]
        if "." in prefix_part:
            continue  # deeper than one level below scope; skip
        first = prefix_part
        m = _TRAILING_DIGITS_RE.match(first)
        if not m:
            continue
        prefix, num = m.group(1), m.group(2)
        if not prefix:
            continue
        width = len(num)
        key = (prefix, width)
        n = int(num)
        base_map[key] = max(base_map.get(key, 0), n)

    permutations = set()
    for (prefix, width), high in base_map.items():
        upper = min(high + 20, 999)
        for i in range(1, upper + 1):
            cand = f"{prefix}{str(i).zfill(width)}"
            permutations.add(f"{cand}.{scope}")

    permutations -= set(found_hosts)

    if verbose and permutations:
        info(f"  permutations: {len(permutations)} extrapolated "
             f"from {len(base_map)} pattern(s)")

    return permutations


# ---------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------

async def _resolve_batch(hosts, scope, verbose=False):
    """Resolve each host once. Returns (live, dangling, cnames)."""
    from core.dns import resolve_a

    live = {}
    dangling = {}
    cnames = {}

    sem = asyncio.Semaphore(50)

    async def _one(host):
        async with sem:
            try:
                ips = await resolve_a(host)
            except Exception:
                return
            if ips:
                live[host] = ips

    await asyncio.gather(*[_one(h) for h in hosts])

    import subprocess
    loop = asyncio.get_event_loop()

    def _cname(host):
        try:
            out = subprocess.run(
                ["nslookup", "-type=CNAME", host],
                capture_output=True, text=True, timeout=6.0)
            text = out.stdout
        except Exception:
            return None
        m = re.search(r"canonical name\s*=\s*(\S+)", text, re.IGNORECASE)
        if m:
            return m.group(1).rstrip(".").lower()
        return None

    to_check = [h for h in hosts if h not in live]
    if to_check:
        cname_sem = asyncio.Semaphore(20)

        async def _one_cname(host):
            async with cname_sem:
                cname = await loop.run_in_executor(None, _cname, host)
                if cname:
                    cnames[host] = cname
                    dangling[host] = cname

        await asyncio.gather(*[_one_cname(h) for h in to_check[:200]])

    return live, dangling, cnames


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def enumerate_subdomains(target, aliases=None, brute=False,
                                 full_brute=False, custom_wordlist=None,
                                 rate=5.0, retry_profile=DEFAULT_RETRY_PROFILE,
                                 apex_mode=False, verbose=False):
    """Enumerate subdomains for a target.

    By default, if the target is a proper subdomain (tyas.tyc.edu.tw),
    scope is that subdomain. Pass apex_mode=True to enumerate the
    whole registrable domain instead.
    """
    import time
    start = time.time()

    host, apex = _normalize_input(target)
    if not apex:
        raise ValueError(f"cannot parse target: {target!r}")

    scope = _compute_scope(host, apex, force_apex=apex_mode)

    info(f"subdomains_deep: target={host} scope={scope} "
         f"apex={apex}"
         + (" [apex mode]" if apex_mode else ""))

    own_session = new_session()
    limiter_passive = RateLimiter(5.0)
    limiter_dns = RateLimiter(rate)

    result = {
        "target": host,
        "apex": apex,
        "scope": scope,
        "live": {},
        "historical": [],
        "dangling": {},
        "cnames": {},
        "by_source": {},
        "sources": {},
        "elapsed": 0.0,
        "wordlist_used": 0,
    }

    try:
        # --- 1. Passive sources ---
        info("phase 1: passive sources")
        passive_hosts = set()
        by_source = result["by_source"]

        async def _one_source(name, fn):
            try:
                hosts, status = await fn(scope, own_session,
                                           limiter_passive,
                                           retry_profile, verbose)
            except Exception as e:
                return name, set(), f"error: {type(e).__name__}"
            return name, hosts, status

        tasks = [_one_source(n, f) for n, f in PASSIVE_SOURCES]
        for coro in asyncio.as_completed(tasks):
            name, hosts, status = await coro
            result["sources"][name] = status
            if hosts:
                by_source[name] = len(hosts)
                passive_hosts |= hosts
                info(f"  {name:16s} {len(hosts):5d} name(s)")
            else:
                if verbose:
                    info(f"  {name:16s} {status}")

        info(f"  passive total: {len(passive_hosts)} unique hostname(s)")

        # --- 2. DNS record mining ---
        info("phase 2: dns record mining")
        dns_hosts, dns_details = await _dns_record_mining(
            apex, scope=scope, verbose=verbose)
        passive_hosts |= dns_hosts
        result["dns_records"] = dns_details

        # --- 3. Resolve passive findings ---
        info("phase 3: resolving passive findings")
        live, dangling, cnames = await _resolve_batch(
            list(passive_hosts), scope, verbose=verbose)
        result["live"].update(live)
        result["dangling"].update(dangling)
        result["cnames"].update(cnames)

        unresolved = [h for h in passive_hosts
                       if h not in live and h not in dangling]
        result["historical"] = sorted(unresolved)

        # --- 4. Brute (opt-in) ---
        all_candidates = set(passive_hosts)

        if brute:
            info("phase 4: target-derived wordlist")
            derived = _generate_target_derived(
                scope, aliases=aliases, verbose=verbose)
            for lab in derived:
                all_candidates.add(f"{lab}.{scope}")

            info(f"phase 5: curated wordlist "
                 f"({len(CURATED_WORDLIST)} entries)")
            for lab in CURATED_WORDLIST:
                all_candidates.add(f"{lab}.{scope}")

            if custom_wordlist:
                try:
                    path = Path(custom_wordlist)
                    lines = path.read_text(encoding="utf-8",
                                            errors="ignore").splitlines()
                    extra = [l.strip().lower() for l in lines
                              if l.strip() and not l.startswith("#")]
                    if verbose:
                        info(f"  custom wordlist: {len(extra)} entries")
                    for lab in extra:
                        if _is_valid_label(lab):
                            all_candidates.add(f"{lab}.{scope}")
                except Exception as e:
                    warn(f"  custom wordlist failed: {e}")

            if full_brute:
                try:
                    path = FULL_WORDLIST_PATH
                    if path.exists():
                        lines = path.read_text(
                            encoding="utf-8",
                            errors="ignore").splitlines()
                        extra = [l.strip().lower() for l in lines
                                  if l.strip()
                                  and not l.startswith("#")]
                        if verbose:
                            info(f"  full wordlist: "
                                 f"{len(extra)} entries")
                        for lab in extra:
                            if _is_valid_label(lab):
                                all_candidates.add(f"{lab}.{scope}")
                except Exception as e:
                    warn(f"  full wordlist failed: {e}")

            result["wordlist_used"] = len(all_candidates)

            new_candidates = all_candidates - set(passive_hosts)
            if new_candidates:
                info(f"phase 6: resolving {len(new_candidates)} "
                     f"brute candidates")
                if len(new_candidates) > 2000:
                    warn(f"  capping brute at 2000 candidates "
                         f"(had {len(new_candidates)})")
                    new_candidates = set(sorted(new_candidates)[:2000])
                new_live, new_dangling, new_cnames = await _resolve_batch(
                    list(new_candidates), scope, verbose=verbose)
                result["live"].update(new_live)
                result["dangling"].update(new_dangling)
                result["cnames"].update(new_cnames)
        else:
            if verbose:
                info("phase 4-7: skipped (--brute not passed)")

        # --- 8. Permutation extrapolation ---
        if brute and result["live"]:
            info("phase 8: permutation extrapolation")
            perms = _extrapolate_permutations(
                set(result["live"].keys()), scope, verbose=verbose)
            if perms:
                info(f"  resolving {len(perms)} permutation(s)")
                p_live, p_dangling, p_cnames = await _resolve_batch(
                    list(perms), scope, verbose=verbose)
                result["live"].update(p_live)
                result["dangling"].update(p_dangling)
                result["cnames"].update(p_cnames)

        result["elapsed"] = round(time.time() - start, 2)
        return result
    finally:
        await own_session.close()


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target, store=None, aliases=None, brute=False,
              full_brute=False, custom_wordlist=None,
              rate=5.0, retry_profile=DEFAULT_RETRY_PROFILE,
              apex_mode=False, verbose=False):
    result = await enumerate_subdomains(
        target, aliases=aliases, brute=brute, full_brute=full_brute,
        custom_wordlist=custom_wordlist, rate=rate,
        retry_profile=retry_profile, apex_mode=apex_mode,
        verbose=verbose)

    print()
    scope = result["scope"]
    n_live = len(result["live"])
    n_hist = len(result["historical"])
    n_dang = len(result["dangling"])

    success(f"subdomains_deep: {scope} "
            f"({n_live} live, {n_hist} historical, "
            f"{n_dang} unresolved CNAMEs) "
            f"in {result['elapsed']}s")
    if result["apex"] != result["scope"]:
        info(f"  apex was {result['apex']}; scope limited to "
             f"{result['scope']} (pass --apex for the full domain)")

    if result["sources"]:
        print()
        info("Source status:")
        for name, status in sorted(result["sources"].items()):
            marker = "ok" if status == "ok" else status
            print(f"    {name:16s} {marker}")

    if result["live"]:
        print()
        success(f"Live ({n_live}):")
        for hostname in sorted(result["live"]):
            ips = result["live"][hostname]
            print(f"    {hostname:50s} {', '.join(ips[:3])}")

    if result["dangling"]:
        print()
        info(f"Unresolved CNAMEs ({n_dang}) — D2 will verify these:")
        for hostname, cname in sorted(result["dangling"].items()):
            print(f"    {hostname:50s} → {cname}")

    if result["historical"]:
        print()
        info(f"Historical ({n_hist}, unreachable now):")
        for hostname in result["historical"][:40]:
            print(f"    {hostname}")
        if n_hist > 40:
            print(f"    ... and {n_hist - 40} more")

    if store is not None:
        for hostname, ips in result["live"].items():
            try:
                store.upsert_host(
                    ip=hostname,
                    hostname=hostname,
                    discovery="subdomains_deep",
                    tags=["subdomain"],
                )
            except Exception:
                pass

        store.add_finding({
            "module": "subdomains_deep",
            "type": "informational",
            "severity": "info",
            "target": scope,
            "evidence": (f"{n_live} live, {n_hist} historical, "
                         f"{n_dang} unresolved CNAMEs"),
            "data": {
                "apex": result["apex"],
                "scope": result["scope"],
                "live": result["live"],
                "historical": result["historical"],
                "dangling": result["dangling"],
                "cnames": result["cnames"],
                "by_source": result["by_source"],
                "sources": result["sources"],
                "elapsed": result["elapsed"],
            },
        })
        success("finding written to store")

    return result


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.subdomains_deep",
        description="Deep subdomain enumeration: passive sources + "
                    "DNS mining + optional brute force.",
    )
    p.add_argument("target", help="domain or URL")
    p.add_argument("--brute", action="store_true",
                   help="enable DNS brute force")
    p.add_argument("--full-brute", action="store_true",
                   help="also load wordlists/subdomains.txt "
                        "(~3400 entries); implies --brute")
    p.add_argument("--wordlist", default=None,
                   help="custom wordlist path (one label per line)")
    p.add_argument("--aliases", default=None,
                   help="comma-separated alternative names for the "
                        "target")
    p.add_argument("--apex", dest="apex_mode", action="store_true",
                   help="enumerate the full registrable domain, not "
                        "just the input subdomain")
    p.add_argument("--rate", type=float, default=5.0,
                   help="DNS queries per second for brute "
                        "(default 5)")
    p.add_argument("--retry-profile",
                   choices=["fast", "moderate", "aggressive"],
                   default="fast",
                   help="retry patience for passive APIs "
                        "(default fast)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--store", action="store_true")
    args = p.parse_args()

    aliases = None
    if args.aliases:
        aliases = [a.strip() for a in args.aliases.split(",")
                    if a.strip()]

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
        args.target, store=store, aliases=aliases,
        brute=args.brute or args.full_brute,
        full_brute=args.full_brute,
        custom_wordlist=args.wordlist,
        rate=args.rate,
        retry_profile=args.retry_profile,
        apex_mode=args.apex,
        verbose=args.verbose,
    ))


if __name__ == "__main__":
    _cli()