"""
Target normalization.

Every recon module accepts a raw string from the user (an IP, a domain,
a URL, an ASN). This module parses that string exactly once and exposes
the pieces every module needs: kind, host, port, registrable domain,
subdomain, TLD, whether it's an IP, whether it's private.

Why this exists: before this, `whois.py`, `emails.py`, `ct_logs.py`,
and `cloud_enum.py` each did their own string-splitting. They disagreed
on edge cases, which meant `https://www.example.co.uk/path` sometimes
went to WHOIS as `www.example.co.uk` (wrong server, wrong record) and
sometimes as `example.co.uk` (right). One parser, one answer.

No third-party dependencies. The registrable-domain extraction uses a
bundled public-suffix list — if you want the full PSL, drop
tldextract in and swap `_registrable_from_host`.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


# ---------------------------------------------------------------------
# Lightweight public-suffix handling
# ---------------------------------------------------------------------
#
# The real Public Suffix List has ~9000 entries. We only need enough to
# correctly handle the multi-label TLDs that appear in the wild on the
# kinds of targets this toolkit gets pointed at. Everything else falls
# through to "last two labels" which is right ~95% of the time.
#
# If you want 100% correctness, install `tldextract` and replace
# `_registrable_from_host` with:
#
#     import tldextract
#     ext = tldextract.extract(host)
#     return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None

_MULTI_LABEL_TLDS = {
    # United Kingdom
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "sch.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "asn.au",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "geek.nz",
    "gen.nz", "kiwi.nz", "maori.nz", "school.nz",
    # Japan
    "co.jp", "or.jp", "ne.jp", "ac.jp", "ad.jp", "ed.jp",
    "go.jp", "gr.jp", "lg.jp",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    # China
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    # India
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
    "ac.in", "edu.in", "res.in", "gov.in", "mil.in",
    # South Africa
    "co.za", "net.za", "org.za", "gov.za", "ac.za", "edu.za",
    "web.za",
    # Singapore
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg", "per.sg",
    # Hong Kong
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk", "idv.hk",
    # Taiwan
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw", "idv.tw",
    # Korea
    "co.kr", "or.kr", "ne.kr", "re.kr", "pe.kr", "go.kr",
    "ac.kr", "mil.kr",
    # Mexico
    "com.mx", "net.mx", "org.mx", "edu.mx", "gob.mx",
    # Argentina
    "com.ar", "net.ar", "org.ar", "gov.ar", "edu.ar",
    # Turkey
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "gen.tr",
    "web.tr",
    # Others commonly seen
    "com.ru", "net.ru", "org.ru",
    "com.pl", "net.pl", "org.pl",
    "com.ua", "net.ua", "org.ua",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "co.th", "in.th", "ac.th", "go.th", "net.th", "or.th",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    "co.id", "or.id", "ac.id", "go.id", "net.id", "web.id",
}


_ASN_RE = re.compile(r"^(?:as)?(\d+)$", re.IGNORECASE)
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\-]{1,63}"
    r"(?:\.(?!-)[A-Za-z0-9\-]{1,63})*\.?$"
)


def _registrable_from_host(host: str) -> tuple[str | None, str | None, str | None]:
    """Return (registrable, subdomain, tld) for a hostname.

    registrable is the domain you'd query in WHOIS / CT logs.
    subdomain is everything to the left of it.
    tld is the suffix (which may be multi-label).
    """
    if not host:
        return None, None, None
    parts = host.rstrip(".").split(".")
    if len(parts) < 2:
        return host, None, None

    # Check for a multi-label TLD
    for i in range(len(parts) - 2, -1, -1):
        candidate = ".".join(parts[i:])
        if candidate.lower() in _MULTI_LABEL_TLDS:
            if i == 0:
                # The whole host is the registrable (no subdomain)
                return candidate, None, candidate
            registrable = ".".join(parts[i - 1:])
            subdomain = ".".join(parts[:i - 1]) or None
            return registrable, subdomain, candidate

    # Single-label TLD
    tld = parts[-1].lower()
    registrable = ".".join(parts[-2:])
    subdomain = ".".join(parts[:-2]) or None
    return registrable, subdomain, tld


# ---------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------

@dataclass
class Target:
    raw: str
    kind: str                       # "ip" | "domain" | "url" | "asn"
    scheme: str | None
    host: str                       # hostname or IP literal
    port: int | None
    path: str
    query: str
    registrable: str | None         # example.com for a.b.example.co.uk
    subdomain: str | None           # "a.b" for a.b.example.com
    tld: str | None
    is_ip: bool
    is_private: bool
    asn: int | None = None
    ips: list[str] = field(default_factory=list)   # filled lazily

    def __str__(self) -> str:
        if self.kind == "asn":
            return f"AS{self.asn}"
        if self.kind == "ip":
            return self.host
        return self.host or self.raw

    @property
    def origin(self) -> str:
        """https://host[:port] or http://host[:port] for URL-ish targets."""
        if self.is_ip:
            scheme = "https"
            host_part = f"[{self.host}]" if ":" in self.host else self.host
        else:
            scheme = self.scheme or "https"
            host_part = self.host
        if self.port and self.port not in (80, 443):
            return f"{scheme}://{host_part}:{self.port}"
        return f"{scheme}://{host_part}"

    def url_for(self, path: str = "/") -> str:
        """Build a full URL for a given path on this target."""
        if not path.startswith("/"):
            path = "/" + path
        return self.origin.rstrip("/") + path


# ---------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------

def parse(raw: str) -> Target:
    """Parse any of: 1.2.3.4, example.com, www.example.com,
    https://example.com/path?q=1, AS15169, 15169."""
    if not raw or not raw.strip():
        raise ValueError("empty target")
    raw = raw.strip()

    # --- ASN? ---
    m = _ASN_RE.match(raw)
    if m:
        n = int(m.group(1))
        if n <= 0 or n > 4294967295:
            raise ValueError(f"ASN out of range: {raw!r}")
        return Target(
            raw=raw, kind="asn", scheme=None, host=f"AS{n}",
            port=None, path="", query="", registrable=None,
            subdomain=None, tld=None, is_ip=False, is_private=False,
            asn=n,
        )

    # --- IP literal (with optional port)? ---
    if "://" not in raw:
        host_part = raw
        port_part = None
        # "1.2.3.4:8080" or "example.com:8080"
        # (but not IPv6 "[::1]:80" — handle that below via urlparse)
        if raw.count(":") == 1 and not raw.startswith("["):
            host_part, _, port_str = raw.partition(":")
            port_part = _safe_int(port_str)
            if port_part is None:
                # Wasn't actually a port; restore the original
                host_part, port_part = raw, None

        try:
            ip = ipaddress.ip_address(host_part)
            return Target(
                raw=raw, kind="ip", scheme=None, host=str(ip),
                port=port_part, path="", query="",
                registrable=None, subdomain=None, tld=None,
                is_ip=True, is_private=ip.is_private,
            )
        except ValueError:
            pass

    # --- URL or bare host ---
    raw_url = raw if "://" in raw else f"https://{raw}"
    try:
        u = urlparse(raw_url)
    except Exception as e:
        raise ValueError(f"could not parse target: {raw!r}: {e}")

    host = (u.hostname or "").lower()
    if not host:
        raise ValueError(f"no host in target: {raw!r}")

    # Is the host actually an IP?
    is_ip = False
    is_private = False
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
        is_private = ip.is_private
    except ValueError:
        # Sanity-check that it looks like a hostname
        if not _HOSTNAME_RE.match(host):
            raise ValueError(f"invalid hostname: {host!r}")

    port = u.port
    path = u.path or ""
    query = u.query or ""

    registrable = None
    subdomain = None
    tld = None
    if not is_ip:
        registrable, subdomain, tld = _registrable_from_host(host)

    # Classify
    if is_ip:
        kind = "ip"
    elif (path and path != "/") or query or port:
        kind = "url"
    else:
        kind = "domain"

    return Target(
        raw=raw, kind=kind, scheme=u.scheme or "https", host=host,
        port=port, path=path, query=query, registrable=registrable,
        subdomain=subdomain, tld=tld, is_ip=is_ip,
        is_private=is_private,
    )


def _safe_int(s: str) -> int | None:
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------

def is_private_ip(host: str) -> bool:
    """True if the string is an IP in a private/reserved range."""
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def resolve_to_ips(t: Target, timeout: float = 5.0) -> list[str]:
    """Resolve a Target to its A/AAAA records. Blocking — use in executor.

    For an IP Target, returns [host]. For a domain/URL Target, tries
    the toolkit's DNS resolver first, then falls back to the OS.
    """
    import socket
    if t.is_ip:
        return [t.host]
    try:
        from core.dns import resolve_a
        ips = resolve_a(t.host)
        if ips:
            return ips
    except Exception:
        pass
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(t.host, None)})
    except Exception:
        return []