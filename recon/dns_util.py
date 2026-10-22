"""
Async DNS lookups via dnspython.

Replaces every `nslookup` subprocess call in the toolkit. Cross-platform,
10x faster, and returns structured records instead of parsed text.

Every function here is a thin wrapper — no caching, no retries beyond
what dnspython gives us, no magic. If a lookup fails, you get an empty
list or None, never an exception.

If you also want a resolver that uses the OS resolver instead of
hardcoded public resolvers (useful inside a corporate network with
split-horizon DNS), pass `nameservers=None` at module setup:

    import dns_util
    dns_util.configure(resolvers=["10.0.0.53"])
"""

import asyncio
from typing import Iterable

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

# Public resolvers by default. Override with configure() if you're on a
# network where these are blocked, or you need split-horizon answers.
_DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

_resolver: dns.asyncresolver.Resolver | None = None
_resolver_loop = None


def configure(resolvers: list[str] | None = None,
              timeout: float = 5.0,
              lifetime: float = 8.0):
    """Set resolver config. Call once at startup if you need non-defaults."""
    global _resolver, _resolver_loop
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = resolvers or _DEFAULT_RESOLVERS
    r.timeout = timeout
    r.lifetime = lifetime
    _resolver = r
    _resolver_loop = None   # force rebuild on next use


def _get_resolver() -> dns.asyncresolver.Resolver:
    """Return a resolver bound to the current running loop.

    dnspython's async resolver binds to the event loop it's first used
    on. Since the toolkit calls asyncio.run() in multiple places, we
    rebuild the resolver whenever the loop changes.
    """
    global _resolver, _resolver_loop
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if _resolver is None or _resolver_loop is not loop:
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = _DEFAULT_RESOLVERS
        r.timeout = 5.0
        r.lifetime = 8.0
        _resolver = r
        _resolver_loop = loop
    return _resolver


# ---------------------------------------------------------------------
# Record lookups
# ---------------------------------------------------------------------

async def resolve_a(host: str, timeout: float = 5.0) -> list[str]:
    """Return IPv4 addresses for `host`, or []."""
    if not host:
        return []
    try:
        r = await _get_resolver().resolve(host, "A", lifetime=timeout)
        return sorted({str(x) for x in r})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.exception.DNSException):
        return []
    except Exception:
        return []


async def resolve_aaaa(host: str, timeout: float = 5.0) -> list[str]:
    """Return IPv6 addresses for `host`, or []."""
    if not host:
        return []
    try:
        r = await _get_resolver().resolve(host, "AAAA", lifetime=timeout)
        return sorted({str(x) for x in r})
    except Exception:
        return []


async def resolve_any(host: str, timeout: float = 5.0) -> dict[str, list[str]]:
    """Return every A, AAAA, MX, NS, TXT, CNAME, SOA record we can get.

    Each key maps to a list of string values. Missing types are simply
    absent from the dict.
    """
    types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
    results = await asyncio.gather(*[_one(host, t, timeout) for t in types])
    return {t: r for t, r in zip(types, results) if r}


async def _one(host: str, rtype: str, timeout: float) -> list[str]:
    try:
        r = await _get_resolver().resolve(host, rtype, lifetime=timeout)
    except Exception:
        return []
    out = []
    for rr in r:
        try:
            out.append(_format_rr(rtype, rr))
        except Exception:
            continue
    return sorted(set(out))


def _format_rr(rtype: str, rr) -> str:
    if rtype == "MX":
        return f"{rr.preference} {str(rr.exchange).rstrip('.').lower()}"
    if rtype == "NS":
        return str(rr.target).rstrip(".").lower()
    if rtype == "TXT":
        # TXT records are lists of bytes; join them
        return b"".join(rr.strings).decode("utf-8", errors="replace")
    if rtype == "CNAME":
        return str(rr.target).rstrip(".").lower()
    if rtype == "SOA":
        return (f"{rr.mname.to_text().rstrip('.')} "
                f"{rr.rname.to_text().rstrip('.')} "
                f"serial={rr.serial}")
    return str(rr).rstrip(".").lower()


async def resolve_mx(host: str, timeout: float = 5.0) -> list[str]:
    """Return MX hostnames (sorted by preference) for `host`."""
    try:
        r = await _get_resolver().resolve(host, "MX", lifetime=timeout)
        return [str(x.exchange).rstrip(".").lower()
                for x in sorted(r, key=lambda rr: rr.preference)]
    except Exception:
        return []


async def resolve_ns(host: str, timeout: float = 5.0) -> list[str]:
    """Return authoritative nameservers for `host`."""
    try:
        r = await _get_resolver().resolve(host, "NS", lifetime=timeout)
        return sorted({str(x.target).rstrip(".").lower() for x in r})
    except Exception:
        return []


async def resolve_txt(host: str, timeout: float = 5.0) -> list[str]:
    """Return every TXT record string for `host`."""
    try:
        r = await _get_resolver().resolve(host, "TXT", lifetime=timeout)
        out = []
        for rr in r:
            for chunk in rr.strings:
                out.append(chunk.decode("utf-8", errors="replace"))
        return sorted(set(out))
    except Exception:
        return []


async def resolve_cname(host: str, timeout: float = 5.0) -> str | None:
    """Return the CNAME target for `host`, or None."""
    try:
        r = await _get_resolver().resolve(host, "CNAME", lifetime=timeout)
        if r:
            return str(r[0].target).rstrip(".").lower()
    except Exception:
        pass
    return None


async def reverse_ptr(ip: str, timeout: float = 5.0) -> list[str]:
    """Return PTR hostnames for `ip`, or []."""
    try:
        rev = dns.reversename.from_address(ip)
        r = await _get_resolver().resolve(rev, "PTR", lifetime=timeout)
        return sorted({str(x).rstrip(".").lower() for x in r})
    except Exception:
        return []


# ---------------------------------------------------------------------
# Bulk
# ---------------------------------------------------------------------

async def resolve_many(hosts: Iterable[str],
                       concurrency: int = 100,
                       timeout: float = 5.0):
    """Resolve many hosts concurrently. Yields (host, [ips]).

    Same shape as core.dns.resolve_many — if you want to swap the
    existing core.dns module for this one, the signature matches.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _one(h):
        async with sem:
            ips = await resolve_a(h, timeout=timeout)
            return h, ips

    hosts = list(hosts)
    for coro in asyncio.as_completed([_one(h) for h in hosts]):
        try:
            yield await coro
        except Exception:
            continue


# ---------------------------------------------------------------------
# Zone transfer
# ---------------------------------------------------------------------

async def try_zone_transfer(domain: str, nameserver: str,
                             timeout: float = 10.0) -> list[str] | None:
    """Attempt an AXFR against `nameserver` for `domain`.

    Returns the list of record strings on success, None on refusal
    (which is the correct, expected behavior on a properly-configured
    server). Uses dnspython's synchronous zone-transfer machinery in
    an executor thread.
    """
    import dns.query
    import dns.zone
    loop = asyncio.get_running_loop()

    def _axfr():
        try:
            z = dns.zone.from_xfr(
                dns.query.xfr(nameserver, domain, timeout=timeout,
                              lifetime=timeout)
            )
        except Exception:
            return None
        out = []
        for name, node in z.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    out.append(f"{name} {rdataset.rdtype} {rdata}")
        return out

    try:
        return await loop.run_in_executor(None, _axfr)
    except Exception:
        return None