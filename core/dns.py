import asyncio
import aiodns

_resolver = None
_resolver_loop = None


def _get_resolver():
    global _resolver, _resolver_loop
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    # Rebuild if the loop changed (e.g. new asyncio.run call)
    if _resolver is None or _resolver_loop is not current_loop:
        _resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1"])
        _resolver_loop = current_loop
    return _resolver


async def resolve_a(hostname: str, verbose: bool = False):
    """Return IPv4 addresses for hostname, or empty list."""
    try:
        result = await _get_resolver().query(hostname, "A")
        return [r.host for r in result]
    except Exception as e:
        if verbose:
            from core.output import warn
            warn(f"resolve {hostname} failed: {type(e).__name__}: {e!r}")
        return []


async def resolve_many(hostnames: list[str], concurrency: int = 100):
    """Resolve many hostnames with a concurrency cap. Yields (host, [ips])."""
    sem = asyncio.Semaphore(concurrency)

    async def _one(h):
        async with sem:
            ips = await resolve_a(h)
            return h, ips

    for coro in asyncio.as_completed([_one(h) for h in hostnames]):
        yield await coro