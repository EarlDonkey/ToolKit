import asyncio
import re
import aiohttp

from core.output import info, success, warn


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Simple tech signatures from response headers
HEADER_TECH = {
    "server": ["nginx", "apache", "iis", "cloudflare", "gunicorn", "caddy"],
    "x-powered-by": ["php", "asp.net", "express", "next.js"],
    "x-generator": ["wordpress", "drupal", "joomla"],
}


async def probe_one(session: aiohttp.ClientSession, host: str, timeout: float = 8.0):
    """Try http:// then https://, return dict of findings or None."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
                ssl=False,  # ignore cert errors; we're fingerprinting, not validating
            ) as resp:
                body = await resp.text(errors="ignore")
                title_match = TITLE_RE.search(body[:5000])
                title = title_match.group(1).strip()[:100] if title_match else ""

                tech = []
                for header, sigs in HEADER_TECH.items():
                    val = resp.headers.get(header, "").lower()
                    for sig in sigs:
                        if sig in val:
                            tech.append(sig)

                return {
                    "url": str(resp.url),
                    "status": resp.status,
                    "server": resp.headers.get("server", ""),
                    "title": title,
                    "tech": tech,
                    "content_length": len(body),
                }
        except Exception:
            continue
    return None


async def run(hosts: list[str], concurrency: int = 50, verbose: bool = False):
    """Probe a list of hosts over HTTP/HTTPS."""
    info(f"probing {len(hosts)} hosts over HTTP/HTTPS")
    warn("Probes hosts..technically..")

    sem = asyncio.Semaphore(concurrency)
    results = []

    async with aiohttp.ClientSession() as session:
        async def _one(h):
            async with sem:
                r = await probe_one(session, h)
                if r:
                    results.append((h, r))
                    if verbose:
                        success(f"{h} -> {r['status']} {r['title'][:50]}")

        await asyncio.gather(*[_one(h) for h in hosts])

    print()
    success(f"{len(results)} hosts responded")
    for host, r in sorted(results):
        tech_str = ",".join(r["tech"]) if r["tech"] else "-"
        print(f"  {host:40s} {r['status']} [{tech_str}] {r['title'][:40]}")