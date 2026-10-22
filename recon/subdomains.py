import asyncio
import aiohttp
from pathlib import Path

from core.dns import resolve_many
from core.output import info, success, warn, error

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


async def fetch_crtsh(domain: str):
    """Query crt.sh certificate transparency log for subdomains."""
    info(f"querying crt.sh for {domain}")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                CRTSH_URL.format(domain=domain),
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    warn(f"crt.sh returned HTTP {resp.status}")
                    return set()
                data = await resp.json(content_type=None)
    except Exception as e:
        error(f"crt.sh request failed: {type(e).__name__}: {e!r}")
        return set()

    names = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name.endswith(domain) and "*" not in name:
                names.add(name)
    return names

async def fetch_hackertarget(domain: str):
    """Fallback: hackertarget's hostsearch API (free, no key)."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    info(f"fallback: querying hackertarget for {domain}")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    warn(f"hackertarget returned HTTP {resp.status}")
                    return set()
                text = await resp.text()
    except Exception as e:
        error(f"hackertarget failed: {type(e).__name__}: {e!r}")
        return set()

    names = set()
    for line in text.splitlines():
        if "," in line:
            name = line.split(",")[0].strip().lower()
            if name.endswith(domain):
                names.add(name)
    return names

def load_wordlist(path: Path):
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


async def run(target: str, output_file: str = None, verbose: bool = False):
    # 1. Passive enumeration with fallbacks
    passive = await fetch_crtsh(target)
    if not passive:
        warn("crt.sh yielded nothing, trying hackertarget")
        passive = await fetch_hackertarget(target)
    if not passive:
        warn("all passive sources failed, relying on DNS brute-force only")
    info(f"passive enumeration yielded {len(passive)} unique names")


    # 2. Active: DNS brute-force from wordlist
    wordlist = load_wordlist(Path("wordlists/subdomains.txt"))
    candidates = {f"{w}.{target}" for w in wordlist}
    candidates -= passive  # don't re-resolve what we already have
    info(f"brute-forcing {len(candidates)} candidates from wordlist")

    # 3. Resolve everything in one async pool
    to_resolve = list(passive | candidates)
    info(f"resolving {len(to_resolve)} hostnames...")

    live = []
    async for host, ips in resolve_many(to_resolve, concurrency=100):
        if ips:
            live.append((host, ips))
            if verbose:
                success(f"{host} -> {', '.join(ips)}")
    
    # 4. Summary
    print()
    success(f"found {len(live)} live subdomains")
    for host, ips in sorted(live):
        print(f"  {host:40s} {', '.join(ips)}")
    
    live_sorted = sorted(live)
    
    if output_file:
        import json
        from datetime import datetime
        report = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "sources": ["crt.sh", "dns-bruteforce"],
            "subdomains": [{"host": h, "ips": ips} for h, ips in live_sorted],
            "count": len(live_sorted),
        }
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        success(f"report saved to {output_file}")