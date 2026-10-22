import asyncio

from core.output import info, success, warn, error


# Top 100 ports — fast default
TOP_100 = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443,
    # extend with a few common extras
    20, 69, 123, 137, 138, 161, 162, 179, 389, 427, 465, 500, 514, 515,
    548, 554, 587, 631, 636, 873, 902, 989, 990, 1025, 1026, 1027, 1028,
    1029, 1080, 1194, 1433, 1434, 1521, 1701, 1720, 1755, 1812, 1813,
    1900, 2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 2483,
    2484, 3000, 3128, 3260, 3268, 3269, 3283, 3690, 4000, 4125, 4243,
    4443, 4444, 4500, 5000, 5060, 5061, 5222, 5269, 5357, 5432, 5555,
    5632, 5800, 5901, 5985, 5986, 6000, 6379, 6666, 7001, 7002, 7443,
    8000, 8008, 8010, 8081, 8082, 8083, 8088, 8090, 8181, 8200, 8333,
    8888, 9000, 9001, 9090, 9100, 9200, 9300, 9418, 9999, 10000, 11211,
    27017, 27018, 50000,
]


async def scan_port(ip: str, port: int, timeout: float = 1.5):
    """Attempt a TCP connect. Return port if open, None otherwise."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_host(ip: str, ports: list[int], concurrency: int = 200):
    """Scan many ports on one host. Returns sorted list of open ports."""
    sem = asyncio.Semaphore(concurrency)

    async def _one(p):
        async with sem:
            return await scan_port(ip, p)

    results = await asyncio.gather(*[_one(p) for p in ports])
    return sorted(p for p in results if p is not None)


async def run(target: str, top: int = 100, verbose: bool = False):
    from core.dns import resolve_a

    info(f"resolving {target}")
    ips = await resolve_a(target)
    if not ips:
        error(f"could not resolve {target}")
        return

    ports = TOP_100[:top]
    info(f"scanning {len(ports)} ports on {len(ips)} IP(s)")
    warn("Scans hosts..technically..")

    for ip in ips:
        info(f"scanning {ip}...")
        open_ports = await scan_host(ip, ports)

        print()
        success(f"{ip}: {len(open_ports)} open ports")
        for p in open_ports:
            print(f"  {ip}:{p}")