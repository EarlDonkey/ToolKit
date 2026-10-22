import asyncio
from typing import Union, Dict
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn


def same_host(url: str, base_host: str) -> bool:
    """Check if the URL belongs to the target hostname."""
    try:
        return urlparse(url).hostname == base_host
    except Exception:
        return False


def has_query_params(url: str) -> bool:
    """Check if the URL contains query parameters."""
    try:
        return bool(urlparse(url).query)
    except Exception:
        return False


async def worker(
    queue: asyncio.Queue,
    session,
    rate_limiter: RateLimiter,
    base_host: str,
    max_depth: int,
    max_urls: int,
    verbose: bool,
    visited: set,
    enqueued: set,
    param_urls: set,
    all_links: set,
    cookies: dict = None,
):
    """Concurrent worker that pulls targets from the shared queue."""
    while True:
        try:
            url, depth = await queue.get()
        except asyncio.CancelledError:
            break

        try:
            if len(visited) >= max_urls:
                continue

            visited.add(url)

            # Pass cookies to fetch
            status, headers, body, final_url = await fetch(
                session, url, rate_limiter, cookies=cookies
            )
            if status is None:
                continue

            if not same_host(final_url, base_host):
                continue

            if verbose:
                info(f"[{status}] {url}")

            if has_query_params(final_url):
                param_urls.add(final_url)

            if depth >= max_depth:
                continue

            ctype = headers.get("Content-Type", "") if headers else ""
            if "html" not in ctype.lower():
                continue

            try:
                soup = BeautifulSoup(body or "", "html.parser")
            except Exception:
                continue

            for a in soup.find_all("a", href=True):
                link = urljoin(final_url, a["href"]).split("#", 1)[0]

                if not link.startswith(("http://", "https://")):
                    continue
                if not same_host(link, base_host):
                    continue

                all_links.add(link)

                if has_query_params(link):
                    param_urls.add(link)

                if link not in enqueued and len(visited) < max_urls:
                    enqueued.add(link)
                    await queue.put((link, depth + 1))
        finally:
            queue.task_done()


async def crawl(
    start_url: str,
    max_depth: int = 2,
    max_urls: int = 500,
    rate: float = 5.0,
    verbose: bool = False,
    concurrency: int = 10,
    cookie: Union[str, Dict[str, str]] = None,
):
    """Crawl start_url concurrently, returning (visited_urls, param_urls, all_links)."""
    base_host = urlparse(start_url).hostname
    rate_limiter = RateLimiter(rate)

    # Parse string cookie to dict if necessary
    if isinstance(cookie, str):
        cookies_dict = parse_cookie_string(cookie)
    else:
        cookies_dict = cookie or {}

    visited = set()
    enqueued = {start_url}
    param_urls = set()
    all_links = set()

    queue = asyncio.Queue()
    await queue.put((start_url, 0))

    async with new_session() as session:
        workers = [
            asyncio.create_task(
                worker(
                    queue, session, rate_limiter, base_host, max_depth, max_urls, verbose, visited, enqueued, param_urls, all_links,
                    cookies=cookies_dict
                )
            )
            for _ in range(concurrency)
        ]

        await queue.join()

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    return visited, param_urls, all_links


async def run(
    target: str,
    max_depth: int = 2,
    rate: float = 5.0,
    verbose: bool = False,
    concurrency: int = 10,
    cookie: Union[str, Dict[str, str]] = None,
):
    """CLI entry point."""
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    info(f"Crawling {target} (depth={max_depth}, rate={rate}/s, workers={concurrency})")

    visited, param_urls, all_links = await crawl(
        target,
        max_depth=max_depth,
        rate=rate,
        verbose=verbose,
        concurrency=concurrency,
        cookie=cookie,
    )

    print()
    success(f"Visited {len(visited)} URLs, found {len(param_urls)} with parameters")

    if param_urls:
        print()
        info("URLs with parameters:")
        for u in sorted(param_urls):
            print(f"  {u}")