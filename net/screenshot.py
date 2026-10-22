"""
Headless-browser screenshots for HTTP services.

Takes a screenshot of each live HTTP/HTTPS service found during a scan
and saves it to the workspace's screenshots/ directory. The images are
referenced from findings by relative path (so the report can render
them if shipped alongside), or base64-embedded into the dossier when
--embed-screenshots is passed to the report generator.

Design:

  - Uses Playwright (already a dependency of the XSS module).
  - One Chromium instance reused across all screenshots — starting
    Chromium per-screenshot is 5-10x slower.
  - Opt-in during scans. Auto-screenshotting every HTTP service in a
    /24 would take 20+ minutes and produce dozens of useless images.
  - Respects HTTPS certificate errors (most targets have self-signed
    or expired certs; we still want the screenshot).
  - Captures full page by default; --viewport-only for just the
    above-the-fold view.
  - Saves PNG at 1280x720 by default; --full-size for 1920x1080.
  - Timeout 15s per page; skips pages that hang.

Usage:

    from net.screenshot import capture, capture_many

    # Single URL
    result = await capture("https://example.com", workspace=ws)
    print(result["path"])

    # Batch from service fingerprinting output
    urls = [
        "http://192.168.1.1:80",
        "https://192.168.1.1:443",
        "http://192.168.1.10:8080",
    ]
    results = await capture_many(urls, workspace=ws)

    # CLI
    python -m net.screenshot https://example.com --store
    python -m net.screenshot 192.168.1.1 --ports 80,443,8080

Findings written to the store:
    one row per URL with the screenshot path in `data`
"""

import asyncio
import base64
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from core.output import info, success, warn, error
from core.workspace import get_active, get_workspace


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

DEFAULT_WIDTH = 1280
DEFAULT_HEIGHT = 720
FULL_WIDTH = 1920
FULL_HEIGHT = 1080
DEFAULT_TIMEOUT = 15.0
DEFAULT_CONCURRENCY = 3   # Chromium is memory-heavy; 3 tabs at a time
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------------------
# Playwright check
# ---------------------------------------------------------------------

try:
    from playwright.async_api import async_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False


def _require_playwright() -> bool:
    if _HAS_PLAYWRIGHT:
        return True
    error("Playwright is not installed.")
    error("  pip install playwright")
    error("  python -m playwright install chromium")
    return False


# ---------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Turn 'host' or 'host:port' into a full URL."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url


def _safe_filename(url: str, ip: str = "", port: int = 0) -> str:
    """Build a filesystem-safe filename stem for a URL."""
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    scheme = parsed.scheme or "http"
    p = parsed.port or (443 if scheme == "https" else 80)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Collapse any remaining odd characters
    host = host.replace(":", "_").replace("/", "_")
    return f"{scheme}_{host}_{p}_{ts}"


# ---------------------------------------------------------------------
# Single capture
# ---------------------------------------------------------------------

async def _screenshot_page(page, url: str, out_path: Path,
                            full_page: bool, timeout: float) -> dict:
    """Take one screenshot using an existing Playwright page."""
    result = {
        "url": url,
        "path": None,
        "width": None,
        "height": None,
        "elapsed": 0.0,
        "error": None,
        "title": None,
        "status": None,
    }
    start = time.time()

    try:
        # Try HTTPS first, fall back to HTTP if HTTPS fails
        response = await page.goto(url, wait_until="domcontentloaded",
                                     timeout=timeout * 1000)
        # Give the page a moment to settle (fonts, images, JS)
        await asyncio.sleep(1.2)

        if response:
            result["status"] = response.status

        # Try to read the page title
        try:
            title = await page.title()
            if title:
                result["title"] = title[:200]
        except Exception:
            pass

        # Ensure the output directory exists
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # Capture
        await page.screenshot(path=str(out_path), full_page=full_page)

        # Get dimensions from the file
        if out_path.exists():
            stat = out_path.stat()
            result["path"] = str(out_path)
            result["size"] = stat.st_size

        result["elapsed"] = round(time.time() - start, 2)
        return result

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)[:200]}"
        result["elapsed"] = round(time.time() - start, 2)
        return result


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def capture(url: str, workspace=None, ip: str = "", port: int = 0,
                   full_page: bool = False, full_size: bool = False,
                   timeout: float = DEFAULT_TIMEOUT,
                   verbose: bool = False) -> dict:
    """Capture a single URL. Uses a fresh browser instance.

    Prefer capture_many() when doing more than one URL — it reuses
    the browser and is much faster.
    """
    results = await capture_many(
        [url], workspace=workspace, full_page=full_page,
        full_size=full_size, timeout=timeout, verbose=verbose,
        concurrency=1)
    return results[0] if results else {}


async def capture_many(urls: list[str], workspace=None,
                        full_page: bool = False,
                        full_size: bool = False,
                        timeout: float = DEFAULT_TIMEOUT,
                        verbose: bool = False,
                        concurrency: int = DEFAULT_CONCURRENCY) -> list[dict]:
    """Capture a list of URLs. Reuses one browser instance.

    Returns a list of result dicts, one per URL, in the same order as
    the input. Never raises — failures are returned as dicts with an
    `error` field.
    """
    if not _require_playwright():
        return [{"url": u, "error": "playwright not installed"}
                for u in urls]

    if not urls:
        return []

    # Where do screenshots go?
    out_dir = None
    if workspace is not None:
        out_dir = workspace.screenshots_dir
    else:
        # Fallback: local screenshots/ dir next to the current working dir
        out_dir = Path("screenshots")
    out_dir.mkdir(parents=True, exist_ok=True)

    width = FULL_WIDTH if full_size else DEFAULT_WIDTH
    height = FULL_HEIGHT if full_size else DEFAULT_HEIGHT

    info(f"screenshot: capturing {len(urls)} URL(s) "
         f"at {width}x{height}")

    results: list[dict] = []
    sem = asyncio.Semaphore(concurrency)

    async with async_playwright() as p:
        # Launch once, reuse for every URL
        try:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--ignore-certificate-errors",
                ],
            )
        except Exception as e:
            error(f"screenshot: could not launch Chromium: "
                  f"{type(e).__name__}: {e}")
            error("  try: python -m playwright install chromium")
            return [{"url": u, "error": "browser launch failed"}
                    for u in urls]

        try:
            async def _one(url: str, idx: int) -> dict:
                async with sem:
                    full_url = _normalize_url(url)
                    stem = _safe_filename(full_url)
                    out_path = out_dir / f"{stem}.png"

                    # Fresh page per URL — no state bleeding between sites
                    context = await browser.new_context(
                        viewport={"width": width, "height": height},
                        user_agent=BROWSER_USER_AGENT,
                        ignore_https_errors=True,
                    )
                    page = await context.new_page()

                    try:
                        r = await _screenshot_page(
                            page, full_url, out_path,
                            full_page=full_page, timeout=timeout)
                    finally:
                        try:
                            await context.close()
                        except Exception:
                            pass

                    if r.get("error"):
                        if verbose:
                            warn(f"  [{idx+1}/{len(urls)}] {url} — "
                                 f"{r['error']}")
                    else:
                        size_kb = (r.get("size") or 0) / 1024
                        title = r.get("title") or ""
                        if title:
                            title = f" — {title[:60]}"
                        success(f"  [{idx+1}/{len(urls)}] {url} → "
                                f"{out_path.name} "
                                f"({size_kb:.0f} KB, {r['elapsed']}s)"
                                f"{title}")

                    r["input_url"] = url
                    return r

            tasks = [_one(u, i) for i, u in enumerate(urls)]
            results = await asyncio.gather(*tasks, return_exceptions=False)

            # gather with return_exceptions=False raises on the first
            # exception, but our _one() catches everything. Should be
            # fine. If something slipped through, convert to error dict.
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    results[i] = {"url": urls[i],
                                  "error": f"{type(r).__name__}: {r}"}

        finally:
            try:
                await browser.close()
            except Exception:
                pass

    ok = sum(1 for r in results if r.get("path"))
    fail = len(results) - ok
    print()
    if fail == 0:
        success(f"screenshot: {ok} image(s) captured in {out_dir}")
    else:
        warn(f"screenshot: {ok} ok, {fail} failed in {out_dir}")

    return results


# ---------------------------------------------------------------------
# Store integration
# ---------------------------------------------------------------------

def _persist(results: list[dict], workspace, store, target: str):
    """Write a finding per URL (success or failure) and artifact rows."""
    if store is None:
        return

    # Summary counts
    ok = sum(1 for r in results if r.get("path"))
    fail = len(results) - ok

    # Per-URL findings (only successful ones get their own artifact;
    # failures are rolled into a summary)
    for r in results:
        if r.get("path"):
            rel_path = r["path"]
            if workspace is not None:
                try:
                    rel_path = str(
                        Path(r["path"]).relative_to(workspace.path))
                except Exception:
                    pass

            store.add_artifact(
                kind="screenshot",
                path=rel_path,
                size=r.get("size"),
                notes=r.get("title") or "",
            )

    # One summary finding
    store.add_finding({
        "module": "screenshot",
        "type": "informational",
        "severity": "info",
        "target": target,
        "evidence": f"{ok} screenshot(s) captured, {fail} failed",
        "data": {
            "target": target,
            "captured": ok,
            "failed": fail,
            "results": [
                {
                    "url": r.get("url"),
                    "path": str(r.get("path")) if r.get("path") else None,
                    "size": r.get("size"),
                    "status": r.get("status"),
                    "title": r.get("title"),
                    "error": r.get("error"),
                    "elapsed": r.get("elapsed"),
                }
                for r in results
            ],
        },
    })


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target: str, ports: list[int] | None = None,
               workspace=None, store=None, verbose: bool = False,
               full_page: bool = False, full_size: bool = False,
               timeout: float = DEFAULT_TIMEOUT) -> list[dict]:
    """CLI entry. Captures target directly or expands it with --ports."""
    # Build the URL list
    urls: list[str] = []

    target = target.strip()
    if target.startswith(("http://", "https://")):
        urls = [target]
    elif ports:
        # Build http://host:port for each
        for port in ports:
            scheme = "https" if port in (443, 8443, 9443) else "http"
            urls.append(f"{scheme}://{target}:{port}")
    else:
        # Single host, try http + https
        urls = [f"http://{target}", f"https://{target}"]

    if not urls:
        error("no URLs to capture")
        return []

    results = await capture_many(
        urls, workspace=workspace, full_page=full_page,
        full_size=full_size, timeout=timeout, verbose=verbose)

    if store is not None:
        _persist(results, workspace, store, target)

    return results


def _cli():
    import argparse

    p = argparse.ArgumentParser(
        prog="net.screenshot",
        description="Capture headless-browser screenshots of HTTP services.",
    )
    p.add_argument("target", help="URL, hostname, or IP")
    p.add_argument("--ports", default=None,
                   help="comma-separated ports (e.g. '80,443,8080')")
    p.add_argument("--full-page", action="store_true",
                   help="capture entire scrollable page, not just viewport")
    p.add_argument("--full-size", action="store_true",
                   help="use 1920x1080 instead of 1280x720")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help=f"per-page timeout in seconds (default {DEFAULT_TIMEOUT})")
    p.add_argument("--store", action="store_true",
                   help="write artifacts + finding to active workspace")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    # Parse ports if given
    ports: list[int] = []
    if args.ports:
        for piece in args.ports.split(","):
            piece = piece.strip()
            if piece.isdigit():
                ports.append(int(piece))

    workspace = None
    store = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; use `toolkit workspace switch`")
        else:
            workspace = get_workspace(active)
            store = open_store(workspace.db_path, workspace_name=active)

    asyncio.run(run(
        args.target,
        ports=ports or None,
        workspace=workspace, store=store,
        verbose=args.verbose,
        full_page=args.full_page,
        full_size=args.full_size,
        timeout=args.timeout,
    ))


if __name__ == "__main__":
    _cli()