"""
Browser-driven session capture.

For CMSes where the login flow requires JavaScript, dynamic CSRF tokens,
or a redirect chain that a plain HTTP client can't follow, this module
drives a headless browser instead. It fills the login form, submits,
waits for navigation, and extracts the resulting cookies.

The cookies can then be fed to the toolkit's SQLi/NoSQL/XSS scanners,
which will operate as the authenticated user.

Requires: playwright (pip install playwright && playwright install chromium)
"""

import asyncio

try:
    from playwright.async_api import async_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False

from core.output import info, success, warn, error


async def capture_session(login_url, email_field, password_field,
                          email, password, success_marker=None,
                          wait_after_submit=3.0, timeout=15.0,
                          headless=True, verbose=False):
    """Drive a real browser through a login flow and return the cookies.

    Returns:
      {
        "success": bool,
        "cookies": {name: value, ...},
        "final_url": "...",
        "error": None | str,
      }
    """
    if not _HAS_PLAYWRIGHT:
        return {
            "success": False, "cookies": {}, "final_url": None,
            "error": "playwright not installed",
        }

    result = {
        "success": False,
        "cookies": {},
        "final_url": None,
        "error": None,
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context()
        page = await context.new_page()

        try:
            if verbose:
                info(f"session: loading {login_url}")
            await page.goto(login_url, wait_until="load",
                            timeout=timeout * 1000)

            # Fill the fields. The selectors are CSS selectors or
            # name= patterns. Playwright accepts both.
            if verbose:
                info(f"session: filling {email_field}")
            await page.fill(email_field, email)

            if verbose:
                info(f"session: filling {password_field}")
            await page.fill(password_field, password)

            # Submit. Try a couple of strategies in order.
            if verbose:
                info("session: submitting")
            try:
                await page.press(password_field, "Enter")
            except Exception:
                try:
                    await page.click('button[type="submit"]')
                except Exception:
                    await page.evaluate(
                        "document.querySelector('form').submit()")

            # Wait for navigation or a marker.
            try:
                await page.wait_for_load_state("networkidle",
                                               timeout=timeout * 1000)
            except Exception:
                pass

            await asyncio.sleep(wait_after_submit)

            final_url = page.url
            result["final_url"] = final_url

            # Extract all cookies for the current origin.
            cookies = await context.cookies()
            for c in cookies:
                result["cookies"][c["name"]] = c["value"]

            # Success detection.
            if success_marker:
                content = await page.content()
                if success_marker.lower() in content.lower():
                    result["success"] = True
                    if verbose:
                        success(f"session: success (marker "
                                f"{success_marker!r} present)")
                else:
                    if verbose:
                        warn(f"session: marker {success_marker!r} not found")
            else:
                # Heuristic: if we ended up somewhere other than the
                # login URL, we probably got in.
                if final_url != login_url and "login" not in final_url.lower():
                    result["success"] = True
                    if verbose:
                        success(f"session: navigated to {final_url}")

            if verbose and result["cookies"]:
                cookie_names = ", ".join(result["cookies"].keys())
                info(f"session: captured cookies: {cookie_names}")

        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}"
            if verbose:
                error(f"session: {result['error']}")
        finally:
            await browser.close()

    return result


# ---------------------------------------------------------------------
# Cookie formatting helpers
# ---------------------------------------------------------------------

def cookies_to_header(cookies: dict) -> str:
    """Format a cookie dict as a Cookie: header value."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def cookies_to_dict(cookies: dict) -> dict:
    """Pass-through, for symmetry with the CLI options."""
    return dict(cookies)