import asyncio
import time
from urllib.parse import urlparse

import aiohttp
from core.output import warn, error

# Default timeout and rate. DEFAULT_USER_AGENT is deliberately gone —
# the UA now comes from the fingerprint profile.
DEFAULT_TIMEOUT = 10.0
DEFAULT_RATE = 1500  # requests per second


def parse_cookie_string(cookie: str) -> dict:
    """Turn 'PHPSESSID=abc; security=low' into a dict."""
    out = {}
    if not cookie:
        return out
    for part in cookie.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


class RateLimiter:
    """A true lazy-fill Token Bucket rate limiter that won't bottleneck under high concurrency."""
    def __init__(self, rate: float, capacity: float = 100.0):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def wait(self):
        if self.rate <= 0:
            return

        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self.tokens = min(self.capacity, self.tokens + (elapsed * self.rate))

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return

            needed_tokens = 1.0 - self.tokens
            sleep_time = needed_tokens / self.rate

            self.tokens = 0.0
            self._last += sleep_time

        await asyncio.sleep(sleep_time)


def _merge_headers(session, headers: dict | None) -> dict:
    """Merge the session's fingerprint profile into the given headers.

    Lazy import so core.http doesn't hard-depend on core.fingerprint —
    if the module is missing (e.g. partial install), requests fall back
    to whatever headers the caller passed.
    """
    try:
        from core import fingerprint as fp
    except ImportError:
        return dict(headers or {})

    profile = fp.get_profile(session) if session is not None else None
    if profile is None:
        profile = fp.get_default()

    return fp.apply_profile(headers, profile)


async def resolve_root(target, session=None, limiter=None,
                        timeout=10.0, quiet=True, verbose=False):
    """Find a working base URL for a target. (unchanged behavior)"""
    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=1000.0)

    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        host = parsed.hostname or ""
    else:
        host = target.split("/")[0].split(":")[0]

    if not host:
        if own_session:
            await session.close()
        return None

    bare_host = host[4:] if host.startswith("www.") else host
    candidates = [
        f"https://{bare_host}",
        f"https://www.{bare_host}",
        f"http://{bare_host}",
        f"http://www.{bare_host}",
    ]

    result = None
    for base in candidates:
        try:
            status, _h, _body, _ = await fetch(
                session, base, limiter, timeout=timeout, quiet=quiet)
        except Exception:
            continue
        if status is not None:
            result = base
            break

    if own_session:
        await session.close()
    return result


async def fetch(
    session,
    url,
    rate_limiter,
    method="GET",
    timeout=DEFAULT_TIMEOUT,
    allow_redirects=True,
    cookies=None,
    headers=None,
    quiet=False,
    **kwargs,
):
    """Perform an HTTP request.

    Header precedence:
      1. Profile headers (from the session's fingerprint profile).
      2. Caller-supplied headers for Authorization, Cookie, Content-Type,
         and other request-specific fields.
      3. Caller-supplied User-Agent is overridden by the profile.

    If quiet=True, suppress the per-request warning on connection
    failure. Used by callers that are intentionally probing multiple
    candidates and don't want a warning for each expected miss.
    """
    await rate_limiter.wait()

    merged = _merge_headers(session, headers)
    kwargs["headers"] = merged

    try:
        async with session.request(
            method,
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=allow_redirects,
            ssl=False,
            cookies=cookies,
            **kwargs,
        ) as resp:
            body = await resp.text(errors="ignore")
            return resp.status, dict(resp.headers), body, str(resp.url)
    except asyncio.TimeoutError:
        if not quiet:
            warn(f"timeout: {url}")
        return None, None, None, None
    except aiohttp.ClientError as e:
        if not quiet:
            warn(f"request failed ({type(e).__name__}): {url}")
        return None, None, None, None


def new_session(profile=None):
    """Create a new aiohttp session with the default fingerprint profile.

    If `profile` is None, uses the process-wide default set by
    fingerprint.set_default() (typically called once by toolkit.py).
    Pass an explicit profile dict to override for this session.
    """
    session = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
    )
    try:
        from core import fingerprint as fp
        if profile is None:
            profile = fp.get_default()
        fp.attach_profile(session, profile)
    except ImportError:
        pass
    return session


# ── Pre-flight reachability check ───────────────────────────────────

class TargetUnreachable(Exception):
    """Raised when the pre-flight check determines the target is down.

    Modules catch this and abort cleanly, reporting one message instead
    of flooding the terminal with per-request connection errors.
    """
    def __init__(self, url, reason):
        self.url = url
        self.reason = reason
        super().__init__(f"target unreachable: {url} ({reason})")


async def preflight(url, session=None, limiter=None, timeout=5.0):
    """Check that a target actually responds before starting a scan.

    Returns (ok, reason). If ok is True, the caller proceeds. If
    ok is False, `reason` is a short human string explaining why.

    Does NOT raise. Callers decide whether to abort or warn.
    """
    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=1000.0)

    try:
        await limiter.wait()
        merged = _merge_headers(session, None)
        async with session.request(
            "GET", url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            ssl=False,
            headers=merged,
        ) as resp:
            return True, f"HTTP {resp.status}"
    except asyncio.TimeoutError:
        return False, f"connection timeout after {timeout}s"
    except aiohttp.ClientConnectorError as e:
        return False, "connection refused (is the server running?)"
    except aiohttp.ClientError as e:
        return False, f"{type(e).__name__}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        if own_session:
            await session.close()


class FailureTracker:
    """Counts consecutive request failures during a scan.

    (unchanged — same as before)
    """
    def __init__(self, trip_after=20):
        self.trip_after = trip_after
        self.consecutive = 0
        self.total_failures = 0
        self.total_successes = 0
        self.tripped = False

    def record_success(self):
        self.consecutive = 0
        self.total_successes += 1

    def record_failure(self):
        self.consecutive += 1
        self.total_failures += 1
        if self.consecutive >= self.trip_after:
            self.tripped = True
        return self.tripped

    def summary(self) -> str:
        return (f"{self.total_successes} success, "
                f"{self.total_failures} failed, "
                f"consecutive={self.consecutive}")