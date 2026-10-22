"""
HTTP fingerprint randomization.

Provides browser-like header profiles so the toolkit's requests don't
look like a Python script. The target of this module is naive WAF
detection, rate-based heuristics, and the "toolkit/0.1" User-Agent
that currently identifies every request.

What this does:

  - Loads a set of realistic browser profiles from
    core/signatures/browser_profiles.json.
  - Picks one profile per scan session (not per request — per-request
    randomization is *more* detectable, not less).
  - Merges the profile into request headers, preserving the profile's
    header order and letting the caller win on headers the profile
    doesn't define (Authorization, Cookie, custom).

What this does NOT do:

  - TLS (JA3/JA4) fingerprint spoofing. Python's ssl module presents a
    completely different ClientHello than Chrome or Firefox. That
    requires swapping aiohttp for curl_cffi, which is out of scope.
  - TCP/IP fingerprint spoofing. Also out of scope.
  - Behavioral mimicry (loading subresources, executing JS). Out of scope.

Design: process-wide default profile.

  Every module calls core.http.new_session() with no arguments. Rather
  than plumbing a profile argument through every call site, we use a
  module-level default that toolkit.py sets once at startup:

      from core import fingerprint
      fingerprint.set_default(args.fingerprint)  # once, in main()

  new_session() then reads the default and attaches it to the session.
  Modules never need to know this exists.

Usage from a module that wants a specific profile (rare):

    from core import fingerprint
    profile = fingerprint.pick_profile("chrome_130_win")
    session = new_session(profile=profile)

Usage from toolkit.py (the normal case):

    fingerprint.set_default("random")   # or a specific profile name
"""

import json
import random
import secrets
from pathlib import Path

from core.output import info, warn


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

PROFILES_PATH = Path(__file__).parent / "signatures" / "browser_profiles.json"

# Set at import time if the JSON can't be loaded. Minimal but functional:
# gives us a Chrome-on-Windows UA and nothing else. Better than crashing.
_FALLBACK_PROFILES = {
    "chrome_130_win": {
        "label": "Chrome 130 / Windows 11 (fallback)",
        "headers": {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/130.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        },
    },
}


# ---------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------

_PROFILES_CACHE: dict | None = None


def load_profiles(force_reload: bool = False) -> dict:
    """Load the profile database.

    Returns {profile_name: {"label": str, "headers": {...}}}.
    Falls back to _FALLBACK_PROFILES if the JSON is missing or malformed.
    """
    global _PROFILES_CACHE
    if _PROFILES_CACHE is not None and not force_reload:
        return _PROFILES_CACHE

    try:
        raw = json.loads(PROFILES_PATH.read_text(encoding="utf-8"))
        profiles = raw.get("profiles") or {}
        # Validate every profile has a headers dict
        cleaned = {}
        for name, spec in profiles.items():
            headers = spec.get("headers")
            if not isinstance(headers, dict) or not headers:
                continue
            cleaned[name] = {
                "label": spec.get("label") or name,
                "headers": dict(headers),
            }
        if not cleaned:
            raise ValueError("no valid profiles in JSON")
        _PROFILES_CACHE = cleaned
        return cleaned
    except FileNotFoundError:
        warn(f"fingerprint: {PROFILES_PATH} not found, using fallback")
    except Exception as e:
        warn(f"fingerprint: could not load profiles "
             f"({type(e).__name__}: {e}), using fallback")

    _PROFILES_CACHE = dict(_FALLBACK_PROFILES)
    return _PROFILES_CACHE


def list_profile_names() -> list[str]:
    """Return the names of every loaded profile, sorted."""
    return sorted(load_profiles().keys())


# ---------------------------------------------------------------------
# Profile selection
# ---------------------------------------------------------------------

def pick_profile(name: str | None = None) -> dict:
    """Return a profile dict.

    name=None or name="random" → random profile.
    name="chrome_130_win"      → that profile (raises if not found).
    """
    profiles = load_profiles()

    if name is None or name == "random":
        chosen = random.choice(list(profiles.keys()))
        spec = profiles[chosen]
        return {
            "name": chosen,
            "label": spec["label"],
            "headers": dict(spec["headers"]),
        }

    if name not in profiles:
        raise ValueError(
            f"unknown profile: {name!r}; "
            f"available: {', '.join(list_profile_names())}"
        )
    spec = profiles[name]
    return {
        "name": name,
        "label": spec["label"],
        "headers": dict(spec["headers"]),
    }


def resolve_user_agent(value: str | None) -> dict | None:
    """Turn a --user-agent value into a profile.

    If value matches a known profile name, returns that profile.
    Otherwise, builds a minimal profile around the literal UA string.
    Returns None if value is None.
    """
    if not value:
        return None

    profiles = load_profiles()
    if value in profiles:
        return pick_profile(value)

    # Literal UA. Build a minimal profile with just UA + sensible defaults.
    # We don't pretend to be a browser here — the user asked for a specific
    # string.
    return {
        "name": "literal",
        "label": f"literal UA: {value[:40]}",
        "headers": {
            "User-Agent": value,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        },
    }


# ---------------------------------------------------------------------
# Header merging
# ---------------------------------------------------------------------

# Headers the caller is always allowed to override, even if the profile
# defines them. These carry request-specific state (auth, cookies) that
# has nothing to do with fingerprint. Everything NOT in this set gets
# overridden by the profile.
_CALLER_PRIORITY_HEADERS = {
    "authorization",
    "cookie",
    "content-type",
    "content-length",
    "referer",
    "origin",
    "x-requested-with",
    "x-csrf-token",
    "x-xsrf-token",
}


def apply_profile(caller_headers: dict | None, profile: dict,
                  override_ua: bool = True) -> dict:
    """Merge a profile into caller-supplied headers.

    Rules:
      - Profile headers are the base, in profile order.
      - Caller-supplied headers whose name is in
        _CALLER_PRIORITY_HEADERS override the profile's value.
      - Caller-supplied headers not in that set are ignored (the
        profile's value wins). This is the "profile wins" rule.
      - If override_ua is False, the caller's User-Agent wins if present.

    Returns a fresh dict; caller_headers is not mutated.
    """
    caller_headers = caller_headers or {}
    caller_lc = {k.lower(): (k, v) for k, v in caller_headers.items()}

    merged: dict = {}

    # Profile headers first, in their stored order.
    # Special-case Host: skip it here — aiohttp sets it from the URL,
    # and setting it manually breaks things.
    for name, value in profile.get("headers", {}).items():
        if name.lower() == "host":
            continue
        merged[name] = value

    # Caller overrides.
    for name_lc, (orig_name, orig_value) in caller_lc.items():
        if name_lc == "host":
            continue
        if name_lc in _CALLER_PRIORITY_HEADERS:
            # Remove any profile entry with the same name (any case),
            # then add the caller's.
            for existing in list(merged.keys()):
                if existing.lower() == name_lc:
                    del merged[existing]
            merged[orig_name] = orig_value
        elif name_lc == "user-agent" and not override_ua:
            for existing in list(merged.keys()):
                if existing.lower() == "user-agent":
                    del merged[existing]
            merged[orig_name] = orig_value

    return merged


# ---------------------------------------------------------------------
# Session attachment
# ---------------------------------------------------------------------

# Attribute name we stash the profile on. Underscore-prefixed so it's
# clearly "internal" — modules should not read it directly.
_SESSION_ATTR = "_tk_profile"


def attach_profile(session, profile: dict):
    """Attach a profile to an aiohttp session object."""
    setattr(session, _SESSION_ATTR, profile)


def get_profile(session) -> dict | None:
    """Return the profile attached to a session, if any."""
    return getattr(session, _SESSION_ATTR, None)


# ---------------------------------------------------------------------
# Process-wide default
# ---------------------------------------------------------------------

_DEFAULT_PROFILE: dict | None = None


def set_default(value) -> dict:
    """Set the process-wide default profile.

    Called once by toolkit.py at startup. value can be:
      - None or "random"      → pick a random profile
      - a profile name string → load that profile
      - a profile dict        → use as-is
      - a literal UA string   → wrapped in a minimal profile

    Returns the resolved profile.
    """
    global _DEFAULT_PROFILE

    if value is None:
        _DEFAULT_PROFILE = pick_profile("random")
    elif isinstance(value, dict):
        _DEFAULT_PROFILE = value
    elif isinstance(value, str):
        # Try profile name first, then literal UA.
        if value in load_profiles() or value == "random":
            _DEFAULT_PROFILE = pick_profile(value)
        else:
            _DEFAULT_PROFILE = resolve_user_agent(value)
            if _DEFAULT_PROFILE is None:
                _DEFAULT_PROFILE = pick_profile("random")
    else:
        _DEFAULT_PROFILE = pick_profile("random")

    return _DEFAULT_PROFILE


def get_default() -> dict:
    """Return the current default profile, initializing if needed."""
    global _DEFAULT_PROFILE
    if _DEFAULT_PROFILE is None:
        _DEFAULT_PROFILE = pick_profile("random")
    return _DEFAULT_PROFILE


def describe(profile: dict | None = None) -> str:
    """One-line human description of a profile."""
    p = profile or get_default()
    return f"{p.get('name')} ({p.get('label')})"