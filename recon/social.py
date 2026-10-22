"""
Social media profile discovery and employee enumeration.

Two things this module does:

  1. Find publicly-linked social media profiles for a target domain
     (Twitter/X, LinkedIn, Facebook, Instagram, YouTube, GitHub,
     GitLab, Reddit, Mastodon, Bluesky). These come from scraping
     the target's own website — footer, header, /contact, /about.

  2. Enumerate people associated with the target. Sources:
       - GitHub org membership (public API, unauthenticated or with
         a token)
       - Team pages on the target's site (/team, /about/team, etc.)
       - Names parsed from discovered emails (john.smith@ → John Smith)

     The output is a unified list of names, each tagged with its
     source. This list feeds recon.emails's pattern generator:
     learn the email format from discovered emails, apply the
     format to these names, get candidate addresses.

GitHub authentication:

  Unauthenticated: 60 requests/hour per IP. Works fine for small
    orgs. Fails partway through large ones; we report how far we got.
  Authenticated:   5000 requests/hour. Set GITHUB_TOKEN in the
    environment, or pass --github-token. No setup needed for the
    common case.

Root resolution:

  Before making many HTTP requests to the target, we probe once to
  find a working base URL. Tries https://{host}, then
  https://www.{host}, then http://{host}, then http://www.{host}.
  Whichever responds first becomes the root for every subsequent
  request. This turns "12 ClientConnectorDNSError warnings" into
  one line: either "resolved root: X" or "does not resolve".

Verification is done per-platform:

  verified   — GitHub, YouTube, Mastodon, Bluesky
               (light-touch: one HEAD/GET to confirm the URL is real)
  unverified — Twitter/X, LinkedIn, Facebook, Instagram
               (these actively block scrapers; we just report the URL)

Findings written to the store:
    one row per target with all discovered profiles and names in `data`
"""

import asyncio
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

CONTACT_PATHS = [
    "/", "/contact", "/contact-us", "/about", "/about-us",
    "/impressum", "/legal", "/company",
]

TEAM_PATHS = [
    "/team", "/about/team", "/about-us/team", "/company/team",
    "/careers/team", "/people", "/about/people", "/staff",
    "/about/staff", "/leadership", "/about/leadership",
    "/management", "/about/management",
]

NON_MASTODON_DOMAINS = {
    "tiktok.com", "www.tiktok.com",
    "twitter.com", "x.com", "www.twitter.com", "www.x.com",
    "instagram.com", "www.instagram.com",
    "threads.net", "www.threads.net",
    "github.com", "www.github.com",
    "medium.com", "www.medium.com",
    "youtube.com", "www.youtube.com",
}


SOCIAL_PATTERNS = {
    "twitter": re.compile(
        r'https?://(?:www\.)?(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,50})',
        re.IGNORECASE),
    "linkedin": re.compile(
        r'https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:company|in|school)/([A-Za-z0-9_\-\.%]+)',
        re.IGNORECASE),
    "facebook": re.compile(
        r'https?://(?:www\.)?facebook\.com/([A-Za-z0-9_\-\.]+)',
        re.IGNORECASE),
    "instagram": re.compile(
        r'https?://(?:www\.)?instagram\.com/([A-Za-z0-9_\.]+)',
        re.IGNORECASE),
    "youtube": re.compile(
        r'https?://(?:www\.)?youtube\.com/(?:@|c/|channel/|user/)?([A-Za-z0-9_\-]+)',
        re.IGNORECASE),
    "github": re.compile(
        r'https?://(?:www\.)?github\.com/([A-Za-z0-9_\-]+)',
        re.IGNORECASE),
    "gitlab": re.compile(
        r'https?://(?:www\.)?gitlab\.com/([A-Za-z0-9_\-]+)',
        re.IGNORECASE),
    "reddit": re.compile(
        r'https?://(?:www\.)?reddit\.com/(?:r|u|user)/([A-Za-z0-9_\-]+)',
        re.IGNORECASE),
    "mastodon": re.compile(
        r'https?://([a-z0-9\-\.]+\.[a-z]{2,})/@([A-Za-z0-9_]+)',
        re.IGNORECASE),
    "bluesky": re.compile(
        r'https?://bsky\.app/profile/([A-Za-z0-9_\-\.]+)',
        re.IGNORECASE),
}

USERNAME_DENYLIST = {
    "share", "sharer", "share.php", "sharing", "intent", "home",
    "index", "pages", "profile.php", "watch", "channel", "user",
    "about", "login", "signup", "help", "support", "explore",
    "hashtag", "search", "dialog", "plugins", "sharer.php",
    "tr", "privacy", "terms", "policies",
}

BAD_PATH_FRAGMENTS = (
    "share?", "sharer", "intent/tweet", "dialog/",
    "plugins/", "tr?", "/p/", "/reel/", "/story/",
)


# ── SESSION S1 ── Employee enumeration constants ─────────────────────

GITHUB_API = "https://api.github.com"
GITHUB_USER_AGENT = "toolkit-recon/0.1"

GITHUB_MAX_PAGES = 10
GITHUB_PAGE_SIZE = 100
GITHUB_MAX_USER_LOOKUPS = 200

_EMAIL_RE = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
)

NOT_A_NAME = {
    "team", "about", "contact", "careers", "jobs", "home",
    "read", "more", "click", "here", "learn", "see", "our",
    "the", "and", "for", "with", "from", "this", "that",
    "privacy", "terms", "legal", "cookie", "cookies",
    "search", "menu", "login", "signup", "register",
    "founder", "co-founder", "ceo", "cto", "cfo", "coo",
    "president", "vice", "director", "manager", "lead",
    "engineer", "developer", "designer", "marketing",
    "sales", "support", "operations", "product",
}

# ── END SESSION S1 constants ─────────────────────────────────────────


# ---------------------------------------------------------------------
# Root resolution (S1.1)
# ---------------------------------------------------------------------

async def _resolve_root(domain: str, session, limiter,
                        verbose: bool = False) -> str | None:
    """Pick a working base URL for the domain.

    Accepts a bare domain ("tyas.tyc.edu.tw") or a full URL
    ("https://www.tyas.tyc.edu.tw/"). Extracts the hostname from
    either form, strips any leading "www.", and tries every scheme
    + host combination until one responds.

    Returns the first base URL that returned any HTTP status, or
    None if all four candidates failed to connect.

    Fetches are done with quiet=True so the expected misses on the
    first few candidates don't print warnings.
    """
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        host = parsed.hostname or ""
    else:
        host = domain.split("/")[0].split(":")[0]

    if not host:
        return None

    bare_host = host[4:] if host.startswith("www.") else host

    candidates = [
        f"https://{bare_host}",
        f"https://www.{bare_host}",
        f"http://{bare_host}",
        f"http://www.{bare_host}",
    ]

    for base in candidates:
        try:
            status, _h, _body, _ = await fetch(
                session, base, limiter, timeout=10.0, quiet=True)
        except Exception:
            continue
        if status is not None:
            if verbose:
                info(f"    resolved root: {base}")
            return base
    return None

# ── END SESSION S1.1 ──


# ---------------------------------------------------------------------
# Page scraping (social profile discovery)
# ---------------------------------------------------------------------

def _clean_username(u: str) -> str:
    """Normalize a captured username and strip query strings."""
    u = u.strip().rstrip("/")
    for sep in ("?", "#"):
        if sep in u:
            u = u.split(sep, 1)[0]
    return u


def _looks_like_username(u: str) -> bool:
    """Reject junk usernames caught by an over-greedy regex."""
    if not u:
        return False
    low = u.lower()
    if low in USERNAME_DENYLIST:
        return False
    if any(bad in low for bad in BAD_PATH_FRAGMENTS):
        return False
    if len(u) > 40:
        return False
    if u.isdigit():
        return False
    return True


def extract_social_links(html: str) -> dict[str, set[str]]:
    """Return {platform: {identifier, ...}} from an HTML body."""
    out: dict[str, set[str]] = {}
    for platform, rx in SOCIAL_PATTERNS.items():
        for m in rx.finditer(html):
            if platform == "mastodon":
                instance = m.group(1).lower()
                username = _clean_username(m.group(2))
                if instance in NON_MASTODON_DOMAINS:
                    continue
                if not _looks_like_username(username):
                    continue
                out.setdefault(platform, set()).add(
                    f"{instance}/{username}")
            else:
                username = _clean_username(m.group(1))
                if not _looks_like_username(username):
                    continue
                out.setdefault(platform, set()).add(username)
    return out


async def scrape_profiles(base_url: str, session, limiter,
                           verbose: bool = False) -> dict[str, set[str]]:
    """Fetch contact pages and extract social links."""
    root = await _resolve_root(base_url, session, limiter,
                                verbose=verbose)
    if root is None:
        if verbose:
            warn(f"    {base_url} does not resolve; skipping scrape")
        return {}

    found: dict[str, set[str]] = {}
    consecutive_failures = 0

    for path in CONTACT_PATHS:
        url = root + path
        try:
            status, _h, body, _ = await fetch(session, url, limiter,
                                                timeout=15.0)
        except Exception as e:
            if verbose:
                warn(f"    {type(e).__name__}: {url}")
            consecutive_failures += 1
            if consecutive_failures >= 5:
                if verbose:
                    warn("    aborting after 5 consecutive failures")
                break
            continue

        if status is None:
            consecutive_failures += 1
            if consecutive_failures >= 5:
                break
            continue

        consecutive_failures = 0

        if status != 200 or not body:
            continue
        if len(body) < 500:
            continue

        if verbose:
            info(f"    scraped {url} ({len(body)} bytes)")

        page_links = extract_social_links(body)
        for platform, usernames in page_links.items():
            found.setdefault(platform, set()).update(usernames)

        await asyncio.sleep(0.3)

    return found


# ---------------------------------------------------------------------
# DNS TXT verification tokens
# ---------------------------------------------------------------------

async def fetch_dns_verifications(domain: str, verbose: bool = False) -> dict:
    """Look up DNS TXT records for known verification token patterns."""
    import subprocess
    out = {}
    try:
        proc = await asyncio.get_event_loop().run_in_executor(
            None, lambda: subprocess.run(
                ["nslookup", "-type=TXT", domain],
                capture_output=True, text=True, timeout=8.0))
        text = proc.stdout
    except Exception:
        return out

    token_patterns = {
        "google-site-verification":       r"google-site-verification=([A-Za-z0-9_\-]+)",
        "ms-verify":                      r"ms=ms(\d+)",
        "facebook-domain-verification":   r"facebook-domain-verification=([a-z0-9]+)",
        "atlassian-domain-verification":  r"atlassian-domain-verification=([A-Za-z0-9_\-]+)",
        "github-challenge":               r"_github-challenge-([A-Za-z0-9\-]+)",
        "stripe-verification":            r"stripe-verification=([A-Za-z0-9_\-]+)",
        "apple-domain-verification":      r"apple-domain-verification=([A-Za-z0-9]+)",
        "adobe-idp-site-verification":    r"adobe-idp-site-verification=([A-Za-z0-9_\-]+)",
        "have-i-been-pwned-verification": r"have-i-been-pwned-verification=([a-f0-9]+)",
    }
    for name, rx in token_patterns.items():
        m = re.search(rx, text, re.IGNORECASE)
        if m:
            out[name] = m.group(1) if m.groups() else "present"

    m = re.search(r'"?(v=spf1[^"]+)"?', text)
    if m:
        out["spf"] = m.group(1)

    return out


# ---------------------------------------------------------------------
# Profile verification
# ---------------------------------------------------------------------

VERIFIABLE_PLATFORMS = {"github", "youtube", "mastodon", "bluesky"}


async def verify_profile(platform: str, username: str,
                          session, limiter, verbose: bool = False) -> dict:
    """Confirm a profile URL actually resolves."""
    if platform == "github":
        url = f"https://github.com/{username}"
    elif platform == "youtube":
        if not username.startswith("@"):
            url = f"https://www.youtube.com/@{username}"
        else:
            url = f"https://www.youtube.com/{username}"
    elif platform == "mastodon":
        if "/" not in username:
            return {"verified": False, "status": None,
                    "reason": "no instance"}
        instance, user = username.split("/", 1)
        url = f"https://{instance}/@{user}"
    elif platform == "bluesky":
        url = f"https://bsky.app/profile/{username}"
    else:
        return {"verified": False, "status": None,
                "reason": "unverifiable platform"}

    try:
        status, _h, _body, _ = await fetch(session, url, limiter,
                                             timeout=10.0)
    except Exception as e:
        if verbose:
            warn(f"    verify {platform}/{username}: "
                 f"{type(e).__name__}")
        return {"verified": False, "status": None,
                "reason": type(e).__name__}

    verified = status == 200
    return {
        "verified": verified,
        "status": status,
        "url": url,
    }


# ── SESSION S1 ── GitHub org enumeration ────────────────────────────


def _github_headers(token: str | None = None) -> dict:
    """Build request headers for a GitHub API call."""
    headers = {
        "User-Agent": GITHUB_USER_AGENT,
        "Accept": "application/vnd.github+json",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _gh_rate_limit_info(headers: dict) -> dict:
    """Extract rate-limit metadata from GitHub response headers."""
    out = {"limit": None, "remaining": None, "reset": None}
    for k, v in (headers or {}).items():
        kl = k.lower()
        if kl == "x-ratelimit-limit":
            try:
                out["limit"] = int(v)
            except (TypeError, ValueError):
                pass
        elif kl == "x-ratelimit-remaining":
            try:
                out["remaining"] = int(v)
            except (TypeError, ValueError):
                pass
        elif kl == "x-ratelimit-reset":
            try:
                out["reset"] = int(v)
            except (TypeError, ValueError):
                pass
    return out


async def _gh_get(session, limiter, url, token=None, verbose=False):
    """GET a GitHub API endpoint. Returns (status, json_or_none, headers)."""
    try:
        status, headers, body, _ = await fetch(
            session, url, limiter, timeout=20.0,
            headers=_github_headers(token),
        )
    except Exception as e:
        if verbose:
            warn(f"  github: {type(e).__name__}: {e}")
        return None, None, {}

    if body is None:
        return status, None, headers or {}

    try:
        data = json.loads(body) if body else None
    except json.JSONDecodeError:
        data = None

    return status, data, headers or {}


async def _github_org_metadata(org, session, limiter, token=None,
                                verbose=False):
    """Fetch basic org info. Used to confirm the org exists."""
    url = f"{GITHUB_API}/orgs/{org}"
    status, data, headers = await _gh_get(
        session, limiter, url, token=token, verbose=verbose)
    if status == 404:
        return None
    if status != 200 or not isinstance(data, dict):
        return None
    return {
        "login": data.get("login"),
        "name": data.get("name"),
        "description": data.get("description"),
        "blog": data.get("blog"),
        "location": data.get("location"),
        "email": data.get("email"),
        "public_repos": data.get("public_repos"),
        "public_members": data.get("public_members"),
    }


async def _github_public_members(org, session, limiter, token=None,
                                  verbose=False):
    """Fetch the public member list for a GitHub org."""
    out = {
        "members": [],
        "pages_fetched": 0,
        "rate_limited": False,
        "rate_limit": {},
    }

    for page in range(1, GITHUB_MAX_PAGES + 1):
        url = (f"{GITHUB_API}/orgs/{org}/public_members"
               f"?per_page={GITHUB_PAGE_SIZE}&page={page}")
        status, data, headers = await _gh_get(
            session, limiter, url, token=token, verbose=verbose)

        rl = _gh_rate_limit_info(headers)
        if rl.get("remaining") is not None:
            out["rate_limit"] = rl

        if status == 403 and rl.get("remaining") == 0:
            out["rate_limited"] = True
            if verbose:
                warn(f"  github: rate limit hit "
                     f"(reset={rl.get('reset')})")
            break

        if status != 200 or not isinstance(data, list):
            break

        out["pages_fetched"] += 1

        if not data:
            break

        for item in data:
            login = item.get("login")
            if login:
                out["members"].append(login)

        if len(data) < GITHUB_PAGE_SIZE:
            break

        await asyncio.sleep(0.2)

    if out["rate_limit"].get("remaining") == 0:
        out["rate_limited"] = True

    return out


async def _github_user_details(login, session, limiter, token=None,
                                verbose=False):
    """Fetch a single user's profile. Returns a normalized dict."""
    url = f"{GITHUB_API}/users/{login}"
    status, data, headers = await _gh_get(
        session, limiter, url, token=token, verbose=verbose)

    rl = _gh_rate_limit_info(headers)
    if status == 403 and rl.get("remaining") == 0:
        return {"login": login, "rate_limited": True}
    if status != 200 or not isinstance(data, dict):
        return {"login": login}

    return {
        "login": data.get("login"),
        "name": data.get("name"),
        "email": data.get("email"),
        "company": data.get("company"),
        "location": data.get("location"),
        "bio": data.get("bio"),
        "blog": data.get("blog"),
        "twitter_username": data.get("twitter_username"),
        "public_repos": data.get("public_repos"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
    }


async def _resolve_org_from_domain(domain, session, limiter,
                                    token=None, verbose=False):
    """Try to find the GitHub org name for a domain."""
    root = await _resolve_root(domain, session, limiter,
                                verbose=verbose)
    if root is None:
        return None

    try:
        status, _h, body, _ = await fetch(
            session, root, limiter, timeout=15.0)
    except Exception:
        return None

    if status != 200 or not body:
        return None

    for m in re.finditer(
            r'github\.com/(?:orgs/)?([A-Za-z0-9_\-]+)',
            body, re.IGNORECASE):
        candidate = m.group(1).lower()
        if candidate in NON_MASTODON_DOMAINS:
            continue
        if candidate in USERNAME_DENYLIST:
            continue
        if candidate in ("features", "pricing", "login", "signup",
                          "explore", "topics", "trending",
                          "collections", "sponsors", "settings",
                          "marketplace", "enterprise", "about",
                          "security", "apps", "mobile"):
            continue
        if verbose:
            info(f"  resolved GitHub org from {domain}: "
                 f"{candidate}")
        return candidate
    return None


async def github_enumerate(org, session, limiter, token=None,
                            max_user_lookups=GITHUB_MAX_USER_LOOKUPS,
                            verbose=False):
    """Full GitHub org enumeration."""
    out = {
        "org": org,
        "metadata": None,
        "members": [],
        "member_count": 0,
        "rate_limited": False,
        "rate_limit": {},
        "errors": [],
    }

    meta = await _github_org_metadata(
        org, session, limiter, token=token, verbose=verbose)
    if meta is None:
        out["errors"].append(f"org {org!r} not found or not public")
        return out
    out["metadata"] = meta
    if verbose:
        info(f"  github org: {meta.get('name') or org}")

    members_resp = await _github_public_members(
        org, session, limiter, token=token, verbose=verbose)
    logins = members_resp["members"]
    out["rate_limited"] = members_resp["rate_limited"]
    out["rate_limit"] = members_resp["rate_limit"]

    if verbose:
        info(f"  github members: {len(logins)} "
             f"({members_resp['pages_fetched']} page(s))")

    to_lookup = logins[:max_user_lookups]
    if len(logins) > max_user_lookups and verbose:
        info(f"  capping per-user lookups at {max_user_lookups}")

    for login in to_lookup:
        details = await _github_user_details(
            login, session, limiter, token=token, verbose=verbose)
        if details.get("rate_limited"):
            out["rate_limited"] = True
            if verbose:
                warn(f"  github: rate limit hit at "
                     f"user {login!r}; stopping lookups")
            break
        out["members"].append(details)
        await asyncio.sleep(0.05)

    out["member_count"] = len(out["members"])
    return out

# ── END SESSION S1 GitHub enumeration ───────────────────────────────


# ── SESSION S1 ── Name harvesting ───────────────────────────────────


def _looks_like_name(word: str) -> bool:
    """Return True if a token looks like a person's name."""
    if not word or len(word) < 2 or len(word) > 40:
        return False
    if word.lower() in NOT_A_NAME:
        return False
    if not re.fullmatch(r"[A-Za-z][A-Za-z'\-]*(?:\s+[A-Za-z][A-Za-z'\-]*)?",
                         word):
        return False
    if word.isupper() and len(word) <= 4:
        return False
    return True


def _split_full_name(raw: str) -> tuple[str, str] | None:
    """Split 'John Smith' into ('John', 'Smith')."""
    if not raw:
        return None
    raw = raw.strip()
    raw = re.sub(r"\s+", " ", raw)
    parts = raw.split(" ")
    if len(parts) < 2:
        return None
    first = parts[0]
    last = parts[-1]
    if not _looks_like_name(first) or not _looks_like_name(last):
        return None
    return first, last


def name_from_email(email: str) -> tuple[str, str] | None:
    """Parse 'john.smith@acme.com' → ('John', 'Smith')."""
    if "@" not in email:
        return None
    local = email.rsplit("@", 1)[0].lower()
    for sep in (".", "_", "-"):
        if sep in local:
            parts = [p for p in local.split(sep) if p]
            if len(parts) == 2:
                first, last = parts
            elif len(parts) == 3:
                first, last = parts[0], parts[2]
            else:
                continue
            if not (first and last):
                continue
            if not all(p.isalpha() for p in (first, last)):
                continue
            return first.capitalize(), last.capitalize()
    return None


def _names_from_team_page(html: str, verbose: bool = False) -> list[dict]:
    """Extract names from a team page."""
    out = []

    for m in re.finditer(
            r"\b([A-Z][a-z]{1,20})\s+([A-Z][a-z]{1,20})(?:\s+([A-Z][a-z]{1,20}))?\b",
            html):
        first = m.group(1)
        last = m.group(2)
        if last.lower() in NOT_A_NAME:
            continue
        if first.lower() in NOT_A_NAME:
            continue
        start = max(0, m.start() - 20)
        ctx = html[start:m.start()]
        if re.search(r"[<=]\"?$", ctx):
            continue
        if re.search(r"class=|href=|src=|id=", ctx):
            continue
        out.append({
            "first": first,
            "last": last,
            "source": "team-page",
        })

    seen = set()
    deduped = []
    for entry in out:
        key = (entry["first"].lower(), entry["last"].lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)

    if verbose and deduped:
        info(f"    team page: {len(deduped)} name(s)")

    return deduped


async def harvest_names_from_team_pages(domain, session, limiter,
                                         verbose=False):
    """Scrape team-like pages for names."""
    out = []

    root = await _resolve_root(domain, session, limiter,
                                verbose=verbose)
    if root is None:
        if verbose:
            warn(f"    {domain} does not resolve; skipping team pages")
        return []

    for path in TEAM_PATHS:
        url = root + path
        try:
            status, _h, body, _ = await fetch(session, url, limiter,
                                                timeout=15.0)
        except Exception:
            continue
        if status != 200 or not body or len(body) < 200:
            continue
        if verbose:
            info(f"    scraped {url} ({len(body)} bytes)")
        names = _names_from_team_page(body, verbose=verbose)
        for n in names:
            n["source_url"] = url
        out.extend(names)
        await asyncio.sleep(0.3)

    seen = set()
    deduped = []
    for n in out:
        key = (n["first"].lower(), n["last"].lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(n)
    return deduped


def names_from_github_members(members):
    """Turn GitHub member records into name entries."""
    out = []
    for m in members:
        full = m.get("name")
        first, last = None, None
        if full:
            split = _split_full_name(full)
            if split:
                first, last = split
        if not (first and last):
            login = m.get("login") or ""
            cleaned = re.sub(r"\d+", "", login)
            if "-" in cleaned or "_" in cleaned:
                parts = re.split(r"[-_]", cleaned)
                if len(parts) >= 2:
                    first = parts[0].capitalize()
                    last = parts[-1].capitalize()
        entry = {
            "first": first,
            "last": last,
            "login": m.get("login"),
            "email": m.get("email"),
            "company": m.get("company"),
            "location": m.get("location"),
            "source": "github",
        }
        if first and last:
            out.append(entry)
    return out


def names_from_discovered_emails(emails):
    """Parse (first, last) out of email local-parts."""
    out = []
    for e in emails:
        split = name_from_email(e)
        if not split:
            continue
        first, last = split
        out.append({
            "first": first,
            "last": last,
            "email": e,
            "source": "email-parsed",
        })
    return out


def dedupe_names(names):
    """Dedupe by (first.lower(), last.lower()), merging sources."""
    merged = {}
    for n in names:
        first = (n.get("first") or "").strip()
        last = (n.get("last") or "").strip()
        if not (first and last):
            continue
        key = (first.lower(), last.lower())
        entry = merged.setdefault(key, {
            "first": first,
            "last": last,
            "sources": set(),
            "emails": set(),
            "logins": set(),
            "roles": set(),
        })
        entry["sources"].add(n.get("source", "unknown"))
        if n.get("email"):
            entry["emails"].add(n["email"])
        if n.get("login"):
            entry["logins"].add(n["login"])
        if n.get("role"):
            entry["roles"].add(n["role"])
    out = []
    for entry in merged.values():
        out.append({
            "first": entry["first"],
            "last": entry["last"],
            "sources": sorted(entry["sources"]),
            "emails": sorted(entry["emails"]),
            "logins": sorted(entry["logins"]),
            "roles": sorted(entry["roles"]),
        })
    out.sort(key=lambda x: (x["last"].lower(), x["first"].lower()))
    return out


def write_names_file(path, names):
    """Write names to a file in 'First Last' format, one per line."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for n in names:
        first = n.get("first")
        last = n.get("last")
        if first and last:
            lines.append(f"{first} {last}")
    p.write_text("\n".join(lines) + ("\n" if lines else ""),
                  encoding="utf-8")
    return len(lines)

# ── END SESSION S1 name harvesting ──────────────────────────────────


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def lookup(domain: str, session=None, verbose: bool = False,
                 verify: bool = True,
                 github_token: str | None = None,
                 github_org: str | None = None,
                 enable_github: bool = True,
                 enable_team_pages: bool = True) -> dict:
    """Find social profiles and enumerate employees for a domain."""
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0].split(":")[0].lower()

    token = github_token or os.environ.get("GITHUB_TOKEN")
    if verbose:
        if token:
            info("  github: using authenticated access")
        else:
            info("  github: unauthenticated (60 req/hour)")

    result = {
        "domain": domain,
        "profiles": {},
        "dns_verifications": {},
        "counts": {},
        "github": None,
        "names": [],
        "name_count": 0,
        "rate_limited": False,
    }

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(5.0)

    try:
        info(f"scraping {domain} for social links")
        raw = await scrape_profiles(domain, session, limiter,
                                      verbose=verbose)

        info(f"querying DNS TXT records for {domain}")
        dns_tokens = await fetch_dns_verifications(domain, verbose=verbose)
        result["dns_verifications"] = dns_tokens

        org = github_org
        if not org and enable_github:
            org = await _resolve_org_from_domain(
                domain, session, limiter, token=token, verbose=verbose)
            if not org and "github" in raw:
                for cand in sorted(raw["github"]):
                    org = cand
                    break

        github_result = None
        if enable_github and org:
            info(f"enumerating GitHub org: {org}")
            github_result = await github_enumerate(
                org, session, limiter, token=token, verbose=verbose)
            result["github"] = github_result
            result["rate_limited"] = github_result.get("rate_limited", False)

        team_names = []
        if enable_team_pages:
            info(f"scraping team pages on {domain}")
            team_names = await harvest_names_from_team_pages(
                domain, session, limiter, verbose=verbose)

        all_names = []
        all_names.extend(team_names)
        if github_result:
            all_names.extend(
                names_from_github_members(github_result.get("members", [])))

        deduped = dedupe_names(all_names)
        result["names"] = deduped
        result["name_count"] = len(deduped)

        verified_profiles: dict[str, list[dict]] = {}
        for platform, usernames in raw.items():
            entries = []
            for username in sorted(usernames):
                entry = {"username": username}
                if platform == "github":
                    entry["url"] = f"https://github.com/{username}"
                elif platform == "youtube":
                    entry["url"] = f"https://www.youtube.com/@{username}"
                elif platform == "bluesky":
                    entry["url"] = f"https://bsky.app/profile/{username}"
                elif platform == "twitter":
                    entry["url"] = f"https://twitter.com/{username}"
                elif platform == "linkedin":
                    entry["url"] = f"https://linkedin.com/company/{username}"
                elif platform == "facebook":
                    entry["url"] = f"https://facebook.com/{username}"
                elif platform == "instagram":
                    entry["url"] = f"https://instagram.com/{username}"
                elif platform == "gitlab":
                    entry["url"] = f"https://gitlab.com/{username}"
                elif platform == "reddit":
                    entry["url"] = f"https://reddit.com/r/{username}"
                elif platform == "mastodon":
                    if "/" in username:
                        inst, user = username.split("/", 1)
                        entry["url"] = f"https://{inst}/@{user}"
                    else:
                        entry["url"] = f"https://{username}"
                else:
                    entry["url"] = f"https://{platform}.com/{username}"

                if verify and platform in VERIFIABLE_PLATFORMS:
                    v = await verify_profile(platform, username,
                                               session, limiter,
                                               verbose=verbose)
                    entry["verified"] = v.get("verified", False)
                    entry["status"] = v.get("status")
                    await asyncio.sleep(0.2)

                entries.append(entry)

            if entries:
                verified_profiles[platform] = entries
                result["counts"][platform] = len(entries)

        result["profiles"] = verified_profiles

        return result
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
              verify: bool = True,
              github_token: str | None = None,
              github_org: str | None = None,
              names_out: str | None = None) -> dict:
    """CLI entry. Writes finding to store if provided."""
    result = await lookup(target, verbose=verbose, verify=verify,
                          github_token=github_token,
                          github_org=github_org)

    print()
    total = sum(result["counts"].values())
    if not result["profiles"]:
        warn(f"no social profiles found for {result['domain']}")
    else:
        success(f"{total} social profile(s) for {result['domain']}")
        for platform, entries in sorted(result["profiles"].items()):
            print(f"  {platform}:")
            for e in entries[:15]:
                marker = ""
                if "verified" in e:
                    if e["verified"]:
                        marker = " ✓"
                    elif e.get("status") is not None:
                        marker = f" (HTTP {e['status']})"
                    else:
                        marker = " (unverified)"
                print(f"    {e['url']}{marker}")
            if len(entries) > 15:
                print(f"    ... and {len(entries) - 15} more")

    gh = result.get("github")
    if gh:
        print()
        md = gh.get("metadata") or {}
        info(f"  GitHub org: {gh['org']}")
        if md.get("name"):
            print(f"    name:      {md['name']}")
        if md.get("location"):
            print(f"    location:  {md['location']}")
        if md.get("blog"):
            print(f"    blog:      {md['blog']}")
        print(f"    members:   {gh['member_count']}")
        if gh.get("rate_limited"):
            rl = gh.get("rate_limit") or {}
            reset = rl.get("reset")
            reset_str = ""
            if reset:
                from datetime import datetime, timezone
                reset_str = f" (resets {datetime.fromtimestamp(reset, tz=timezone.utc).isoformat()[:19]} UTC)"
            warn(f"    rate limit hit{reset_str}")
            warn(f"    pass --github-token or set GITHUB_TOKEN for "
                 f"5000 req/hour")
        for m in gh.get("members", [])[:20]:
            name = m.get("name") or "?"
            login = m.get("login") or "?"
            email = m.get("email") or ""
            extra = f" — {email}" if email else ""
            print(f"      {login:24s} {name}{extra}")
        if len(gh.get("members", [])) > 20:
            print(f"      ... and {len(gh['members']) - 20} more")

    if result["name_count"]:
        print()
        success(f"  {result['name_count']} employee name(s) collected")
        for n in result["names"][:20]:
            sources = ",".join(n["sources"])
            print(f"    {n['first']:12s} {n['last']:15s} [{sources}]")
        if result["name_count"] > 20:
            print(f"    ... and {result['name_count'] - 20} more")
        if not names_out:
            info("  (pass --names-out <path> to save for "
                 "`emails.py --names-file`)")

    if names_out and result["names"]:
        n = write_names_file(names_out, result["names"])
        success(f"  wrote {n} name(s) to {names_out}")

    if result["dns_verifications"]:
        print()
        info("  DNS verification tokens:")
        for name, value in sorted(result["dns_verifications"].items()):
            print(f"    {name}: {value}")

    if store is not None:
        store.add_finding({
            "module": "social",
            "type": "informational",
            "severity": "info",
            "target": result["domain"],
            "evidence": (f"{total} social profile(s) across "
                         f"{len(result['profiles'])} platform(s), "
                         f"{result['name_count']} employee name(s)"),
            "data": result,
        })
        success("finding written to store")

    return result


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.social",
        description="Discover social media profiles and employee names "
                    "for a domain.",
    )
    p.add_argument("target", help="domain or URL")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-verify", action="store_true",
                   help="skip profile verification")
    p.add_argument("--no-github", action="store_true",
                   help="skip GitHub org enumeration")
    p.add_argument("--no-team-pages", action="store_true",
                   help="skip team page scraping")
    p.add_argument("--github-token", default=None,
                   help="GitHub API token for higher rate limit "
                        "(defaults to $GITHUB_TOKEN if set)")
    p.add_argument("--github-org", default=None,
                   help="GitHub org name to enumerate (skips "
                        "auto-detection from the domain)")
    p.add_argument("--names-out", default=None,
                   help="write collected names to a file, one "
                        "'First Last' per line (suitable for "
                        "emails.py --names-file)")
    p.add_argument("--store", action="store_true")
    args = p.parse_args()

    store = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; use `toolkit workspace switch`")
            return
        ws = get_workspace(active)
        store = open_store(ws.db_path, workspace_name=active)

    asyncio.run(run(args.target, store=store, verbose=args.verbose,
                    verify=not args.no_verify,
                    github_token=args.github_token,
                    github_org=args.github_org,
                    names_out=args.names_out))


if __name__ == "__main__":
    _cli()