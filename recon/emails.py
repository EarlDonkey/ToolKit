"""
Email address discovery.

Finds publicly-discoverable email addresses associated with a target:

  Sources:
    1. Scrape target pages             /, /contact, /about, /team, ...
    2. Scrape subdomains (if provided)
    3. /.well-known/security.txt       RFC 9116 security contact
    4. WHOIS                           registrant/admin/tech emails
    5. Hunter.io                       optional, requires --hunter-key
    6. Role-account guesses            info@, admin@, security@, ...

  Verification (optional, --verify):
    - MX check on the domain (always on)
    - SMTP RCPT TO check on a small curated list (opt-in, may be
      blocked by anti-spam systems)

  Pattern learning (new in this version):
    After discovery, if at least two emails were found for the
    target domain, we try to work out the local-part pattern:

        john.smith@acme.com    →  {first}.{last}
        jsmith@acme.com        →  {first}{last}
        smithj@acme.com        →  {last}{f}

    With a learned pattern, we can generate plausible emails for
    names we already know (from discovered emails themselves, or
    from a --names-file the operator supplies). This is the pivot
    that turns "we found 4 emails" into "here are 40 candidates
    ranked by how likely they are to be real".

  Every reported email has a confidence level:

      verified   — SMTP RCPT TO confirmed the mailbox exists
      mx-ok      — MX record exists, RCPT TO not checked
      public     — found on a web page / WHOIS / security.txt
      guess      — role-account guess, existence unknown
      pattern    — generated from a learned pattern (new)

Findings written to the store:
    one row per target with all discovered emails in `data`
"""

import asyncio
import re
import socket
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Pages to scrape for contact info
CONTACT_PATHS = [
    "/", "/contact", "/contact-us", "/contactus", "/about",
    "/about-us", "/team", "/staff", "/support", "/help",
    "/impressum", "/legal", "/privacy", "/security",
]

# Common role accounts to guess
ROLE_ACCOUNTS = [
    "info", "contact", "hello", "admin", "administrator",
    "support", "help", "helpdesk", "sales", "marketing",
    "security", "abuse", "postmaster", "webmaster", "hostmaster",
    "noreply", "no-reply", "donotreply", "billing", "accounts",
    "hr", "careers", "jobs", "press", "media", "legal", "privacy",
]

# Email regex — simple but effective
EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# mailto: links
MAILTO_PATTERN = re.compile(
    r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
    re.IGNORECASE,
)

# Junk emails we never want to report
EMAIL_DENYLIST = {
    "you@domain.com", "user@domain.com", "email@domain.com",
    "name@domain.com", "your@email.com", "user@example.com",
    "name@example.com", "someone@example.com",
    "noreply@example.com", "test@test.com", "foo@bar.com",
    "example@example.com", "someone@example.org",
    "user@localhost", "webmaster@localhost",
    "yourname@example.com", "yourname@domain.com",
    "your.name@example.com", "firstname.lastname@example.com",
}

# Trailing character classes that shouldn't be part of an email
EMAIL_TRIM = ".,;:!?)"

# SMTP verification settings
SMTP_TIMEOUT = 10.0
SMTP_HELO = "mail.example.com"   # FQDN we announce during HELO
SMTP_FROM = "verify@example.com"  # Mail-from we use for RCPT TO


# ── SESSION E1 ── Pattern learning constants ────────────────────────

# Every pattern we know how to detect. The value is a lambda that
# builds a local-part from (first, last). Detection runs the same
# lambda and compares against the observed local-part.
#
# Ordering here is not significant — the ranking comes from
# confidence scoring, not from list order.

PATTERNS = {
    "first.last":   lambda f, l: f"{f}.{l}",
    "firstlast":    lambda f, l: f"{f}{l}",
    "first_last":   lambda f, l: f"{f}_{l}",
    "last.first":   lambda f, l: f"{l}.{f}",
    "flast":        lambda f, l: f"{f[0]}{l}",
    "firstl":       lambda f, l: f"{f}{l[0]}",
    "first":        lambda f, l: f"{f}",
    "last":         lambda f, l: f"{l}",
    "lastf":        lambda f, l: f"{l}{f[0]}",
    "last.first":   lambda f, l: f"{l}.{f}",
    "lastfirst":    lambda f, l: f"{l}{f}",
    "first-last":   lambda f, l: f"{f}-{l}",
}

# Patterns that are structurally specific. Generic patterns like
# "{first}" and "{last}" will match a lot of emails by accident —
# "alice@acme.com" could just as easily be a first name, a nickname,
# or a username. We score generic patterns lower.
GENERIC_PATTERNS = {"first", "last"}

# Minimum number of discovered emails needed to attempt pattern
# learning. Below this, there's not enough signal.
MIN_EMAILS_FOR_PATTERN = 2

# Default confidence threshold for generated candidates.
DEFAULT_MIN_CONFIDENCE = 0.5

# ── END SESSION E1 constants ─────────────────────────────────────────


# ---------------------------------------------------------------------
# Scraping
# ---------------------------------------------------------------------

_EMAIL_LOCAL_JUNK_RE = re.compile(
    r"^(?:u003[0-9a-f]|\\u003[0-9a-f]|&#x?[0-9a-f]+;|&[a-z]+;|x3[ce]|3[ce])+",
    re.IGNORECASE,
)


def _clean_email(e: str) -> str:
    """Strip leading HTML-entity debris and trailing punctuation."""
    if "@" not in e:
        return e
    local, _, domain = e.partition("@")
    # Strip leading junk from the local part
    local = _EMAIL_LOCAL_JUNK_RE.sub("", local)
    # Strip trailing punctuation from the domain
    domain = domain.rstrip(EMAIL_TRIM)
    return f"{local}@{domain}" if local and domain else e


def extract_emails_from_text(text: str) -> set[str]:
    """Extract email addresses from arbitrary text (HTML, JS, etc.)."""
    emails = set()

    # From mailto: links (most reliable)
    for m in MAILTO_PATTERN.finditer(text):
        cleaned = _clean_email(m.group(1).lower())
        if cleaned not in EMAIL_DENYLIST:
            emails.add(cleaned)

    # From plain text
    for match in EMAIL_PATTERN.finditer(text):
        e = match.group(0).lower()
        # Trim trailing punctuation
        e = e.rstrip(EMAIL_TRIM)
        e = _clean_email(e)
        if e in EMAIL_DENYLIST:
            continue
        emails.add(e)

    # Filter obvious junk
    junk_domains = (
        ".sentry.io",              # Sentry DSNs, not real emails
        ".ingest.sentry.io",
        ".browser.sentry-cdn.com",
        "sentry.wixpress.com",
        ".bugsnag.com",            # Bugsnag API keys
        "rollbar.com",
        "datadoghq.com",           # Datadog client tokens
        "newrelic.com",
    )
    junk_local_patterns = (
        r"^[0-9a-f]{32}$",         # bare MD5-looking locals
        r"^[0-9a-f]{40}$",         # bare SHA1
        r"^[0-9a-f]{64}$",         # bare SHA256
        r"^[0-9a-f\-]{20,}$",      # UUID-ish
    )
    out = set()
    for e in emails:
        local, _, domain = e.partition("@")
        if not local or not domain:
            continue
        if "." not in domain:
            continue
        if domain.endswith((".png", ".jpg", ".jpeg", ".gif",
                            ".webp", ".svg", ".css", ".js")):
            continue
        # Skip known-junk service domains
        if any(domain.endswith(j) or domain == j.lstrip(".")
               for j in junk_domains):
            continue
        # Skip machine-generated locals (DSNs, tokens, hashes)
        if any(re.match(p, local) for p in junk_local_patterns):
            continue
        if len(local) > 64 or len(e) > 254:
            continue
        out.add(e)
    return out


async def scrape_page(session, url, limiter, verbose=False) -> set[str]:
    """Fetch a page and extract emails. Returns set (empty on failure)."""
    try:
        status, _headers, body, _ = await fetch(session, url, limiter,
                                                  timeout=15.0)
    except Exception:
        return set()
    if status != 200 or not body:
        return set()
    if verbose:
        info(f"    scraped {url} ({len(body)} bytes)")
    return extract_emails_from_text(body)


async def scrape_contact_pages(base_url: str, session, limiter,
                                verbose=False) -> set[str]:
    """Scrape common contact pages for emails."""
    # Normalize base
    if not base_url.startswith(("http://", "https://")):
        base_url = f"http://{base_url}"
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    emails = set()
    sem = asyncio.Semaphore(5)

    async def _one(path):
        async with sem:
            return await scrape_page(session, urljoin(root, path),
                                      limiter, verbose=verbose)

    results = await asyncio.gather(*[_one(p) for p in CONTACT_PATHS])
    for r in results:
        emails.update(r)
    return emails


async def fetch_security_txt(domain: str, session, limiter,
                              verbose=False) -> dict:
    """Fetch /.well-known/security.txt (RFC 9116).

    Returns {"emails": [...], "raw": "..."} or empty.
    """
    out = {"emails": [], "raw": ""}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/.well-known/security.txt"
        try:
            status, _headers, body, _ = await fetch(session, url, limiter,
                                                      timeout=10.0)
        except Exception:
            continue
        if status == 200 and body:
            out["raw"] = body[:5000]
            out["emails"] = sorted(extract_emails_from_text(body))
            if verbose:
                info(f"  security.txt: {len(out['emails'])} email(s)")
            return out
    return out


# ---------------------------------------------------------------------
# Hunter.io
# ---------------------------------------------------------------------

async def hunter_domain_search(domain: str, api_key: str,
                                session, limiter,
                                verbose=False) -> list[dict]:
    """Query Hunter.io for emails on a domain. Requires API key."""
    url = (
        f"https://api.hunter.io/v2/domain-search"
        f"?domain={domain}&api_key={api_key}&limit=50"
    )
    try:
        status, _headers, body, _ = await fetch(session, url, limiter,
                                                  timeout=20.0)
    except Exception as e:
        if verbose:
            warn(f"Hunter.io failed: {type(e).__name__}: {e}")
        return []
    if status != 200 or not body:
        if verbose:
            warn(f"Hunter.io returned status={status}")
        return []

    import json as _json
    try:
        data = _json.loads(body)
    except _json.JSONDecodeError:
        return []

    emails = []
    for item in (data.get("data") or {}).get("emails") or []:
        emails.append({
            "email": item.get("value", "").lower(),
            "first_name": item.get("first_name") or "",
            "last_name": item.get("last_name") or "",
            "position": item.get("position") or "",
            "department": item.get("department") or "",
            "confidence": item.get("confidence", 0),
            "source": "hunter.io",
        })
    return [e for e in emails if e["email"]]


# ── SESSION E1 ── Pattern learning ──────────────────────────────────


def _split_local_part(local: str) -> tuple[str, str] | None:
    """Best-effort split of a local-part into (first, last).

    Handles the common separators: '.', '_', '-'. Also splits
    camelCase-ish and concatenated forms by looking for a
    plausible boundary — but concatenated forms are ambiguous
    ("jsmith" could be j+smith or js+mith), so we don't try to
    split those without a separator.

    Returns (first, last) or None if we can't split.
    """
    if not local:
        return None
    for sep in (".", "_", "-"):
        if sep in local:
            parts = [p for p in local.split(sep) if p]
            if len(parts) == 2:
                return parts[0].lower(), parts[1].lower()
            if len(parts) == 3:
                # first.middle.last → first, last
                return parts[0].lower(), parts[2].lower()
    # No separator — can't reliably split. If it's a single token
    # we might treat it as a first name only, but we don't know.
    # Return None so the caller doesn't invent a fake last name.
    return None


def _extract_patterns(emails: list[str], domain: str) -> list[tuple]:
    """Given emails for a domain, learn the local-part pattern(s).

    Returns a list of tuples, sorted by confidence descending:
        (pattern_name, confidence, examples_list, match_count)

    Confidence is:
      - base = matches / total_emails_for_domain
      - multiplied by a specificity factor:
            generic patterns ({first}, {last}) → ×0.6
            everything else                    → ×1.0

    Only patterns that match at least 2 emails are returned.
    """
    # Filter to emails on the target domain
    domain_low = domain.lower()
    on_domain = [
        e.lower() for e in emails
        if e.lower().endswith("@" + domain_low)
    ]

    if len(on_domain) < MIN_EMAILS_FOR_PATTERN:
        return []

    # For each email, try to parse (first, last) from the local-part.
    # Emails whose local-part we can't split contribute to the
    # denominator but not the numerator — they're evidence against a
    # structured pattern.
    parsed: list[tuple[str, str, str]] = []  # (email, first, last)
    unparseable = 0
    for e in on_domain:
        local = e.rsplit("@", 1)[0]
        split = _split_local_part(local)
        if split is None:
            unparseable += 1
            continue
        first, last = split
        if not first or not last:
            unparseable += 1
            continue
        parsed.append((e, first, last))

    if not parsed:
        return []

    total = len(on_domain)

    # For each pattern, count how many parsed emails match it exactly
    results = []
    for pname, builder in PATTERNS.items():
        matches = []
        for e, first, last in parsed:
            local = e.rsplit("@", 1)[0]
            try:
                expected = builder(first, last)
            except (IndexError, TypeError):
                continue
            if expected == local:
                matches.append(e)

        if len(matches) < MIN_EMAILS_FOR_PATTERN:
            continue

        base = len(matches) / total
        specificity = 0.6 if pname in GENERIC_PATTERNS else 1.0
        confidence = round(base * specificity, 3)

        results.append((pname, confidence, matches[:5], len(matches)))

    # Sort by confidence desc, then by match count desc
    results.sort(key=lambda r: (-r[1], -r[3]))
    return results


def _name_to_candidates(first: str, last: str,
                        patterns: list[tuple]) -> list[tuple]:
    """Apply patterns to a name. Returns [(local_part, pattern_name)].

    Only the pattern names present in `patterns` are applied. If a
    pattern builder would produce an empty or duplicate string, it's
    skipped.
    """
    if not first or not last:
        return []
    first = first.lower().strip()
    last = last.lower().strip()
    if not first or not last:
        return []

    out = []
    seen = set()
    for pname, _conf, _examples, _count in patterns:
        builder = PATTERNS.get(pname)
        if builder is None:
            continue
        try:
            local = builder(first, last)
        except (IndexError, TypeError):
            continue
        if not local or local in seen:
            continue
        seen.add(local)
        out.append((local, pname))
    return out


def _parse_name_from_local_part(local: str) -> tuple[str, str] | None:
    """Try to recover a human name from a local-part.

    Used to bootstrap the name pool: if we see john.smith@acme.com and
    learn {first}.{last}, we can feed "John Smith" back into the
    generator to produce johnsmith@, jsmith@, etc. — different
    patterns, same person.
    """
    return _split_local_part(local)


def _generate_candidates(discovered_emails: list[str], domain: str,
                          patterns: list[tuple],
                          extra_names: list[str] | None = None,
                          min_confidence: float = DEFAULT_MIN_CONFIDENCE,
                          ) -> list[dict]:
    """Generate candidate emails from patterns + names.

    Names come from two sources:
      1. Discovered emails whose local-parts parse into (first, last)
      2. extra_names — a list of "First Last" or "local-part" strings

    For each name, every learned pattern is applied. Generated
    candidates whose confidence (the pattern's) is below
    `min_confidence` are dropped.

    Returns a list of dicts:
        {
          "email": "david.brown@acme.com",
          "pattern": "first.last",
          "source_name": "David Brown" | "david.brown",
          "confidence": 0.97,
        }
    """
    domain_low = domain.lower()

    # Filter patterns to those above the confidence threshold
    patterns = [(n, c, e, m) for (n, c, e, m) in patterns
                if c >= min_confidence]
    if not patterns:
        return []

    # Names observed so far: (first, last, source_label)
    names: list[tuple[str, str, str]] = []
    seen_names = set()

    # Source 1: parse names out of discovered emails
    for e in discovered_emails:
        e_low = e.lower()
        if not e_low.endswith("@" + domain_low):
            continue
        local = e_low.rsplit("@", 1)[0]
        split = _parse_name_from_local_part(local)
        if split is None:
            continue
        first, last = split
        key = (first, last)
        if key in seen_names:
            continue
        seen_names.add(key)
        names.append((first, last, f"{first}.{last}"))

    # Source 2: operator-provided names
    for raw in (extra_names or []):
        raw = raw.strip()
        if not raw:
            continue
        # "First Last" — split on whitespace
        if " " in raw:
            parts = raw.split()
            if len(parts) < 2:
                continue
            first = parts[0].lower()
            last = parts[-1].lower()
        else:
            # Single token — try to split by a separator
            split = _split_local_part(raw.lower())
            if split is None:
                # Can't make a first/last, skip
                continue
            first, last = split
        key = (first, last)
        if key in seen_names:
            continue
        seen_names.add(key)
        names.append((first, last, raw))

    if not names:
        return []

    # Apply every pattern to every name
    out = []
    seen_emails = set(e.lower() for e in discovered_emails)
    for first, last, source_label in names:
        for local, pname in _name_to_candidates(first, last, patterns):
            email = f"{local}@{domain_low}"
            if email in seen_emails:
                continue
            seen_emails.add(email)
            confidence = next((c for (n, c, _e, _m) in patterns
                                if n == pname), 0.0)
            out.append({
                "email": email,
                "pattern": pname,
                "source_name": source_label,
                "confidence": confidence,
            })

    # Sort by confidence desc, then alphabetical
    out.sort(key=lambda r: (-r["confidence"], r["email"]))
    return out


def load_names(path: str) -> list[str]:
    """Load names from a file, one per line.

    Blank lines and lines starting with '#' are ignored. Each line
    can be either "First Last" or a local-part like "john.smith".
    """
    p = Path(path)
    if not p.exists():
        warn(f"emails: names file not found: {path}")
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out

# ── END SESSION E1 pattern learning ─────────────────────────────────


# ---------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------

async def mx_check(domain: str, verbose=False) -> list[str]:
    """Check if a domain has MX records. Returns list of MX hostnames."""
    try:
        return await asyncio.get_event_loop().run_in_executor(
            None, _mx_lookup, domain)
    except Exception as e:
        if verbose:
            warn(f"MX lookup failed for {domain}: {e}")
        return []


def _mx_lookup(domain: str) -> list[str]:
    """Blocking MX lookup via nslookup."""
    import subprocess
    try:
        out = subprocess.run(
            ["nslookup", "-type=MX", domain],
            capture_output=True, text=True, timeout=8.0,
        )
        text = out.stdout
    except Exception:
        return []

    # Parse "mail exchanger = 10 mail.example.com."
    mx = []
    for m in re.finditer(
        r"mail exchanger\s*=\s*\d+\s+(\S+)", text, re.IGNORECASE):
        host = m.group(1).rstrip(".").lower()
        if host:
            mx.append(host)
    return mx


async def smtp_verify(email: str, mx_host: str,
                       verbose=False) -> dict:
    """Connect to mx_host and issue RCPT TO <email>.

    Returns {"code": int, "message": str, "result": "verified" |
             "rejected" | "unknown" | "error"}.
    """
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, _smtp_verify_sync, email, mx_host)
        return result
    except Exception as e:
        return {"code": 0, "message": str(e), "result": "error"}


def _smtp_verify_sync(email: str, mx_host: str) -> dict:
    """Blocking SMTP RCPT TO verification."""
    try:
        s = socket.create_connection((mx_host, 25), timeout=SMTP_TIMEOUT)
    except Exception as e:
        return {"code": 0, "message": f"connect: {e}", "result": "error"}

    try:
        s.settimeout(SMTP_TIMEOUT)

        def read_reply():
            chunks = []
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                text = b"".join(chunks).decode("utf-8", errors="ignore")
                lines = text.splitlines()
                if lines and re.match(r"^\d{3} ", lines[-1]):
                    return lines[-1]
                if len(chunks) > 20:  # safety
                    break
            return ""

        def send(data):
            s.sendall((data + "\r\n").encode("ascii", errors="ignore"))

        greeting = read_reply()
        if not greeting.startswith("220"):
            return {"code": 0, "message": greeting, "result": "error"}

        send(f"HELO {SMTP_HELO}")
        read_reply()

        send(f"MAIL FROM:<{SMTP_FROM}>")
        mail_reply = read_reply()
        if not mail_reply.startswith("250"):
            send("QUIT")
            return {"code": 0, "message": mail_reply, "result": "rejected"}

        send(f"RCPT TO:<{email}>")
        rcpt_reply = read_reply()

        try:
            send("QUIT")
            s.close()
        except Exception:
            pass

        code = int(rcpt_reply.split()[0]) if rcpt_reply[:3].isdigit() else 0
        if code in (250, 251):
            return {"code": code, "message": rcpt_reply, "result": "verified"}
        if code in (550, 551, 552, 553):
            return {"code": code, "message": rcpt_reply, "result": "rejected"}
        return {"code": code, "message": rcpt_reply, "result": "unknown"}
    except Exception as e:
        try:
            s.close()
        except Exception:
            pass
        return {"code": 0, "message": str(e), "result": "error"}


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def discover(domain: str, session=None, verbose=False,
                    hunter_key: str | None = None,
                    verify: bool = False,
                    subdomains: list[str] | None = None,
                    whois_result: dict | None = None,
                    names: list[str] | None = None,
                    enable_patterns: bool = False,
                    min_confidence: float = DEFAULT_MIN_CONFIDENCE) -> dict:
    """Find emails associated with a domain.

    Every email comes with a confidence level:
        verified | mx-ok | public | guess | pattern
    """
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0].split(":")[0].lower()

    result = {
        "domain": domain,
        "emails": [],           # [{email, confidence, sources, ...}]
        "mx": [],
        "patterns": [],         # [(pattern_name, confidence, examples, count)]
        "generated": [],        # [{email, pattern, source_name, confidence}]
        "errors": [],
    }

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(5.0)

    try:
        # Collect raw evidence into a temp map
        raw: dict[str, dict] = {}   # email -> {"sources": set, "meta": {}}

        def add(email: str, source: str, meta: dict | None = None,
                confidence: str = "public"):
            email = email.lower().strip()
            if not email or "@" not in email:
                return
            if email in EMAIL_DENYLIST:
                return
            entry = raw.setdefault(email, {
                "sources": set(),
                "meta": {},
                "confidence": confidence,
            })
            entry["sources"].add(source)
            if meta:
                entry["meta"].update(meta)
            # Upgrade confidence if this source is higher tier
            tiers = ["guess", "pattern", "public", "mx-ok", "verified"]
            if tiers.index(confidence) > tiers.index(entry["confidence"]):
                entry["confidence"] = confidence

        # 1. Scrape contact pages
        info(f"scraping contact pages on {domain}")
        scraped = await scrape_contact_pages(f"https://{domain}",
                                              session, limiter,
                                              verbose=verbose)
        for e in scraped:
            add(e, "scraped-homepage")

        # Also try the www variant if the bare domain didn't work
        if not scraped:
            scraped = await scrape_contact_pages(f"https://www.{domain}",
                                                  session, limiter,
                                                  verbose=verbose)
            for e in scraped:
                add(e, "scraped-homepage")

        # 2. Scrape subdomains
        if subdomains:
            info(f"scraping {len(subdomains)} subdomain(s)")
            sem = asyncio.Semaphore(5)

            async def _sub(sub):
                async with sem:
                    return await scrape_contact_pages(
                        f"https://{sub}", session, limiter)

            sub_results = await asyncio.gather(
                *[_sub(s) for s in subdomains[:10]])   # cap at 10
            for r in sub_results:
                for e in r:
                    add(e, "scraped-subdomain")

        # 3. security.txt
        info(f"checking /.well-known/security.txt")
        sectxt = await fetch_security_txt(domain, session, limiter,
                                            verbose=verbose)
        for e in sectxt["emails"]:
            add(e, "security.txt")

        # 4. WHOIS (if provided)
        if whois_result:
            for contact_type in ("registrant", "admin", "tech"):
                block = whois_result.get(contact_type) or {}
                if block.get("email"):
                    add(block["email"], f"whois-{contact_type}",
                        confidence="public")

        # 5. Hunter.io
        if hunter_key:
            info(f"querying Hunter.io for {domain}")
            hunter = await hunter_domain_search(domain, hunter_key,
                                                  session, limiter,
                                                  verbose=verbose)
            for h in hunter:
                add(h["email"], "hunter.io",
                    meta={
                        "first_name": h.get("first_name"),
                        "last_name": h.get("last_name"),
                        "position": h.get("position"),
                        "department": h.get("department"),
                        "hunter_confidence": h.get("confidence"),
                    })

        # 6. MX check
        info(f"checking MX records for {domain}")
        mx = await mx_check(domain, verbose=verbose)
        result["mx"] = mx
        mx_ok = bool(mx)

        # Upgrade all "public" findings to "mx-ok" if the domain has MX
        for email, entry in raw.items():
            _, _, email_domain = email.partition("@")
            if email_domain == domain and mx_ok:
                if entry["confidence"] == "public":
                    entry["confidence"] = "mx-ok"
                entry["meta"]["mx_present"] = True

        # 7. SMTP verification (opt-in)
        if verify and mx and raw:
            info(f"verifying {len(raw)} email(s) via SMTP")
            to_verify = list(raw.keys())[:20]
            for email in to_verify:
                _, _, email_domain = email.partition("@")
                if email_domain != domain:
                    continue
                v = await smtp_verify(email, mx[0], verbose=verbose)
                entry = raw[email]
                entry["meta"]["smtp"] = v
                if v["result"] == "verified":
                    entry["confidence"] = "verified"
                elif v["result"] == "rejected":
                    entry["confidence"] = "rejected"
                await asyncio.sleep(0.5)

        # 8. Role-account guesses
        if mx_ok:
            for role in ROLE_ACCOUNTS:
                guess = f"{role}@{domain}"
                if guess not in raw:
                    raw[guess] = {
                        "sources": {"role-guess"},
                        "meta": {},
                        "confidence": "guess",
                    }

        # Remove rejected emails
        for email in list(raw.keys()):
            if raw[email]["confidence"] == "rejected":
                del raw[email]

        # ── SESSION E1 ── Pattern learning + generation ──
        # Build the list of *confirmed* emails (those with a
        # confidence above "guess" — we don't want to learn patterns
        # from our own guesses).
        confirmed = [
            e for e, entry in raw.items()
            if entry["confidence"] in ("verified", "mx-ok", "public")
        ]

        # Only learn if we have enough signal
        if len(confirmed) >= MIN_EMAILS_FOR_PATTERN:
            info(f"emails: learning local-part patterns "
                 f"from {len(confirmed)} confirmed email(s)")
            patterns = _extract_patterns(confirmed, domain)
            if patterns:
                result["patterns"] = patterns
                success(f"  learned {len(patterns)} pattern(s):")
                for pname, conf, examples, count in patterns[:5]:
                    print(f"    {pname:20s} confidence={conf} "
                          f"({count} match{'es' if count != 1 else ''})")
                    for ex in examples[:2]:
                        print(f"      e.g. {ex}")
            else:
                if verbose:
                    info("  no consistent pattern found")

        # Generation: only if we learned patterns AND either the
        # operator supplied names or --patterns was set.
        if result["patterns"] and (names or enable_patterns):
            info(f"emails: generating candidate emails")
            generated = _generate_candidates(
                confirmed, domain, result["patterns"],
                extra_names=names,
                min_confidence=min_confidence,
            )
            if generated:
                result["generated"] = generated
                success(f"  {len(generated)} candidate(s) generated")
                for c in generated[:15]:
                    print(f"    {c['email']:40s} "
                          f"[{c['pattern']}] "
                          f"from {c['source_name']!r} "
                          f"(conf={c['confidence']})")
                if len(generated) > 15:
                    print(f"    ... and {len(generated) - 15} more")
            else:
                if verbose:
                    info("  no new candidates generated "
                         "(names yielded no new patterns)")
        elif result["patterns"] and verbose:
            info("  (patterns learned but no names source — "
                 "pass --names-file or --patterns to generate)")
        # ── END SESSION E1 ──

        # Build the final list, sorted by confidence
        tier_order = {"verified": 0, "mx-ok": 1, "public": 2,
                      "pattern": 3, "guess": 4}
        emails = []
        for email, entry in raw.items():
            emails.append({
                "email": email,
                "confidence": entry["confidence"],
                "sources": sorted(entry["sources"]),
                "meta": entry["meta"],
            })
        emails.sort(key=lambda x: (tier_order.get(x["confidence"], 9),
                                     x["email"]))
        result["emails"] = emails

        return result
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose=False,
              hunter_key: str | None = None,
              verify: bool = False,
              subdomains: list[str] | None = None,
              names: list[str] | None = None,
              enable_patterns: bool = False,
              min_confidence: float = DEFAULT_MIN_CONFIDENCE) -> dict:
    """CLI entry. Writes finding to store if provided."""
    result = await discover(target, verbose=verbose,
                             hunter_key=hunter_key,
                             verify=verify,
                             subdomains=subdomains,
                             names=names,
                             enable_patterns=enable_patterns,
                             min_confidence=min_confidence)

    print()
    if not result["emails"]:
        warn(f"no emails found for {result['domain']}")
    else:
        # Count by confidence
        by_conf = {}
        for e in result["emails"]:
            by_conf[e["confidence"]] = by_conf.get(e["confidence"], 0) + 1
        parts = [f"{n} {c}" for c, n in by_conf.items()]
        success(f"{len(result['emails'])} email(s) for "
                f"{result['domain']} ({', '.join(parts)})")

        if result["mx"]:
            info(f"  MX: {', '.join(result['mx'][:3])}")
        else:
            warn(f"  no MX records")

        print()
        by_tier = {"verified": [], "mx-ok": [], "public": [],
                   "pattern": [], "guess": []}
        for e in result["emails"]:
            by_tier.setdefault(e["confidence"], []).append(e)

        for tier in ("verified", "mx-ok", "public", "pattern", "guess"):
            entries = by_tier.get(tier, [])
            if not entries:
                continue
            label = {
                "verified": "VERIFIED",
                "mx-ok": "MX OK (not SMTP-verified)",
                "public": "FOUND (public page)",
                "pattern": "GENERATED (pattern match, not verified)",
                "guess": "GUESS (role account, not verified)",
            }[tier]
            print(f"  {label} ({len(entries)}):")
            limit = 200 if verbose else 20
            for e in entries[:limit]:
                srcs = ",".join(e["sources"])
                extra = ""
                meta = e["meta"]
                if meta.get("position"):
                    extra = f" — {meta['position']}"
                elif meta.get("first_name") or meta.get("last_name"):
                    name = f"{meta.get('first_name', '')} " \
                           f"{meta.get('last_name', '')}".strip()
                    extra = f" — {name}"
                print(f"    {e['email']:40s} [{srcs}]{extra}")
            if len(entries) > limit:
                print(f"    ... and {len(entries) - limit} more "
                      f"(use -v for all, up to 200)")

    if store is not None:
        store.add_finding({
            "module": "emails",
            "type": "informational",
            "severity": "info",
            "target": result["domain"],
            "evidence": (f"{len(result['emails'])} email(s) discovered, "
                         f"{len(result.get('patterns', []))} pattern(s), "
                         f"{len(result.get('generated', []))} generated"),
            "data": {
                "domain": result["domain"],
                "mx": result["mx"],
                "emails": result["emails"],
                "patterns": result.get("patterns", []),
                "generated": result.get("generated", []),
            },
        })
        success(f"finding written to store")

    return result


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.emails",
        description="Email discovery via scraping, WHOIS, and Hunter.io.",
    )
    p.add_argument("target", help="domain or URL")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--hunter-key", default=None,
                   help="Hunter.io API key for corporate email search")
    p.add_argument("--verify", action="store_true",
                   help="SMTP RCPT TO verify found emails (opt-in, may be "
                        "blocked by mail server anti-spam)")
    p.add_argument("--names-file", default=None,
                   help="file with candidate names, one per line "
                        "(either 'First Last' or 'john.smith')")
    p.add_argument("--patterns", action="store_true",
                   help="enable candidate generation from discovered "
                        "emails even without --names-file")
    p.add_argument("--min-confidence", type=float,
                   default=DEFAULT_MIN_CONFIDENCE,
                   help=f"minimum pattern confidence to generate "
                        f"candidates (default {DEFAULT_MIN_CONFIDENCE})")
    p.add_argument("--store", action="store_true")
    args = p.parse_args()

    names = None
    if args.names_file:
        names = load_names(args.names_file)
        if names:
            info(f"loaded {len(names)} name(s) from {args.names_file}")

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
                    hunter_key=args.hunter_key, verify=args.verify,
                    names=names,
                    enable_patterns=args.patterns,
                    min_confidence=args.min_confidence))


if __name__ == "__main__":
    _cli()