"""
CMS fingerprinting for login pages.

Detects common CMS platforms (Craft, WordPress, Drupal, Joomla, Magento,
Ghost) from a login URL and, where possible, extracts a version number.
The version is the input to CVE matching; without it you're guessing.

Design notes:
  - Multiple heuristics per CMS. Any single marker can appear on a
    non-CMS page; requiring several markers to agree raises confidence.
  - Version detection tries the HTML body, response headers, JS bundle
    names, and a couple of CMS-specific endpoints that sometimes leak.
  - All checks are read-only GETs (or a single HEAD) against public
    URLs. Nothing here attempts to authenticate.
"""

import re
import asyncio

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------
#
# Each signature contributes to a confidence score. Confidence >= 0.5
# is treated as "identified". This avoids false positives from a single
# coincidental string.

CRAFT_MARKERS = {
    "html": [
        (r"craft\s*cms", 0.4, "Craft branding in HTML"),
        (r"craft_csrf_token", 0.4, "CRAFT_CSRF_TOKEN hidden input"),
        (r"craftsessionid", 0.3, "CraftSessionId cookie"),
        (r"/admin/login", 0.1, "Craft admin login path"),
        (r"craft\.js", 0.2, "Craft JS bundle referenced"),
        (r"cp\.css", 0.2, "Craft control-panel CSS referenced"),
    ],
    "headers": [
        ("x-powered-by", r"craft", 0.4, "X-Powered-By: Craft"),
        ("set-cookie", r"craftsessionid", 0.4, "CraftSessionId cookie"),
        ("server", r"craft", 0.3, "Server header mentions Craft"),
    ],
}

WORDPRESS_MARKERS = {
    "html": [
        (r"wp-content", 0.4, "wp-content path"),
        (r"wp-includes", 0.4, "wp-includes path"),
        (r"wordpress", 0.3, "WordPress branding"),
        (r"/wp-login\.php", 0.5, "wp-login.php path"),
        (r'name="log"', 0.2, 'wp-login "log" field'),
    ],
    "headers": [
        ("x-powered-by", r"wordpress", 0.4, "X-Powered-By: WordPress"),
        ("link", r"wp-json", 0.3, "wp-json Link header"),
    ],
}

DRUPAL_MARKERS = {
    "html": [
        (r"drupal", 0.4, "Drupal branding"),
        (r"/sites/default/files", 0.4, "Drupal files path"),
        (r"/core/misc/drupal\.js", 0.4, "Drupal core JS"),
        (r'name="form_build_id"', 0.3, "Drupal form_build_id"),
    ],
    "headers": [
        ("x-generator", r"drupal", 0.5, "X-Generator: Drupal"),
        ("x-drupal-cache", r".", 0.5, "X-Drupal-Cache header present"),
        ("x-drupal-dynamic-cache", r".", 0.5, "X-Drupal-Dynamic-Cache present"),
    ],
}

JOOMLA_MARKERS = {
    "html": [
        (r"/administrator/", 0.4, "Joomla administrator path"),
        (r"joomla", 0.4, "Joomla branding"),
        (r"/media/jui/", 0.3, "Joomla UI path"),
        (r"com_users", 0.3, "Joomla com_users component"),
    ],
    "headers": [],
}

MAGENTO_MARKERS = {
    "html": [
        (r"magento", 0.4, "Magento branding"),
        (r"/skin/frontend/", 0.4, "Magento skin path"),
        (r"mage/cookies", 0.3, "Magento cookies JS"),
        (r"form_key", 0.3, "Magento form_key field"),
    ],
    "headers": [
        ("set-cookie", r"frontend=", 0.4, "Magento frontend cookie"),
        ("x-magento-cache-debug", r".", 0.5, "X-Magento-Cache-Debug header"),
    ],
}

GHOST_MARKERS = {
    "html": [
        (r"ghost", 0.3, "Ghost branding"),
        (r"/ghost/", 0.4, "Ghost admin path"),
        (r"ghost-url", 0.3, "ghost-url meta"),
    ],
    "headers": [],
}

CMS_SIGNATURES = {
    "craft":     CRAFT_MARKERS,
    "wordpress": WORDPRESS_MARKERS,
    "drupal":    DRUPAL_MARKERS,
    "joomla":    JOOMLA_MARKERS,
    "magento":   MAGENTO_MARKERS,
    "ghost":     GHOST_MARKERS,
}


# ---------------------------------------------------------------------
# Version extraction patterns
# ---------------------------------------------------------------------
#
# Each CMS leaks its version differently. Ordered by reliability — the
# first match wins. None of these are guaranteed; version detection is
# best-effort.

CRAFT_VERSION_PATTERNS = [
    # e.g. "Craft CMS 4.5.2"
    r"craft\s*cms\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    # e.g. "Craft 3.7.9"
    r"craft\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    # Cache-busting query on the CP CSS, e.g. cp.css?v=4.5.2
    r"cp\.css\?v=([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    # Cache-busting query on craft.js
    r"craft\.js\?v=([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    # Generator meta tag
    r'<meta\s+name=["\']generator["\']\s+content=["\']craft\s*cms\s*([^"\']+)["\']',
]

WORDPRESS_VERSION_PATTERNS = [
    r'<meta\s+name=["\']generator["\']\s+content=["\']wordpress\s+([0-9.]+)',
    r"wp-includes/js/wp-embed\.js\?ver=([0-9.]+)",
    r"/wp-includes/css/dashicons\.min\.css\?ver=([0-9.]+)",
]

DRUPAL_VERSION_PATTERNS = [
    r'<meta\s+name=["\']generator["\']\s+content=["\']drupal\s+([0-9.]+)',
    r"drupal-settings-json",
]

JOOMLA_VERSION_PATTERNS = [
    r'<meta\s+name=["\']generator["\']\s+content=["\']joomla!?\s*-?\s*([0-9.]+)',
]

VERSION_PATTERNS = {
    "craft":     CRAFT_VERSION_PATTERNS,
    "wordpress": WORDPRESS_VERSION_PATTERNS,
    "drupal":    DRUPAL_VERSION_PATTERNS,
    "joomla":    JOOMLA_VERSION_PATTERNS,
}


# ---------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------

def _score_markers(body_low, headers, markers):
    """Return (confidence, evidence) for one CMS given a response body
    and headers. markers is a dict with 'html' and 'headers' keys."""
    score = 0.0
    evidence = []

    for pattern, weight, description in markers.get("html", []):
        if re.search(pattern, body_low):
            score += weight
            evidence.append(description)

    for header_name, pattern, weight, description in markers.get("headers", []):
        val = headers.get(header_name, "") or headers.get(header_name.title(), "")
        if val and re.search(pattern, str(val), re.IGNORECASE):
            score += weight
            evidence.append(description)

    return min(score, 1.0), evidence


def _extract_version(body, headers, cms):
    """Return a version string or None. Tries the CMS-specific patterns
    in order, then falls back to the generator meta tag."""
    for pattern in VERSION_PATTERNS.get(cms, []):
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            try:
                return m.group(1).strip()
            except IndexError:
                continue
    return None


def _normalize_headers(headers):
    """HTTP header dicts are case-insensitive but aiohttp gives them
    lowercased already in some versions. Normalize just in case."""
    if not headers:
        return {}
    return {k.lower(): v for k, v in headers.items()}


# ---------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------

async def fingerprint(url, session=None, rate_limiter=None, verbose=False):
    """Fetch the URL and attempt to identify the CMS.

    Returns a dict:
      {
        "url":         final URL after redirects,
        "status":      HTTP status code,
        "cms":         "craft" | "wordpress" | ... | None,
        "version":     "4.5.2" | None,
        "confidence":  0.0 .. 1.0,
        "evidence":    [str, ...],
        "all_scores":  {"craft": 0.7, "wordpress": 0.1, ...},
      }
    """
    own_session = session is None
    if own_session:
        session = new_session()
    if rate_limiter is None:
        rate_limiter = RateLimiter(5.0)

    result = {
        "url": url,
        "status": None,
        "cms": None,
        "version": None,
        "confidence": 0.0,
        "evidence": [],
        "all_scores": {},
    }

    try:
        r = await fetch(session, url, rate_limiter)
        if r is None or r[2] is None:
            warn(f"fingerprint: no response from {url}")
            return result

        status, headers, body, final_url = r
        headers = _normalize_headers(headers)
        result["status"] = status
        result["url"] = final_url

        body_low = body.lower()

        scores = {}
        evidence_by_cms = {}
        for cms, markers in CMS_SIGNATURES.items():
            score, evidence = _score_markers(body_low, headers, markers)
            scores[cms] = score
            evidence_by_cms[cms] = evidence

        result["all_scores"] = scores

        best_cms = max(scores, key=scores.get)
        best_score = scores[best_cms]

        if best_score >= 0.5:
            result["cms"] = best_cms
            result["confidence"] = best_score
            result["evidence"] = evidence_by_cms[best_cms]
            result["version"] = _extract_version(body, headers, best_cms)

            if verbose:
                success(f"fingerprint: {best_cms} "
                        f"(confidence {best_score:.2f}, "
                        f"version {result['version'] or 'unknown'})")
        else:
            if verbose:
                warn(f"fingerprint: no CMS identified "
                     f"(best guess {best_cms} at {best_score:.2f})")

    except Exception as e:
        warn(f"fingerprint failed on {url}: "
             f"{type(e).__name__}: {e!r}")
    finally:
        if own_session:
            await session.close()

    return result


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target, verbose=False, output_file=None):
    """Called by toolkit.py recon --cms --target <url>."""
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    info(f"fingerprinting {target}")
    result = await fingerprint(target, verbose=verbose)

    print()
    if result["cms"]:
        success(f"CMS: {result['cms']} "
                f"(confidence {result['confidence']:.2f})")
        if result["version"]:
            success(f"Version: {result['version']}")
        else:
            warn("Version: could not determine")
        info("Evidence:")
        for e in result["evidence"]:
            print(f"  - {e}")
    else:
        warn("no CMS identified from this URL")

    if verbose and result["all_scores"]:
        info("All CMS scores:")
        for cms, score in sorted(result["all_scores"].items(),
                                 key=lambda x: -x[1]):
            print(f"  {cms:12s} {score:.2f}")

    if output_file:
        import json
        from pathlib import Path
        Path(output_file).write_text(json.dumps(result, indent=2, default=str))
        success(f"report saved to {output_file}")

    return result