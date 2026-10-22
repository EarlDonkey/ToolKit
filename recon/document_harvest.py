"""
Public document harvesting.

Finds every document the target publishes, downloads it, extracts
text and metadata, and mines the result for useful information.

The full docstring is at the top of the file — see the module
header for design and usage.
"""

import asyncio
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Extensions we look for and the mime types we treat as "documents"
DOC_EXTENSIONS = {
    "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt",
    "txt", "csv", "rtf", "odt", "ods", "odp",
    "pages", "numbers", "key",
}

# Default extensions to actually fetch (narrower than DOC_EXTENSIONS;
# we don't want to fetch .doc/.xls binaries we can't parse)
DEFAULT_FETCH_EXTS = {"pdf", "docx", "xlsx", "pptx", "txt", "csv"}

# Content-Type substrings that mark a response as a document even if
# the URL extension is wrong or missing
DOC_CONTENT_TYPES = (
    "application/pdf",
    "application/vnd.openxmlformats-officedocument",
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/rtf",
    "text/plain",
    "text/csv",
    "application/vnd.oasis.opendocument",
)

# Directory paths that commonly host documents
COMMON_DOC_PATHS = [
    "/sitemap.xml",
    "/documents/",
    "/docs/",
    "/files/",
    "/file/",
    "/downloads/",
    "/download/",
    "/uploads/",
    "/upload/",
    "/media/",
    "/attachments/",
    "/attachment/",
    "/public/",
    "/resources/",
    "/library/",
    "/forms/",
    "/policies/",
    "/news/",
    "/announcements/",
]

# Pages we crawl for links to documents (only with --doc-crawl)
CRAWL_PATHS = [
    "/", "/about", "/about-us", "/contact", "/news",
    "/announcements", "/policies", "/forms", "/resources",
    "/staff", "/faculty", "/students", "/parents",
]

# Regexes for mining
EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# Taiwan phone patterns:
#   +886 X XXXX XXXX / +886-2-XXXX-XXXX
#   0X-XXXX-XXXX / 0X XXXX XXXX
#   09XX-XXX-XXX (mobile)
PHONE_RE = re.compile(
    r"(?:\+?886[\-\s]?)?"          # optional country code
    r"(?:\(?0\d{1,2}\)?[\-\s]?)"    # area code 02..089
    r"\d{3,4}[\-\s]?\d{4}"          # main number
    r"(?:[\-\s]?(?:#|ext\.?|轉)?[\-\s]?\d{1,5})?"  # optional ext
)

# Extensions we recognise in phone patterns to avoid false positives
PHONE_EXT_MARKERS = ("#", "ext", "ext.", "轉")

# Name-like patterns for extraction (same spirit as social.py)
NAME_RE = re.compile(
    r"\b([A-Z][a-z]{1,20})\s+([A-Z][a-z]{1,20})\b"
)

# Words that are not names when seen in "First Last" patterns
NOT_A_NAME = {
    "page", "table", "chapter", "section", "figure", "appendix",
    "monday", "tuesday", "wednesday", "thursday", "friday",
    "saturday", "sunday",
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november",
    "december",
    "school", "class", "grade", "student", "teacher", "staff",
    "principal", "vice", "director", "manager", "department",
    "office", "center", "committee", "council", "board",
    "annual", "monthly", "weekly", "daily", "report",
    "total", "summary", "introduction", "conclusion", "notes",
    "the", "and", "for", "with", "from", "this", "that",
}

# Internal hostname patterns
INTERNAL_HOST_RE = re.compile(
    r"\b((?:[a-z0-9][a-z0-9\-]{0,62}\.)+"
    r"(?:internal|local|corp|lan|intranet|localdomain))\b",
    re.IGNORECASE,
)

# IP addresses
IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

# URLs in document text
URL_RE = re.compile(
    r"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]+"
)

# Lines that look suspicious
SUSPICIOUS_MARKERS = (
    "password", "passwd", "pass:", "user:", "username:",
    "api_key", "apikey", "api key", "secret", "token",
    "private key", "ssh-rsa", "begin rsa", "begin private",
    "internal use only", "confidential", "do not distribute",
    "not for public", "restricted",
)

# Cap per document download
MAX_DOC_BYTES = 20 * 1024 * 1024   # 20 MB

# Limits on mining output per document
MAX_LINES_PER_DOC = 200_000


# ---------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------

def _normalize_target(target):
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def _ext_of(url):
    path = urlparse(url).path.lower()
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return path.rsplit(".", 1)[-1]


def _url_host(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _same_host(url, base_host):
    return _url_host(url) == base_host


# ---------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------

async def _fetch_sitemap(session, root, limiter, verbose=False):
    """Fetch and parse sitemap.xml. Returns list of URLs found."""
    urls = set()
    for name in ("sitemap.xml", "sitemap_index.xml",
                 "sitemap-index.xml", "sitemap1.xml"):
        url = root + "/" + name
        try:
            status, _h, body, _ = await fetch(
                session, url, limiter, timeout=15.0, quiet=True)
        except Exception:
            continue
        if status != 200 or not body:
            continue
        # Extract <loc> entries
        for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", body,
                              re.IGNORECASE):
            urls.add(m.group(1).strip())
        if verbose and urls:
            info(f"    sitemap: {len(urls)} URL(s) from {name}")
    return list(urls)


def _extract_doc_links(html, base_url):
    """Extract document URLs from HTML body."""
    out = set()
    for m in re.finditer(
            r'''<a[^>]*\bhref\s*=\s*["']([^"']+)["']''',
            html, re.IGNORECASE):
        href = m.group(1).strip()
        full = urljoin(base_url, href)
        if not full.startswith(("http://", "https://")):
            continue
        ext = _ext_of(full)
        if ext in DOC_EXTENSIONS:
            out.add(full)
    return out


async def _discover_via_crawl(session, root, base_host, limiter,
                                verbose=False):
    """Fetch a small set of pages and extract doc links."""
    urls = set()
    for path in CRAWL_PATHS:
        page_url = urljoin(root + "/", path.lstrip("/"))
        try:
            status, _h, body, _ = await fetch(
                session, page_url, limiter, timeout=15.0, quiet=True)
        except Exception:
            continue
        if status != 200 or not body:
            continue
        links = _extract_doc_links(body, page_url)
        if links:
            urls |= {u for u in links if _same_host(u, base_host)}
            if verbose:
                info(f"    crawl {path}: {len(links)} doc link(s)")
    return urls


async def _discover_via_common_paths(session, root, base_host,
                                       limiter, verbose=False):
    """Try common document directories. Returns set of doc URLs."""
    urls = set()
    sem = asyncio.Semaphore(5)

    async def _one(path):
        page_url = root + path
        async with sem:
            try:
                status, _h, body, _ = await fetch(
                    session, page_url, limiter, timeout=10.0,
                    quiet=True)
            except Exception:
                return set()
        if status != 200 or not body:
            return set()
        # Either it's a directory listing HTML, or it IS a document
        ext = _ext_of(page_url)
        if ext in DOC_EXTENSIONS:
            return {page_url}
        return _extract_doc_links(body, page_url)

    results = await asyncio.gather(*[_one(p) for p in COMMON_DOC_PATHS])
    for r in results:
        urls |= {u for u in r if _same_host(u, base_host)}
    return urls


# ---------------------------------------------------------------------
# Metadata extraction (no library required)
# ---------------------------------------------------------------------

def _pdf_metadata_from_bytes(raw):
    """Extract PDF metadata with regex. No pypdf required.

    Looks for /Author, /Title, /Producer, /Creator, /CreationDate,
    /ModDate in the PDF trailer dict. Values can be either literal
    strings (parenthesized) or hex strings (<...>).
    """
    if not raw:
        return {}
    # Only look at the last ~200 KB where the trailer lives
    chunk = raw[-200_000:] if len(raw) > 200_000 else raw
    try:
        text = chunk.decode("latin-1", errors="ignore")
    except Exception:
        return {}
    out = {}
    for field in ("Author", "Title", "Producer", "Creator",
                   "CreationDate", "ModDate", "Subject", "Keywords"):
        # Literal string form: /Author (John Smith)
        m = re.search(
            rf"/{field}\s*\(((?:[^()\\]|\\.)*)\)", text)
        if m:
            val = m.group(1)
            # Unescape PDF string escapes
            val = re.sub(r"\\([nrt()\\])", r"\1", val)
            out[field.lower()] = val.strip()
            continue
        # Hex string form: /Author <FEFF...>
        m = re.search(rf"/{field}\s*<([0-9A-Fa-f\s]+)>", text)
        if m:
            hexstr = re.sub(r"\s+", "", m.group(1))
            try:
                b = bytes.fromhex(hexstr)
                # UTF-16 BE if it starts with BOM
                if b.startswith(b"\xfe\xff"):
                    val = b[2:].decode("utf-16-be", errors="ignore")
                else:
                    val = b.decode("latin-1", errors="ignore")
                out[field.lower()] = val.strip()
            except Exception:
                pass
    return out


def _office_metadata_from_zip(raw):
    """Extract Office metadata from docProps/core.xml. Works for
    DOCX/XLSX/PPTX without requiring python-docx/openpyxl/pptx.
    """
    if not raw:
        return {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except Exception:
        return {}
    out = {}
    try:
        if "docProps/core.xml" in zf.namelist():
            content = zf.read("docProps/core.xml").decode(
                "utf-8", errors="ignore")
            for field in ("creator", "lastModifiedBy", "title",
                           "subject", "description", "created",
                           "modified", "keywords", "category"):
                m = re.search(
                    rf"<[^>]*{field}[^>]*>\s*([^<]+?)\s*</",
                    content, re.IGNORECASE)
                if m:
                    out[field.lower()] = m.group(1).strip()
        if "docProps/app.xml" in zf.namelist():
            content = zf.read("docProps/app.xml").decode(
                "utf-8", errors="ignore")
            for field in ("Company", "Manager", "Application",
                           "AppVersion", "TotalTime"):
                m = re.search(
                    rf"<{field}>\s*([^<]+?)\s*</{field}>",
                    content, re.IGNORECASE)
                if m:
                    out[field.lower()] = m.group(1).strip()
    except Exception:
        pass
    finally:
        try:
            zf.close()
        except Exception:
            pass
    return out


# ---------------------------------------------------------------------
# Body extraction (library-required, lazy)
# ---------------------------------------------------------------------

def _pdf_body_text(raw):
    """Extract body text from PDF bytes. Requires pypdf.

    Returns "" if pypdf isn't installed or extraction fails.
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        return ""
    try:
        reader = PdfReader(io.BytesIO(raw))
        out = []
        for page in reader.pages:
            try:
                t = page.extract_text() or ""
            except Exception:
                t = ""
            if t:
                out.append(t)
            if sum(len(x) for x in out) > 500_000:
                break
        return "\n".join(out)
    except Exception:
        return ""


def _docx_body_text(raw):
    """Extract DOCX body text. Requires python-docx."""
    try:
        from docx import Document
    except ImportError:
        return ""
    try:
        doc = Document(io.BytesIO(raw))
        return "\n".join(p.text for p in doc.paragraphs if p.text)
    except Exception:
        return ""


def _xlsx_body_text(raw):
    """Extract XLSX cell text. Requires openpyxl."""
    try:
        from openpyxl import load_workbook
    except ImportError:
        return ""
    try:
        wb = load_workbook(io.BytesIO(raw), data_only=True,
                            read_only=True)
        out = []
        for ws in wb.worksheets:
            out.append(f"--- sheet: {ws.title} ---")
            for row in ws.iter_rows(values_only=True):
                cells = [str(c) for c in row if c is not None]
                if cells:
                    out.append(" | ".join(cells))
            if sum(len(x) for x in out) > 500_000:
                break
        try:
            wb.close()
        except Exception:
            pass
        return "\n".join(out)
    except Exception:
        return ""


def _pptx_body_text(raw):
    """Extract PPTX slide text. Requires python-pptx."""
    try:
        from pptx import Presentation
    except ImportError:
        return ""
    try:
        prs = Presentation(io.BytesIO(raw))
        out = []
        for i, slide in enumerate(prs.slides):
            out.append(f"--- slide {i+1} ---")
            for shape in slide.shapes:
                if hasattr(shape, "text") and shape.text:
                    out.append(shape.text)
            if sum(len(x) for x in out) > 500_000:
                break
        return "\n".join(out)
    except Exception:
        return ""


def _extract_body(ext, raw):
    """Dispatch to the right extractor based on extension."""
    if ext == "pdf":
        return _pdf_body_text(raw)
    if ext == "docx":
        return _docx_body_text(raw)
    if ext == "xlsx":
        return _xlsx_body_text(raw)
    if ext == "pptx":
        return _pptx_body_text(raw)
    if ext in ("txt", "csv", "rtf"):
        try:
            return raw.decode("utf-8", errors="ignore")
        except Exception:
            return raw.decode("latin-1", errors="ignore")
    return ""


def _extract_metadata(ext, raw):
    """Dispatch to the right metadata extractor."""
    if ext == "pdf":
        return _pdf_metadata_from_bytes(raw)
    if ext in ("docx", "xlsx", "pptx"):
        return _office_metadata_from_zip(raw)
    return {}


# ---------------------------------------------------------------------
# Mining
# ---------------------------------------------------------------------

def _mine_text(text):
    """Run every extractor on a block of text. Returns a dict."""
    if not text:
        return {}

    out = {
        "emails": set(),
        "phones": set(),
        "names": set(),
        "hosts": set(),
        "urls": set(),
        "ips": set(),
        "suspicious": [],
    }

    # Emails
    for m in EMAIL_RE.finditer(text):
        e = m.group(0).lower().rstrip(".,;:!?")
        # Skip obvious junk
        if e.endswith((".png", ".jpg", ".gif", ".svg", ".css", ".js")):
            continue
        out["emails"].add(e)

    # Phones
    for m in PHONE_RE.finditer(text):
        p = m.group(0).strip()
        # Reject if it looks like a date or a version number
        if len(p) < 8:
            continue
        out["phones"].add(p)

    # Names — "First Last" patterns, filtered
    for m in NAME_RE.finditer(text):
        first, last = m.group(1), m.group(2)
        if first.lower() in NOT_A_NAME:
            continue
        if last.lower() in NOT_A_NAME:
            continue
        out["names"].add(f"{first} {last}")

    # Internal hosts
    for m in INTERNAL_HOST_RE.finditer(text):
        out["hosts"].add(m.group(1).lower())

    # URLs
    for m in URL_RE.finditer(text):
        out["urls"].add(m.group(0))

    # IPs
    for m in IP_RE.finditer(text):
        ip = m.group(0)
        # Sanity check: reject octets > 255
        parts = ip.split(".")
        try:
            if not all(0 <= int(p) <= 255 for p in parts):
                continue
        except ValueError:
            continue
        out["ips"].add(ip)

    # Suspicious lines
    line_count = 0
    for line in text.splitlines():
        line_count += 1
        if line_count > MAX_LINES_PER_DOC:
            break
        low = line.lower()
        if any(marker in low for marker in SUSPICIOUS_MARKERS):
            out["suspicious"].append(line.strip()[:200])

    return out


# ---------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------

async def _download(session, url, limiter, timeout=30.0):
    """Download a document. Returns (raw_bytes, headers) or (None, None)."""
    try:
        status, headers, body, _ = await fetch(
            session, url, limiter, timeout=timeout, quiet=True)
    except Exception:
        return None, None
    if status != 200 or body is None:
        return None, None
    # body comes back as str from our fetch wrapper; convert back to
    # bytes. This works for most documents because aiohttp handles
    # the encoding.
    try:
        raw = body.encode("utf-8", errors="surrogateescape")
    except Exception:
        return None, headers
    if len(raw) > MAX_DOC_BYTES:
        return None, headers
    return raw, headers or {}


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def harvest(target, session=None, max_docs=100,
                   extensions=None, crawl=False,
                   rate=10.0, verbose=False):
    """Harvest public documents from a target.

    Returns a dict with:
        target, documents, metadata, emails, phones, names, hosts,
        urls, ips, suspicious, elapsed, errors
    """
    import time
    start = time.time()

    base = _normalize_target(target)
    parsed = urlparse(base)
    base_host = (parsed.hostname or "").lower()
    if not base_host:
        raise ValueError(f"cannot parse target: {target!r}")
    root = f"{parsed.scheme}://{parsed.netloc}"

    fetch_exts = (set(extensions) if extensions
                  else set(DEFAULT_FETCH_EXTS))

    info(f"document_harvest: target={base_host} "
         f"max_docs={max_docs} types={sorted(fetch_exts)}")

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(rate=rate)

    result = {
        "target": base_host,
        "documents": [],
        "metadata": {},
        "emails": [],
        "phones": [],
        "names": [],
        "hosts": [],
        "urls": [],
        "ips": [],
        "suspicious": [],
        "elapsed": 0.0,
        "errors": [],
    }

    try:
        # --- 1. Discovery ---
        info("phase 1: discovering document URLs")
        candidates = set()

        sitemap_urls = await _fetch_sitemap(session, root, limiter,
                                              verbose=verbose)
        for u in sitemap_urls:
            if _ext_of(u) in DOC_EXTENSIONS:
                candidates.add(u)
        if verbose:
            info(f"  sitemap: {len(candidates)} doc URL(s)")

        # Common directory probes
        discovered = await _discover_via_common_paths(
            session, root, base_host, limiter, verbose=verbose)
        candidates |= discovered
        if verbose:
            info(f"  common paths: +{len(discovered)} "
                 f"(total {len(candidates)})")

        # Optional crawl
        if crawl:
            crawled = await _discover_via_crawl(
                session, root, base_host, limiter, verbose=verbose)
            candidates |= crawled
            if verbose:
                info(f"  crawl: +{len(crawled)} "
                     f"(total {len(candidates)})")

        # Filter by fetch extensions
        to_fetch = [u for u in candidates
                     if _ext_of(u) in fetch_exts]
        # Dedup while preserving order
        seen = set()
        to_fetch = [u for u in to_fetch
                     if not (u in seen or seen.add(u))]
        # Apply max
        if len(to_fetch) > max_docs:
            info(f"  capping at {max_docs} documents "
                 f"(had {len(to_fetch)})")
            to_fetch = to_fetch[:max_docs]

        info(f"phase 2: downloading {len(to_fetch)} document(s)")

        # --- 2. Download + extract ---
        all_emails = set()
        all_phones = set()
        all_names = set()
        all_hosts = set()
        all_urls = set()
        all_ips = set()
        all_suspicious = []

        sem = asyncio.Semaphore(5)

        async def _one(url):
            async with sem:
                ext = _ext_of(url)
                raw, headers = await _download(session, url, limiter)

                entry = {
                    "url": url,
                    "extension": ext,
                    "size": len(raw) if raw else 0,
                    "sha256": (hashlib.sha256(raw).hexdigest()
                                if raw else ""),
                    "error": None,
                }
                if raw is None:
                    entry["error"] = "download failed or too large"
                    return entry, None, None

                meta = _extract_metadata(ext, raw)
                body_text = _extract_body(ext, raw)
                mined = _mine_text(body_text)

                if verbose:
                    info(f"    [{ext}] {url.rsplit('/', 1)[-1]:40s} "
                         f"{len(raw):>8d}B body={len(body_text):>6d} "
                         f"emails={len(mined.get('emails', []))} "
                         f"names={len(mined.get('names', []))}")

                return entry, meta, mined

        tasks = [_one(u) for u in to_fetch]
        for coro in asyncio.as_completed(tasks):
            entry, meta, mined = await coro
            result["documents"].append(entry)
            if meta:
                result["metadata"][entry["url"]] = meta
            if mined:
                all_emails |= mined["emails"]
                all_phones |= mined["phones"]
                all_names |= mined["names"]
                all_hosts |= mined["hosts"]
                all_urls |= mined["urls"]
                all_ips |= mined["ips"]
                for line in mined["suspicious"][:20]:
                    all_suspicious.append({
                        "source": entry["url"],
                        "line": line,
                    })

        result["emails"] = sorted(all_emails)
        result["phones"] = sorted(all_phones)
        result["names"] = sorted(all_names)
        result["hosts"] = sorted(all_hosts)
        result["urls"] = sorted(all_urls)
        result["ips"] = sorted(all_ips)
        result["suspicious"] = all_suspicious[:200]

        result["elapsed"] = round(time.time() - start, 2)
        return result
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(target, store=None, max_docs=100,
              extensions=None, crawl=False, rate=10.0,
              verbose=False):
    result = await harvest(
        target, max_docs=max_docs, extensions=extensions,
        crawl=crawl, rate=rate, verbose=verbose)

    print()
    n_docs = len(result["documents"])
    n_ok = sum(1 for d in result["documents"] if not d.get("error"))
    n_err = n_docs - n_ok
    success(f"document_harvest: {result['target']} "
            f"({n_ok} doc(s), {n_err} failed) "
            f"in {result['elapsed']}s")

    if result["documents"]:
        print()
        info(f"Documents ({n_ok}):")
        for d in result["documents"][:40]:
            if d.get("error"):
                print(f"    [err] {d['url']} — {d['error']}")
            else:
                print(f"    [{d['extension']:5s}] {d['url']} "
                      f"({d['size']} B)")
        if n_docs > 40:
            print(f"    ... and {n_docs - 40} more")

    if result["metadata"]:
        print()
        success(f"Document metadata ({len(result['metadata'])}):")
        for url, meta in list(result["metadata"].items())[:20]:
            fname = url.rsplit("/", 1)[-1]
            interesting = []
            for k in ("author", "creator", "lastmodifiedby",
                       "company", "producer", "title"):
                if meta.get(k):
                    interesting.append(f"{k}={meta[k]!r}")
            if interesting:
                print(f"    {fname}")
                for s in interesting:
                    print(f"      {s}")

    if result["emails"]:
        print()
        success(f"Emails ({len(result['emails'])}):")
        for e in result["emails"][:40]:
            print(f"    {e}")
        if len(result["emails"]) > 40:
            print(f"    ... and {len(result['emails']) - 40} more")

    if result["phones"]:
        print()
        success(f"Phone numbers ({len(result['phones'])}):")
        for p in result["phones"][:20]:
            print(f"    {p}")
        if len(result["phones"]) > 20:
            print(f"    ... and {len(result['phones']) - 20} more")

    if result["names"]:
        print()
        success(f"Names ({len(result['names'])}):")
        for n in result["names"][:30]:
            print(f"    {n}")
        if len(result["names"]) > 30:
            print(f"    ... and {len(result['names']) - 30} more")
        info("  (pass --names-out via recon --social to save for "
             "emails.py --names-file)")

    if result["hosts"]:
        print()
        warn(f"Internal hostnames ({len(result['hosts'])}):")
        for h in result["hosts"][:20]:
            print(f"    {h}")

    if result["ips"]:
        print()
        info(f"IPs ({len(result['ips'])}):")
        for ip in result["ips"][:20]:
            print(f"    {ip}")

    if result["suspicious"]:
        print()
        warn(f"Suspicious lines ({len(result['suspicious'])}):")
        for s in result["suspicious"][:15]:
            fname = s["source"].rsplit("/", 1)[-1]
            print(f"    [{fname}] {s['line'][:120]}")

    if store is not None:
        # One finding per doc with metadata
        for d in result["documents"]:
            if d.get("error"):
                continue
            meta = result["metadata"].get(d["url"]) or {}
            store.add_finding({
                "module": "document_harvest",
                "type": "informational",
                "severity": "info",
                "target": d["url"],
                "evidence": (f"{d['extension']} document "
                             f"({d['size']} B)"),
                "data": {
                    "url": d["url"],
                    "extension": d["extension"],
                    "size": d["size"],
                    "sha256": d["sha256"],
                    "metadata": meta,
                },
            })

        # One aggregate finding
        store.add_finding({
            "module": "document_harvest",
            "type": "informational",
            "severity": ("medium"
                          if result["suspicious"] else "info"),
            "target": result["target"],
            "evidence": (f"{n_ok} document(s), "
                         f"{len(result['emails'])} email(s), "
                         f"{len(result['names'])} name(s), "
                         f"{len(result['suspicious'])} "
                         f"suspicious line(s)"),
            "data": {
                "documents": result["documents"],
                "metadata": result["metadata"],
                "emails": result["emails"],
                "phones": result["phones"],
                "names": result["names"],
                "hosts": result["hosts"],
                "urls": result["urls"],
                "ips": result["ips"],
                "suspicious": result["suspicious"],
            },
        })
        success("findings written to store")

    return result


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.document_harvest",
        description="Harvest public documents and mine them for "
                    "information.",
    )
    p.add_argument("target", help="domain or URL")
    p.add_argument("--max-docs", type=int, default=100,
                   help="max documents to fetch (default 100)")
    p.add_argument("--types", default=None,
                   help="comma-separated extensions "
                        "(default: pdf,docx,xlsx,pptx,txt,csv)")
    p.add_argument("--crawl", action="store_true",
                   help="also crawl the site for links (slower)")
    p.add_argument("--rate", type=float, default=10.0,
                   help="requests per second (default 10)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--store", action="store_true")
    args = p.parse_args()

    exts = None
    if args.types:
        exts = [e.strip().lower().lstrip(".")
                 for e in args.types.split(",") if e.strip()]

    store = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; use `toolkit workspace switch`")
        else:
            ws = get_workspace(active)
            store = open_store(ws.db_path, workspace_name=active)

    asyncio.run(run(
        args.target, store=store,
        max_docs=args.max_docs,
        extensions=exts,
        crawl=args.crawl,
        rate=args.rate,
        verbose=args.verbose,
    ))


if __name__ == "__main__":
    _cli()