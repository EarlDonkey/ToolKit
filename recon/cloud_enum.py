"""
Cloud storage enumeration (conservative).

Given a base name (usually a domain or company name), probes three
providers for public cloud storage buckets:

  - AWS S3         {name}.s3.amazonaws.com
                   s3.amazonaws.com/{name}
  - Google Cloud   storage.googleapis.com/{name}
  - Firebase       {name}.firebaseio.com
                   {name}.firebaseapp.com

DigitalOcean Spaces is available but disabled by default — it adds
significant DNS-lookup cost for a very low hit rate. Enable explicitly
with --providers digitalocean.

Azure is deliberately excluded — Blob storage requires knowing both
the account name AND the container name. Container names are
user-chosen, so guessing produces thousands of pointless DNS lookups.
If you want to enumerate Azure, do it manually against a known account.

Response interpretation:

  200  → bucket exists AND is publicly readable     (critical finding)
  403  → bucket exists, access denied                (still a finding)
  301  → bucket exists (region redirect)
  404  → no bucket
  DNS failure → no bucket (silent, expected)

For public (200) S3/GCS buckets we also extract the object count from
the XML listing so you can distinguish empty registered names from
real data exposures.

Findings written to the store:
    one row per target with all discovered buckets in `data`
"""

import asyncio
import re
import time
from pathlib import Path

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error, console


SIGNATURES_PATH = Path(__file__).parent / "signatures" / "cloud_suffixes.txt"
DEFAULT_CONCURRENCY = 12
DEFAULT_MAX_CANDIDATES = 100


# ---------------------------------------------------------------------
# Wordlist
# ---------------------------------------------------------------------

def load_suffixes(path=SIGNATURES_PATH) -> list[str]:
    """Load bucket-name suffixes. Always includes '' (bare base name)."""
    if not path.exists():
        return _embedded_suffixes()

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return _embedded_suffixes()

    out = [""]
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _embedded_suffixes() -> list[str]:
    """Minimal fallback if the wordlist file is missing."""
    return [
        "",
        "-backup", "-backups", "-bak",
        "-dev", "-develop", "-development",
        "-test", "-testing",
        "-stage", "-staging",
        "-qa", "-sandbox",
        "-prod", "-production",
        "-public", "-share", "-shared",
        "-media", "-assets", "-static",
        "-uploads", "-upload", "-files", "-file",
        "-data", "-logs",
        "-app", "-apps", "-api",
        "-cdn", "-web", "-website",
        "-internal", "-admin", "-portal",
    ]


def build_base_names(target: str) -> list[str]:
    """Derive plausible base names from a target (domain or company)."""
    base = target.lower().strip()
    if base.startswith(("http://", "https://")):
        base = base.split("://", 1)[1]
    base = base.split("/")[0].split(":")[0]
    if base.startswith("www."):
        base = base[4:]

    names = {base}

    if "." in base:
        parts = base.split(".")
        names.add(parts[0])
        names.add("".join(parts))
        if len(parts) >= 3:
            names.add(".".join(parts[1:]))
            names.add(parts[1])

    names.add(base.replace(".", "-"))

    simple = "".join(c for c in base.split(".")[0] if c.isalnum())
    if simple:
        names.add(simple)

    return sorted(n for n in names if n)


# ---------------------------------------------------------------------
# Object count extraction
# ---------------------------------------------------------------------

def _count_objects(body: str) -> int | None:
    """Count objects in an S3/GCS XML listing body.

    Returns None if the body doesn't look like a listing.
    Returns 0 if it's a listing with no objects.
    Otherwise returns the count of <Contents> entries.
    """
    if not body:
        return None
    low = body.lower()
    if "<listbucketresult" not in low:
        return None
    return low.count("<contents>")


# ---------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------

async def probe_s3(name: str, session, limiter) -> dict | None:
    """Probe AWS S3."""
    urls = [
        f"https://{name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{name}/",
    ]
    for url in urls:
        try:
            status, _h, body, final = await fetch(
                session, url, limiter, timeout=8.0)
        except Exception:
            continue
        if status is None or status == 404:
            continue

        object_count = _count_objects(body) if status == 200 else None

        return {
            "provider": "aws-s3",
            "name": name,
            "url": url,
            "status": status,
            "size": len(body) if body else 0,
            "final_url": final,
            "object_count": object_count,
        }
    return None


async def probe_gcs(name: str, session, limiter) -> dict | None:
    """Probe Google Cloud Storage."""
    url = f"https://storage.googleapis.com/{name}/"
    try:
        status, _h, body, final = await fetch(
            session, url, limiter, timeout=8.0)
    except Exception:
        return None
    if status is None or status == 404:
        return None

    object_count = _count_objects(body) if status == 200 else None

    return {
        "provider": "gcs",
        "name": name,
        "url": url,
        "status": status,
        "size": len(body) if body else 0,
        "final_url": final,
        "object_count": object_count,
    }


DO_REGIONS = ["nyc3", "sfo3", "sgp1", "ams3", "fra1"]


async def probe_digitalocean(name: str, session, limiter) -> dict | None:
    """Probe DigitalOcean Spaces across common regions."""
    async def _try(region):
        url = f"https://{name}.{region}.digitaloceanspaces.com/"
        try:
            status, _h, body, final = await fetch(
                session, url, limiter, timeout=6.0)
        except Exception:
            return None
        if status is None or status == 404:
            return None
        object_count = _count_objects(body) if status == 200 else None
        return {
            "provider": "digitalocean-spaces",
            "name": name,
            "region": region,
            "url": url,
            "status": status,
            "size": len(body) if body else 0,
            "final_url": final,
            "object_count": object_count,
        }

    results = await asyncio.gather(*[_try(r) for r in DO_REGIONS])
    return next((r for r in results if r), None)


async def probe_firebase(name: str, session, limiter) -> dict | None:
    """Probe Firebase Realtime Database / Hosting.

    Firebase returns HTTP 200 with a "project not found" HTML page for
    unclaimed project names. We reject those explicitly.
    """
    urls = [
        f"https://{name}.firebaseio.com/.json",
        f"https://{name}.firebaseapp.com/",
    ]
    # Markers of Firebase's "unclaimed project" pages.
    _UNCLAIMED_MARKERS = (
        "project not found",
        "the firebase project",
        "firebase hosting",
        "site not found",
        "404 not found",
        "this project does not exist",
    )
    for url in urls:
        try:
            status, _h, body, final = await fetch(
                session, url, limiter, timeout=6.0)
        except Exception:
            continue
        if status is None or status == 404:
            continue
        if body and any(m in body.lower() for m in _UNCLAIMED_MARKERS):
            continue
        object_count = None
        return {
            "provider": "firebase",
            "name": name,
            "url": url,
            "status": status,
            "size": len(body) if body else 0,
            "final_url": final,
            "object_count": object_count,
        }
    return None


PROVIDER_PROBES = {
    "s3":           probe_s3,
    "gcs":          probe_gcs,
    "digitalocean": probe_digitalocean,
    "firebase":     probe_firebase,
}


# ---------------------------------------------------------------------
# Main enumeration
# ---------------------------------------------------------------------

async def enumerate(target: str,
                     session=None,
                     verbose: bool = False,
                     providers: list[str] | None = None,
                     suffixes: list[str] | None = None,
                     max_candidates: int = DEFAULT_MAX_CANDIDATES,
                     concurrency: int = DEFAULT_CONCURRENCY) -> dict:
    """Enumerate public cloud storage for a target."""
    # DigitalOcean disabled by default; S3/GCS/Firebase only
    providers = providers or ["s3", "gcs", "firebase"]
    providers = [p for p in providers if p in PROVIDER_PROBES]
    if not providers:
        warn("no valid providers specified")
        return {"target": target, "buckets": [], "candidates_tested": 0,
                "base_names": [], "providers": [], "elapsed": 0.0}

    if suffixes is None:
        suffixes = load_suffixes()

    bases = build_base_names(target)
    candidates = []
    seen = set()
    for base in bases:
        for suffix in suffixes:
            name = f"{base}{suffix}"
            if not re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", name):
                continue
            if name in seen:
                continue
            seen.add(name)
            candidates.append(name)
            if len(candidates) >= max_candidates:
                break
        if len(candidates) >= max_candidates:
            break

    total_probes = len(candidates) * len(providers)
    info(f"cloud_enum: {len(candidates)} candidate(s) × "
         f"{len(providers)} provider(s) = {total_probes} probe(s)")

    own_session = session is None
    if own_session:
        session = new_session()
    limiter = RateLimiter(10.0)

    sem = asyncio.Semaphore(concurrency)
    buckets: list[dict] = []
    completed = 0
    start = time.time()
    lock = asyncio.Lock()

    async def check_one(candidate: str) -> list[dict]:
        nonlocal completed
        hits = []
        async with sem:
            for provider in providers:
                fn = PROVIDER_PROBES.get(provider)
                if not fn:
                    continue
                try:
                    r = await fn(candidate, session, limiter)
                except Exception:
                    r = None
                if r:
                    hits.append(r)
                    label = "PUBLIC" if r["status"] == 200 \
                            else f"HTTP {r['status']}"
                    count_str = ""
                    if r.get("object_count") is not None:
                        n = r["object_count"]
                        count_str = (f" ({n:,} objects)" if n
                                     else " (empty)")
                    with_print = True
                    try:
                        from net.util import PRINT_LOCK
                        with PRINT_LOCK:
                            success(f"  [{label:9s}] "
                                    f"{r['provider']:20s} "
                                    f"{r['name']}{count_str}")
                    except Exception:
                        pass
        async with lock:
            completed += 1
        return hits

    try:
        all_results = await asyncio.gather(
            *[check_one(c) for c in candidates],
            return_exceptions=True)

        for group in all_results:
            if isinstance(group, Exception):
                continue
            buckets.extend(group)

        # Sort: 200 first (by object count desc), then 403s, then others
        def sort_key(b):
            s = b["status"]
            tier = 0 if s == 200 else (1 if s in (403, 409) else 2)
            count = b.get("object_count") or 0
            return (tier, -count, b["provider"], b["name"])
        buckets.sort(key=sort_key)

        elapsed = time.time() - start
        return {
            "target": target,
            "base_names": bases,
            "candidates_tested": len(candidates),
            "providers": providers,
            "buckets": buckets,
            "elapsed": round(elapsed, 2),
        }
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

def _format_count(b: dict) -> str:
    """Return a ' (N objects)' or ' (empty)' suffix, or '' if unknown."""
    count = b.get("object_count")
    if count is None:
        return ""
    if count == 0:
        return " (empty)"
    return f" ({count:,} object{'s' if count != 1 else ''})"


async def run(target: str, store=None, verbose: bool = False,
              providers: list[str] | None = None) -> dict:
    """CLI entry. Writes finding to store if provided."""
    result = await enumerate(target, verbose=verbose, providers=providers)

    print()
    if not result["buckets"]:
        info(f"no cloud buckets found for {target} "
             f"({result['candidates_tested']} candidates × "
             f"{len(result['providers'])} providers, "
             f"{result.get('elapsed', 0)}s)")
    else:
        public = [b for b in result["buckets"] if b["status"] == 200]
        denied = [b for b in result["buckets"] if b["status"] in (403, 409)]
        other = [b for b in result["buckets"]
                 if b not in public and b not in denied]

        success(f"{len(result['buckets'])} bucket(s) for {target} "
                f"({len(public)} public, {len(denied)} denied/exists, "
                f"{result.get('elapsed', 0)}s)")

        if public:
            print()
            error("  PUBLIC (data exposure!):")
            for b in public:
                detail = _format_count(b)
                print(f"    {b['provider']:20s} {b['name']}{detail}")
                print(f"      {b['url']}")

        if denied:
            print()
            warn("  EXISTS but not public:")
            for b in denied:
                print(f"    {b['provider']:20s} {b['name']} "
                      f"(HTTP {b['status']})")

        if other and verbose:
            print()
            info("  Other responses:")
            for b in other:
                print(f"    {b['provider']:20s} {b['name']} "
                      f"(HTTP {b['status']})")

    if store is not None:
        public = [b for b in result["buckets"] if b["status"] == 200]
        if public:
            severity = "high"
            ftype = "cloud_bucket_exposed"
        else:
            severity = "info"
            ftype = "informational"

        store.add_finding({
            "module": "cloud_enum",
            "type": ftype,
            "severity": severity,
            "target": target,
            "evidence": (f"{len(public)} public bucket(s), "
                         f"{len(result['buckets'])} total found "
                         f"in {result.get('elapsed', 0)}s"),
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
        prog="recon.cloud_enum",
        description="Enumerate public cloud storage for a target.",
    )
    p.add_argument("target", help="domain or company name")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--providers", action="append",
                   choices=["s3", "gcs", "digitalocean", "firebase"],
                   help="restrict to specific provider(s); repeatable. "
                        "Default: s3, gcs, firebase. Add digitalocean "
                        "explicitly to enable it.")
    p.add_argument("--max-candidates", type=int,
                   default=DEFAULT_MAX_CANDIDATES)
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
                    providers=args.providers))


if __name__ == "__main__":
    _cli()