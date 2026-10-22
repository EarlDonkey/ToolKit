"""
OpenAPI / Swagger specification discovery.

Fetches a curated list of ~60 common spec paths, parses every valid
JSON or YAML response, and flattens the spec into a list of documented
endpoints, parameters, schemas, and servers.

Why this matters:

  - Unauthenticated /swagger.json on a corporate API is a critical
    finding on its own.
  - Even an authenticated spec tells you every endpoint, parameter,
    and data model the API exposes.
  - Server lists often reveal internal hostnames
    (http://api.internal.corp/) that DNS never sees.
  - Schema names reveal the internal data model
    (User, Account, BillingRecord, ...).

Design:

  - Discovery phase fetches all candidate URLs concurrently.
  - Parse phase runs on every 2xx response; anything that fails to
    parse as JSON or YAML is ignored.
  - Endpoint flattening is best-effort: specs vary wildly in how much
    metadata they include. We extract what's there.
  - Both OpenAPI 3.x (components/schemas) and Swagger 2.0
    (definitions) are supported.

Usage:

    from recon.openapi import discover

    result = await discover("https://api.example.com")
    print(f"{len(result['endpoints'])} endpoints found")

    # CLI
    python -m recon.openapi api.example.com
    python -m recon.openapi api.example.com -v
    python -m recon.openapi api.example.com --store

Findings written to the store:
    one row per spec discovered, with endpoints and schemas in `data`.
"""

import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn
from core.target import parse

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Paths to try, in rough order of likelihood. Every path is tried
# against the target's origin (scheme + host + port).
SPEC_PATHS = [
    # --- Direct spec files (OpenAPI 3.x) ---
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/openapi",

    # --- Direct spec files (Swagger 2.0) ---
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/swagger",

    # --- ASP.NET convention ---
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/swagger/1.0/swagger.json",

    # --- Spring Boot (springdoc / springfox) ---
    "/v2/api-docs",
    "/v3/api-docs",
    "/v2/api-docs?group=public",
    "/v3/api-docs/swagger-config",
    "/swagger-resources",
    "/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security",

    # --- FastAPI / drf-yasg / others ---
    "/api-docs",
    "/api-docs.json",
    "/api-docs.yaml",
    "/api/docs",
    "/docs",
    "/docs/",
    "/redoc",
    "/redoc/",

    # --- API-scoped ---
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/schema",
    "/api/schema.json",
    "/api/v1/openapi.json",
    "/api/v1/swagger.json",
    "/api/v2/openapi.json",
    "/api/v2/swagger.json",
    "/api/v3/openapi.json",
    "/api/v3/swagger.json",

    # --- Swagger UI shells (HTML, but reveal the spec URL) ---
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger/index.html",
    "/swagger/",

    # --- .well-known ---
    "/.well-known/openapi.json",
    "/.well-known/openapi.yaml",
    "/.well-known/swagger.json",

    # --- WordPress REST API (sometimes exposes a schema) ---
    "/wp-json/",
    "/wp-json/swagger",
    "/wp-json/openapi",

    # --- Common alt locations ---
    "/spec",
    "/spec.json",
    "/spec.yaml",
    "/specs",
    "/api/spec",
    "/api/spec.json",
    "/api/spec.yaml",
]


# Content markers that indicate a spec file even if we can't parse it
# (e.g. because it's YAML and pyyaml isn't installed).
_SPEC_MARKERS = (
    '"openapi"',       # OpenAPI 3.x
    '"swagger"',       # Swagger 2.0
    "openapi:",        # YAML OpenAPI 3.x
    "swagger:",        # YAML Swagger 2.0
    '"swaggerVersion"',  # Springfox
    '"swaggerUrl"',      # Swagger UI config
)


# HTML markers that indicate a Swagger UI shell we should parse for a
# `url:` value pointing to the actual spec.
_SWAGGER_UI_MARKERS = (
    "swagger-ui",
    "swaggerui",
    "swagger ui",
    "redoc",
    "rapidoc",
)


# ---------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------

def _try_parse_spec(body: str, content_type: str = "") -> dict | None:
    """Attempt to parse a spec body as JSON or YAML.

    Returns the parsed dict, or None if neither works. A dict is only
    returned if it looks like an OpenAPI / Swagger spec (has "openapi"
    or "swagger" key, or "paths" and "info" together).
    """
    if not body:
        return None

    ct = (content_type or "").lower()

    # --- JSON path ---
    if "json" in ct or body.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(body)
            if _looks_like_spec(data):
                return data
        except Exception:
            pass

    # --- YAML path ---
    if _HAS_YAML:
        try:
            data = yaml.safe_load(body)
            if _looks_like_spec(data):
                return data
        except Exception:
            pass

    # --- Last-ditch: extract a JSON object from an HTML page that
    # contains one (Swagger UI sometimes embeds the spec) ---
    if "<html" in body.lower() or "<!doctype" in body.lower():
        embedded = _extract_embedded_json(body)
        if embedded and _looks_like_spec(embedded):
            return embedded

    return None


def _looks_like_spec(data: Any) -> bool:
    """Return True if `data` looks like an OpenAPI / Swagger spec."""
    if not isinstance(data, dict):
        return False
    if "openapi" in data or "swagger" in data:
        return True
    # Some legacy specs only have paths + info
    if "paths" in data and "info" in data and isinstance(data["paths"], dict):
        return True
    return False


def _extract_embedded_json(html: str) -> dict | None:
    """Find the first top-level JSON object in an HTML body.

    Crude but works for Swagger UI pages that embed `{"openapi": ...}`
    or `spec: {...}` inline. We look for a `{` followed by a
    plausible spec key.
    """
    import re
    # Look for the spec-in-JS pattern: `spec: {...}` or
    # `"openapi": {...}` etc.
    for m in re.finditer(r"\{", html):
        start = m.start()
        # Find the matching closing brace
        depth = 0
        in_string = False
        escape = False
        for i in range(start, min(len(html), start + 500_000)):
            ch = html[i]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = html[start:i + 1]
                    # Only try if it looks plausible
                    if '"openapi"' in candidate or '"swagger"' in candidate:
                        try:
                            return json.loads(candidate)
                        except Exception:
                            pass
                    break
    return None


# ---------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------

def _extract_servers(spec: dict, spec_url: str = "") -> list[str]:
    """Return every server URL in the spec.

    OpenAPI 3.x uses `servers: [{url: ...}, ...]`. URLs can be absolute
    (`https://api.example.com/v1`) or relative (`/api/v3`). Relative
    URLs are resolved against the spec's own URL, since that's how a
    client using the spec would interpret them.

    Swagger 2.0 uses `host`, `basePath`, and `schemes: [...]`.
    """
    from urllib.parse import urljoin

    servers = []

    # OpenAPI 3.x
    for s in spec.get("servers") or []:
        if not isinstance(s, dict):
            continue
        url = s.get("url")
        if not url:
            continue
        # Resolve relative URLs against the spec's location
        if spec_url and not url.startswith(("http://", "https://")):
            url = urljoin(spec_url, url)
        servers.append(url)

    # Swagger 2.0
    host = spec.get("host")
    base = spec.get("basePath") or ""
    schemes = spec.get("schemes") or ["https"]
    if host:
        for scheme in schemes:
            servers.append(f"{scheme}://{host}{base}")

    return sorted(set(servers))


def _extract_security_schemes(spec: dict) -> dict:
    """Return the spec's security schemes (auth methods)."""
    if "components" in spec and isinstance(spec["components"], dict):
        schemes = spec["components"].get("securitySchemes") or {}
        if isinstance(schemes, dict):
            return {k: _summarize_security_scheme(v)
                    for k, v in schemes.items()}
    # Swagger 2.0
    schemes = spec.get("securityDefinitions") or {}
    if isinstance(schemes, dict):
        return {k: _summarize_security_scheme(v)
                for k, v in schemes.items()}
    return {}


def _summarize_security_scheme(scheme: dict) -> dict:
    """Return a compact dict for a security scheme."""
    if not isinstance(scheme, dict):
        return {}
    out = {
        "type": scheme.get("type"),
        "description": scheme.get("description"),
    }
    if scheme.get("type") == "apiKey":
        out["in"] = scheme.get("in")
        out["name"] = scheme.get("name")
    elif scheme.get("type") == "http":
        out["scheme"] = scheme.get("scheme")
        out["bearerFormat"] = scheme.get("bearerFormat")
    elif scheme.get("type") == "oauth2":
        out["flows"] = list((scheme.get("flows") or {}).keys())
    return {k: v for k, v in out.items() if v is not None}


def _flatten_parameters(params: Any) -> list[dict]:
    """Normalize a `parameters:` list into a flat shape."""
    out = []
    if not isinstance(params, list):
        return out
    for p in params:
        if not isinstance(p, dict):
            continue
        entry = {
            "name": p.get("name"),
            "in": p.get("in"),                 # query/path/header/cookie
            "required": p.get("required", False),
            "type": None,
            "format": None,
            "description": p.get("description"),
        }
        # OpenAPI 3.x: schema is nested
        schema = p.get("schema") or {}
        if isinstance(schema, dict):
            entry["type"] = schema.get("type")
            entry["format"] = schema.get("format")
            # Enum values are often interesting
            if schema.get("enum"):
                entry["enum"] = schema["enum"]
        # Swagger 2.0: type is inline
        elif p.get("type"):
            entry["type"] = p.get("type")
            entry["format"] = p.get("format")
            if p.get("enum"):
                entry["enum"] = p["enum"]
        out.append(entry)
    return out


def _extract_request_body_schema(op: dict) -> dict | None:
    """Extract a compact shape of the request body schema for OpenAPI 3.x."""
    rb = op.get("requestBody")
    if not isinstance(rb, dict):
        return None
    content = rb.get("content") or {}
    for ct, spec in content.items():
        schema = (spec or {}).get("schema")
        if schema:
            return {
                "content_type": ct,
                "required": rb.get("required", False),
                "schema": schema,
            }
    return None


def _flatten_endpoints(spec: dict, spec_url: str) -> list[dict]:
    """Turn the spec's paths into a flat list of endpoint rows."""
    out = []
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return out

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            method_upper = method.upper()
            if method_upper not in ("GET", "POST", "PUT", "PATCH",
                                     "DELETE", "HEAD", "OPTIONS",
                                     "TRACE"):
                continue
            if not isinstance(op, dict):
                continue
            entry = {
                "method": method_upper,
                "path": path,
                "summary": op.get("summary"),
                "description": op.get("description"),
                "operationId": op.get("operationId"),
                "tags": op.get("tags") or [],
                "deprecated": bool(op.get("deprecated", False)),
                "security": op.get("security") or [],
                "parameters": _flatten_parameters(op.get("parameters")),
                "request_body": _extract_request_body_schema(op),
                "responses": list((op.get("responses") or {}).keys()),
                "spec_url": spec_url,
            }
            out.append(entry)
    return out


def _extract_schemas(spec: dict) -> list[str]:
    """Return the list of schema names defined in the spec."""
    # OpenAPI 3.x
    if "components" in spec and isinstance(spec["components"], dict):
        schemas = spec["components"].get("schemas") or {}
        if isinstance(schemas, dict):
            return sorted(schemas.keys())
    # Swagger 2.0
    defs = spec.get("definitions") or {}
    if isinstance(defs, dict):
        return sorted(defs.keys())
    return []


def _extract_tags(spec: dict) -> list[dict]:
    """Return the spec's tags (used to group endpoints)."""
    out = []
    for t in spec.get("tags") or []:
        if isinstance(t, dict):
            out.append({
                "name": t.get("name"),
                "description": t.get("description"),
            })
    return out


# ---------------------------------------------------------------------
# Swagger UI HTML extraction
# ---------------------------------------------------------------------

def _extract_spec_url_from_html(html: str, base_url: str) -> str | None:
    """Look for a URL to the actual spec inside a Swagger UI / Redoc page.

    Swagger UI typically has something like:
        url: "/v3/api-docs"
        url: "https://api.example.com/openapi.json"
        urls: [{url: "...", name: "..."}]

    Redoc has:
        spec-url="/openapi.json"
        <redoc spec-url="...">

    We do a regex pass; it's not perfect but catches the common cases.
    """
    if not html:
        return None
    import re

    # Swagger UI: `url: "..."` or `url: '...'`
    m = re.search(r'url\s*:\s*["\']([^"\']+)["\']', html)
    if m:
        return urljoin(base_url, m.group(1))

    # Swagger UI: `urls: [{ url: "..." }]` — take the first
    m = re.search(r'urls\s*:\s*\[\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
                  html, re.DOTALL)
    if m:
        return urljoin(base_url, m.group(1))

    # Redoc: `spec-url="..."` (attribute) or `spec-url='...'`
    m = re.search(r'spec-url\s*=\s*["\']([^"\']+)["\']', html)
    if m:
        return urljoin(base_url, m.group(1))

    # Data attribute in any UI shell
    m = re.search(r'data-spec-url\s*=\s*["\']([^"\']+)["\']', html)
    if m:
        return urljoin(base_url, m.group(1))

    return None


# ---------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------

async def _fetch_one(session, url: str, limiter,
                     timeout: float = 10.0) -> dict | None:
    """Fetch a URL, return a result dict with status/headers/body."""
    try:
        r = await fetch(session, url, limiter, timeout=timeout,
                        allow_redirects=True)
    except Exception:
        return None
    if r is None or r[0] is None:
        return None
    status, headers, body, final = r
    return {
        "url": url,
        "final_url": final,
        "status": status,
        "headers": headers or {},
        "body": body or "",
        "size": len(body or ""),
    }


async def _discover_specs(session, base_url: str, limiter,
                          verbose: bool,
                          timeout: float) -> list[dict]:
    """Fetch every SPEC_PATH against base_url concurrently.

    Returns a list of {url, final_url, status, spec, size, content_type}
    entries for every response that successfully parsed as a spec.
    """
    sem = asyncio.Semaphore(8)
    found = []

    async def _one(path: str) -> tuple[str, dict | None]:
        url = urljoin(base_url, path)
        async with sem:
            r = await _fetch_one(session, url, limiter, timeout=timeout)
        return path, r

    results = await asyncio.gather(
        *[_one(p) for p in SPEC_PATHS],
        return_exceptions=True)

    for item in results:
        if isinstance(item, Exception):
            continue
        path, r = item
        if r is None:
            continue

        # Only consider 2xx responses
        if not (200 <= r["status"] < 300):
            if verbose and r["status"] not in (404, 405, 410):
                info(f"  {path:45s} HTTP {r['status']}")
            continue

        body = r["body"]
        ctype = r["headers"].get("content-type", "")

        # Try to parse as spec
        spec = _try_parse_spec(body, ctype)
        if spec:
            found.append({
                "url": r["final_url"] or r["url"],
                "original_url": r["url"],
                "status": r["status"],
                "size": r["size"],
                "content_type": ctype,
                "spec": spec,
            })
            if verbose:
                success(f"  {path:45s} HTTP {r['status']} "
                        f"({r['size']} bytes, spec)")
            continue

        # Not a spec — is it a Swagger UI shell that reveals a spec URL?
        if any(m in body.lower() for m in _SWAGGER_UI_MARKERS):
            spec_url = _extract_spec_url_from_html(body, r["final_url"]
                                                   or r["url"])
            if spec_url and spec_url != r["url"]:
                # Fetch the pointed-to spec
                inner = await _fetch_one(session, spec_url, limiter,
                                          timeout=timeout)
                if inner and 200 <= inner["status"] < 300:
                    inner_spec = _try_parse_spec(
                        inner["body"],
                        inner["headers"].get("content-type", ""))
                    if inner_spec:
                        found.append({
                            "url": inner["final_url"] or inner["url"],
                            "original_url": inner["url"],
                            "status": inner["status"],
                            "size": inner["size"],
                            "content_type": inner["headers"].get(
                                "content-type", ""),
                            "spec": inner_spec,
                            "via_ui": r["url"],
                        })
                        if verbose:
                            success(f"  {path:45s} UI → {spec_url}")
                        continue
            if verbose:
                info(f"  {path:45s} HTTP {r['status']} "
                     f"(UI shell, no spec URL found)")
            continue

        if verbose:
            info(f"  {path:45s} HTTP {r['status']} "
                 f"({r['size']} bytes, not a spec)")

    return found


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def discover(target: str, session=None, limiter=None,
                    verbose: bool = False,
                    rate: float = 10.0,
                    timeout: float = 10.0) -> dict:
    """Discover and parse OpenAPI / Swagger specs for a target.

    Args:
        target: URL, hostname, or IP
        session, limiter: optional shared session/limiter
        verbose: print progress
        rate: requests per second (default 10)
        timeout: per-request timeout

    Returns:
        {
          "target": "https://api.example.com",
          "specs": [
            {
              "url": "https://api.example.com/openapi.json",
              "title": "...",
              "version": "...",
              "openapi_version": "3.0.0" | "2.0",
              "servers": ["https://api.example.com"],
              "tags": [{"name": "..."}, ...],
              "security_schemes": {"bearerAuth": {...}, ...},
              "schema_names": ["User", "Account", ...],
              "endpoints": [{method, path, summary, ...}, ...],
              "endpoint_count": N,
            },
            ...
          ],
          "total_endpoints": N,
          "total_schemas": N,
          "all_servers": [...],
          "all_endpoints": [...],   # flat, deduped across specs
          "errors": [...],
          "elapsed": ...,
        }
    """
    import time
    start = time.time()

    t = parse(target)
    if t.is_ip:
        base_url = f"https://{t.host}"
    elif t.kind == "url":
        base_url = target if target.startswith(("http://", "https://")) \
            else f"https://{target}"
    else:
        base_url = f"https://{t.host}"

    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=rate)

    info(f"openapi: probing {len(SPEC_PATHS)} spec path(s) on {base_url}")

    result = {
        "target": base_url,
        "specs": [],
        "total_endpoints": 0,
        "total_schemas": 0,
        "all_servers": [],
        "all_endpoints": [],
        "errors": [],
        "elapsed": 0.0,
    }

    try:
        found = await _discover_specs(
            session, base_url, limiter, verbose=verbose, timeout=timeout)

        if not found:
            if verbose:
                info("openapi: no specs discovered")
            result["elapsed"] = round(time.time() - start, 2)
            return result

        # --- Parse each spec ---
        all_servers = set()
        all_endpoints: dict[tuple[str, str], dict] = {}   # (method, path) -> endpoint

        for item in found:
            spec = item["spec"]
            spec_url = item["url"]

            info_block = spec.get("info") or {}
            openapi_version = spec.get("openapi") or spec.get("swagger") or "?"

            endpoints = _flatten_endpoints(spec, spec_url)
            schemas = _extract_schemas(spec)
            servers = _extract_servers(spec, spec_url=spec_url)
            schemes = _extract_security_schemes(spec)
            tags = _extract_tags(spec)

            all_servers.update(servers)
            for ep in endpoints:
                key = (ep["method"], ep["path"])
                all_endpoints.setdefault(key, ep)

            parsed = {
                "url": spec_url,
                "title": info_block.get("title"),
                "version": info_block.get("version"),
                "description": info_block.get("description"),
                "openapi_version": openapi_version,
                "servers": servers,
                "tags": tags,
                "security_schemes": schemes,
                "schema_names": schemas,
                "endpoints": endpoints,
                "endpoint_count": len(endpoints),
                "schema_count": len(schemas),
                "size": item.get("size"),
                "via_ui": item.get("via_ui"),
            }
            result["specs"].append(parsed)

        result["total_endpoints"] = len(all_endpoints)
        result["total_schemas"] = sum(s["schema_count"]
                                       for s in result["specs"])
        result["all_servers"] = sorted(all_servers)
        result["all_endpoints"] = sorted(
            all_endpoints.values(),
            key=lambda e: (e["path"], e["method"]))
        result["elapsed"] = round(time.time() - start, 2)
        return result
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# Store integration
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
              rate: float = 10.0) -> dict:
    """CLI entry. Writes findings to store if provided."""
    result = await discover(target, verbose=verbose, rate=rate)

    print()
    if not result["specs"]:
        info(f"openapi: no specs found for {target} "
             f"({result['elapsed']}s)")
        return result

    success(f"openapi: {len(result['specs'])} spec(s) discovered "
            f"({result['total_endpoints']} endpoint(s) total, "
            f"{result['elapsed']}s)")

    for spec in result["specs"]:
        print()
        info(f"  {spec['url']}")
        if spec.get("via_ui"):
            print(f"    (via UI shell: {spec['via_ui']})")
        if spec.get("title"):
            print(f"    title:      {spec['title']}")
        if spec.get("version"):
            print(f"    version:    {spec['version']}")
        print(f"    openapi:    {spec['openapi_version']}")
        print(f"    endpoints:  {spec['endpoint_count']}")
        print(f"    schemas:    {spec['schema_count']}")

        if spec.get("servers"):
            print(f"    servers:")
            for s in spec["servers"]:
                print(f"      {s}")

        if spec.get("security_schemes"):
            print(f"    security schemes:")
            for name, scheme in spec["security_schemes"].items():
                desc = scheme.get("type") or "?"
                extra = ""
                if scheme.get("scheme"):
                    extra = f" ({scheme['scheme']})"
                elif scheme.get("in") and scheme.get("name"):
                    extra = f" ({scheme['in']}: {scheme['name']})"
                print(f"      {name}: {desc}{extra}")

        # --- Endpoint list ---
        limit = None if verbose else 20
        shown = spec["endpoints"] if limit is None else \
            spec["endpoints"][:limit]
        if shown:
            print(f"    sample endpoints:")
            for ep in shown:
                path = ep["path"]
                method = ep["method"]
                summary = ep.get("summary") or ""
                if summary:
                    summary = " — " + summary[:60]
                print(f"      {method:6s} {path}{summary}")
            if limit is not None and len(spec["endpoints"]) > limit:
                info(f"      ... and "
                     f"{len(spec['endpoints']) - limit} more "
                     f"(use -v for all)")

        # --- Schema names in verbose ---
        if verbose and spec.get("schema_names"):
            info(f"    schema names ({spec['schema_count']}):")
            for name in spec["schema_names"]:
                print(f"      {name}")

    # --- All servers summary ---
    if result["all_servers"]:
        print()
        success(f"  All servers referenced across specs "
                f"({len(result['all_servers'])}):")
        for s in result["all_servers"]:
            print(f"    {s}")

    # --- Store ---
    if store is not None:
        for spec in result["specs"]:
            store.add_finding({
                "module": "openapi",
                "type": "api_spec_exposed",
                "severity": "high" if not spec.get("security_schemes")
                            else "medium",
                "target": spec["url"],
                "evidence": (f"{spec['openapi_version']} spec: "
                             f"{spec['endpoint_count']} endpoint(s), "
                             f"{spec['schema_count']} schema(s)"
                             + (" (no auth schemes declared)"
                                if not spec.get("security_schemes")
                                else "")),
                "data": spec,
            })
            # Register every server hostname as a host, and every
            # endpoint path as a candidate for other modules
            try:
                for s in spec.get("servers") or []:
                    host = urlparse(s).hostname
                    if host:
                        store.upsert_host(
                            ip=host, hostname=host,
                            discovery=f"openapi ({spec['url']})",
                            tags=["openapi-server"],
                        )
            except Exception:
                pass
        success(f"wrote {len(result['specs'])} finding(s) to store")

    return result


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.openapi",
        description="Discover OpenAPI / Swagger specifications.",
    )
    p.add_argument("target", help="URL, hostname, or IP")
    p.add_argument("--rate", type=float, default=10.0,
                   help="requests per second (default 10)")
    p.add_argument("--store", action="store_true",
                   help="write findings to active workspace")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show every probed path and every endpoint, "
                        "not just the first 20")
    args = p.parse_args()

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
        args.target, store=store, verbose=args.verbose, rate=args.rate))


if __name__ == "__main__":
    _cli()