# Recon Dossier — akads.org

**Kind:** domain  
**Started:** 2026-10-22T01:23:02 UTC  
**Elapsed:** 283.93s  
**Mode:** sequential  

---

## Module Summary

| Module | Status | Summary |
|--------|--------|---------|
| `tech_fingerprint` | OK | 1 technologies detected |
| `web_intel` | OK | 0 CSP host(s), 0 well-known file(s) |
| `cms_fingerprint` | OK | none |
| `leak_check` | OK | 4 path(s), 0 public |
| `ct_logs` | OK | 12 cert(s), 3 names |
| `tls_cert` | OK | CN=?, 0 SAN(s) |
| `whois` | OK | Cloudflare, Inc. |
| `asn` | OK | AS13335 |
| `historical` | OK | 10 archived URL(s), 2 host(s) |
| `js_analysis` | OK | 4 JS file(s), 12 API path(s), 0 secret(s) |
| `emails` | OK | 0 email(s) |
| `cloud_enum` | OK | 0 public, 0 other |
| `social` | OK | 0 profile(s) |
| `subdomain_takeover` | OK |  |
| `openapi` | OK |  |
| `cors` | FAILED | module not installed: No module named 'recon.cors' |

---

## tech_fingerprint — Technology stack

- **cdn**: cloudflare

## web_intel — Web intelligence (headers, CSP, robots, well-known)

**URL:** https://akads.org
**Status:** HTTP 200
**Title:** Akads Session

**Security headers missing:** strict-transport-security, content-security-policy, content-security-policy-report-only, x-frame-options, x-content-type-options, referrer-policy, permissions-policy, cross-origin-opener-policy, cross-origin-embedder-policy, cross-origin-resource-policy, x-xss-protection, x-permitted-cross-domain-policies, expect-ct


## cms_fingerprint — CMS detection

_No CMS identified._

## leak_check — Exposed sensitive paths

- HTTP 403 `/wp-config.php` (4910 bytes)
- HTTP 403 `/wp-config.php.bak` (0 bytes)
- HTTP 403 `/wp-config.php.old` (4910 bytes)
- HTTP 403 `/wp-config.php~` (4910 bytes)

## ct_logs — Certificate transparency

- Total certificates: 12
- Unique names: 3
- Wildcards: —

- `akads.org`
- `api.akads.org`
- `www.akads.org`

## tls_cert — TLS certificate


## whois — Domain WHOIS + IP RDAP

- **registrar:** Cloudflare, Inc.
- **created:** 2026-09-14T14:20:28Z
- **updated:** 2026-09-19T14:21:09Z
- **expires:** 2027-09-14T14:20:28Z
- **nameservers:** deborah.ns.cloudflare.com, mack.ns.cloudflare.com

## asn — ASN / netblocks

- **ASN:** AS13335
- **Name:** CLOUDFLARENET - Cloudflare, Inc.
- **Prefix:** 104.21.16.0/20

**IPv4 prefixes (2698):**

- `172.70.233.0/24`
- `162.158.221.0/24`
- `104.23.238.0/24`
- `104.29.167.0/24`
- `194.34.82.0/24`
- `8.28.213.0/24`
- `104.29.147.0/24`
- `172.66.176.0/24`
- `8.45.146.0/24`
- `104.27.48.0/20`
- `172.69.155.0/24`
- `172.70.126.0/24`
- `138.249.21.0/24`
- `172.68.109.0/24`
- `172.70.135.0/24`
- `104.23.244.0/24`
- `172.68.148.0/24`
- `172.71.195.0/24`
- `206.206.104.0/23`
- `172.71.7.0/24`
- `172.69.253.0/24`
- `161.115.162.0/24`
- `188.114.100.0/24`
- `199.7.70.0/24`
- `172.69.220.0/24`
- `172.71.247.0/24`
- `87.85.66.0/24`
- `172.71.179.0/24`
- `144.56.84.0/24`
- `23.227.48.0/23`
- `172.70.181.0/24`
- `172.70.56.0/24`
- `172.65.240.0/20`
- `162.159.10.0/24`
- `172.68.16.0/24`
- `162.158.186.0/24`
- `172.69.213.0/24`
- `173.245.59.0/24`
- `172.70.88.0/24`
- `162.158.244.0/24`

## historical — Wayback + URLScan

- Wayback URLs: 10
- URLScan results: 0

- `akads.org`
- `www.akads.org`

## js_analysis — JS files + API endpoints

- Files analyzed: 4
- API paths: 12
- Secrets: 0

- `/api/auth/token`
- `/api/me`
- `/api/me/language`
- `/api/review-audit/check`
- `/api/review-audit/words`
- `/api/review/classes`
- `/api/review/events`
- `/api/review/runs`
- `/api/review/words`
- `/api/seb/bypass`
- `/api/seb/exchange`
- `/api/seb/launch`

## emails — Email addresses


## cloud_enum — Public cloud buckets

_No buckets found._

## social — Social profiles


## subdomain_takeover — Subdomain takeover scan

```json
{
  "domain": "akads.org",
  "candidates": [
    "akads.org",
    "api.akads.org",
    "leaderboards.akads.org",
    "www.akads.org"
  ],
  "scanned": 4,
  "vulnerable": [],
  "potential": [],
  "results": [
    {
      "host": "akads.org",
      "cname_chain": [],
      "service": null,
      "vulnerable": false,
      "evidence": null,
      "status": null,
      "final_url": null,
      "error": null
    },
    {
      "host": "api.akads.org",
      "cname_chain": [],
      "service": null,
      "vulnerable": false,
      "evidence": null,
      "status": null,
      "final_url": null,
      "error": null
    },
    {
      "host": "leaderboards.akads.org",
      "cname_chain": [],
      "service": null,
      "vulnerable": false,
      "evidence": null,
      "status": null,
      "final_url": null,
      "error": null
    },
    {
      "host": "www.akads.org",
      "cname_chain": [],
      "service": null,
      "vulnerable": false,
      "evidence": null,
      "status": null,
      "final_url": null,
      "error": null
    }
  ],
  "elapsed": 2.45,
  "errors": []
}
```

## openapi — OpenAPI / Swagger discovery

```json
{
  "target": "https://akads.org",
  "specs": [],
  "total_endpoints": 0,
  "total_schemas": 0,
  "all_servers": [],
  "all_endpoints": [],
  "errors": [],
  "elapsed": 1.54
}
```

## cors — CORS misconfiguration

**FAILED:** module not installed: No module named 'recon.cors'

---

*Generated 2026-10-22T01:27:46 UTC*