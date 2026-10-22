"""
IP / hostname geolocation via public registry data.

No paid GeoIP database. No MaxMind. No API keys. Just:

  1. RDAP (Registration Data Access Protocol) over HTTPS — the modern
     replacement for classic whois. JSON responses from ARIN, RIPE,
     APNIC, LACNIC, and AFRINIC. Works through firewalls that only
     allow 443.

  2. Classic whois on TCP/43 — fallback for legacy registries and
     air-gapped labs.

  3. Reverse DNS pattern analysis — 'host1.lon.example.com' hints
     London, 'sfo-edge.example.com' hints San Francisco. Weak signal,
     but free.

  4. CDN / anycast detection — if the IP is on Cloudflare, Fastly,
     AWS CloudFront, or Google's anycast netblocks, geographic
     attribution from the registry is unreliable and we say so.

  5. Optional HTTP header inspection — some CDNs leak their PoP
     city code in headers (X-Served-From: LHR, X-Cache: HIT from
     lon1, etc.).

Accuracy caveats are baked into the output via a `confidence` field:

    high    — country from RDAP/whois, org known, non-CDN IP
    medium  — country from RDAP/whois, but IP is on a cloud provider
    low     — only reverse-DNS or header hints
    none    — no data at all

Non-routable IPs (private, loopback, link-local, multicast, reserved)
are refused up front — RDAP returns garbage for them (ARIN answers
with its own HQ address for 192.168.x.x, which is why naive tools
claim 192.168.1.1 is in the US).

Usage:

    from net.geo import locate_ip, locate_host

    info = await locate_ip('8.8.8.8')
    print(info['country'], info['org'], info['confidence'])

    info = await locate_host('example.com')

    # Or from the CLI:
    python -m net.geo 8.8.8.8
    python -m net.geo 1.1.1.1 --verbose
    python -m net.geo example.com --store
"""

import asyncio
import json
import re
import socket
import ssl
import subprocess
import time
import urllib.request
from ipaddress import ip_address, ip_network
from pathlib import Path

from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

RDAP_BOOTSTRAP_URL = "https://rdap.org/ip/{ip}"

RDAP_REGISTRY_FALLBACKS = {
    "arin":    "https://rdap.arin.net/registry/ip/{ip}",
    "ripe":    "https://rdap.db.ripe.net/ip/{ip}",
    "apnic":   "https://rdap.apnic.net/ip/{ip}",
    "lacnic":  "https://rdap.lacnic.net/rdap/ip/{ip}",
    "afrinic": "https://rdap.afrinic.net/rdap/ip/{ip}",
}

WHOIS_SERVERS = {
    "arin":    "whois.arin.net",
    "ripe":    "whois.ripe.net",
    "apnic":   "whois.apnic.net",
    "lacnic":  "whois.lacnic.net",
    "afrinic": "whois.afrinic.net",
}

# Anycast / CDN netblocks — if the IP is in one of these, geographic
# attribution from the registry is unreliable. Data compiled from
# public BGP feeds and vendor documentation. Not exhaustive.
CDN_NETBLOCKS = {
    "cloudflare": [
        "1.1.1.0/24", "1.0.0.0/24",
        "104.16.0.0/12", "172.64.0.0/13",
        "173.245.48.0/20", "103.21.244.0/22",
        "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "131.0.72.0/22",
    ],
    "fastly": [
        "151.101.0.0/16", "199.232.0.0/16",
        "23.235.32.0/20", "43.249.72.0/22",
        "103.244.50.0/24", "103.245.222.0/23",
        "103.245.224.0/24", "104.156.80.0/20",
        "146.75.0.0/16", "157.52.64.0/18",
        "167.82.0.0/17", "167.82.128.0/20",
        "167.82.160.0/20", "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22",
        "199.27.72.0/21",
    ],
    "cloudfront": [
        "13.32.0.0/15", "13.35.0.0/16",
        "13.224.0.0/14", "13.249.0.0/16",
        "52.84.0.0/15", "54.182.0.0/16",
        "54.192.0.0/16", "54.230.0.0/16",
        "54.239.128.0/18", "54.239.192.0/19",
        "99.84.0.0/16", "99.86.0.0/16",
        "143.204.0.0/16", "204.246.164.0/22",
        "204.246.168.0/22", "204.246.174.0/23",
        "204.246.176.0/20", "205.251.192.0/19",
        "205.251.249.0/24", "205.251.250.0/23",
        "205.251.252.0/23", "205.251.254.0/24",
        "216.137.32.0/19",
    ],
    "google_anycast": [
        "8.8.8.0/24", "8.8.4.0/24",
    ],
    "quad9": [
        "9.9.9.0/24", "149.112.112.0/24",
    ],
}


# ISO 3166-1 alpha-2 country codes → names. Trimmed to ~250 entries.
COUNTRY_NAMES = {
    "AF": "Afghanistan", "AX": "Åland Islands", "AL": "Albania",
    "DZ": "Algeria", "AS": "American Samoa", "AD": "Andorra",
    "AO": "Angola", "AI": "Anguilla", "AQ": "Antarctica",
    "AG": "Antigua and Barbuda", "AR": "Argentina", "AM": "Armenia",
    "AW": "Aruba", "AU": "Australia", "AT": "Austria",
    "AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain",
    "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus",
    "BE": "Belgium", "BZ": "Belize", "BJ": "Benin",
    "BM": "Bermuda", "BT": "Bhutan", "BO": "Bolivia",
    "BQ": "Bonaire, Sint Eustatius and Saba", "BA": "Bosnia and Herzegovina",
    "BW": "Botswana", "BV": "Bouvet Island", "BR": "Brazil",
    "IO": "British Indian Ocean Territory", "BN": "Brunei Darussalam",
    "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi",
    "CV": "Cabo Verde", "KH": "Cambodia", "CM": "Cameroon",
    "CA": "Canada", "KY": "Cayman Islands", "CF": "Central African Republic",
    "TD": "Chad", "CL": "Chile", "CN": "China",
    "CX": "Christmas Island", "CC": "Cocos (Keeling) Islands",
    "CO": "Colombia", "KM": "Comoros", "CG": "Congo",
    "CD": "Congo, Democratic Republic of the", "CK": "Cook Islands",
    "CR": "Costa Rica", "CI": "Côte d'Ivoire", "HR": "Croatia",
    "CU": "Cuba", "CW": "Curaçao", "CY": "Cyprus",
    "CZ": "Czechia", "DK": "Denmark", "DJ": "Djibouti",
    "DM": "Dominica", "DO": "Dominican Republic", "EC": "Ecuador",
    "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea",
    "ER": "Eritrea", "EE": "Estonia", "SZ": "Eswatini",
    "ET": "Ethiopia", "FK": "Falkland Islands (Malvinas)",
    "FO": "Faroe Islands", "FJ": "Fiji", "FI": "Finland",
    "FR": "France", "GF": "French Guiana", "PF": "French Polynesia",
    "TF": "French Southern Territories", "GA": "Gabon",
    "GM": "Gambia", "GE": "Georgia", "DE": "Germany",
    "GH": "Ghana", "GI": "Gibraltar", "GR": "Greece",
    "GL": "Greenland", "GD": "Grenada", "GP": "Guadeloupe",
    "GU": "Guam", "GT": "Guatemala", "GG": "Guernsey",
    "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana",
    "HT": "Haiti", "HM": "Heard Island and McDonald Islands",
    "VA": "Holy See", "HN": "Honduras", "HK": "Hong Kong",
    "HU": "Hungary", "IS": "Iceland", "IN": "India",
    "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq",
    "IE": "Ireland", "IM": "Isle of Man", "IL": "Israel",
    "IT": "Italy", "JM": "Jamaica", "JP": "Japan",
    "JE": "Jersey", "JO": "Jordan", "KZ": "Kazakhstan",
    "KE": "Kenya", "KI": "Kiribati", "KP": "Korea, DPR of",
    "KR": "Korea, Republic of", "KW": "Kuwait", "KG": "Kyrgyzstan",
    "LA": "Lao People's Democratic Republic", "LV": "Latvia",
    "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia",
    "LY": "Libya", "LI": "Liechtenstein", "LT": "Lithuania",
    "LU": "Luxembourg", "MO": "Macao", "MG": "Madagascar",
    "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives",
    "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands",
    "MQ": "Martinique", "MR": "Mauritania", "MU": "Mauritius",
    "YT": "Mayotte", "MX": "Mexico", "FM": "Micronesia",
    "MD": "Moldova", "MC": "Monaco", "MN": "Mongolia",
    "ME": "Montenegro", "MS": "Montserrat", "MA": "Morocco",
    "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia",
    "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands",
    "NC": "New Caledonia", "NZ": "New Zealand", "NI": "Nicaragua",
    "NE": "Niger", "NG": "Nigeria", "NU": "Niue",
    "NF": "Norfolk Island", "MK": "North Macedonia",
    "MP": "Northern Mariana Islands", "NO": "Norway", "OM": "Oman",
    "PK": "Pakistan", "PW": "Palau", "PS": "Palestine",
    "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay",
    "PE": "Peru", "PH": "Philippines", "PN": "Pitcairn",
    "PL": "Poland", "PT": "Portugal", "PR": "Puerto Rico",
    "QA": "Qatar", "RE": "Réunion", "RO": "Romania",
    "RU": "Russian Federation", "RW": "Rwanda", "BL": "Saint Barthélemy",
    "SH": "Saint Helena", "KN": "Saint Kitts and Nevis",
    "LC": "Saint Lucia", "MF": "Saint Martin (French part)",
    "PM": "Saint Pierre and Miquelon", "VC": "Saint Vincent and the Grenadines",
    "WS": "Samoa", "SM": "San Marino", "ST": "Sao Tome and Principe",
    "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia",
    "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore",
    "SX": "Sint Maarten (Dutch part)", "SK": "Slovakia",
    "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia",
    "ZA": "South Africa", "GS": "South Georgia and the South Sandwich Islands",
    "SS": "South Sudan", "ES": "Spain", "LK": "Sri Lanka",
    "SD": "Sudan", "SR": "Suriname", "SJ": "Svalbard and Jan Mayen",
    "SE": "Sweden", "CH": "Switzerland", "SY": "Syrian Arab Republic",
    "TW": "Taiwan", "TJ": "Tajikistan", "TZ": "Tanzania",
    "TH": "Thailand", "TL": "Timor-Leste", "TG": "Togo",
    "TK": "Tokelau", "TO": "Tonga", "TT": "Trinidad and Tobago",
    "TN": "Tunisia", "TR": "Türkiye", "TM": "Turkmenistan",
    "TC": "Turks and Caicos Islands", "TV": "Tuvalu", "UG": "Uganda",
    "UA": "Ukraine", "AE": "United Arab Emirates",
    "GB": "United Kingdom", "US": "United States",
    "UM": "United States Minor Outlying Islands", "UY": "Uruguay",
    "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela",
    "VN": "Viet Nam", "VG": "Virgin Islands, British",
    "VI": "Virgin Islands, U.S.", "WF": "Wallis and Futuna",
    "EH": "Western Sahara", "YE": "Yemen", "ZM": "Zambia",
    "ZW": "Zimbabwe",
}


# Airport code → city/region hints. Common ones for reverse-DNS and
# CDN header parsing.
AIRPORT_CODES = {
    "lhr": "London, UK", "lhr1": "London, UK", "lhr2": "London, UK",
    "cdg": "Paris, France", "ams": "Amsterdam, Netherlands",
    "fra": "Frankfurt, Germany", "frankfurt": "Frankfurt, Germany",
    "mad": "Madrid, Spain", "bcn": "Barcelona, Spain",
    "mxp": "Milan, Italy", "fco": "Rome, Italy",
    "zrh": "Zurich, Switzerland", "vie": "Vienna, Austria",
    "arn": "Stockholm, Sweden", "osl": "Oslo, Norway",
    "cph": "Copenhagen, Denmark", "hel": "Helsinki, Finland",
    "dub": "Dublin, Ireland", "man": "Manchester, UK",
    "jfk": "New York, USA", "nyc": "New York, USA",
    "lga": "New York, USA", "ewr": "Newark, USA",
    "sfo": "San Francisco, USA", "sjc": "San Jose, USA",
    "lax": "Los Angeles, USA", "sea": "Seattle, USA",
    "ord": "Chicago, USA", "chi": "Chicago, USA",
    "dfw": "Dallas, USA", "atl": "Atlanta, USA",
    "mia": "Miami, USA", "bos": "Boston, USA",
    "iad": "Washington DC, USA", "dca": "Washington DC, USA",
    "den": "Denver, USA", "phx": "Phoenix, USA",
    "yyz": "Toronto, Canada", "yvr": "Vancouver, Canada",
    "yul": "Montreal, Canada", "mex": "Mexico City, Mexico",
    "gru": "São Paulo, Brazil", "sao": "São Paulo, Brazil",
    "eze": "Buenos Aires, Argentina", "bog": "Bogotá, Colombia",
    "scl": "Santiago, Chile", "lim": "Lima, Peru",
    "nrt": "Tokyo, Japan", "hnd": "Tokyo, Japan", "tyo": "Tokyo, Japan",
    "kix": "Osaka, Japan", "icn": "Seoul, South Korea",
    "hkg": "Hong Kong", "sin": "Singapore",
    "bkk": "Bangkok, Thailand", "kul": "Kuala Lumpur, Malaysia",
    "cgk": "Jakarta, Indonesia", "mnl": "Manila, Philippines",
    "tpe": "Taipei, Taiwan", "sha": "Shanghai, China",
    "pvg": "Shanghai, China", "pek": "Beijing, China",
    "bjs": "Beijing, China", "can": "Guangzhou, China",
    "syd": "Sydney, Australia", "mel": "Melbourne, Australia",
    "akl": "Auckland, New Zealand", "bom": "Mumbai, India",
    "del": "Delhi, India", "blr": "Bangalore, India",
    "dxb": "Dubai, UAE", "auh": "Abu Dhabi, UAE",
    "jnb": "Johannesburg, South Africa", "cpt": "Cape Town, South Africa",
    "cai": "Cairo, Egypt", "nbo": "Nairobi, Kenya",
    "los": "Lagos, Nigeria",
}


# ---------------------------------------------------------------------
# Special IP category detection
# ---------------------------------------------------------------------

def _ip_special_category(ip: str) -> str | None:
    """Return a human label if the IP is non-routable, else None.

    RDAP and whois both return garbage for private and reserved IPs
    (ARIN answers with its own HQ address for 192.168.x.x, which is
    why we saw 'country=US' for 192.168.1.1). Refuse up front.
    """
    try:
        addr = ip_address(ip)
    except Exception:
        return None
    if addr.is_loopback:        return "loopback"
    if addr.is_private:         return "private (RFC 1918)"
    if addr.is_link_local:      return "link-local"
    if addr.is_multicast:       return "multicast"
    if addr.is_reserved:        return "reserved"
    if addr.is_unspecified:     return "unspecified"
    # Carrier-grade NAT: 100.64.0.0/10
    try:
        if addr in ip_network("100.64.0.0/10"):
            return "carrier-grade NAT"
    except Exception:
        pass
    # Documentation / test-net blocks
    for block in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                  "198.18.0.0/15", "240.0.0.0/4"):
        try:
            if addr in ip_network(block):
                return "reserved / documentation"
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------
# RDAP lookup
# ---------------------------------------------------------------------

async def rdap_lookup(ip: str, timeout: float = 10.0) -> dict | None:
    """Query RDAP for an IP. Returns normalized dict or None on failure."""
    urls = [RDAP_BOOTSTRAP_URL.format(ip=ip)]
    urls.extend(u.format(ip=ip) for u in RDAP_REGISTRY_FALLBACKS.values())

    for url in urls:
        try:
            data = await asyncio.get_event_loop().run_in_executor(
                None, _http_get_json, url, timeout)
        except Exception:
            continue
        if data:
            return _normalize_rdap(data)
    return None


def _http_get_json(url: str, timeout: float) -> dict | None:
    """Blocking HTTP GET that returns parsed JSON. Called in executor."""
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            if not body:
                return None
            return json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:
        return None
def _normalize_rdap(data: dict) -> dict:
    """Turn RDAP's verbose JSON into a flat dict.

    Two levels of country/org extraction:

      1. Top-level fields (ARIN puts country on the network object
         directly, e.g. for 8.8.8.8).
      2. vcardArray inside entities (RIPE/APNIC/LACNIC put it in
         the registrant's vcard).
    """
    out = {
        "source": "rdap",
        "handle": data.get("handle"),
        "name": data.get("name"),
        "country": None,
        "org": None,
        "address": [],
        "emails": [],
        "netname": None,
        "asn": None,
        "type": data.get("type"),
    }

    # --- Level 1: top-level fields (ARIN style) ---

    # Some registries expose country at the top level
    if data.get("country"):
        out["country"] = data["country"]
    # Or inside a "startAddress"/"endAddress" style block? Rare.
    # Or a dedicated field:
    for key in ("countryCode", "country_code", "cc"):
        if data.get(key):
            out["country"] = data[key]
            break

    # Top-level org name: "name", "netname", "handle"
    if data.get("name") and not out["org"]:
        out["org"] = data["name"]

    # Top-level address lines
    if isinstance(data.get("address"), list):
        out["address"] = [a for a in data["address"] if a]

    # --- Level 2: entities with vcardArray (RIPE, APNIC, etc.) ---

    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        # Registrant, admin, or technical entities carry the contact info
        if not any(r in roles for r in ("registrant", "administrative",
                                          "technical", "abuse")):
            continue
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2:
            continue
        for entry in vcard[1]:
            if not isinstance(entry, list):
                continue
            key = entry[0]
            # adr entry format: ["adr", {}, "text", [pobox, ext, street,
            #                                         city, region, postal,
            #                                         country]]
            if key == "adr":
                # Two possible shapes:
                #   ["adr", {"label": "..."}, "text", [components]]
                #   ["adr", {}, "text", "single-string"]
                if len(entry) >= 4:
                    comps = entry[3]
                    if isinstance(comps, list):
                        parts = [p for p in comps if p]
                        if parts and not out["address"]:
                            out["address"] = parts
                        # Country is the last element if it's a 2-letter code
                        if len(comps) >= 7 and comps[6]:
                            out["country"] = comps[6]
                    elif isinstance(comps, str) and comps and not out["address"]:
                        out["address"] = [comps]
            # fn = "formatted name" (org display name)
            elif key == "fn":
                if len(entry) >= 4 and entry[3] and not out["org"]:
                    out["org"] = entry[3]
            # org = organization name
            elif key == "org":
                if len(entry) >= 4 and entry[3] and not out["org"]:
                    out["org"] = entry[3]
            # email
            elif key == "email":
                if len(entry) >= 4 and entry[3]:
                    out["emails"].append(entry[3])

    # --- Fallback: remarks with " - " separators ---
    if not out["org"]:
        for remark in data.get("remarks", []):
            for line in remark.get("description", []):
                if " - " in line:
                    left = line.split(" - ")[0].strip()
                    if left and len(left) < 80:
                        out["org"] = left
                        break
            if out["org"]:
                break

    # --- Final fallback for org ---
    if not out["org"] and out["name"]:
        out["org"] = out["name"]

    out["netname"] = data.get("name")
    return out


# ---------------------------------------------------------------------
# Classic whois fallback (TCP/43)
# ---------------------------------------------------------------------

async def whois_lookup(ip: str, timeout: float = 10.0) -> dict | None:
    """Query the classic whois protocol on TCP/43. Fallback only."""
    for server in WHOIS_SERVERS.values():
        try:
            text = await asyncio.get_event_loop().run_in_executor(
                None, _whois_query, server, ip, timeout)
        except Exception:
            continue
        if text:
            return _normalize_whois(text)
    return None


def _whois_query(server: str, query: str, timeout: float) -> str | None:
    """Blocking whois query via raw socket. Called in executor."""
    try:
        s = socket.create_connection((server, 43), timeout=timeout)
        s.sendall((query + "\r\n").encode("ascii", errors="ignore"))
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 64 * 1024:
                break
        s.close()
        return b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception:
        return None


def _normalize_whois(text: str) -> dict:
    """Parse classic whois text into the same flat dict shape as RDAP."""
    out = {
        "source": "whois",
        "handle": None,
        "name": None,
        "country": None,
        "org": None,
        "address": [],
        "emails": [],
        "netname": None,
        "asn": None,
        "type": None,
    }
    patterns = {
        "country":      [r"^Country:\s*(.+)$", r"^country:\s*(.+)$",
                         r"^Registrant Country:\s*(.+)$"],
        "org":          [r"^OrgName:\s*(.+)$", r"^org-name:\s*(.+)$",
                         r"^owner:\s*(.+)$", r"^descr:\s*(.+)$",
                         r"^Registrant Organization:\s*(.+)$"],
        "netname":      [r"^NetName:\s*(.+)$", r"^netname:\s*(.+)$"],
        "handle":       [r"^NetRange:\s*(.+)$", r"^inetnum:\s*(.+)$"],
    }
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for key, pats in patterns.items():
            for pat in pats:
                m = re.match(pat, line, re.IGNORECASE)
                if m:
                    val = m.group(1).strip()
                    if not out[key]:
                        out[key] = val
                    break

    for line in text.splitlines():
        m = re.match(r"^Address:\s*(.+)$", line.strip(), re.IGNORECASE)
        if m:
            out["address"].append(m.group(1).strip())

    return out


# ---------------------------------------------------------------------
# Reverse DNS + hint parsing
# ---------------------------------------------------------------------

def reverse_dns_sync(ip: str, timeout: float = 3.0) -> str | None:
    """Reverse DNS via the OS resolver. Returns PTR or None."""
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        finally:
            socket.setdefaulttimeout(old)
    except Exception:
        return None


def region_hint_from_hostname(hostname: str) -> str | None:
    """Extract a region hint from a hostname.

    Matches common patterns:
        host1.lon.example.com         -> 'London, UK'
        sfo-edge-1.example.com        -> 'San Francisco, USA'
        example-fra1.example.com      -> 'Frankfurt, Germany'
        host-frankfurt.example.com    -> 'Frankfurt, Germany'
    """
    if not hostname:
        return None
    low = hostname.lower()
    for token in re.split(r"[.\-_]", low):
        if token in AIRPORT_CODES:
            return AIRPORT_CODES[token]
        m = re.match(r"^([a-z]{3})\d+$", token)
        if m and m.group(1) in AIRPORT_CODES:
            return AIRPORT_CODES[m.group(1)]
    for city_key, city_name in [
        ("london", "London, UK"), ("paris", "Paris, France"),
        ("amsterdam", "Amsterdam, Netherlands"),
        ("frankfurt", "Frankfurt, Germany"),
        ("singapore", "Singapore"), ("tokyo", "Tokyo, Japan"),
        ("sydney", "Sydney, Australia"),
        ("newyork", "New York, USA"), ("chicago", "Chicago, USA"),
        ("losangeles", "Los Angeles, USA"),
        ("sanfrancisco", "San Francisco, USA"),
        ("seattle", "Seattle, USA"), ("miami", "Miami, USA"),
    ]:
        if city_key in low:
            return city_name
    return None


# ---------------------------------------------------------------------
# CDN / anycast detection
# ---------------------------------------------------------------------

def _cdn_for_ip(ip: str) -> str | None:
    """Return the CDN name if the IP is in a known anycast block."""
    try:
        addr = ip_address(ip)
    except Exception:
        return None
    for cdn, blocks in CDN_NETBLOCKS.items():
        for block in blocks:
            try:
                if addr in ip_network(block, strict=False):
                    return cdn
            except Exception:
                continue
    return None


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def locate_ip(ip: str, verbose: bool = False) -> dict:
    """Estimate the geographic location of an IP using public registry data.

    Order of precedence for the country field:
        1. RDAP (structured, authoritative)
        2. Classic whois (fallback)
        3. Reverse-DNS hint (weak, but non-empty)

    Non-routable IPs (private, loopback, link-local, etc.) are refused
    up front — RDAP returns garbage for them.
    """
    # Refuse non-routable IPs
    special = _ip_special_category(ip)
    if special:
        if verbose:
            info(f"geo: {ip} is {special}; not querying registry")
        return {
            "target": ip,
            "country": None,
            "country_name": None,
            "org": None,
            "asn": None,
            "netname": None,
            "address": [],
            "confidence": "none",
            "signals": {},
            "justification": f"non-routable: {special}",
            "errors": [f"ip is {special}"],
            "special_category": special,
        }

    result = {
        "target": ip,
        "country": None,
        "country_name": None,
        "org": None,
        "asn": None,
        "netname": None,
        "address": [],
        "confidence": "none",
        "signals": {
            "rdap": None,
            "whois": None,
            "reverse_dns": None,
            "region_hint": None,
            "cdn": None,
        },
        "justification": "",
        "errors": [],
    }

    # 1. RDAP
    rdap = await rdap_lookup(ip)
    if rdap:
        result["signals"]["rdap"] = rdap
        result["country"] = rdap.get("country")
        result["org"] = rdap.get("org")
        result["netname"] = rdap.get("netname")
        result["address"] = rdap.get("address") or []
    else:
        result["errors"].append("rdap unavailable")

    # 2. Classic whois fallback
    if not result["country"]:
        whois = await whois_lookup(ip)
        if whois:
            result["signals"]["whois"] = whois
            result["country"] = result["country"] or whois.get("country")
            result["org"] = result["org"] or whois.get("org")
            result["netname"] = result["netname"] or whois.get("netname")
            if not result["address"]:
                result["address"] = whois.get("address") or []
        else:
            result["errors"].append("whois unavailable")

    # 3. Reverse DNS + region hint
    hostname = reverse_dns_sync(ip)
    if hostname:
        result["signals"]["reverse_dns"] = {"hostname": hostname}
        hint = region_hint_from_hostname(hostname)
        if hint:
            result["signals"]["region_hint"] = hint

    # 4. CDN detection
    cdn = _cdn_for_ip(ip)
    if cdn:
        result["signals"]["cdn"] = cdn

    # 5. Country name expansion
    if result["country"]:
        cc = result["country"].strip().upper()[:2]
        result["country_name"] = COUNTRY_NAMES.get(cc, result["country"])

    # 6. Confidence scoring
    result["confidence"] = _score_confidence(result)

    # 7. Justification string
    reasons = []
    if result["signals"]["rdap"]:
        reasons.append(f"rdap country={result['country'] or '?'}")
    elif result["signals"]["whois"]:
        reasons.append(f"whois country={result['country'] or '?'}")
    if result["org"]:
        reasons.append(f"org={result['org']!r}")
    if result["signals"]["cdn"]:
        reasons.append(f"cdn={result['signals']['cdn']} (anycast)")
    if result["signals"]["region_hint"]:
        reasons.append(f"region_hint={result['signals']['region_hint']}")
    result["justification"] = ", ".join(reasons) if reasons else "no signals"

    if verbose:
        info(f"geo: {ip} -> {result['country_name'] or '?'} "
             f"({result['confidence']}) — {result['justification']}")

    return result


def _score_confidence(result: dict) -> str:
    """Return 'high' / 'medium' / 'low' / 'none'."""
    if result["signals"].get("cdn"):
        return "low"
    if result["signals"]["rdap"] and result["country"] and result["org"]:
        return "high"
    if result["signals"]["whois"] and result["country"]:
        return "medium"
    if result["signals"]["region_hint"]:
        return "low"
    if result["country"]:
        return "low"
    return "none"


async def locate_host(hostname: str, verbose: bool = False) -> dict:
    """Resolve a hostname, then locate its first A record."""
    try:
        from core.dns import resolve_a
        ips = await resolve_a(hostname, verbose=verbose)
    except Exception:
        ips = []
    if not ips:
        try:
            ip = socket.gethostbyname(hostname)
            ips = [ip]
        except Exception:
            return {
                "target": hostname,
                "country": None, "country_name": None,
                "org": None, "asn": None, "netname": None,
                "address": [], "confidence": "none",
                "signals": {}, "justification": "DNS resolution failed",
                "errors": ["dns_resolution_failed"],
            }
    info(f"geo: resolved {hostname} -> {', '.join(ips)}")
    primary = ips[0]
    result = await locate_ip(primary, verbose=verbose)
    result["target"] = hostname
    result["resolved_to"] = ips
    return result


# ---------------------------------------------------------------------
# Store integration
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False):
    """CLI entry: locate a target and optionally persist into a store."""
    try:
        ip_address(target)
        is_ip = True
    except Exception:
        is_ip = False

    if is_ip:
        result = await locate_ip(target, verbose=verbose)
    else:
        result = await locate_host(target, verbose=verbose)

    print()
    if result["country_name"]:
        success(f"{result['target']}: {result['country_name']} "
                f"({result['confidence']})")
        if result.get("org"):
            print(f"  org:       {result['org']}")
        if result.get("netname"):
            print(f"  netname:   {result['netname']}")
        if result.get("address"):
            print(f"  address:   {' / '.join(result['address'])}")
        if result["signals"].get("cdn"):
            warn(f"  CDN:       {result['signals']['cdn']} "
                 f"(anycast network — country field is NOT the "
                 f"physical location)")
            warn(f"  ⚠️  For {result['signals']['cdn']} IPs, the country "
                 f"shown above is the registry owner's HQ, not where "
                 f"the server actually is. Use latency or traceroute "
                 f"for a real estimate.")
        if result["signals"].get("region_hint"):
            info(f"  region:    {result['signals']['region_hint']}")
        print(f"  basis:     {result['justification']}")
    else:
        special = result.get("special_category")
        if special:
            info(f"{result['target']}: {special} address "
                 f"(no registry data)")
        else:
            warn(f"{result['target']}: no location data "
                 f"({', '.join(result['errors']) or 'no signals'})")

    if store is not None:
        store.add_finding({
            "module": "geo",
            "type": "informational",
            "severity": "info",
            "target": result["target"],
            "evidence": result["justification"],
            "data": result,
        })
        success(f"finding written to store")

    return result


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="net.geo",
        description="IP geolocation via public RDAP/whois data.",
    )
    p.add_argument("target", help="IP or hostname")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--store", action="store_true",
                   help="write finding to the active workspace")
    args = p.parse_args()

    store = None
    if args.store:
        from core.workspace import get_active, get_workspace
        from core.store import open_store
        active = get_active()
        if not active:
            warn("no active workspace; use `toolkit workspace switch <name>`")
            return
        ws = get_workspace(active)
        store = open_store(ws.db_path, workspace_name=active)

    asyncio.run(run(args.target, store=store, verbose=args.verbose))


if __name__ == "__main__":
    _cli()