"""
TLS certificate grabber.

Connects to host:port over TLS, pulls the certificate, and extracts:
  - subject CN + full DN
  - issuer CN + full DN
  - SAN list  (the payload — often contains internal names)
  - validity window
  - signature algorithm, key size, serial
  - whether the cert is self-signed, expired, or expiring soon
  - the full certificate chain if the server presents one

No verification is performed. We're fingerprinting, not validating.

Why this matters:

  - SAN lists leak internal subdomains that never show up in DNS.
  - Self-signed and expired certs are informative on their own.
  - Chain depth and issuer identity tell you what kind of PKI the
    target runs (public CA vs internal vs nothing).
  - The cert's key size and signature algorithm date the deployment.

Two-pass design:

  1. Try each candidate port (443 first, then 8443, 9443, ...). When
     a port accepts a TLS handshake, extract the leaf cert.
  2. Optionally, check whether the connection actually presents a
     valid chain — a bare handshake can succeed while the server's
     chain is broken or missing intermediates.
"""

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from core.output import info, success, warn
from core.target import parse

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        rsa, ec, dsa, ed25519, ed448,
    )
    from cryptography.x509.oid import NameOID, ExtensionOID
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

# Ports we'll try, in order. Most sites only have 443, but corporate
# gear often puts an admin panel on one of the higher ones.
DEFAULT_PORTS = [443, 8443, 9443, 4443, 10443, 6443]

# Per-attempt timeout
HANDSHAKE_TIMEOUT = 8.0


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _key_size(pub) -> int | None:
    """Extract the key size in bits, where applicable."""
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            return pub.key_size
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return pub.curve.key_size
        if isinstance(pub, dsa.DSAPublicKey):
            return pub.key_size
        # ed25519 and ed448 have a fixed size; return the nominal bit size
        if isinstance(pub, (ed25519.Ed25519PublicKey,
                            ed448.Ed448PublicKey)):
            return 256 if isinstance(pub, ed25519.Ed25519PublicKey) else 448
    except Exception:
        return None
    return None


def _name_to_dict(name: x509.Name) -> dict:
    """Turn an X.509 Name into a flat dict of the common OIDs."""
    out = {}
    if not _HAS_CRYPTO or name is None:
        return out
    for attr in name:
        oid = attr.oid
        value = attr.value
        if oid == NameOID.COMMON_NAME:
            out["CN"] = value
        elif oid == NameOID.ORGANIZATION_NAME:
            out["O"] = value
        elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
            out["OU"] = value
        elif oid == NameOID.COUNTRY_NAME:
            out["C"] = value
        elif oid == NameOID.STATE_OR_PROVINCE_NAME:
            out["ST"] = value
        elif oid == NameOID.LOCALITY_NAME:
            out["L"] = value
        elif oid == NameOID.EMAIL_ADDRESS:
            out["emailAddress"] = value
    return out


def _names_to_set(name: x509.Name) -> set[str]:
    """Return every attribute value as a string (used for comparisons)."""
    out = set()
    if not _HAS_CRYPTO or name is None:
        return out
    for attr in name:
        out.add(str(attr.value))
    return out


def _parse_der(der: bytes) -> dict | None:
    """Parse a DER-encoded cert into a flat dict."""
    if not _HAS_CRYPTO:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    out = {}

    # Subject + issuer
    out["subject"] = _name_to_dict(cert.subject)
    out["issuer"] = _name_to_dict(cert.issuer)
    out["subject_cn"] = out["subject"].get("CN")
    out["issuer_cn"] = out["issuer"].get("CN")
    out["subject_dn"] = cert.subject.rfc4514_string()
    out["issuer_dn"] = cert.issuer.rfc4514_string()

    # Serial
    try:
        out["serial"] = format(cert.serial_number, "x")
    except Exception:
        out["serial"] = None

    # Dates — handle both modern and older cryptography versions
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
    out["not_before"] = nb.isoformat()
    out["not_after"] = na.isoformat()

    now = datetime.now(timezone.utc)
    try:
        out["expired"] = na < now
        out["days_until_expiry"] = (na - now).days
        out["days_since_issued"] = (now - nb).days
    except Exception:
        out["expired"] = None
        out["days_until_expiry"] = None
        out["days_since_issued"] = None

    # SAN list — the payload
    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for n in ext.value:
            if isinstance(n, x509.DNSName):
                sans.append(n.value.lower())
            elif isinstance(n, x509.IPAddress):
                sans.append(str(n.value))
            elif isinstance(n, x509.RFC822Name):
                sans.append(n.value)
    except x509.ExtensionNotFound:
        pass
    out["sans"] = sorted(set(sans))

    # Subject CN as a SAN fallback (older certs sometimes only have CN)
    if out["subject_cn"] and out["subject_cn"].lower() not in out["sans"]:
        out["sans"].insert(0, out["subject_cn"].lower())

    # Self-signed?
    try:
        out["self_signed"] = (cert.subject == cert.issuer)
    except Exception:
        out["self_signed"] = False

    # Signature algorithm
    try:
        out["sig_alg"] = cert.signature_hash_algorithm.name
    except Exception:
        out["sig_alg"] = None

    # Key algorithm + size
    try:
        pub = cert.public_key()
        out["key_alg"] = type(pub).__name__
        out["key_size"] = _key_size(pub)
    except Exception:
        out["key_alg"] = None
        out["key_size"] = None

    # Key usage / extended key usage
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE)
        out["ext_key_usage"] = sorted(
            ku.name for ku in ext.value
        )
    except Exception:
        out["ext_key_usage"] = []

    # Basic constraints (is this a CA cert?)
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS)
        out["is_ca"] = bool(ext.value.ca)
    except Exception:
        out["is_ca"] = False

    return out


# ---------------------------------------------------------------------
# The actual handshake
# ---------------------------------------------------------------------

def _grab_one(host: str, port: int, timeout: float = HANDSHAKE_TIMEOUT,
              send_sni: bool = True) -> dict | None:
    """Blocking TLS handshake + cert extract. Runs in an executor."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # For IP literals, SNI is technically invalid, but many servers
    # require something to be sent. We can disable it or send the
    # IP. Most libraries tolerate it.
    sni = host if send_sni else None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                der = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()
                cipher = ssock.cipher()
                # Python 3.10+: get the whole verified chain in DER
                try:
                    chain = ssock.get_verified_chain()
                    if not chain:
                        chain = [der]
                    chain_der = [c.public_bytes() for c in chain]
                except Exception:
                    chain_der = [der] if der else []
    except (socket.timeout, socket.gaierror, ConnectionRefusedError,
            ConnectionResetError, OSError):
        return None
    except ssl.SSLError as e:
        return {"error": f"TLS error: {e}", "port": port}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "port": port}

    if not der:
        return None

    out = {
        "port": port,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
        "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
    }

    leaf = _parse_der(der)
    if leaf is None:
        out["error"] = "could not parse certificate"
        return out

    out.update(leaf)

    # Chain info — number of certs, and the topmost issuer
    out["chain_length"] = len(chain_der)
    out["chain"] = []
    for i, c_der in enumerate(chain_der):
        parsed = _parse_der(c_der)
        if parsed is None:
            continue
        out["chain"].append({
            "position": i,
            "subject_cn": parsed.get("subject_cn"),
            "issuer_cn": parsed.get("issuer_cn"),
            "self_signed": parsed.get("self_signed"),
            "is_ca": parsed.get("is_ca"),
            "not_before": parsed.get("not_before"),
            "not_after": parsed.get("not_after"),
        })

    return out


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

async def grab(host: str, ports: list[int] | None = None,
               verbose: bool = False) -> dict:
    """Try every port in `ports`; return the first successful TLS handshake.

    Returns {} if no port accepted a TLS connection. Returns a dict
    with an "error" key if TLS was spoken but something went wrong.
    """
    if ports is None:
        ports = DEFAULT_PORTS
    loop = asyncio.get_running_loop()

    last_error = None
    for port in ports:
        if verbose:
            info(f"tls_cert: trying {host}:{port}")
        result = await loop.run_in_executor(
            None, _grab_one, host, port)
        if result is None:
            continue
        if "error" in result and "sans" not in result:
            # Handshake failed; remember but keep trying other ports
            last_error = result
            if verbose:
                warn(f"tls_cert: {host}:{port} — {result['error']}")
            continue
        # Success — return the leaf cert for this port
        return result

    if last_error:
        return last_error
    return {}


# ---------------------------------------------------------------------
# Store integration
# ---------------------------------------------------------------------

async def run(target: str, store=None, verbose: bool = False,
              ports: list[int] | None = None) -> dict:
    """CLI entry. Grabs the cert and writes to store if provided."""
    t = parse(target)
    host = t.host
    info(f"tls_cert: grabbing certificate for {host}")

    result = await grab(host, ports=ports, verbose=verbose)

    print()
    if not result:
        warn(f"tls_cert: no TLS listener found on {host} "
             f"(tried {ports or DEFAULT_PORTS})")
        return {"target": host, "result": {}}

    if "error" in result and "sans" not in result:
        warn(f"tls_cert: {result['error']}")
        return {"target": host, "result": result}

    # ---------- Print summary ----------
    cn = result.get("subject_cn") or "?"
    issuer = result.get("issuer_cn") or "?"
    sans = result.get("sans") or []
    chain_len = result.get("chain_length") or 1

    success(f"tls_cert: {host}:{result['port']} "
            f"(TLS {result.get('protocol')})")
    print(f"  subject CN:  {cn}")
    print(f"  issuer CN:   {issuer}")
    print(f"  serial:      {result.get('serial')}")
    print(f"  valid:       {result.get('not_before')} → "
          f"{result.get('not_after')}")

    due = result.get("days_until_expiry")
    if result.get("expired"):
        warn(f"  status:      EXPIRED "
             f"({-due if due is not None else '?'} days ago)")
    elif due is not None and due < 30:
        warn(f"  status:      expiring soon ({due} days)")
    elif due is not None:
        info(f"  status:      valid ({due} days remaining)")

    if result.get("self_signed"):
        warn("  self-signed: yes (no CA in chain)")
    if chain_len > 1:
        info(f"  chain:       {chain_len} certificate(s)")
    if result.get("key_alg"):
        info(f"  key:         {result['key_alg']} "
             f"{result.get('key_size') or '?'} bits, "
             f"sig={result.get('sig_alg') or '?'}")

    if sans:
        print()
        success(f"  {len(sans)} SAN(s) in certificate:")
        for s in sans[:60]:
            print(f"    {s}")
        if len(sans) > 60:
            print(f"    ... and {len(sans) - 60} more")
    else:
        info("  no SANs in certificate (only CN)")

    # ---------- Store ----------
    if store is not None:
        store.add_finding({
            "module": "tls_cert",
            "type": "informational",
            "severity": "info",
            "target": host,
            "evidence": (f"CN={cn} issuer={issuer} "
                         f"SANs={len(sans)} chain={chain_len}"),
            "data": result,
        })

        # Also upsert each SAN as a host, so the store's host list
        # grows as you scan. That's how the graph forms.
        try:
            for name in sans:
                if name and not name.replace(".", "").replace("-", "").isdigit():
                    store.upsert_host(
                        ip=name,  # hostname-as-ip trick; store doesn't
                                  # strictly require an IP but keeps
                                  # hostname in a distinct column
                        hostname=name,
                        discovery=f"tls-cert ({host})",
                        tags=["san"],
                    )
        except Exception as e:
            if verbose:
                warn(f"tls_cert: could not persist SANs: {e}")

        success("finding written to store")

    return {"target": host, "result": result}


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="recon.tls_cert",
        description="Grab and parse the TLS certificate on a host.",
    )
    p.add_argument("target", help="hostname or IP")
    p.add_argument("--ports", default=None,
                   help="comma-separated ports (default: 443,8443,9443,"
                        "4443,10443,6443)")
    p.add_argument("--store", action="store_true",
                   help="write finding to active workspace")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    ports = None
    if args.ports:
        ports = []
        for p_ in args.ports.split(","):
            p_ = p_.strip()
            if p_.isdigit():
                ports.append(int(p_))

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
        args.target, store=store, verbose=args.verbose, ports=ports))


if __name__ == "__main__":
    _cli()