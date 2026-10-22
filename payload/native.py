"""
GCC (mingw-w64) compiler wrapper for the payload framework.

Compiles C or C++ source into Windows PE binaries (EXEs or DLLs)
and can extract raw shellcode from a compiled artifact.

How it works:

  1. The Payload's source is written to a temp directory as main.c
     (or whatever name the payload specifies via `source_filename`).

  2. Any auxiliary files (headers, additional .c files) are also
     written.

  3. `gcc` is invoked with flags that produce the right kind of
     artifact:
       - shared library:  -shared -o name.dll
       - console exe:     -o name.exe
       - windowed exe:    -mwindows -o name.exe
       - raw object:      -c -o name.obj

  4. Optionally strip symbols and/or extract .text as shellcode.

Output type is chosen by the payload's extra_files metadata:
  __output_type: "dll" | "exe" | "windowed" | "obj"
  __entry: main symbol name (default "main")
  __ldflags: extra linker flags
  __cflags: extra compiler flags
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.output import info, warn
from payload.framework import BuildError


# =====================================================================
# Flag builders
# =====================================================================

# Base flags we always pass. These produce small, optimized,
# self-contained binaries.
_BASE_CFLAGS = [
    "-Os",                  # optimize for size
    "-Wall",                # basic warnings
    "-Wno-unused-function", # don't warn on unused helpers
    "-Wno-unused-variable",
    "-Wno-unused-but-set-variable",
    "-fno-asynchronous-unwind-tables",  # smaller PE
    "-fno-ident",           # no GCC version comment
]

_BASE_LDFLAGS = [
    "-s",                   # strip symbols at link time
]


def _build_cmd(payload, build_dir: Path, output_name: str,
               verbose: bool = False) -> list[str]:
    """Assemble the gcc command line."""
    from payload import compilers
    gcc = compilers.detect_gcc()
    if not gcc.available:
        raise BuildError(
            "gcc not found on PATH. Install mingw-w64 "
            "(e.g. via MSYS2, WinLibs, or the standalone mingw-w64 "
            "build) and add it to PATH.")

    extra = payload.extra_files or {}
    output_type = extra.get("__output_type", "dll")
    user_cflags = extra.get("__cflags", [])
    user_ldflags = extra.get("__ldflags", [])

    if isinstance(user_cflags, str):
        user_cflags = user_cflags.split()
    if isinstance(user_ldflags, str):
        user_ldflags = user_ldflags.split()

    # Collect source files
    source_files = []
    for name in sorted(extra.keys()):
        if name.startswith("__"):
            continue
        if name.endswith((".c", ".cpp", ".cxx", ".cc")):
            source_files.append(str(build_dir / name))

    # The main source file is always Program's source written as
    # main.c (or whatever the source_filename was)
    source_filename = extra.get("__source_filename", "main.c")
    source_files.insert(0, str(build_dir / source_filename))

    cmd = [gcc.path] + _BASE_CFLAGS + list(user_cflags)

    if output_type == "dll":
        cmd += ["-shared"]
        out_path = build_dir / f"{output_name}.dll"
    elif output_type == "exe":
        cmd += []
        out_path = build_dir / f"{output_name}.exe"
    elif output_type == "windowed":
        cmd += ["-mwindows"]
        out_path = build_dir / f"{output_name}.exe"
    elif output_type == "obj":
        cmd += ["-c"]
        out_path = build_dir / f"{output_name}.obj"
    else:
        raise BuildError(f"unknown output_type: {output_type}")

    cmd += list(user_ldflags)
    cmd += source_files
    cmd += ["-o", str(out_path)]

    if verbose:
        info(f"  gcc: {' '.join(cmd)}")

    return cmd


# =====================================================================
# Build
# =====================================================================

def compile_payload(payload, verbose: bool = False) -> tuple[bytes, str]:
    """Compile a C/C++ Payload. Returns (bytes, extension)."""
    extra = payload.extra_files or {}

    source_filename = extra.get("__source_filename", "main.c")
    output_name = extra.get("__output_name", "Payload")
    output_type = extra.get("__output_type", "dll")

    with tempfile.TemporaryDirectory(prefix="tk_payload_") as tmp:
        build_dir = Path(tmp)

        # Write the main source
        (build_dir / source_filename).write_text(
            payload.source, encoding="utf-8")

        # Write auxiliary files
        for name, content in extra.items():
            if name.startswith("__"):
                continue
            target_path = build_dir / name
            target_path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                target_path.write_bytes(content)
            else:
                target_path.write_text(content, encoding="utf-8")

        cmd = _build_cmd(payload, build_dir, output_name, verbose=verbose)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120.0,
                cwd=str(build_dir),
            )
        except subprocess.TimeoutExpired:
            raise BuildError("gcc timed out after 120s")

        if result.returncode != 0:
            stderr = (result.stderr or "")[-2000:]
            raise BuildError(
                f"gcc failed (exit {result.returncode}):\n{stderr}")

        # Find output
        if output_type == "dll":
            out_path = build_dir / f"{output_name}.dll"
            ext = "dll"
        elif output_type == "obj":
            out_path = build_dir / f"{output_name}.obj"
            ext = "obj"
        else:
            out_path = build_dir / f"{output_name}.exe"
            ext = "exe"

        if not out_path.exists():
            raise BuildError(
                f"compiled output missing: {out_path}")

        if verbose:
            info(f"  gcc: output {out_path.name} "
                 f"({out_path.stat().st_size} bytes)")

        artifact = out_path.read_bytes()
        return artifact, ext


# =====================================================================
# Post-processing: extract .text as shellcode
# =====================================================================

def extract_text_section(artifact: bytes) -> bytes:
    """Extract the .text section from a PE binary as raw bytes.

    Used to turn a compiled .exe or .dll into position-independent
    shellcode. The result is not always usable as shellcode without
    further processing — some binaries reference global data, use
    relocations, or import Windows APIs via the IAT, none of which
    survive the extraction. But for simple stubs written to be
    position-independent, this works.
    """
    from payload import compilers
    objcopy = compilers.detect_objcopy()
    if not objcopy.available:
        raise BuildError(
            "objcopy not found on PATH (it ships with mingw-w64)")

    # objcopy needs file paths, not stdin/stdout
    with tempfile.TemporaryDirectory(prefix="tk_extract_") as tmp:
        tmp_dir = Path(tmp)
        src = tmp_dir / "input.bin"
        dst = tmp_dir / "text.bin"
        src.write_bytes(artifact)

        cmd = [
            objcopy.path,
            "-O", "binary",
            "--only-section=.text",
            str(src),
            str(dst),
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30.0)
        except subprocess.TimeoutExpired:
            raise BuildError("objcopy timed out")

        if result.returncode != 0:
            stderr = (result.stderr or "")[-1000:]
            raise BuildError(
                f"objcopy failed (exit {result.returncode}):\n{stderr}")

        if not dst.exists():
            raise BuildError("objcopy produced no output")

        return dst.read_bytes()


def strip_artifact(artifact: bytes) -> bytes:
    """Strip symbols from a PE binary using the `strip` tool."""
    from payload import compilers
    strip = compilers.detect_strip()
    if not strip.available:
        # If strip isn't available, return unchanged (already
        # stripped by -s flag at link time in most builds)
        return artifact

    with tempfile.TemporaryDirectory(prefix="tk_strip_") as tmp:
        tmp_dir = Path(tmp)
        src = tmp_dir / "input.bin"
        src.write_bytes(artifact)

        cmd = [strip.path, str(src)]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30.0)
        except subprocess.TimeoutExpired:
            return artifact

        if result.returncode != 0:
            return artifact

        return src.read_bytes()