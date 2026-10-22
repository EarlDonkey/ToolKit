"""
Toolchain detection for the payload build framework.

The payload framework compiles source code into runnable artifacts
(DLLs, EXEs, shellcode blobs). It needs to know what compilers are
available on this machine before it can build anything.

What we look for:

  dotnet      The .NET SDK. Used for C# compilation. Multiple versions
              can be installed side by side; we report all of them.

  gcc         The GNU C Compiler (mingw-w64 on Windows). Used for
              native C/C++ compilation into Windows PE binaries.

  objcopy     GNU binutils. Used to extract a section from a compiled
              PE (e.g. .text) as raw bytes → shellcode.

  strip       GNU binutils. Used to remove symbols from a compiled
              binary to make it smaller and less informative.

  csc         Legacy .NET Framework C# compiler. Not required if
              `dotnet` is present, but we detect it in case a future
              payload needs net48-specific compilation.

  cl          Microsoft Visual C++ compiler. Not required if `gcc`
              is present.

Each detection returns:
  - path: full path to the executable, or None
  - version: version string, or None
  - extra: dict with compiler-specific info (e.g. gcc target triple)

All checks are cached after the first call so repeated lookups are
free.
"""

import re
import shutil
import subprocess
from dataclasses import dataclass, field


# =====================================================================
# Data model
# =====================================================================

@dataclass
class ToolInfo:
    """One detected tool."""
    name: str
    path: str | None = None
    version: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return self.path is not None


# =====================================================================
# Detector
# =====================================================================

_CACHE: dict[str, ToolInfo] = {}


def _run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr).

    Never raises. On failure returns (-1, "", error_message).
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", f"{type(e).__name__}: {e}"


def _which(name: str) -> str | None:
    """Cross-platform `which`. Returns the full path or None."""
    path = shutil.which(name)
    return path


# =====================================================================
# Individual tool detectors
# =====================================================================

def detect_dotnet() -> ToolInfo:
    """Detect the .NET SDK.

    Reports the path to the `dotnet` executable plus a list of
    installed SDK versions and installed runtime versions.
    """
    info = ToolInfo(name="dotnet")
    path = _which("dotnet")
    if path is None:
        return info

    info.path = path

    # Version banner (works even when only the runtime is installed)
    rc, out, _ = _run([path, "--version"])
    if rc == 0:
        info.version = out.strip()

    # Installed SDKs — one per line, format "X.Y.ZZZ [path]"
    rc, out, _ = _run([path, "--list-sdks"])
    if rc == 0:
        sdks = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            # Extract the leading version number
            m = re.match(r"^(\d+\.\d+\.\d+)", line)
            if m:
                sdks.append(m.group(1))
        info.extra["sdks"] = sdks

    # Installed runtimes — format "Name X.Y.Z [path]"
    rc, out, _ = _run([path, "--list-runtimes"])
    if rc == 0:
        runtimes = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                runtimes.setdefault(parts[0], []).append(parts[1])
        info.extra["runtimes"] = runtimes

    return info


def detect_gcc() -> ToolInfo:
    """Detect GCC (mingw-w64 on Windows).

    Reports the path, version, and target triple. The target triple
    tells us what kind of binaries this compiler produces.
    """
    info = ToolInfo(name="gcc")
    path = _which("gcc")
    if path is None:
        return info

    info.path = path

    rc, out, _ = _run([path, "--version"])
    if rc == 0:
        first_line = out.splitlines()[0] if out.splitlines() else ""
        # "gcc.exe (x86_64-posix-seh-rev0, ...) 15.2.0"
        m = re.search(r"(\d+\.\d+\.\d+)", first_line)
        if m:
            info.version = m.group(1)

    rc, out, _ = _run([path, "-dumpmachine"])
    if rc == 0:
        info.extra["target"] = out.strip()

    return info


def detect_objcopy() -> ToolInfo:
    """Detect objcopy (part of GNU binutils)."""
    info = ToolInfo(name="objcopy")
    path = _which("objcopy")
    if path is None:
        # mingw ships it alongside gcc as objcopy.exe — try
        # to find it next to gcc
        gcc = detect_gcc()
        if gcc.available:
            import os
            gcc_dir = os.path.dirname(gcc.path)
            candidate = os.path.join(gcc_dir, "objcopy.exe")
            if os.path.exists(candidate):
                path = candidate
            else:
                candidate = os.path.join(gcc_dir, "objcopy")
                if os.path.exists(candidate):
                    path = candidate
    if path is None:
        return info

    info.path = path

    rc, out, _ = _run([path, "--version"])
    if rc == 0:
        first_line = out.splitlines()[0] if out.splitlines() else ""
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", first_line)
        if m:
            info.version = m.group(1)

    return info


def detect_strip() -> ToolInfo:
    """Detect strip (part of GNU binutils)."""
    info = ToolInfo(name="strip")
    path = _which("strip")
    if path is None:
        gcc = detect_gcc()
        if gcc.available:
            import os
            gcc_dir = os.path.dirname(gcc.path)
            candidate = os.path.join(gcc_dir, "strip.exe")
            if os.path.exists(candidate):
                path = candidate
            else:
                candidate = os.path.join(gcc_dir, "strip")
                if os.path.exists(candidate):
                    path = candidate
    if path is None:
        return info

    info.path = path

    rc, out, _ = _run([path, "--version"])
    if rc == 0:
        first_line = out.splitlines()[0] if out.splitlines() else ""
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", first_line)
        if m:
            info.version = m.group(1)

    return info


def detect_csc() -> ToolInfo:
    """Detect the legacy .NET Framework C# compiler."""
    info = ToolInfo(name="csc")
    path = _which("csc")
    if path is None:
        # Well-known install locations for .NET Framework
        candidates = [
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
            r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
        ]
        import os
        for c in candidates:
            if os.path.exists(c):
                path = c
                break
    if path is None:
        return info

    info.path = path

    rc, out, _ = _run([path, "/version"])
    if rc == 0:
        info.version = out.strip().splitlines()[0] if out.strip() else ""

    return info


def detect_cl() -> ToolInfo:
    """Detect the Microsoft Visual C++ compiler.

    cl.exe is almost never on PATH by default; it's inside a Visual
    Studio developer command prompt. We check PATH and a couple of
    known install locations.
    """
    info = ToolInfo(name="cl")
    path = _which("cl")
    if path is None:
        # Look under Visual Studio install dirs
        import os
        import glob
        candidates = []
        for pattern in (
            r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
            r"C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
        ):
            candidates.extend(glob.glob(pattern))
        if candidates:
            path = sorted(candidates)[-1]
    if path is None:
        return info

    info.path = path
    return info


# =====================================================================
# Public API
# =====================================================================

def detect_all(force_reload: bool = False) -> dict[str, ToolInfo]:
    """Detect every tool we care about. Results are cached.

    Pass force_reload=True to re-run detection.
    """
    global _CACHE
    if _CACHE and not force_reload:
        return _CACHE

    _CACHE = {
        "dotnet":   detect_dotnet(),
        "gcc":      detect_gcc(),
        "objcopy":  detect_objcopy(),
        "strip":    detect_strip(),
        "csc":      detect_csc(),
        "cl":       detect_cl(),
    }
    return _CACHE


def get(name: str) -> ToolInfo | None:
    """Get a specific tool by name. Cached after first call."""
    tools = detect_all()
    return tools.get(name)


def summary() -> str:
    """Return a human-readable summary of what's available."""
    tools = detect_all()
    lines = ["Toolchain detection:"]
    for name in ("dotnet", "gcc", "objcopy", "strip", "csc", "cl"):
        t = tools.get(name)
        if t is None or not t.available:
            lines.append(f"  {name:10s} NOT FOUND")
            continue
        ver = t.version or "?"
        lines.append(f"  {name:10s} {ver:20s} {t.path}")
        for k, v in t.extra.items():
            if k == "sdks":
                lines.append(f"    SDKs: {', '.join(v) if v else '(none)'}")
            elif k == "target":
                lines.append(f"    target: {v}")
            elif k == "runtimes":
                # Summarize: "Name (X.Y.Z, X.Y.W)"
                for rt_name, versions in sorted(v.items()):
                    vers = ", ".join(versions)
                    lines.append(f"    {rt_name}: {vers}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(summary())