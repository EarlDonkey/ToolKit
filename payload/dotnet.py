"""
C# compiler wrapper for the payload framework.

Uses `dotnet build` to compile a .cs source file into a .dll or .exe.

How it works:

  1. The Payload's source is written to a temp directory as Program.cs
     (or whatever name the payload specifies via `source_filename`).

  2. A minimal .csproj is generated with the target framework, output
     type, and any additional properties the payload asked for.

  3. `dotnet build -c Release` is invoked in the temp directory.

  4. The output binary is found under bin/Release/<target>/ and its
     bytes are returned.

Caching:

  The framework caches by content hash, so this function is only
  called on a cache miss. The first build of a fresh project can
  take 5-30 seconds (NuGet restore, compiler startup). Subsequent
  builds with the same source are instant cache hits.
"""

import os
import subprocess
import tempfile
from pathlib import Path

from core.output import info, warn
from payload.framework import BuildError


# =====================================================================
# .csproj template
# =====================================================================

_CSPROJ_TEMPLATE = """<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>{target}</TargetFramework>
    <OutputType>{output_type}</OutputType>
    <AssemblyName>{assembly_name}</AssemblyName>
    <RootNamespace>{namespace}</RootNamespace>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <LangVersion>latest</LangVersion>
    <DebugType>none</DebugType>
    <Optimize>true</Optimize>
    <GenerateDocumentationFile>false</GenerateDocumentationFile>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <Platforms>AnyCPU;x64</Platforms>
    <PlatformTarget>x64</PlatformTarget>
    <NoWarn>CS0169;CS0414;CS0649;CS1998</NoWarn>
    <Deterministic>true</Deterministic>
    <DebugSymbols>false</DebugSymbols>
  </PropertyGroup>

  <PropertyGroup Condition="'$(TargetFrameworkIdentifier)' == '.NETFramework'">
    <AutoGenerateBindingRedirects>false</AutoGenerateBindingRedirects>
    <GenerateBindingRedirectsOutputType>false</GenerateBindingRedirectsOutputType>
  </PropertyGroup>

</Project>
"""


# =====================================================================
# Helpers
# =====================================================================

def _find_output_binary(build_dir: Path, target: str,
                        assembly_name: str,
                        output_type: str) -> Path | None:
    """Locate the compiled binary under bin/Release/."""
    candidates = [
        build_dir / "bin" / "Release" / target / f"{assembly_name}.dll",
        build_dir / "bin" / "Release" / target / f"{assembly_name}.exe",
        build_dir / "bin" / "Release" / target / "publish" /
            f"{assembly_name}.dll",
        build_dir / "bin" / "Release" / target / "publish" /
            f"{assembly_name}.exe",
    ]
    for c in candidates:
        if c.exists():
            return c
    # Fallback: walk bin/
    bin_dir = build_dir / "bin" / "Release"
    if bin_dir.exists():
        for p in bin_dir.rglob(f"{assembly_name}.*"):
            if p.suffix.lower() in (".dll", ".exe"):
                return p
    return None


def _clean_build_dir(build_dir: Path):
    """Remove bin/ and obj/ so a rebuild is clean."""
    for sub in ("bin", "obj"):
        p = build_dir / sub
        if p.exists():
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# =====================================================================
# Main entry point
# =====================================================================

def compile_payload(payload, verbose: bool = False) -> tuple[bytes, str]:
    """Compile a C# Payload. Returns (bytes, extension)."""

    # Determine output type from the payload
    extra = payload.extra_files or {}

    # Allow payloads to specify these via a special key in extra_files
    source_filename = extra.get("__source_filename", "Program.cs")
    assembly_name = extra.get("__assembly_name", "Payload")
    namespace = extra.get("__namespace", "Payload")
    output_type = extra.get("__output_type", "Library")
    target = payload.target or "net48"

    if verbose:
        info(f"  dotnet: building {assembly_name} ({target}) "
             f"as {output_type}")

    # Clean extra_files of the __ keys (they're metadata, not files)
    real_files = {k: v for k, v in extra.items()
                  if not k.startswith("__")}

    # Locate dotnet
    from payload import compilers
    dotnet = compilers.detect_dotnet()
    if not dotnet.available:
        raise BuildError(
            "dotnet SDK not found on PATH. Install it from "
            "https://dotnet.microsoft.com/download")

    # Sanity: does the payload target an SDK we actually have?
    sdks = dotnet.extra.get("sdks") or []
    if sdks and target.startswith("net"):
        # Extract the major.minor from the target
        import re
        m = re.match(r"net(\d+)\.(\d+)", target)
        if m:
            wanted = f"{m.group(1)}.{m.group(2)}"
            # The SDK major must be >= wanted major. This is a loose
            # check — the real compatibility rules are more complex.
            wanted_major = int(m.group(1))
            have_major = max((int(s.split(".")[0]) for s in sdks),
                              default=0)
            if have_major < wanted_major:
                raise BuildError(
                    f"target {target} requires SDK {wanted_major}.x or "
                    f"newer, but only {sdks} are installed")

    # Write source into a temp dir and build
    with tempfile.TemporaryDirectory(prefix="tk_payload_") as tmp:
        build_dir = Path(tmp)

        # Write the .csproj
        csproj = _CSPROJ_TEMPLATE.format(
            target=target,
            output_type=output_type,
            assembly_name=assembly_name,
            namespace=namespace,
        )
        (build_dir / f"{assembly_name}.csproj").write_text(
            csproj, encoding="utf-8")

        # Write the main source
        (build_dir / source_filename).write_text(
            payload.source, encoding="utf-8")

        # Write any auxiliary files
        for name, content in real_files.items():
            target_path = build_dir / name
            target_path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                target_path.write_bytes(content)
            else:
                target_path.write_text(content, encoding="utf-8")

        # Invoke dotnet build
        cmd = [
            dotnet.path, "build",
            str(build_dir / f"{assembly_name}.csproj"),
            "-c", "Release",
            "--nologo",
            "-v", "quiet" if not verbose else "minimal",
        ]

        if verbose:
            info(f"  dotnet: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180.0,
                cwd=str(build_dir),
            )
        except subprocess.TimeoutExpired:
            raise BuildError("dotnet build timed out after 180s")

        if result.returncode != 0:
            stderr = (result.stderr or "")[-2000:]
            stdout = (result.stdout or "")[-2000:]
            raise BuildError(
                f"dotnet build failed (exit {result.returncode}):\n"
                f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}")

        # Find the compiled binary
        out_bin = _find_output_binary(
            build_dir, target, assembly_name, output_type)
        if out_bin is None:
            raise BuildError(
                f"compiled binary not found under {build_dir}/bin/Release")

        if verbose:
            info(f"  dotnet: output {out_bin.name} "
                 f"({out_bin.stat().st_size} bytes)")

        artifact = out_bin.read_bytes()
        ext = out_bin.suffix.lstrip(".")
        return artifact, ext