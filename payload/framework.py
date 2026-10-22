"""
Payload build framework.

A Payload is a source-code template + a compiler + a set of post-
processing steps. Compiling it produces one of:

  - a .dll / .exe (runnable artifact)
  - a raw byte blob (shellcode)
  - an encoded string (base64, hex, etc.)

Design:

  - Every Payload is content-addressable. The cache key is
    sha256(language + target + source + extra_files + post_steps).
    Building the same payload twice is a cache hit.
  - The compiler is chosen by `language`:
      "csharp"     → dotnet.py (uses `dotnet build`)
      "c"          → native.py (uses `gcc`)
      "cpp"        → native.py
      "powershell" → not compiled, returned as-is
      "python"     → not compiled, returned as-is
  - Post-processing is a list of (name, fn) pairs applied to the
    compiler output in order. Standard post-processors:
      "extract_text"  → objcopy .text section → raw shellcode
      "strip"         → strip symbols
      "b64"           → base64 encode the artifact
  - The cache lives at ~/.toolkit/payloads/<hash>.<ext>. Built
    artifacts are copied into the workspace's loot/payloads/ when
    the operator calls `.save(workspace)`.

This module doesn't know what any specific payload does. It just
compiles source into an artifact. What goes in `source` is up to
the caller.
"""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from core.output import info, success, warn, error


# =====================================================================
# Cache
# =====================================================================

def _cache_dir() -> Path:
    """Return the global build cache directory."""
    home = Path.home()
    d = home / ".toolkit" / "payloads"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _hash_payload(payload: "Payload") -> str:
    """Compute a content hash for cache keying."""
    h = hashlib.sha256()
    h.update(payload.language.encode())
    h.update(b"\x00")
    h.update(payload.target.encode())
    h.update(b"\x00")
    h.update(payload.source.encode())
    h.update(b"\x00")
    for name in sorted(payload.extra_files.keys()):
        h.update(name.encode())
        h.update(b"\x00")
        content = payload.extra_files[name]
        if isinstance(content, str):
            content = content.encode()
        h.update(content)
        h.update(b"\x00")
    for step_name, _fn in payload.post_processing:
        h.update(step_name.encode())
        h.update(b"\x00")
    return h.hexdigest()[:32]


# =====================================================================
# Payload
# =====================================================================

@dataclass
class Payload:
    """A buildable payload."""

    language: str
    source: str
    target: str = ""
    extra_files: dict = field(default_factory=dict)
    post_processing: list = field(default_factory=list)
    description: str = ""

    # Filled in by build()
    built_bytes: bytes | None = None
    built_path: Path | None = None
    built_extension: str = ""
    build_elapsed: float = 0.0
    from_cache: bool = False

    # -----------------------------------------------------------------
    # Cache
    # -----------------------------------------------------------------

    def cache_key(self) -> str:
        return _hash_payload(self)

    def cache_path(self, ext: str | None = None) -> Path:
        ext = ext or self.built_extension or "bin"
        return _cache_dir() / f"{self.cache_key()}.{ext}"

    def is_cached(self) -> bool:
        return self.cache_path().exists()

    # -----------------------------------------------------------------
    # Build
    # -----------------------------------------------------------------

    def build(self, force_rebuild: bool = False,
              verbose: bool = False) -> bytes:
        """Compile this payload. Returns the built artifact bytes.

        Raises BuildError on compilation failure. If the payload
        has already been built successfully, this is a no-op.

        Cache behavior:
          - If not force_rebuild and the cache file exists, load
            from cache without invoking any compiler.
          - Otherwise compile, run post-processing, write the cache
            file, and return the bytes.
        """
        # Already built in this instance
        if self.built_bytes is not None and not force_rebuild:
            return self.built_bytes

        # Cache hit
        if not force_rebuild:
            for ext in (self.built_extension, "bin", "dll", "exe", "so"):
                if not ext:
                    continue
                p = self.cache_path(ext)
                if p.exists():
                    self.built_bytes = p.read_bytes()
                    self.built_path = p
                    self.built_extension = ext
                    self.from_cache = True
                    if verbose:
                        info(f"  payload: cache hit ({p.name}, "
                             f"{len(self.built_bytes)} bytes)")
                    return self.built_bytes

        # Cache miss — compile
        start = time.time()
        artifact, ext = self._compile(verbose=verbose)

        # Post-processing
        for step_name, fn in self.post_processing:
            artifact = fn(artifact)
            ext = _ext_for_post_step(step_name, ext)

        elapsed = time.time() - start
        self.built_bytes = artifact
        self.built_extension = ext
        self.build_elapsed = elapsed
        self.from_cache = False

        # Write to cache
        try:
            cache_file = self.cache_path(ext)
            cache_file.write_bytes(artifact)
            self.built_path = cache_file
        except Exception as e:
            warn(f"  payload: could not write cache: {e}")

        return self.built_bytes

    def _compile(self, verbose: bool = False) -> tuple[bytes, str]:
        """Dispatch to the right compiler. Returns (bytes, extension)."""
        lang = self.language.lower()

        if lang in ("csharp", "cs", "dotnet"):
            from payload import dotnet
            return dotnet.compile_payload(self, verbose=verbose)

        if lang in ("c", "cpp", "cxx", "native"):
            from payload import native
            return native.compile_payload(self, verbose=verbose)

        if lang == "powershell":
            # Not compiled — just the bytes
            return self.source.encode("utf-8"), "ps1"

        if lang == "python":
            return self.source.encode("utf-8"), "py"

        if lang == "bash":
            return self.source.encode("utf-8"), "sh"

        raise BuildError(f"unknown language: {self.language}")

    # -----------------------------------------------------------------
    # Save
    # -----------------------------------------------------------------

    def save(self, workspace, filename: str | None = None) -> Path:
        """Copy the built artifact into the workspace's loot/payloads/.

        Returns the path it was saved to. Raises if not built yet.
        """
        if self.built_bytes is None:
            self.build()

        base = workspace.loot_dir / "payloads"
        base.mkdir(parents=True, exist_ok=True)

        if filename is None:
            stem = self.description.replace(" ", "_")[:32] or "payload"
            stem = "".join(c for c in stem if c.isalnum() or c in "_-")
            filename = f"{stem}_{self.cache_key()[:8]}.{self.built_extension}"

        out_path = base / filename
        out_path.write_bytes(self.built_bytes)

        # Also register as an artifact in the store if one is
        # accessible from the workspace
        try:
            from core.store import open_store
            store = open_store(workspace.db_path,
                                workspace_name=workspace.name)
            import hashlib as _h
            sha = _h.sha256(self.built_bytes).hexdigest()
            store.add_artifact(
                kind="payload",
                path=str(out_path.relative_to(workspace.path)),
                sha256=sha,
                size=len(self.built_bytes),
                notes=self.description or self.language,
            )
        except Exception:
            pass

        return out_path


class BuildError(Exception):
    """Raised when a payload fails to compile."""
    pass


# =====================================================================
# Post-processing helpers
# =====================================================================

def _ext_for_post_step(step_name: str, current_ext: str) -> str:
    """Return the new file extension after a post-processing step."""
    if step_name in ("extract_text", "extract_section"):
        return "bin"
    if step_name == "strip":
        return current_ext          # strip preserves the format
    if step_name in ("b64", "base64"):
        return "b64"
    if step_name in ("hex",):
        return "hex"
    return current_ext


def post_b64(artifact: bytes) -> bytes:
    """Base64-encode the artifact."""
    import base64
    return base64.b64encode(artifact)


def post_hex(artifact: bytes) -> bytes:
    """Hex-encode the artifact (lowercase, no prefix)."""
    return artifact.hex().encode("ascii")


def post_extract_text(artifact: bytes) -> bytes:
    """Extract the .text section from a PE/ELF.

    This requires writing the artifact to a temp file, running
    objcopy, and reading the result back. Expensive but only runs
    when the caller explicitly asks for it.
    """
    from payload import native
    return native.extract_text_section(artifact)


def post_strip(artifact: bytes) -> bytes:
    """Strip symbols from a PE/ELF."""
    from payload import native
    return native.strip_artifact(artifact)


# Registry of standard post-processors
POST_PROCESSORS = {
    "b64":      post_b64,
    "base64":   post_b64,
    "hex":      post_hex,
    "extract_text": post_extract_text,
    "extract_section": post_extract_text,
    "strip":    post_strip,
}


def make_post_chain(names: list[str]) -> list[tuple[str, callable]]:
    """Build a post_processing list from a list of names."""
    out = []
    for name in names:
        fn = POST_PROCESSORS.get(name)
        if fn is None:
            raise BuildError(f"unknown post-processor: {name}")
        out.append((name, fn))
    return out


# =====================================================================
# Convenience
# =====================================================================

def build_csharp(source: str, target: str = "net8.0",
                 extra_files: dict | None = None,
                 post: list[str] | None = None,
                 description: str = "",
                 verbose: bool = False) -> Payload:
    """Convenience: build a C# payload in one call."""
    p = Payload(
        language="csharp",
        source=source,
        target=target,
        extra_files=extra_files or {},
        post_processing=make_post_chain(post or []),
        description=description,
    )
    p.build(verbose=verbose)
    return p


def build_c(source: str, target: str = "windows-x64",
            extra_files: dict | None = None,
            post: list[str] | None = None,
            description: str = "",
            verbose: bool = False) -> Payload:
    """Convenience: build a C payload in one call."""
    p = Payload(
        language="c",
        source=source,
        target=target,
        extra_files=extra_files or {},
        post_processing=make_post_chain(post or []),
        description=description,
    )
    p.build(verbose=verbose)
    return p