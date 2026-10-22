"""
Workspace management.

A workspace is an on-disk folder that gathers everything from one
engagement: raw recon outputs, the SQLite findings store, screenshots,
loot, and reports. It exists so you can run 15 different scans across
as many sessions and still find anything by looking in one place.

Layout (created on demand):

    workspaces/<name>/
        workspace.json         — metadata: target scope, operator, dates
        workspace.db           — SQLite store (created lazily by core.store)
        recon/                 — raw outputs, one file per run
        scans/                 — full-scan artifacts (HTML, CSV, JSON)
        loot/
            credentials.txt    — human-readable credential list
            hashes.txt         — captured hashes
            shells/            — captured reverse shells
        screenshots/           — headless-browser captures
        report/
            evidence/          — copied artifacts referenced by reports

Active workspace tracking lives at workspaces/.active. Deleting a
workspace does not delete the tracking file; if it points at a missing
workspace, get_active() returns None.
"""

import json
import os
import shutil
import socket
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from core.output import info, success, warn, error


# Where all workspaces live. Relative to the current working directory
# so the toolkit stays portable — drop it on a USB stick, works anywhere.
DEFAULT_ROOT = Path("workspaces")
ACTIVE_FILE = ".active"
WORKSPACE_META = "workspace.json"


# ---------------------------------------------------------------------
# Dataclass: the metadata written to workspace.json
# ---------------------------------------------------------------------

@dataclass
class WorkspaceMeta:
    """Everything we persist about a workspace besides the findings."""
    name: str
    created_at: str = ""
    updated_at: str = ""
    operator: str = ""
    target_scope: list = field(default_factory=list)   # e.g. ["172.16.11.0/24"]
    notes: str = ""
    toolkit_version: str = "0.1"

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        self.updated_at = now
        if not self.operator:
            try:
                self.operator = os.getlogin()
            except Exception:
                self.operator = os.environ.get("USERNAME") or \
                                os.environ.get("USER") or "unknown"


# ---------------------------------------------------------------------
# Workspace object
# ---------------------------------------------------------------------

class Workspace:
    """Handle for one workspace directory.

    Paths are exposed as attributes so callers don't do path arithmetic:

        ws = Workspace.load("acme-corp")
        ws.db_path                # .../workspace.db
        ws.scans_dir              # .../scans/
        ws.recon_dir              # .../recon/
        ws.loot_dir / "hash.txt"  # Path arithmetic for anything else

    All directories are created lazily by `create()` or `load()`, so
    callers never have to check `dir.exists()` before writing.
    """

    def __init__(self, root: Path, name: str):
        self.root = Path(root)
        self.name = name
        self.path = self.root / name
        self._meta = None

    # -- paths ------------------------------------------------------------

    @property
    def meta_path(self):        return self.path / WORKSPACE_META
    @property
    def db_path(self):          return self.path / "workspace.db"
    @property
    def recon_dir(self):        return self.path / "recon"
    @property
    def scans_dir(self):        return self.path / "scans"
    @property
    def loot_dir(self):         return self.path / "loot"
    @property
    def shells_dir(self):       return self.loot_dir / "shells"
    @property
    def credentials_path(self): return self.loot_dir / "credentials.txt"
    @property
    def hashes_path(self):      return self.loot_dir / "hashes.txt"
    @property
    def screenshots_dir(self):  return self.path / "screenshots"
    @property
    def report_dir(self):       return self.path / "report"
    @property
    def evidence_dir(self):     return self.report_dir / "evidence"

    # -- metadata ---------------------------------------------------------

    @property
    def meta(self) -> WorkspaceMeta:
        if self._meta is None:
            self._meta = self._read_meta() or WorkspaceMeta(name=self.name)
        return self._meta

    def _read_meta(self):
        if not self.meta_path.exists():
            return None
        try:
            raw = json.loads(self.meta_path.read_text(encoding="utf-8"))
            return WorkspaceMeta(**raw)
        except Exception as e:
            warn(f"could not read {self.meta_path}: {type(e).__name__}: {e}")
            return None

    def _write_meta(self):
        self.meta.updated_at = datetime.now(timezone.utc).isoformat()
        tmp = self.meta_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(asdict(self.meta), indent=2),
                       encoding="utf-8")
        tmp.replace(self.meta_path)   # atomic rename

    def touch(self):
        """Update the 'updated_at' field without changing anything else."""
        self._write_meta()

    # -- lifecycle --------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists() and self.meta_path.exists()

    def create(self, operator=None, target_scope=None, notes=""):
        """Create the folder tree and write workspace.json.

        Safe to call on an existing workspace — it only creates what's
        missing and will not overwrite the metadata.
        """
        if self.path.exists() and self.meta_path.exists():
            warn(f"workspace '{self.name}' already exists at {self.path}")
            return self

        self.path.mkdir(parents=True, exist_ok=True)
        for d in (self.recon_dir, self.scans_dir, self.loot_dir,
                  self.shells_dir, self.screenshots_dir,
                  self.report_dir, self.evidence_dir):
            d.mkdir(parents=True, exist_ok=True)

        self._meta = WorkspaceMeta(name=self.name)
        if operator:
            self._meta.operator = operator
        if target_scope:
            self._meta.target_scope = list(target_scope)
        if notes:
            self._meta.notes = notes
        self._write_meta()

        success(f"workspace '{self.name}' created at {self.path}")
        return self

    def load(self):
        """Verify the workspace exists; raise if not."""
        if not self.path.exists():
            raise FileNotFoundError(
                f"workspace '{self.name}' not found at {self.path}")
        if not self.meta_path.exists():
            warn(f"workspace '{self.name}' is missing {WORKSPACE_META}; "
                 f"creating a fresh metadata file")
            self._meta = WorkspaceMeta(name=self.name)
            self._write_meta()
        # Ensure the subdirs exist (in case someone deleted them)
        for d in (self.recon_dir, self.scans_dir, self.loot_dir,
                  self.shells_dir, self.screenshots_dir,
                  self.report_dir, self.evidence_dir):
            d.mkdir(parents=True, exist_ok=True)
        return self

    def delete(self, confirm=True):
        """Remove the entire workspace directory from disk."""
        if not self.path.exists():
            warn(f"workspace '{self.name}' does not exist")
            return False
        if confirm:
            ans = input(f"Delete workspace '{self.name}' at {self.path}? "
                        f"[y/N]: ").strip().lower()
            if ans != "y":
                info("cancelled")
                return False
        shutil.rmtree(self.path)
        success(f"workspace '{self.name}' deleted")
        return True

    # -- convenience ------------------------------------------------------

    def new_recon_file(self, module: str, ext: str = "json") -> Path:
        """Return a timestamped path under recon/ for a fresh run."""
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        return self.recon_dir / f"{ts}_{module}.{ext}"

    def new_scan_file(self, module: str, ext: str = "json") -> Path:
        """Return a timestamped path under scans/ for a fresh run."""
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        return self.scans_dir / f"{ts}_{module}.{ext}"

    def new_screenshot_path(self, ip: str, port: int, ext: str = "png") -> Path:
        """Return a timestamped path under screenshots/."""
        ts = datetime.now().strftime("%Y-%m-%dT%H%M%S")
        safe_ip = ip.replace(":", "_").replace("/", "_")
        return self.screenshots_dir / f"{safe_ip}_{port}_{ts}.{ext}"

    def __repr__(self):
        return f"<Workspace {self.name!r} at {self.path}>"


# ---------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------

def _root(root: Path | str | None = None) -> Path:
    return Path(root) if root else DEFAULT_ROOT


def list_workspaces(root=None):
    """Return a sorted list of workspace names found under `root`."""
    r = _root(root)
    if not r.exists():
        return []
    names = []
    for child in r.iterdir():
        if child.is_dir() and (child / WORKSPACE_META).exists():
            names.append(child.name)
    return sorted(names)


def get_workspace(name: str, root=None) -> Workspace:
    """Load an existing workspace. Raises if it doesn't exist."""
    ws = Workspace(_root(root), name)
    return ws.load()


def get_or_create_workspace(name: str, root=None,
                            target_scope=None, operator=None) -> Workspace:
    """Load if exists, otherwise create. This is what --workspace calls."""
    ws = Workspace(_root(root), name)
    if ws.exists():
        return ws.load()
    return ws.create(target_scope=target_scope, operator=operator)


def delete_workspace(name: str, root=None, confirm=True) -> bool:
    ws = Workspace(_root(root), name)
    return ws.delete(confirm=confirm)


# ---------------------------------------------------------------------
# Active-workspace tracking
# ---------------------------------------------------------------------

def _active_file(root=None) -> Path:
    return _root(root) / ACTIVE_FILE


def set_active(name: str, root=None):
    """Mark a workspace as the default for subsequent runs."""
    r = _root(root)
    r.mkdir(parents=True, exist_ok=True)
    ws = Workspace(r, name)
    if not ws.exists():
        raise FileNotFoundError(f"cannot activate: workspace '{name}' missing")
    _active_file(r).write_text(name, encoding="utf-8")
    success(f"active workspace → {name}")


def get_active(root=None):
    """Return the active workspace name, or None if unset/stale."""
    r = _root(root)
    f = _active_file(r)
    if not f.exists():
        return None
    name = f.read_text(encoding="utf-8").strip()
    if not name:
        return None
    if not (r / name / WORKSPACE_META).exists():
        warn(f"active workspace '{name}' no longer exists")
        return None
    return name


def clear_active(root=None):
    r = _root(root)
    f = _active_file(r)
    if f.exists():
        f.unlink()


# ---------------------------------------------------------------------
# CLI entry (toolkit.py workspace ...)
# ---------------------------------------------------------------------

def cli_new(args):
    ws = Workspace(_root(), args.name)
    scope = args.scope.split(",") if args.scope else None
    ws.create(target_scope=scope, operator=args.operator, notes=args.notes)


def cli_list(args):
    names = list_workspaces()
    if not names:
        info("no workspaces found")
        return
    active = get_active()
    success(f"{len(names)} workspace(s):")
    for n in names:
        marker = " *" if n == active else ""
        ws = Workspace(_root(), n)
        meta = ws.meta
        scope = ",".join(meta.target_scope) if meta.target_scope else "-"
        print(f"  {n:24s} scope={scope:24s} updated={meta.updated_at}{marker}")


def cli_info(args):
    ws = Workspace(_root(), args.name)
    if not ws.exists():
        error(f"workspace '{args.name}' not found")
        return
    ws.load()
    m = ws.meta
    print(f"name:        {m.name}")
    print(f"path:        {ws.path}")
    print(f"created:     {m.created_at}")
    print(f"updated:     {m.updated_at}")
    print(f"operator:    {m.operator}")
    print(f"scope:       {', '.join(m.target_scope) or '-'}")
    print(f"notes:       {m.notes or '-'}")
    print(f"db:          {ws.db_path if ws.db_path.exists() else '(not yet created)'}")
    print(f"recon files: {len(list(ws.recon_dir.glob('*')))}")
    print(f"scan files:  {len(list(ws.scans_dir.glob('*')))}")
    print(f"screenshots: {len(list(ws.screenshots_dir.glob('*')))}")
    print(f"loot files:  {len(list(ws.loot_dir.glob('**/*')))}")


def cli_switch(args):
    set_active(args.name)


def cli_delete(args):
    delete_workspace(args.name, confirm=not args.force)