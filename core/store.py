"""
SQLite findings store.

Every module in the toolkit that discovers something — a live host, an
open port, an SQLi finding, a captured credential — writes it here. The
unified report generator reads from here. Everything survives process
restarts.

Design:

  - One SQLite file per workspace, stored at workspace.db.
  - WAL journal mode: concurrent readers + one writer, no locking drama.
  - Auto-migration for additive schema changes; destructive changes are
    refused with a clear error so we never silently corrupt data.
  - Thread-safe: each thread gets its own connection; writes serialize
    through a lock.
  - Simple dict API. No ORM. Add a finding, get an ID. Query it back.

Schema version tracking:

  A single-row `schema_version` table holds the current integer. The
  MIGRATIONS list below is a list of (target_version, callable) pairs.
  On open, we run every migration whose target_version is greater than
  the current version, in order. Migrations are additive only — if you
  need to drop or retype a column, write a new table and copy.

Usage:

    from core.store import Store

    store = Store.open("workspaces/acme-corp/workspace.db")
    fid = store.add_finding({
        "module": "sqli",
        "type": "sqli",
        "severity": "high",
        "target": "http://example.com/login",
        "param": "username",
        "payload": "' OR '1'='1",
        "evidence": "error-based",
        "data": {"dbms": "mysql", "tables": ["users"]},
    })

    for f in store.query_findings(severity="high"):
        print(f["id"], f["target"], f["type"])
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from core.output import info, success, warn, error


# ---------------------------------------------------------------------
# Schema — the base tables, current version = 2
# ---------------------------------------------------------------------
#
# New columns in the future get added via MIGRATIONS below. Never edit
# the base schema after it's shipped to a user — create a migration.
#
# Base schema corresponds to schema_version = 1. Version 2 adds the
# `shells` table.

SCHEMA_VERSION = 2

BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    module      TEXT NOT NULL,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info',
    target      TEXT,
    port        INTEGER,
    param       TEXT,
    payload     TEXT,
    evidence    TEXT,
    data_json   TEXT,           -- arbitrary extra fields
    workspace   TEXT,           -- filled in by the store
    UNIQUE(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_module   ON findings(module);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_type     ON findings(type);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL UNIQUE,
    mac         TEXT,
    hostname    TEXT,
    os_guess    TEXT,
    discovery   TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    tags_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac);

CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip     TEXT NOT NULL,
    port        INTEGER NOT NULL,
    proto       TEXT NOT NULL DEFAULT 'tcp',
    service     TEXT,
    version     TEXT,
    banner      TEXT,
    tls_json    TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(host_ip, port, proto)
);

CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_ip);

CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    target      TEXT,
    username    TEXT,
    password    TEXT,
    hash        TEXT,
    source      TEXT,          -- module that found it
    notes       TEXT
);

CREATE INDEX IF NOT EXISTS idx_creds_target ON credentials(target);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    target      TEXT NOT NULL,
    cookie_json TEXT,
    headers_json TEXT,
    expires_at  TEXT,
    notes       TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_target ON sessions(target);

CREATE TABLE IF NOT EXISTS artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    kind        TEXT NOT NULL,   -- 'screenshot', 'response', 'loot'
    path        TEXT NOT NULL,
    sha256      TEXT,
    size        INTEGER,
    finding_id  INTEGER,          -- optional link to findings.id
    notes       TEXT,
    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_kind ON artifacts(kind);
"""


# ---------------------------------------------------------------------
# Migrations — additive only
# ---------------------------------------------------------------------
#
# Each entry is (target_version, callable). The callable receives the
# sqlite3.Connection and performs whatever DDL is needed.
#
# To run migrations 1→N, we iterate from current+1 to N, calling each
# function and updating schema_version. If a migration raises, we roll
# back the entire transaction. This means partial migrations can never
# leave the DB in an inconsistent state.

def _migrate_v1_to_v2(conn):
    """v1 → v2: add a shells table for reverse-shell sessions.

    A row per session. Transcript path is a relative path under the
    workspace's loot/shells/ directory. Byte counts and opened/closed
    timestamps let the operator see session history even if the
    transcript file was deleted.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS shells (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            opened_at       TEXT NOT NULL,
            closed_at       TEXT,
            listen_host     TEXT,
            listen_port     INTEGER,
            remote_host     TEXT,
            remote_port     INTEGER,
            shell_type      TEXT,
            bytes_sent      INTEGER DEFAULT 0,
            bytes_received  INTEGER DEFAULT 0,
            transcript_path TEXT,
            notes           TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_shells_opened "
        "ON shells(opened_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_shells_remote "
        "ON shells(remote_host)"
    )


MIGRATIONS = [
    (2, _migrate_v1_to_v2),
]


# ---------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------

class Store:
    """Handle for one findings database.

    Not thread-safe on a single instance across threads; each thread
    should call `store.connection()` to get its own connection, or use
    the module-level `open_store()` which caches per (path, thread).
    """

    def __init__(self, db_path: Path, workspace_name: str | None = None):
        self.db_path = Path(db_path)
        self.workspace_name = workspace_name
        self._lock = threading.Lock()
        self._conn = None

    # -- lifecycle --------------------------------------------------------

    @classmethod
    def open(cls, db_path, workspace_name=None) -> "Store":
        """Open (or create) the DB, run migrations, return a Store."""
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        store = cls(db_path, workspace_name=workspace_name)
        store._ensure_schema()
        return store

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Performance + concurrency
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def connection(self) -> sqlite3.Connection:
        """Return this instance's connection, creating it on first use."""
        if self._conn is None:
            self._conn = self._connect()
        return self._conn

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # -- schema -----------------------------------------------------------

    def _ensure_schema(self):
        conn = self.connection()
        with self._lock:
            conn.executescript(BASE_SCHEMA)
            # Initialize schema_version if empty
            cur = conn.execute("SELECT version FROM schema_version LIMIT 1")
            row = cur.fetchone()
            if row is None:
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, now),
                )
                conn.commit()
                return

            current = row["version"]
            if current == SCHEMA_VERSION:
                return
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"workspace.db schema version {current} is newer than "
                    f"this toolkit ({SCHEMA_VERSION}). Downgrade not supported."
                )
            self._run_migrations(conn, current, SCHEMA_VERSION)

    def _run_migrations(self, conn, current, target):
        pending = sorted([(v, fn) for v, fn in MIGRATIONS if v > current])
        if not pending:
            # Nothing declared between current and target. This is fine
            # only if target == current; otherwise someone bumped
            # SCHEMA_VERSION without adding a migration.
            if target != current:
                raise RuntimeError(
                    f"schema version {current} < {target} but no migration "
                    f"registered. Add one to MIGRATIONS."
                )
            return
        info(f"migrating workspace.db: v{current} → v{target}")
        try:
            conn.execute("BEGIN")
            for target_v, fn in pending:
                if target_v > target:
                    break
                info(f"  applying migration → v{target_v}")
                fn(conn)
                conn.execute(
                    "UPDATE schema_version SET version=?, applied_at=?",
                    (target_v, datetime.now(timezone.utc).isoformat()),
                )
            conn.commit()
            success(f"workspace.db migrated to v{target}")
        except Exception as e:
            conn.rollback()
            raise RuntimeError(f"migration failed: {e}") from e

    # -- internal helpers -------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @contextmanager
    def _write(self):
        """Serialize writes through a lock; commit or rollback atomically."""
        with self._lock:
            conn = self.connection()
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    # ---------------------------------------------------------------------
    # findings
    # ---------------------------------------------------------------------

    def add_finding(self, finding: dict) -> int:
        """Insert a finding. Returns the new row ID.

        Accepts a plain dict; unknown keys go into `data_json`. Recognized
        top-level keys: module, type, severity, target, port, param,
        payload, evidence, ts, data.
        """
        known = {"module", "type", "severity", "target", "port",
                 "param", "payload", "evidence", "ts", "data"}
        extra = {k: v for k, v in finding.items() if k not in known}

        data_blob = dict(finding.get("data") or {})
        if extra:
            data_blob.update(extra)

        row = (
            finding.get("ts") or self._now(),
            finding.get("module", "unknown"),
            finding.get("type", "unknown"),
            finding.get("severity", "info"),
            finding.get("target"),
            finding.get("port"),
            finding.get("param"),
            finding.get("payload"),
            finding.get("evidence"),
            json.dumps(data_blob, default=str) if data_blob else None,
            self.workspace_name,
        )
        with self._write() as conn:
            cur = conn.execute(
                "INSERT INTO findings "
                "(ts, module, type, severity, target, port, param, "
                " payload, evidence, data_json, workspace) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                row,
            )
            return cur.lastrowid

    def query_findings(self, module=None, type=None, severity=None,
                       target=None, limit=None) -> list[dict]:
        """Query findings. All filters are AND-combined; None means 'any'."""
        sql = "SELECT * FROM findings WHERE 1=1"
        args = []
        if module:
            sql += " AND module = ?"
            args.append(module)
        if type:
            sql += " AND type = ?"
            args.append(type)
        if severity:
            sql += " AND severity = ?"
            args.append(severity)
        if target:
            sql += " AND target LIKE ?"
            args.append(f"%{target}%")
        sql += " ORDER BY ts DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        conn = self.connection()
        cur = conn.execute(sql, args)
        return [self._row_to_dict(r) for r in cur.fetchall()]

    def count_findings(self, **filters) -> int:
        return len(self.query_findings(**filters))

    # ---------------------------------------------------------------------
    # hosts
    # ---------------------------------------------------------------------

    def upsert_host(self, ip: str, mac=None, hostname=None, os_guess=None,
                    discovery=None, tags=None) -> int:
        """Insert a host or update the existing row.

        first_seen is preserved on update; last_seen is always refreshed.
        """
        now = self._now()
        tags_json = json.dumps(tags or [], default=str) if tags else None
        with self._write() as conn:
            cur = conn.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
            row = cur.fetchone()
            if row is None:
                cur = conn.execute(
                    "INSERT INTO hosts "
                    "(ip, mac, hostname, os_guess, discovery, "
                    " first_seen, last_seen, tags_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (ip, mac, hostname, os_guess, discovery, now, now, tags_json),
                )
                return cur.lastrowid
            else:
                conn.execute(
                    "UPDATE hosts SET "
                    " mac       = COALESCE(?, mac), "
                    " hostname  = COALESCE(?, hostname), "
                    " os_guess  = COALESCE(?, os_guess), "
                    " discovery = COALESCE(?, discovery), "
                    " last_seen = ?, "
                    " tags_json = COALESCE(?, tags_json) "
                    "WHERE ip = ?",
                    (mac, hostname, os_guess, discovery, now, tags_json, ip),
                )
                return row["id"]

    def query_hosts(self, ip=None) -> list[dict]:
        conn = self.connection()
        if ip:
            cur = conn.execute("SELECT * FROM hosts WHERE ip = ?", (ip,))
        else:
            cur = conn.execute("SELECT * FROM hosts ORDER BY ip")
        return [self._row_to_dict(r) for r in cur.fetchall()]

    # ---------------------------------------------------------------------
    # services
    # ---------------------------------------------------------------------

    def upsert_service(self, host_ip: str, port: int, proto="tcp",
                       service=None, version=None, banner=None,
                       tls=None) -> int:
        now = self._now()
        tls_json = json.dumps(tls, default=str) if tls else None
        with self._write() as conn:
            cur = conn.execute(
                "SELECT id FROM services "
                "WHERE host_ip=? AND port=? AND proto=?",
                (host_ip, port, proto),
            )
            row = cur.fetchone()
            if row is None:
                cur = conn.execute(
                    "INSERT INTO services "
                    "(host_ip, port, proto, service, version, banner, "
                    " tls_json, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (host_ip, port, proto, service, version, banner,
                     tls_json, now, now),
                )
                return cur.lastrowid
            else:
                conn.execute(
                    "UPDATE services SET "
                    " service    = COALESCE(?, service), "
                    " version    = COALESCE(?, version), "
                    " banner     = COALESCE(?, banner), "
                    " tls_json   = COALESCE(?, tls_json), "
                    " last_seen  = ? "
                    "WHERE id = ?",
                    (service, version, banner, tls_json, now, row["id"]),
                )
                return row["id"]

    def query_services(self, host_ip=None) -> list[dict]:
        conn = self.connection()
        if host_ip:
            cur = conn.execute(
                "SELECT * FROM services WHERE host_ip=? ORDER BY port",
                (host_ip,),
            )
        else:
            cur = conn.execute(
                "SELECT * FROM services ORDER BY host_ip, port")
        return [self._row_to_dict(r) for r in cur.fetchall()]

    # ---------------------------------------------------------------------
    # credentials
    # ---------------------------------------------------------------------

    def add_credential(self, target=None, username=None, password=None,
                       hash=None, source=None, notes=None) -> int:
        with self._write() as conn:
            cur = conn.execute(
                "INSERT INTO credentials "
                "(ts, target, username, password, hash, source, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self._now(), target, username, password, hash,
                 source, notes),
            )
            return cur.lastrowid

    def query_credentials(self, target=None) -> list[dict]:
        conn = self.connection()
        if target:
            cur = conn.execute(
                "SELECT * FROM credentials WHERE target LIKE ?",
                (f"%{target}%",),
            )
        else:
            cur = conn.execute("SELECT * FROM credentials ORDER BY ts DESC")
        return [self._row_to_dict(r) for r in cur.fetchall()]

    # ---------------------------------------------------------------------
    # sessions (web auth sessions)
    # ---------------------------------------------------------------------

    def add_session(self, target: str, cookies: dict, headers=None,
                    expires_at=None, notes=None) -> int:
        with self._write() as conn:
            cur = conn.execute(
                "INSERT INTO sessions "
                "(ts, target, cookie_json, headers_json, expires_at, notes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (self._now(), target,
                 json.dumps(cookies or {}, default=str),
                 json.dumps(headers or {}, default=str),
                 expires_at, notes),
            )
            return cur.lastrowid

    def query_sessions(self, target=None) -> list[dict]:
        conn = self.connection()
        if target:
            cur = conn.execute(
                "SELECT * FROM sessions WHERE target LIKE ? ORDER BY ts DESC",
                (f"%{target}%",),
            )
        else:
            cur = conn.execute("SELECT * FROM sessions ORDER BY ts DESC")
        return [self._row_to_dict(r) for r in cur.fetchall()]

    # ---------------------------------------------------------------------
    # shells (Session 6)
    # ---------------------------------------------------------------------

    def open_shell(self, listen_host: str, listen_port: int,
                    remote_host: str, remote_port: int,
                    shell_type: str | None = None,
                    transcript_path: str | None = None,
                    notes: str | None = None) -> int:
        """Insert a new shell session row. Returns the row id."""
        with self._write() as conn:
            cur = conn.execute(
                "INSERT INTO shells "
                "(opened_at, listen_host, listen_port, remote_host, "
                " remote_port, shell_type, transcript_path, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (self._now(), listen_host, listen_port,
                 remote_host, remote_port, shell_type,
                 transcript_path, notes),
            )
            return cur.lastrowid

    def close_shell(self, shell_id: int,
                    bytes_sent: int | None = None,
                    bytes_received: int | None = None,
                    notes: str | None = None):
        """Mark a shell session as closed and update its byte counts."""
        with self._write() as conn:
            conn.execute(
                "UPDATE shells SET "
                " closed_at = ?, "
                " bytes_sent = COALESCE(?, bytes_sent), "
                " bytes_received = COALESCE(?, bytes_received), "
                " notes = COALESCE(?, notes) "
                "WHERE id = ?",
                (self._now(), bytes_sent, bytes_received,
                 notes, shell_id),
            )

    def query_shells(self, open_only: bool = False) -> list[dict]:
        conn = self.connection()
        if open_only:
            cur = conn.execute(
                "SELECT * FROM shells WHERE closed_at IS NULL "
                "ORDER BY opened_at DESC"
            )
        else:
            cur = conn.execute(
                "SELECT * FROM shells ORDER BY opened_at DESC"
            )
        return [self._row_to_dict(r) for r in cur.fetchall()]

    def get_shell(self, shell_id: int) -> dict | None:
        conn = self.connection()
        cur = conn.execute("SELECT * FROM shells WHERE id = ?",
                            (shell_id,))
        row = cur.fetchone()
        return self._row_to_dict(row) if row else None

    # ---------------------------------------------------------------------
    # artifacts
    # ---------------------------------------------------------------------

    def add_artifact(self, kind: str, path: str, sha256=None, size=None,
                     finding_id=None, notes=None) -> int:
        with self._write() as conn:
            cur = conn.execute(
                "INSERT INTO artifacts "
                "(ts, kind, path, sha256, size, finding_id, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self._now(), kind, path, sha256, size, finding_id, notes),
            )
            return cur.lastrowid

    def query_artifacts(self, kind=None) -> list[dict]:
        conn = self.connection()
        if kind:
            cur = conn.execute(
                "SELECT * FROM artifacts WHERE kind=? ORDER BY ts DESC",
                (kind,),
            )
        else:
            cur = conn.execute("SELECT * FROM artifacts ORDER BY ts DESC")
        return [self._row_to_dict(r) for r in cur.fetchall()]

    # ---------------------------------------------------------------------
    # summary (used by reports)
    # ---------------------------------------------------------------------

    def summary(self) -> dict:
        """Return counts of everything. Used at the top of reports."""
        conn = self.connection()
        def _count(table):
            cur = conn.execute(f"SELECT COUNT(*) AS c FROM {table}")
            return cur.fetchone()["c"]

        by_severity = {}
        cur = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM findings GROUP BY severity"
        )
        for row in cur.fetchall():
            by_severity[row["severity"]] = row["c"]

        by_module = {}
        cur = conn.execute(
            "SELECT module, COUNT(*) AS c FROM findings GROUP BY module"
        )
        for row in cur.fetchall():
            by_module[row["module"]] = row["c"]

        return {
            "findings": _count("findings"),
            "hosts": _count("hosts"),
            "services": _count("services"),
            "credentials": _count("credentials"),
            "sessions": _count("sessions"),
            "shells": _count("shells"),
            "artifacts": _count("artifacts"),
            "by_severity": by_severity,
            "by_module": by_module,
        }

    # ---------------------------------------------------------------------
    # raw access for reports
    # ---------------------------------------------------------------------

    def all_findings(self) -> list[dict]:
        return self.query_findings()

    def all_hosts(self) -> list[dict]:
        return self.query_hosts()

    # ---------------------------------------------------------------------
    # helpers
    # ---------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row) -> dict:
        d = dict(row)
        # Expand JSON blobs
        for k in ("data_json", "tags_json", "tls_json",
                  "cookie_json", "headers_json"):
            if k in d and d[k]:
                try:
                    d[k[:-5] if k.endswith("_json") else k] = \
                        json.loads(d[k])
                except Exception:
                    pass
        return d


# ---------------------------------------------------------------------
# Module-level convenience: per-thread store cache
# ---------------------------------------------------------------------
#
# Opening the DB per call is expensive and defeats WAL. We cache one
# Store per (path, thread) so each thread writes on its own connection
# without hitting the module import path every time.

_STORES = {}
_STORES_LOCK = threading.Lock()


def open_store(db_path, workspace_name=None) -> Store:
    """Get a per-thread Store for db_path, opening it on first access."""
    key = (str(Path(db_path).resolve()), threading.get_ident())
    with _STORES_LOCK:
        store = _STORES.get(key)
        if store is None:
            store = Store.open(db_path, workspace_name=workspace_name)
            _STORES[key] = store
        return store


def close_all():
    """Close every cached store. Call at process exit if you care."""
    with _STORES_LOCK:
        for store in _STORES.values():
            store.close()
        _STORES.clear()