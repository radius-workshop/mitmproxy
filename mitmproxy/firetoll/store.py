"""Layer 2 1/2: the Firetoll session store.

SQLite at ~/.mitmproxy/firetoll/session.sqlite (or `firetoll_store_path`).
Identifier values are never stored raw - only a salted hash, so the store
itself cannot become a credential trove. Retention is enforced in code, not
just documented: rows older than `firetoll_retention_hours` are deleted on
startup and on a periodic sweep.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy.firetoll.finding import Finding
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)

DEFAULT_STORE_PATH = Path.home() / ".mitmproxy" / "firetoll" / "session.sqlite"
RETENTION_SWEEP_INTERVAL = 15 * 60  # seconds

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    started_at REAL NOT NULL,
    ended_at REAL,
    unattributed_flows INTEGER NOT NULL DEFAULT 0,
    connect_only_flows INTEGER NOT NULL DEFAULT 0,
    streamed_bodies INTEGER NOT NULL DEFAULT 0,
    bodies_truncated INTEGER NOT NULL DEFAULT 0,
    websocket_frames_captured INTEGER NOT NULL DEFAULT 0,
    body_access TEXT NOT NULL DEFAULT 'redacted'
);

CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    process TEXT,
    path TEXT,
    parent TEXT,
    source TEXT NOT NULL,
    first_seen REAL NOT NULL,
    UNIQUE(process, path, parent, source)
);

CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    app_id INTEGER REFERENCES apps(id) ON DELETE SET NULL,
    method TEXT,
    host TEXT,
    path TEXT,
    status INTEGER,
    request_bytes INTEGER,
    response_bytes INTEGER,
    tls_profile_hash TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    cls TEXT NOT NULL,
    label TEXT NOT NULL,
    confidence TEXT NOT NULL,
    evidence TEXT NOT NULL,
    facts TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (
    value_hash TEXT NOT NULL,
    value_prefix TEXT NOT NULL,
    etld1 TEXT NOT NULL,
    flow_id TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    seen_at REAL NOT NULL,
    PRIMARY KEY (value_hash, etld1, flow_id)
);

CREATE TABLE IF NOT EXISTS bodies (
    flow_id TEXT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    part TEXT NOT NULL CHECK (part IN ('request', 'response')),
    content BLOB NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0,
    redacted INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (flow_id, part)
);

CREATE TABLE IF NOT EXISTS access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL,
    part TEXT NOT NULL,
    mode TEXT NOT NULL,
    accessed_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS flows_created_at_idx
    ON flows(created_at DESC);
CREATE INDEX IF NOT EXISTS flows_host_created_at_idx
    ON flows(host, created_at DESC);
CREATE INDEX IF NOT EXISTS flows_app_created_at_idx
    ON flows(app_id, created_at DESC);
CREATE INDEX IF NOT EXISTS findings_flow_idx
    ON findings(flow_id);
CREATE INDEX IF NOT EXISTS findings_class_created_at_idx
    ON findings(cls, created_at DESC);
"""

SESSION_COUNTERS = (
    "unattributed_flows",
    "connect_only_flows",
    "streamed_bodies",
    "bodies_truncated",
)


class Store:
    """Thin synchronous wrapper around the session SQLite file. Not
    thread-safe; used from the proxy event loop only."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._ensure_permissions()
        self.conn = sqlite3.connect(str(path))
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        os.chmod(path, 0o600)
        self._ensure_salt()
        self._ensure_session_row()
        self.conn.commit()

    def _ensure_permissions(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)

    def _ensure_salt(self) -> None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = 'salt'").fetchone()
        if row is None:
            salt = secrets.token_hex(16)
            self.conn.execute(
                "INSERT INTO meta (key, value) VALUES ('salt', ?)", (salt,)
            )
            self._salt = salt
        else:
            self._salt = row[0]

    def _ensure_session_row(self) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO session (id, started_at) VALUES (1, ?)",
            (time.time(),),
        )

    # -- identifiers -----------------------------------------------------

    def hash_identifier(self, value: str) -> tuple[str, str]:
        """Returns (full_hash, display_prefix). The raw value is never
        stored - joins work on hash equality, so a salted hash is sufficient."""
        digest = hashlib.sha256(self._salt.encode() + value.encode()).hexdigest()
        return digest, digest[:8]

    # -- writes ------------------------------------------------------------

    def record_app(
        self,
        *,
        process: str | None,
        path: str | None,
        parent: str | None,
        source: str,
    ) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO apps (process, path, parent, source, first_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(process, path, parent, source) DO UPDATE SET process = process
            RETURNING id
            """,
            (process, path, parent, source, time.time()),
        )
        (app_id,) = cur.fetchone()
        self.conn.commit()
        return app_id

    def record_flow(
        self,
        *,
        flow_id: str,
        app_id: int | None,
        method: str | None,
        host: str | None,
        path: str | None,
        status: int | None,
        request_bytes: int | None,
        response_bytes: int | None,
        tls_profile_hash: str | None = None,
        created_at: float | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO flows
                (id, created_at, app_id, method, host, path, status,
                 request_bytes, response_bytes, tls_profile_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                app_id = excluded.app_id,
                method = excluded.method,
                host = excluded.host,
                path = excluded.path,
                status = excluded.status,
                request_bytes = excluded.request_bytes,
                response_bytes = excluded.response_bytes,
                tls_profile_hash = excluded.tls_profile_hash
            """,
            (
                flow_id,
                created_at if created_at is not None else time.time(),
                app_id,
                method,
                host,
                path,
                status,
                request_bytes,
                response_bytes,
                tls_profile_hash,
            ),
        )
        self.conn.commit()

    def record_finding(self, flow_id: str, finding: Finding) -> None:
        self.conn.execute(
            """
            INSERT INTO findings (flow_id, cls, label, confidence, evidence, facts, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                flow_id,
                finding.cls,
                finding.label,
                finding.confidence,
                json.dumps(finding.evidence),
                json.dumps(finding.facts),
                time.time(),
            ),
        )
        self.conn.commit()

    def record_body(
        self,
        *,
        flow_id: str,
        part: str,
        content: bytes,
        truncated: bool,
        redacted: bool,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO bodies (flow_id, part, content, truncated, redacted)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(flow_id, part) DO UPDATE SET
                content = excluded.content,
                truncated = excluded.truncated,
                redacted = excluded.redacted
            """,
            (flow_id, part, content, int(truncated), int(redacted)),
        )
        self.conn.commit()

    def get_body(self, flow_id: str, part: str) -> tuple[bytes, bool, bool] | None:
        row = self.conn.execute(
            "SELECT content, truncated, redacted FROM bodies WHERE flow_id = ? AND part = ?",
            (flow_id, part),
        ).fetchone()
        if row is None:
            return None
        content, truncated, redacted = row
        return content, bool(truncated), bool(redacted)

    def get_body_window(
        self, flow_id: str, part: str, offset: int, limit: int
    ) -> tuple[bytes, bool, bool, int] | None:
        row = self.conn.execute(
            """
            SELECT substr(content, ?, ?), truncated, redacted, length(content)
            FROM bodies
            WHERE flow_id = ? AND part = ?
            """,
            (offset + 1, limit, flow_id, part),
        ).fetchone()
        if row is None:
            return None
        content, truncated, redacted, content_bytes = row
        return bytes(content), bool(truncated), bool(redacted), int(content_bytes)

    def list_body_metadata(
        self, flow_id: str | None = None, limit: int = 100
    ) -> list[tuple[str, str, int, bool, bool, float | None]]:
        query = """
            SELECT b.flow_id, b.part, length(b.content), b.truncated, b.redacted,
                   f.created_at
            FROM bodies b
            LEFT JOIN flows f ON f.id = b.flow_id
        """
        params: list[object] = []
        if flow_id is not None:
            query += " WHERE b.flow_id = ?"
            params.append(flow_id)
        query += " ORDER BY f.created_at DESC, b.flow_id, b.part LIMIT ?"
        params.append(limit)
        return [
            (body_flow_id, part, int(content_bytes), bool(truncated), bool(redacted), created_at)
            for body_flow_id, part, content_bytes, truncated, redacted, created_at in self.conn.execute(
                query, params
            )
        ]

    def record_access(self, *, flow_id: str, part: str, mode: str) -> None:
        self.conn.execute(
            "INSERT INTO access_log (flow_id, part, mode, accessed_at) VALUES (?, ?, ?, ?)",
            (flow_id, part, mode, time.time()),
        )
        self.conn.commit()

    def list_access_log(self, limit: int = 100) -> list[tuple[str, str, str, float]]:
        return self.conn.execute(
            """
            SELECT flow_id, part, mode, accessed_at FROM access_log
            ORDER BY accessed_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def record_identity(self, *, value: str, etld1: str, flow_id: str) -> None:
        value_hash, value_prefix = self.hash_identifier(value)
        self.conn.execute(
            """
            INSERT OR IGNORE INTO identities (value_hash, value_prefix, etld1, flow_id, seen_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (value_hash, value_prefix, etld1, flow_id, time.time()),
        )
        self.conn.commit()

    def find_identity_joins(self) -> list[tuple[str, str, list[str], list[str]]]:
        """Every identifier value observed under two or more distinct
        eTLD+1s - the cross-site join computation. Returns
        (value_hash, value_prefix, sorted_etld1s, flow_ids)."""
        rows = self.conn.execute(
            """
            SELECT value_hash, value_prefix,
                   GROUP_CONCAT(DISTINCT etld1), GROUP_CONCAT(DISTINCT flow_id)
            FROM identities
            GROUP BY value_hash
            HAVING COUNT(DISTINCT etld1) >= 2
            """
        ).fetchall()
        return [
            (value_hash, value_prefix, sorted(etlds.split(",")), flow_ids.split(","))
            for value_hash, value_prefix, etlds, flow_ids in rows
        ]

    def increment_counter(self, name: str, by: int = 1) -> None:
        if name not in SESSION_COUNTERS:
            raise ValueError(f"unknown session counter: {name}")
        self.conn.execute(f"UPDATE session SET {name} = {name} + ? WHERE id = 1", (by,))
        self.conn.commit()

    def set_websocket_frames_captured(self, value: bool) -> None:
        self.conn.execute(
            "UPDATE session SET websocket_frames_captured = ? WHERE id = 1",
            (1 if value else 0,),
        )
        self.conn.commit()

    def set_body_access(self, value: str) -> None:
        self.conn.execute("UPDATE session SET body_access = ? WHERE id = 1", (value,))
        self.conn.commit()

    def get_body_access(self) -> str:
        (value,) = self.conn.execute(
            "SELECT body_access FROM session WHERE id = 1"
        ).fetchone()
        return value

    def close_session(self) -> None:
        self.conn.execute(
            "UPDATE session SET ended_at = ? WHERE id = 1", (time.time(),)
        )
        self.conn.commit()

    # -- retention -----------------------------------------------------

    def enforce_retention(
        self, retention_hours: float, now: float | None = None
    ) -> int:
        cutoff = (now if now is not None else time.time()) - retention_hours * 3600
        cur = self.conn.execute("DELETE FROM flows WHERE created_at < ?", (cutoff,))
        self.conn.commit()
        return cur.rowcount

    def wipe(self) -> None:
        for table in ("bodies", "identities", "findings", "flows", "apps"):
            self.conn.execute(f"DELETE FROM {table}")
        self.conn.execute(
            "UPDATE session SET started_at = ?, ended_at = NULL, "
            "unattributed_flows = 0, connect_only_flows = 0, "
            "streamed_bodies = 0, bodies_truncated = 0, "
            "websocket_frames_captured = 0 WHERE id = 1",
            (time.time(),),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


def _refuse_write(self, *_args, **_kwargs):
    raise PermissionError(
        "ReadOnlyStore cannot write to the Firetoll session store "
        "(this is a bug - the MCP server must never mutate proxy state)"
    )


class ReadOnlyStore(Store):
    """The MCP server's view of the session store: a read-only connection
    for everything except its own audit trail. `record_access` uses a
    second, separate connection so the server can log its own `get_body`
    calls without needing (or being able to abuse) write access to flows,
    findings, or identities - every inherited write method is disabled.
    """

    def __init__(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"no Firetoll session store at {path}")
        self.path = path
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        self._audit_conn = sqlite3.connect(str(path))
        row = self.conn.execute("SELECT value FROM meta WHERE key = 'salt'").fetchone()
        self._salt = row[0] if row else ""

    def record_access(self, *, flow_id: str, part: str, mode: str) -> None:
        self._audit_conn.execute(
            "INSERT INTO access_log (flow_id, part, mode, accessed_at) VALUES (?, ?, ?, ?)",
            (flow_id, part, mode, time.time()),
        )
        self._audit_conn.commit()

    def close(self) -> None:
        self.conn.close()
        self._audit_conn.close()

    record_app = _refuse_write
    record_flow = _refuse_write
    record_finding = _refuse_write
    record_identity = _refuse_write
    record_body = _refuse_write
    increment_counter = _refuse_write
    set_websocket_frames_captured = _refuse_write
    set_body_access = _refuse_write
    close_session = _refuse_write
    enforce_retention = _refuse_write
    wipe = _refuse_write


class FiretollStore:
    """Addon: owns the store's lifecycle - opening with correct permissions,
    an initial retention sweep, a periodic sweep while running, and a clean
    close on exit."""

    def __init__(self) -> None:
        self.db: Store | None = None
        self._retention_task: asyncio.Task | None = None

    def _resolve_path(self) -> Path:
        configured = ctx.options.firetoll_store_path
        return Path(configured) if configured else DEFAULT_STORE_PATH

    def running(self) -> None:
        if not ctx.options.firetoll:
            return
        self.db = Store(self._resolve_path())
        self.db.set_body_access(ctx.options.firetoll_body_access)
        self.db.enforce_retention(ctx.options.firetoll_retention_hours)
        self._retention_task = asyncio_utils.create_task(
            self._retention_loop(), name="firetoll-retention", keep_ref=True
        )

    async def _retention_loop(self) -> None:
        while True:
            await asyncio.sleep(RETENTION_SWEEP_INTERVAL)
            if self.db is not None:
                deleted = self.db.enforce_retention(
                    ctx.options.firetoll_retention_hours
                )
                if deleted:
                    logger.info(f"firetoll: retention swept {deleted} flow(s)")

    def done(self) -> None:
        if self._retention_task is not None:
            self._retention_task.cancel()
        if self.db is not None:
            self.db.close_session()
            self.db.close()
            self.db = None

    @command.command("firetoll.wipe")
    def wipe(self) -> None:
        """Delete all Firetoll session data (flows, findings, identities, bodies)."""
        if self.db is None:
            logger.warning("firetoll.wipe: no open session store")
            return
        self.db.wipe()
        logger.info("firetoll: session store wiped")
