"""Layer 2 1/2: the Firetoll session store.

SQLite at ~/.mitmproxy/firetoll/session.sqlite (or `firetoll_store_path`).
Identifier values are never stored raw - only a salted hash, so the store
itself cannot become a credential trove. Retention is enforced in code, not
just documented: rows older than `firetoll_retention_hours` are deleted on
startup and on a periodic sweep.

Each time this store is opened for writing, a new row is inserted into
`sessions` - one `mitmdump`/`mitmproxy` run, one session. This is what lets
`is_live` and per-run totals be trustworthy: a stale `ended_at` from a
previous run can never leak into the row a new run is writing to, and
`flow_count` for "this session" cannot silently become a multi-day,
multi-run total.
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

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    ended_at REAL,
    unattributed_flows INTEGER NOT NULL DEFAULT 0,
    connect_only_flows INTEGER NOT NULL DEFAULT 0,
    streamed_bodies INTEGER NOT NULL DEFAULT 0,
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
    session_id INTEGER REFERENCES sessions(id),
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
    sha256 TEXT,
    content_type TEXT,
    captured_at REAL,
    PRIMARY KEY (flow_id, part)
);

CREATE TABLE IF NOT EXISTS tool_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT,
    args_json TEXT,
    flow_id TEXT,
    part TEXT,
    mode TEXT,
    row_count INTEGER,
    bytes_returned INTEGER,
    session_id INTEGER,
    called_at REAL NOT NULL
);
"""

# Applied after _migrate_schema() has added any columns these indexes
# reference (e.g. flows.session_id on a store predating that column) -
# CREATE INDEX would otherwise fail on a store created before this schema.
INDEX_SCHEMA = """
CREATE INDEX IF NOT EXISTS flows_created_at_idx
    ON flows(created_at DESC);
CREATE INDEX IF NOT EXISTS flows_host_created_at_idx
    ON flows(host, created_at DESC);
CREATE INDEX IF NOT EXISTS flows_app_created_at_idx
    ON flows(app_id, created_at DESC);
CREATE INDEX IF NOT EXISTS flows_session_idx
    ON flows(session_id);
CREATE INDEX IF NOT EXISTS findings_flow_idx
    ON findings(flow_id);
CREATE INDEX IF NOT EXISTS findings_class_created_at_idx
    ON findings(cls, created_at DESC);
"""

SESSION_COUNTERS = (
    "unattributed_flows",
    "connect_only_flows",
    "streamed_bodies",
)


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        is not None
    )


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    return any(row[1] == column for row in conn.execute(f"PRAGMA table_info({table})"))


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Bring a store created before `sessions`/`tool_log`/body digests
    existed up to the current schema. Additive and idempotent: only adds
    columns/renames tables that are missing, never rewrites data that's
    already in the new shape."""
    if _table_exists(conn, "session"):
        # Superseded by `sessions`; the singleton row's counters described a
        # cross-run aggregate that this migration is specifically fixing, so
        # there is nothing worth preserving from it.
        conn.execute("DROP TABLE session")

    if not _column_exists(conn, "flows", "session_id"):
        conn.execute("ALTER TABLE flows ADD COLUMN session_id INTEGER REFERENCES sessions(id)")

    for column, decl in (
        ("sha256", "TEXT"),
        ("content_type", "TEXT"),
        ("captured_at", "REAL"),
    ):
        if not _column_exists(conn, "bodies", column):
            conn.execute(f"ALTER TABLE bodies ADD COLUMN {column} {decl}")

    if _table_exists(conn, "access_log"):
        # `tool_log` already exists by this point (CREATE TABLE IF NOT
        # EXISTS ran before this function), so a rename won't fire - copy
        # the rows across instead. access_log's only writer was ever
        # get_body, so every row becomes a get_body entry.
        conn.execute(
            """
            INSERT INTO tool_log (tool, flow_id, part, mode, called_at)
            SELECT 'get_body', flow_id, part, mode, accessed_at FROM access_log
            """
        )
        conn.execute("DROP TABLE access_log")

    conn.commit()

    # Digests and content_type are pure functions of already-stored bytes,
    # so backfilling them for pre-existing bodies is a correctness fix, not
    # fabrication.
    rows = conn.execute(
        "SELECT flow_id, part, content FROM bodies WHERE sha256 IS NULL"
    ).fetchall()
    for flow_id, part, content in rows:
        conn.execute(
            "UPDATE bodies SET sha256 = ?, content_type = ? WHERE flow_id = ? AND part = ?",
            (
                hashlib.sha256(content).hexdigest(),
                _guess_content_type(content),
                flow_id,
                part,
            ),
        )
    if rows:
        conn.commit()


def _guess_content_type(content: bytes) -> str | None:
    """A best-effort hint, not a validated claim - a body truncated at the
    64 KiB cap may look like something else once cut mid-token."""
    if not content:
        return None
    stripped = content.lstrip()
    if stripped[:1] in (b"{", b"["):
        return "application/json"
    if b"\nevent:" in content or b"\ndata:" in content:
        return "text/event-stream"
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    return "text/plain"


class Store:
    """Thin synchronous wrapper around the session SQLite file. Not
    thread-safe; used from the proxy event loop only."""

    # None only for ReadOnlyStore opened against a store with zero rows in
    # `sessions` - a writer always has a current session by construction.
    session_id: int | None

    def __init__(self, path: Path) -> None:
        self.path = path
        self._ensure_permissions()
        self.conn = sqlite3.connect(str(path))
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        os.chmod(path, 0o600)
        _migrate_schema(self.conn)
        self.conn.executescript(INDEX_SCHEMA)
        self._ensure_salt()
        self.session_id = self._start_session()
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

    def _start_session(self) -> int:
        cur = self.conn.execute(
            "INSERT INTO sessions (started_at, body_access) VALUES (?, 'redacted')",
            (time.time(),),
        )
        assert cur.lastrowid is not None
        return cur.lastrowid

    def is_live(self) -> bool:
        """Whether the session this store instance is writing to has been
        closed. A fresh row per run means this can never be confused by a
        previous run's `ended_at`."""
        row = self.conn.execute(
            "SELECT ended_at FROM sessions WHERE id = ?", (self.session_id,)
        ).fetchone()
        return row is not None and row[0] is None

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
                (id, session_id, created_at, app_id, method, host, path, status,
                 request_bytes, response_bytes, tls_profile_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                self.session_id,
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
        digest = hashlib.sha256(content).hexdigest()
        content_type = _guess_content_type(content)
        self.conn.execute(
            """
            INSERT INTO bodies
                (flow_id, part, content, truncated, redacted, sha256, content_type, captured_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(flow_id, part) DO UPDATE SET
                content = excluded.content,
                truncated = excluded.truncated,
                redacted = excluded.redacted,
                sha256 = excluded.sha256,
                content_type = excluded.content_type,
                captured_at = excluded.captured_at
            """,
            (
                flow_id,
                part,
                content,
                int(truncated),
                int(redacted),
                digest,
                content_type,
                time.time(),
            ),
        )
        self.conn.commit()

    def get_body(
        self, flow_id: str, part: str
    ) -> tuple[bytes, bool, bool, str | None, str | None] | None:
        row = self.conn.execute(
            "SELECT content, truncated, redacted, sha256, content_type "
            "FROM bodies WHERE flow_id = ? AND part = ?",
            (flow_id, part),
        ).fetchone()
        if row is None:
            return None
        content, truncated, redacted, sha256, content_type = row
        return content, bool(truncated), bool(redacted), sha256, content_type

    def get_body_window(
        self, flow_id: str, part: str, offset: int, limit: int
    ) -> tuple[bytes, bool, bool, int, str | None, str | None] | None:
        row = self.conn.execute(
            """
            SELECT substr(content, ?, ?), truncated, redacted, length(content),
                   sha256, content_type
            FROM bodies
            WHERE flow_id = ? AND part = ?
            """,
            (offset + 1, limit, flow_id, part),
        ).fetchone()
        if row is None:
            return None
        content, truncated, redacted, content_bytes, sha256, content_type = row
        return (
            bytes(content),
            bool(truncated),
            bool(redacted),
            int(content_bytes),
            sha256,
            content_type,
        )

    def list_body_metadata(
        self, flow_id: str | None = None, limit: int = 100
    ) -> list[tuple[str, str, int, bool, bool, float | None, str | None, str | None]]:
        query = """
            SELECT b.flow_id, b.part, length(b.content), b.truncated, b.redacted,
                   f.created_at, b.sha256, b.content_type
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
            (
                body_flow_id,
                part,
                int(content_bytes),
                bool(truncated),
                bool(redacted),
                created_at,
                sha256,
                content_type,
            )
            for body_flow_id, part, content_bytes, truncated, redacted, created_at, sha256, content_type in self.conn.execute(
                query, params
            )
        ]

    def record_tool_call(
        self,
        *,
        tool: str,
        args: dict | None = None,
        flow_id: str | None = None,
        part: str | None = None,
        mode: str | None = None,
        row_count: int | None = None,
        bytes_returned: int | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO tool_log
                (tool, args_json, flow_id, part, mode, row_count, bytes_returned,
                 session_id, called_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tool,
                json.dumps(args or {}),
                flow_id,
                part,
                mode,
                row_count,
                bytes_returned,
                self.session_id,
                time.time(),
            ),
        )
        self.conn.commit()

    def list_tool_log(
        self, limit: int = 100
    ) -> list[
        tuple[
            str,
            str,
            str | None,
            str | None,
            str | None,
            int | None,
            int | None,
            int | None,
            float,
        ]
    ]:
        return self.conn.execute(
            """
            SELECT tool, args_json, flow_id, part, mode, row_count, bytes_returned,
                   session_id, called_at
            FROM tool_log
            ORDER BY called_at DESC LIMIT ?
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

    def find_identity_joins(
        self, session_id: int | None = None
    ) -> list[tuple[str, str, list[str], list[str]]]:
        """Every identifier value observed under two or more distinct
        eTLD+1s - the cross-site join computation. Returns
        (value_hash, value_prefix, sorted_etld1s, flow_ids). Unscoped by
        default - a cross-site join is often meaningful precisely because it
        spans sessions; pass `session_id` to scope it to one run."""
        query = """
            SELECT i.value_hash, i.value_prefix,
                   GROUP_CONCAT(DISTINCT i.etld1), GROUP_CONCAT(DISTINCT i.flow_id)
            FROM identities i
        """
        params: list[object] = []
        if session_id is not None:
            query += " JOIN flows f ON f.id = i.flow_id WHERE f.session_id = ?"
            params.append(session_id)
        query += " GROUP BY i.value_hash HAVING COUNT(DISTINCT i.etld1) >= 2"
        rows = self.conn.execute(query, params).fetchall()
        return [
            (value_hash, value_prefix, sorted(etlds.split(",")), flow_ids.split(","))
            for value_hash, value_prefix, etlds, flow_ids in rows
        ]

    def increment_counter(self, name: str, by: int = 1) -> None:
        if name not in SESSION_COUNTERS:
            raise ValueError(f"unknown session counter: {name}")
        self.conn.execute(
            f"UPDATE sessions SET {name} = {name} + ? WHERE id = ?",
            (by, self.session_id),
        )
        self.conn.commit()

    def set_websocket_frames_captured(self, value: bool) -> None:
        self.conn.execute(
            "UPDATE sessions SET websocket_frames_captured = ? WHERE id = ?",
            (1 if value else 0, self.session_id),
        )
        self.conn.commit()

    def set_body_access(self, value: str) -> None:
        self.conn.execute(
            "UPDATE sessions SET body_access = ? WHERE id = ?", (value, self.session_id)
        )
        self.conn.commit()

    def get_body_access(self) -> str:
        (value,) = self.conn.execute(
            "SELECT body_access FROM sessions WHERE id = ?", (self.session_id,)
        ).fetchone()
        return value

    def close_session(self) -> None:
        self.conn.execute(
            "UPDATE sessions SET ended_at = ? WHERE id = ?",
            (time.time(), self.session_id),
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
        """Erase all captured traffic data and start a fresh session. The
        tool_log audit trail is deliberately not cleared: it is a record of
        what an agent already read, which remains meaningful evidence even
        after the underlying traffic data is gone."""
        for table in ("bodies", "identities", "findings", "flows", "apps"):
            self.conn.execute(f"DELETE FROM {table}")
        self.conn.execute("DELETE FROM sessions")
        self.session_id = self._start_session()
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
    for everything except its own audit trail. `record_tool_call` uses a
    second, separate connection so the server can log its own tool calls
    without needing (or being able to abuse) write access to flows,
    findings, or identities - every inherited write method is disabled.
    Defaults to the most recently started session; every read scoped to
    "the current session" uses that id, frozen for this process's lifetime.
    """

    def __init__(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"no Firetoll session store at {path}")
        self.path = path
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        self._audit_conn = sqlite3.connect(str(path))
        row = self.conn.execute("SELECT value FROM meta WHERE key = 'salt'").fetchone()
        self._salt = row[0] if row else ""
        self.session_id = self._latest_session_id()

    def _latest_session_id(self) -> int | None:
        row = self.conn.execute("SELECT id FROM sessions ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else None

    def record_tool_call(
        self,
        *,
        tool: str,
        args: dict | None = None,
        flow_id: str | None = None,
        part: str | None = None,
        mode: str | None = None,
        row_count: int | None = None,
        bytes_returned: int | None = None,
    ) -> None:
        self._audit_conn.execute(
            """
            INSERT INTO tool_log
                (tool, args_json, flow_id, part, mode, row_count, bytes_returned,
                 session_id, called_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tool,
                json.dumps(args or {}),
                flow_id,
                part,
                mode,
                row_count,
                bytes_returned,
                self.session_id,
                time.time(),
            ),
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
