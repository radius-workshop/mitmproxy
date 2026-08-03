"""Layer 3b: the Firetoll MCP server.

A separate process (console script `firetoll-mcp`), stdio transport, that
opens the session store read-only (see `store.ReadOnlyStore`) and answers
an agent's questions about a Firetoll session - live or finished.

It must never sit in the data path: it does not run inside the proxy, it
cannot widen its own body access (`firetoll_body_access` is read from the
store, set only by the human running mitmproxy - see `enrich.py`), and
every `get_body` call is written to `access_log` so the human can audit
what the agent actually read.

Install:
    claude mcp add firetoll -- firetoll-mcp
"""

import argparse
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from mitmproxy.firetoll import redact
from mitmproxy.firetoll import store
from mitmproxy.firetoll.report import _app_label
from mitmproxy.firetoll.report import build_report

mcp = FastMCP("firetoll")

DEFAULT_BODY_READ_BYTES = 4 * 1024
MAX_BODY_READ_BYTES = 64 * 1024

_db: store.ReadOnlyStore | None = None


def _require_db() -> store.ReadOnlyStore:
    if _db is None:
        raise RuntimeError(
            "Firetoll store not open - the server must be started via main()"
        )
    return _db


@mcp.tool()
def session_overview() -> dict:
    """Session window, totals, per-class finding counts, and the
    non-observability counters - what this session cannot show."""
    return build_report(_require_db()).to_dict()


@mcp.tool()
def list_apps() -> list[dict]:
    """Attributed processes seen this session, with flow counts and
    destination hosts."""
    return [
        {"label": row.label, "flow_count": row.flow_count, "hosts": row.hosts}
        for row in build_report(_require_db()).apps
    ]


@mcp.tool()
def query_flows(
    app: str | None = None,
    host: str | None = None,
    cls: str | None = None,
    status: int | None = None,
    since: float | None = None,
    limit: int = 100,
) -> list[dict]:
    """Flow metadata rows - method, host, path, status, attributed app -
    never bodies. Filter by attributed app label, host, a finding class
    that was detected on the flow, response status, or a minimum
    created_at timestamp."""
    db = _require_db()
    query = (
        "SELECT DISTINCT f.id, f.created_at, f.method, f.host, f.path, f.status, "
        "a.process, a.parent, a.source FROM flows f LEFT JOIN apps a ON f.app_id = a.id"
    )
    conditions = []
    params: list = []
    if cls:
        query += " JOIN findings fi ON fi.flow_id = f.id"
        conditions.append("fi.cls = ?")
        params.append(cls)
    if host:
        conditions.append("f.host = ?")
        params.append(host)
    if status is not None:
        conditions.append("f.status = ?")
        params.append(status)
    if since is not None:
        conditions.append("f.created_at >= ?")
        params.append(since)
    if app:
        conditions.append("a.process = ?")
        params.append(app)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY f.created_at DESC LIMIT ?"
    params.append(limit)

    rows = db.conn.execute(query, params).fetchall()
    return [
        {
            "flow_id": flow_id,
            "created_at": created_at,
            "method": method,
            "host": host_value,
            "path": path,
            "status": status_value,
            "app": _app_label(source, process, parent),
        }
        for flow_id, created_at, method, host_value, path, status_value, process, parent, source in rows
    ]


@mcp.tool()
def get_findings(
    cls: str | None = None,
    host: str | None = None,
    app: str | None = None,
    min_confidence: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """Findings with their evidence lines - the exact header/path/body key
    that fired, never empty. `min_confidence="signature"` excludes
    heuristic-confidence findings."""
    db = _require_db()
    query = (
        "SELECT fi.cls, fi.label, fi.confidence, fi.evidence, fi.facts, fl.host, fl.path "
        "FROM findings fi JOIN flows fl ON fl.id = fi.flow_id "
        "LEFT JOIN apps a ON fl.app_id = a.id"
    )
    conditions = []
    params: list = []
    if cls:
        conditions.append("fi.cls = ?")
        params.append(cls)
    if host:
        conditions.append("fl.host = ?")
        params.append(host)
    if app:
        conditions.append("a.process = ?")
        params.append(app)
    if min_confidence == "signature":
        conditions.append("fi.confidence = 'signature'")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY fi.created_at DESC LIMIT ?"
    params.append(limit)

    rows = db.conn.execute(query, params).fetchall()
    return [
        {
            "cls": cls_value,
            "label": label,
            "confidence": confidence,
            "evidence": json.loads(evidence),
            "facts": json.loads(facts),
            "host": host_value,
            "path": path,
        }
        for cls_value, label, confidence, evidence, facts, host_value, path in rows
    ]


@mcp.tool()
def explain_identity_joins() -> list[dict]:
    """Identifier values seen under two or more distinct eTLD+1s, with the
    flow ids that carried them - a cross-site join computed from this
    session's own traffic, not a blocklist."""
    return [
        {"value_prefix": value_prefix, "etld1s": etlds, "flow_ids": flow_ids}
        for _value_hash, value_prefix, etlds, flow_ids in _require_db().find_identity_joins()
    ]


@mcp.tool()
def agent_activity() -> dict:
    """Rollup of AI-agent egress: providers/models seen, MCP method calls,
    WebSocket upgrade handshakes, and byte counts - never prompt or
    completion text."""
    db = _require_db()
    rows = db.conn.execute(
        "SELECT label, facts FROM findings WHERE cls = 'agent_egress'"
    ).fetchall()

    providers: dict[str, int] = {}
    models: set[str] = set()
    mcp_calls: dict[str, int] = {}
    websocket_upgrades = 0
    total_request_bytes = 0
    total_response_bytes = 0

    for label, facts_json in rows:
        facts = json.loads(facts_json)
        if label == "WebSocket upgrade":
            websocket_upgrades += 1
            continue
        if provider := facts.get("provider"):
            providers[provider] = providers.get(provider, 0) + 1
        if model := facts.get("model"):
            models.add(model)
        if method := facts.get("method"):
            mcp_calls[method] = mcp_calls.get(method, 0) + 1
        total_request_bytes += facts.get("request", {}).get("bytes", 0)
        total_response_bytes += facts.get("response", {}).get("bytes", 0)

    return {
        "providers": providers,
        "models": sorted(models),
        "mcp_calls": mcp_calls,
        "websocket_upgrades": websocket_upgrades,
        "total_request_bytes": total_request_bytes,
        "total_response_bytes": total_response_bytes,
    }


@mcp.tool()
def x402_offers() -> list[dict]:
    """Decoded x402 payment offers: amount, asset, network, resource,
    scheme, and a dry-run quote - never signed, no wallet involved."""
    rows = (
        _require_db()
        .conn.execute("SELECT facts FROM findings WHERE cls = 'x402'")
        .fetchall()
    )
    return [json.loads(facts) for (facts,) in rows]


@mcp.tool()
def redaction_report() -> dict:
    """What gets redacted, and by which rule, so the model knows its own
    blind spots."""
    db = _require_db()
    (bodies_stored,) = db.conn.execute("SELECT COUNT(*) FROM bodies").fetchone()
    (bodies_redacted,) = db.conn.execute(
        "SELECT COUNT(*) FROM bodies WHERE redacted = 1"
    ).fetchone()
    return {
        "body_access": db.get_body_access(),
        "bodies_stored": bodies_stored,
        "bodies_redacted": bodies_redacted,
        "rules": [{"name": r.name, "description": r.description} for r in redact.RULES],
    }


@mcp.tool()
def list_bodies(flow_id: str | None = None, limit: int = 100) -> list[dict]:
    """List stored body metadata without returning body content."""
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    return [
        {
            "flow_id": body_flow_id,
            "part": part,
            "content_bytes": content_bytes,
            "truncated": truncated,
            "redacted": redacted,
            "created_at": created_at,
        }
        for body_flow_id, part, content_bytes, truncated, redacted, created_at in _require_db().list_body_metadata(
            flow_id, limit
        )
    ]


def _body_access_error(access: str) -> dict | None:
    if access == "none":
        return {
            "error": (
                "Body access is disabled (firetoll_body_access=none). "
                "The human running mitmproxy can enable it with "
                "--set firetoll_body_access=redacted (or =full)."
            )
        }
    return None


def _validate_body_window(offset: int, limit: int) -> None:
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if limit < 1 or limit > MAX_BODY_READ_BYTES:
        raise ValueError(f"limit must be between 1 and {MAX_BODY_READ_BYTES}")


@mcp.tool()
def get_body(flow_id: str, part: str, offset: int = 0, limit: int = DEFAULT_BODY_READ_BYTES) -> dict:
    """The stored body for a flow's request or response. Gated by
    firetoll_body_access: refuses when access is "none". Reads are bounded
    by default; every call is written to access_log."""
    _validate_body_window(offset, limit)
    db = _require_db()
    access = db.get_body_access()
    db.record_access(flow_id=flow_id, part=part, mode=access)

    if error := _body_access_error(access):
        return error

    stored = db.get_body_window(flow_id, part, offset, limit)
    if stored is None:
        return {
            "error": (
                "No body stored for this flow/part - firetoll_store_bodies may "
                "be off, or the body was streamed and never captured."
            )
        }

    content, truncated, redacted, content_bytes = stored
    result = {
        "flow_id": flow_id,
        "part": part,
        "offset": offset,
        "bytes_returned": len(content),
        "content_bytes": content_bytes,
        "truncated": truncated,
        "redacted": redacted,
        "content": content.decode(errors="replace"),
    }
    if offset + len(content) < content_bytes:
        result["has_more"] = True
    if access == "full":
        result["warning"] = (
            "firetoll_body_access=full: this body is being sent to a cloud "
            "model. This access has been logged."
        )
    return result


@mcp.tool()
def get_body_range(flow_id: str, part: str, offset: int, limit: int) -> dict:
    """Read an explicit bounded byte range from a stored body."""
    return get_body(flow_id=flow_id, part=part, offset=offset, limit=limit)


@mcp.tool()
def access_log(limit: int = 100) -> list[dict]:
    """Every get_body call made this session, so the human can audit the
    agent."""
    return [
        {"flow_id": flow_id, "part": part, "mode": mode, "accessed_at": accessed_at}
        for flow_id, part, mode, accessed_at in _require_db().list_access_log(limit)
    ]


def main(argv: list[str] | None = None) -> None:
    global _db
    parser = argparse.ArgumentParser(description="Firetoll MCP server")
    parser.add_argument(
        "--store-path",
        default=str(store.DEFAULT_STORE_PATH),
        help="Path to the Firetoll session store (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    _db = store.ReadOnlyStore(Path(args.store_path))
    try:
        mcp.run()
    finally:
        _db.close()


if __name__ == "__main__":
    main()
