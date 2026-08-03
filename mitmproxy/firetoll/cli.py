"""Layer 3c: the Firetoll CLI.

A local, read-only command over the session store - the same data the MCP
server exposes to an agent, reachable directly by the human who owns the
traffic. `firetoll audit` in particular must never depend on the MCP
server running: auditing an agent by asking the agent is not an audit, so
this reads `tool_log` straight from the store file.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mitmproxy.firetoll import store
from mitmproxy.firetoll.report import _app_label


def _open(store_path: str) -> store.ReadOnlyStore:
    return store.ReadOnlyStore(Path(store_path))


def _print_rows(rows: list[dict], as_json: bool) -> None:
    if as_json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print("(none)")
        return
    columns = list(rows[0].keys())
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in columns}
    print("  ".join(c.ljust(widths[c]) for c in columns))
    for row in rows:
        print("  ".join(str(row.get(c, "")).ljust(widths[c]) for c in columns))


def cmd_sessions(args: argparse.Namespace) -> None:
    db = _open(args.store_path)
    try:
        rows = [
            {
                "id": session_id,
                "started_at": started_at,
                "ended_at": ended_at if ended_at is not None else "",
                "is_live": ended_at is None,
                "flow_count": flow_count,
            }
            for session_id, started_at, ended_at, flow_count in db.conn.execute(
                """
                SELECT s.id, s.started_at, s.ended_at, COUNT(f.id)
                FROM sessions s LEFT JOIN flows f ON f.session_id = s.id
                GROUP BY s.id
                ORDER BY s.id DESC
                """
            )
        ]
        _print_rows(rows, args.json)
    finally:
        db.close()


def cmd_audit(args: argparse.Namespace) -> None:
    db = _open(args.store_path)
    try:
        rows = [
            {
                "tool": tool,
                "args": json.loads(args_json) if args_json else {},
                "flow_id": flow_id or "",
                "part": part or "",
                "mode": mode or "",
                "row_count": row_count if row_count is not None else "",
                "bytes_returned": bytes_returned if bytes_returned is not None else "",
                "session_id": session_id if session_id is not None else "",
                "called_at": called_at,
            }
            for tool, args_json, flow_id, part, mode, row_count, bytes_returned, session_id, called_at in db.list_tool_log(
                args.limit
            )
        ]
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            _print_rows(
                [{**row, "args": json.dumps(row["args"])} for row in rows],
                as_json=False,
            )
    finally:
        db.close()


def cmd_flows(args: argparse.Namespace) -> None:
    db = _open(args.store_path)
    try:
        query = (
            "SELECT f.id, f.created_at, f.method, f.host, f.path, f.status, "
            "a.process, a.parent, a.source FROM flows f LEFT JOIN apps a ON f.app_id = a.id"
        )
        conditions = []
        params: list = []
        if args.host:
            conditions.append("f.host = ?")
            params.append(args.host)
        if args.status is not None:
            conditions.append("f.status = ?")
            params.append(args.status)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY f.created_at DESC LIMIT ?"
        params.append(args.limit)

        rows = [
            {
                "flow_id": flow_id,
                "created_at": created_at,
                "method": method,
                "host": host,
                "path": path,
                "status": status,
                "app": _app_label(source, process, parent),
            }
            for flow_id, created_at, method, host, path, status, process, parent, source in db.conn.execute(
                query, params
            )
        ]
        _print_rows(rows, args.json)
    finally:
        db.close()


def cmd_bodies(args: argparse.Namespace) -> None:
    db = _open(args.store_path)
    try:
        rows = [
            {
                "flow_id": flow_id,
                "part": part,
                "content_bytes": content_bytes,
                "truncated": truncated,
                "redacted": redacted,
                "created_at": created_at if created_at is not None else "",
                "sha256": sha256 or "",
                "content_type": content_type or "",
            }
            for flow_id, part, content_bytes, truncated, redacted, created_at, sha256, content_type in db.list_body_metadata(
                args.flow_id, args.limit
            )
        ]
        _print_rows(rows, args.json)
    finally:
        db.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firetoll", description="Inspect a Firetoll session store directly."
    )
    parser.add_argument(
        "--store-path",
        default=str(store.DEFAULT_STORE_PATH),
        help="Path to the Firetoll session store (default: %(default)s)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_sessions = subparsers.add_parser(
        "sessions", help="List every recorded session and whether it is still live."
    )
    p_sessions.add_argument("--json", action="store_true")
    p_sessions.set_defaults(func=cmd_sessions)

    p_audit = subparsers.add_parser(
        "audit",
        help="Print every MCP tool call made against this store - works without "
        "firetoll-mcp running.",
    )
    p_audit.add_argument("--limit", type=int, default=100)
    p_audit.add_argument("--json", action="store_true")
    p_audit.set_defaults(func=cmd_audit)

    p_flows = subparsers.add_parser("flows", help="List flow metadata.")
    p_flows.add_argument("--host")
    p_flows.add_argument("--status", type=int)
    p_flows.add_argument("--limit", type=int, default=100)
    p_flows.add_argument("--json", action="store_true")
    p_flows.set_defaults(func=cmd_flows)

    p_bodies = subparsers.add_parser("bodies", help="List stored body metadata.")
    p_bodies.add_argument("--flow-id")
    p_bodies.add_argument("--limit", type=int, default=100)
    p_bodies.add_argument("--json", action="store_true")
    p_bodies.set_defaults(func=cmd_bodies)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
