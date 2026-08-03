"""Layer 3a: the CLI report.

Shaped like the deck it's reproducing: counted totals, then breakdowns, then
the evidence boundary. `firetoll.report` works standalone against a saved
session (`mitmdump -nr session.mitm`) as well as on `done` at the end of a
live run.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import types
from mitmproxy.firetoll.store import FiretollStore
from mitmproxy.firetoll.store import Store
from mitmproxy.log import ALERT

logger = logging.getLogger(__name__)


@dataclass
class AppRow:
    label: str
    flow_count: int
    hosts: list[str]


@dataclass
class FindingRow:
    cls: str
    count: int
    example_host: str | None
    example_label: str
    confidence: str  # "signature" | "heuristic" | "mixed"


@dataclass
class Report:
    started_at: float
    ended_at: float | None
    flow_count: int
    app_count: int
    finding_count: int
    x402_offer_count: int
    apps: list[AppRow] = field(default_factory=list)
    findings: list[FindingRow] = field(default_factory=list)
    unattributed_flows: int = 0
    connect_only_flows: int = 0
    streamed_bodies: int = 0
    bodies_truncated: int = 0
    websocket_frames_captured: bool = False
    body_access: str = "redacted"
    bodies_stored: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _app_label(source: str | None, process: str | None, parent: str | None) -> str:
    if source is None or source == "unknown":
        return "unattributed"
    if source == "user-agent":
        return process or "unattributed"
    if parent:
        return f"{process} (via {parent})"
    return process or "unattributed"


def build_report(db: Store) -> Report:
    conn = db.conn

    (
        started_at,
        ended_at,
        unattributed,
        connect_only,
        streamed,
        truncated,
        ws_captured,
        body_access,
    ) = conn.execute(
        """
            SELECT started_at, ended_at, unattributed_flows, connect_only_flows,
                   streamed_bodies, bodies_truncated, websocket_frames_captured, body_access
            FROM session WHERE id = 1
            """
    ).fetchone()

    (flow_count,) = conn.execute("SELECT COUNT(*) FROM flows").fetchone()
    (app_count,) = conn.execute(
        "SELECT COUNT(DISTINCT app_id) FROM flows WHERE app_id IS NOT NULL"
    ).fetchone()
    (finding_count,) = conn.execute("SELECT COUNT(*) FROM findings").fetchone()
    (x402_count,) = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE cls = 'x402'"
    ).fetchone()
    (bodies_stored,) = conn.execute("SELECT COUNT(*) FROM bodies").fetchone()

    apps = []
    for source, process, parent, count, hosts in conn.execute(
        """
        SELECT a.source, a.process, a.parent, COUNT(*), GROUP_CONCAT(DISTINCT f.host)
        FROM flows f
        LEFT JOIN apps a ON f.app_id = a.id
        GROUP BY f.app_id
        ORDER BY COUNT(*) DESC
        """
    ):
        apps.append(
            AppRow(
                label=_app_label(source, process, parent),
                flow_count=count,
                hosts=sorted((hosts or "").split(",")) if hosts else [],
            )
        )

    findings = []
    for cls, count, example_host, example_label, confidences in conn.execute(
        """
        SELECT
            fi.cls,
            COUNT(*),
            (SELECT fl.host FROM flows fl WHERE fl.id = fi.flow_id),
            (SELECT fi2.label FROM findings fi2 WHERE fi2.cls = fi.cls LIMIT 1),
            GROUP_CONCAT(DISTINCT fi.confidence)
        FROM findings fi
        GROUP BY fi.cls
        ORDER BY COUNT(*) DESC
        """
    ):
        confidence_set = set((confidences or "").split(","))
        confidence = confidence_set.pop() if len(confidence_set) == 1 else "mixed"
        findings.append(
            FindingRow(
                cls=cls,
                count=count,
                example_host=example_host,
                example_label=example_label,
                confidence=confidence,
            )
        )

    identity_joins = db.find_identity_joins()
    if identity_joins:
        _value_hash, value_prefix, etlds, _flow_ids = identity_joins[0]
        findings.append(
            FindingRow(
                cls="identity_join",
                count=len(identity_joins),
                example_host=etlds[0] if etlds else None,
                example_label=(
                    f"value {value_prefix}… seen under {len(etlds)} eTLD+1s: "
                    f"{', '.join(etlds)}"
                ),
                confidence="signature",
            )
        )
        finding_count += len(identity_joins)
    findings.sort(key=lambda row: row.count, reverse=True)

    return Report(
        started_at=started_at,
        ended_at=ended_at,
        flow_count=flow_count,
        app_count=app_count,
        finding_count=finding_count,
        x402_offer_count=x402_count,
        apps=apps,
        findings=findings,
        unattributed_flows=unattributed,
        connect_only_flows=connect_only,
        streamed_bodies=streamed,
        bodies_truncated=truncated,
        websocket_frames_captured=bool(ws_captured),
        body_access=body_access,
        bodies_stored=bool(bodies_stored),
    )


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S UTC")


def _duration(started_at: float, ended_at: float | None) -> str:
    end = ended_at if ended_at is not None else time.time()
    seconds = int(end - started_at)
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes}m {seconds}s"


def render_text(report: Report) -> str:
    lines = []
    window = f"{_fmt_time(report.started_at)} → {_fmt_time(report.ended_at or time.time())} ({_duration(report.started_at, report.ended_at)})"
    lines.append(f"FIRETOLL — session report            {window}")
    lines.append("")
    lines.append(
        f"  {report.flow_count} flows"
        f"        {report.app_count} apps"
        f"        {report.finding_count} findings"
        f"        {report.x402_offer_count} x402 offers"
    )
    lines.append("")

    if report.apps:
        lines.append("BY APPLICATION")
        for app in report.apps:
            hosts = ", ".join(app.hosts) if app.hosts else "—"
            lines.append(f"  {app.label:<16} {app.flow_count:<4} {hosts}")
        lines.append("")

    lines.append("FINDINGS")
    if report.findings:
        for finding in report.findings:
            host = finding.example_host or "—"
            lines.append(
                f"  {finding.cls:<14} {finding.count:<3} {host:<16} "
                f"{finding.example_label}    {finding.confidence}"
            )
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("EVIDENCE BOUNDARY — what this report cannot show")
    lines.append(
        f"  {report.unattributed_flows} flows unattributed "
        "(process lookup failed; User-Agent only)"
    )
    lines.append(
        f"  {report.connect_only_flows} flows were CONNECT-only (not decrypted) — unexamined, not clean"
    )
    lines.append(f"  {report.streamed_bodies} response bodies streamed — not inspected")
    if report.websocket_frames_captured:
        lines.append("  WebSocket frame capture: on")
    else:
        lines.append(
            "  WebSocket frame capture: off (default) — handshakes seen, stream not"
        )
    lines.append(
        f"  bodies: {'stored (redacted)' if report.bodies_stored else 'not stored'} "
        f"(firetoll_body_access={report.body_access})"
    )
    return "\n".join(lines)


def render_markdown(report: Report) -> str:
    lines = [
        "# Firetoll session report",
        "",
        f"- Window: {_fmt_time(report.started_at)} → "
        f"{_fmt_time(report.ended_at or time.time())} "
        f"({_duration(report.started_at, report.ended_at)})",
        f"- {report.flow_count} flows, {report.app_count} apps, "
        f"{report.finding_count} findings, {report.x402_offer_count} x402 offers",
        "",
        "## By application",
        "",
        "| App | Flows | Hosts |",
        "|---|---|---|",
    ]
    for app in report.apps:
        lines.append(f"| {app.label} | {app.flow_count} | {', '.join(app.hosts)} |")

    lines += [
        "",
        "## Findings",
        "",
        "| Class | Count | Example host | Label | Confidence |",
        "|---|---|---|---|---|",
    ]
    for finding in report.findings:
        lines.append(
            f"| {finding.cls} | {finding.count} | {finding.example_host or ''} "
            f"| {finding.example_label} | {finding.confidence} |"
        )

    lines += [
        "",
        "## Evidence boundary",
        "",
        f"- {report.unattributed_flows} flows unattributed (process lookup failed; User-Agent only)",
        f"- {report.connect_only_flows} flows were CONNECT-only (not decrypted) - unexamined, not clean",
        f"- {report.streamed_bodies} response bodies streamed - not inspected",
        f"- WebSocket frame capture: {'on' if report.websocket_frames_captured else 'off (default)'}",
        f"- bodies: {'stored (redacted)' if report.bodies_stored else 'not stored'} "
        f"(firetoll_body_access={report.body_access})",
    ]
    return "\n".join(lines)


class FiretollReport:
    def __init__(self, store_addon: FiretollStore | None = None) -> None:
        self.store_addon = store_addon

    @command.command("firetoll.report")
    def report(self, path: types.Path = types.Path("")) -> None:
        """Render the Firetoll session report to the terminal, or to `path`
        as JSON and Markdown if given."""
        if self.store_addon is None or self.store_addon.db is None:
            logger.warning("firetoll.report: no open session store")
            return
        report = build_report(self.store_addon.db)
        if path:
            _write_exports(report, path)
        else:
            logging.log(ALERT, "\n" + render_text(report))

    def done(self) -> None:
        if not (ctx.options.firetoll and ctx.options.firetoll_report):
            return
        if self.store_addon is None or self.store_addon.db is None:
            return
        report = build_report(self.store_addon.db)
        logging.log(ALERT, "\n" + render_text(report))
        if ctx.options.firetoll_report_path:
            _write_exports(report, ctx.options.firetoll_report_path)


def _write_exports(report: Report, path: str) -> None:
    base = path
    for suffix in (".json", ".md"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    with open(f"{base}.json", "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)
    with open(f"{base}.md", "w", encoding="utf-8") as f:
        f.write(render_markdown(report))
    logging.log(ALERT, f"firetoll: report written to {base}.json and {base}.md")
