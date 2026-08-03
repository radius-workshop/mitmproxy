import json
import sqlite3

from mitmproxy.firetoll import options
from mitmproxy.firetoll import report
from mitmproxy.firetoll import store
from mitmproxy.firetoll.finding import Finding
from mitmproxy.test import taddons


def _context(*addons):
    return taddons.context(options.FiretollOptions(), *addons)


def _populated_store(tmp_path) -> store.Store:
    return _populated_store_at(tmp_path / "session.sqlite")


def _populated_store_at(path) -> store.Store:
    db = store.Store(path)
    app_id = db.record_app(
        process="codex", path="/usr/local/bin/codex", parent=None, source="process"
    )
    db.record_flow(
        flow_id="flow-1",
        app_id=app_id,
        method="POST",
        host="o.statsig.com",
        path="/v1/rgstr",
        status=200,
        request_bytes=10,
        response_bytes=20,
    )
    db.record_finding(
        "flow-1",
        Finding(
            cls="telemetry",
            label="Statsig telemetry",
            confidence="signature",
            evidence=["host=o.statsig.com"],
            facts={"vendor": "Statsig"},
        ),
    )
    db.record_flow(
        flow_id="flow-2",
        app_id=None,
        method="GET",
        host="example.com",
        path="/",
        status=200,
        request_bytes=5,
        response_bytes=5,
    )
    db.increment_counter("unattributed_flows")
    return db


class TestAppLabel:
    def test_user_agent_source_falls_back_to_process(self):
        assert report._app_label("user-agent", "Mozilla/5.0", None) == "Mozilla/5.0"

    def test_user_agent_source_with_no_process_is_unattributed(self):
        assert report._app_label("user-agent", None, None) == "unattributed"

    def test_process_with_parent_is_annotated(self):
        assert (
            report._app_label("process", "codex", "zsh") == "codex (via zsh)"
        )


class TestBuildReport:
    def test_totals(self, tmp_path):
        db = _populated_store(tmp_path)
        try:
            r = report.build_report(db)
            assert r.flow_count == 2
            assert r.app_count == 1
            assert r.finding_count == 1
            assert r.x402_offer_count == 0
            assert r.unattributed_flows == 1
        finally:
            db.close()

    def test_app_rows(self, tmp_path):
        db = _populated_store(tmp_path)
        try:
            r = report.build_report(db)
            labels = {row.label for row in r.apps}
            assert "codex" in labels
            assert "unattributed" in labels
        finally:
            db.close()

    def test_finding_rows(self, tmp_path):
        db = _populated_store(tmp_path)
        try:
            r = report.build_report(db)
            assert len(r.findings) == 1
            assert r.findings[0].cls == "telemetry"
            assert r.findings[0].count == 1
            assert r.findings[0].confidence == "signature"
        finally:
            db.close()

    def test_empty_session_does_not_crash(self, tmp_path):
        db = store.Store(tmp_path / "empty.sqlite")
        try:
            r = report.build_report(db)
            assert r.flow_count == 0
            assert r.findings == []
            assert r.apps == []
        finally:
            db.close()

    def test_identity_join_appears_as_a_finding_row(self, tmp_path):
        db = _populated_store(tmp_path)
        try:
            db.record_flow(
                flow_id="flow-3",
                app_id=None,
                method="GET",
                host="doubleclick.net",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            db.record_identity(
                value="shared-id-value", etld1="example.com", flow_id="flow-2"
            )
            db.record_identity(
                value="shared-id-value", etld1="doubleclick.net", flow_id="flow-3"
            )

            r = report.build_report(db)
            join_rows = [f for f in r.findings if f.cls == "identity_join"]
            assert len(join_rows) == 1
            assert join_rows[0].count == 1
            assert "doubleclick.net" in join_rows[0].example_label
            assert "example.com" in join_rows[0].example_label
            # totals include the identity join in the overall finding count
            assert r.finding_count == 2
        finally:
            db.close()


class TestRenderers:
    def test_render_text_contains_key_sections(self, tmp_path):
        db = _populated_store(tmp_path)
        try:
            r = report.build_report(db)
            text = report.render_text(r)
            assert "FIRETOLL — session report" in text
            assert "BY APPLICATION" in text
            assert "FINDINGS" in text
            assert "EVIDENCE BOUNDARY" in text
            assert "codex" in text
            assert "telemetry" in text
        finally:
            db.close()

    def test_render_markdown_contains_tables(self, tmp_path):
        db = _populated_store(tmp_path)
        try:
            r = report.build_report(db)
            md = report.render_markdown(r)
            assert "## By application" in md
            assert "## Findings" in md
            assert "## Evidence boundary" in md
        finally:
            db.close()

    def test_report_to_dict_is_json_serializable(self, tmp_path):
        db = _populated_store(tmp_path)
        try:
            r = report.build_report(db)
            json.dumps(r.to_dict())
        finally:
            db.close()

    def test_render_text_with_no_findings_shows_none(self, tmp_path):
        db = store.Store(tmp_path / "empty.sqlite")
        try:
            r = report.build_report(db)
            text = report.render_text(r)
            assert "  (none)" in text
        finally:
            db.close()

    def test_render_text_shows_websocket_capture_on(self, tmp_path):
        db = _populated_store(tmp_path)
        try:
            db.set_websocket_frames_captured(True)
            r = report.build_report(db)
            text = report.render_text(r)
            assert "WebSocket frame capture: on" in text
        finally:
            db.close()


class TestFiretollReportAddon:
    def test_command_writes_json_and_markdown(self, tmp_path):
        db = _populated_store(tmp_path)
        store_addon = store.FiretollStore()
        store_addon.db = db
        addon = report.FiretollReport(store_addon)
        with _context(addon):
            out = tmp_path / "out"
            addon.report(str(out))
            assert (tmp_path / "out.json").exists()
            assert (tmp_path / "out.md").exists()
            data = json.loads((tmp_path / "out.json").read_text())
            assert data["flow_count"] == 2
        db.close()

    def test_command_without_path_does_not_write_files(self, tmp_path, capsys):
        db = _populated_store(tmp_path)
        store_addon = store.FiretollStore()
        store_addon.db = db
        addon = report.FiretollReport(store_addon)
        with _context(addon):
            addon.report()
            assert not (tmp_path / ".json").exists()
        db.close()

    def test_command_with_no_store_warns_and_does_not_raise(self):
        addon = report.FiretollReport(None)
        with _context(addon):
            addon.report()  # must not raise

    def test_command_strips_existing_json_suffix_from_path(self, tmp_path):
        db = _populated_store(tmp_path)
        store_addon = store.FiretollStore()
        store_addon.db = db
        addon = report.FiretollReport(store_addon)
        with _context(addon):
            out = tmp_path / "out.json"
            addon.report(str(out))
            assert (tmp_path / "out.json").exists()
            assert (tmp_path / "out.md").exists()
        db.close()

    def test_done_hook_respects_firetoll_report_option(self, tmp_path):
        db = _populated_store(tmp_path)
        store_addon = store.FiretollStore()
        store_addon.db = db
        addon = report.FiretollReport(store_addon)
        with _context(addon) as tctx:
            tctx.options.firetoll_report = False
            addon.done()  # must not raise, and should be a no-op
        db.close()

    def test_done_hook_with_no_store_is_a_noop(self):
        addon = report.FiretollReport(None)
        with _context(addon) as tctx:
            tctx.options.firetoll = True
            tctx.options.firetoll_report = True
            addon.done()  # must not raise

    def test_done_hook_writes_exports_when_enabled(self, tmp_path):
        db = _populated_store(tmp_path)
        store_addon = store.FiretollStore()
        store_addon.db = db
        addon = report.FiretollReport(store_addon)
        with _context(addon) as tctx:
            tctx.options.firetoll = True
            tctx.options.firetoll_report = True
            out = tmp_path / "done-out"
            tctx.options.firetoll_report_path = str(out)
            addon.done()
            assert (tmp_path / "done-out.json").exists()
            assert (tmp_path / "done-out.md").exists()
        db.close()


class TestSessionScoping:
    def test_report_is_scoped_to_the_current_session_only(self, tmp_path):
        db_path = tmp_path / "session.sqlite"
        first = store.Store(db_path)
        first.record_flow(
            flow_id="old-flow",
            app_id=None,
            method="GET",
            host="h",
            path="/",
            status=200,
            request_bytes=None,
            response_bytes=None,
        )
        first.close_session()
        first.close()

        second = _populated_store_at(db_path)
        try:
            r = report.build_report(second)
            # The previous run's flow must not be counted as part of this
            # session's totals.
            assert r.flow_count == 2
            assert r.session_id == second.session_id
        finally:
            second.close()

    def test_is_live_reflects_the_current_session_only(self, tmp_path):
        db_path = tmp_path / "session.sqlite"
        first = store.Store(db_path)
        first.close_session()
        first.close()

        second = store.Store(db_path)
        try:
            r = report.build_report(second)
            assert r.is_live is True
        finally:
            second.close()

    def test_sessions_list_reports_every_session(self, tmp_path):
        db_path = tmp_path / "session.sqlite"
        first = store.Store(db_path)
        first.close_session()
        first.close()

        second = store.Store(db_path)
        try:
            r = report.build_report(second)
            assert {s.id for s in r.sessions} == {first.session_id, second.session_id}
            live_by_id = {s.id: s.is_live for s in r.sessions}
            assert live_by_id[first.session_id] is False
            assert live_by_id[second.session_id] is True
        finally:
            second.close()

    def test_render_text_shows_live_status(self, tmp_path):
        db = _populated_store(tmp_path)
        try:
            r = report.build_report(db)
            text = report.render_text(r)
            assert "[LIVE]" in text
        finally:
            db.close()

    def test_render_markdown_shows_status(self, tmp_path):
        db = _populated_store(tmp_path)
        try:
            r = report.build_report(db)
            md = report.render_markdown(r)
            assert "Status: live" in md
        finally:
            db.close()


class TestNoSessionRow:
    def test_build_report_does_not_crash_with_no_session_row(self, tmp_path):
        path = tmp_path / "session.sqlite"
        store.Store(path).close()
        conn = sqlite3.connect(str(path))
        conn.execute("DELETE FROM sessions")
        conn.commit()
        conn.close()

        reader = store.ReadOnlyStore(path)
        try:
            assert reader.session_id is None
            r = report.build_report(reader)
            assert r.flow_count == 0
            assert r.is_live is False
            assert r.body_access == "redacted"
        finally:
            reader.close()
