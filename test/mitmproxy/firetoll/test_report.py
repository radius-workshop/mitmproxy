import json

from mitmproxy.firetoll import options
from mitmproxy.firetoll import report
from mitmproxy.firetoll import store
from mitmproxy.firetoll.finding import Finding
from mitmproxy.test import taddons


def _context(*addons):
    return taddons.context(options.FiretollOptions(), *addons)


def _populated_store(tmp_path) -> store.Store:
    db = store.Store(tmp_path / "session.sqlite")
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

    def test_done_hook_respects_firetoll_report_option(self, tmp_path):
        db = _populated_store(tmp_path)
        store_addon = store.FiretollStore()
        store_addon.db = db
        addon = report.FiretollReport(store_addon)
        with _context(addon) as tctx:
            tctx.options.firetoll_report = False
            addon.done()  # must not raise, and should be a no-op
        db.close()
