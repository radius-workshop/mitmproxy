import pytest

from mitmproxy.firetoll import store
from mitmproxy.firetoll.finding import Finding
from mitmproxy.firetoll.mcp import server


@pytest.fixture
def populated_db(tmp_path):
    path = tmp_path / "session.sqlite"
    writer = store.Store(path)
    app_id = writer.record_app(
        process="codex", path="/usr/local/bin/codex", parent=None, source="process"
    )
    writer.record_flow(
        flow_id="flow-1",
        app_id=app_id,
        method="POST",
        host="api.anthropic.com",
        path="/v1/messages",
        status=200,
        request_bytes=100,
        response_bytes=200,
    )
    writer.record_finding(
        "flow-1",
        Finding(
            cls="agent_egress",
            label="Anthropic inference call",
            confidence="signature",
            evidence=["host=api.anthropic.com"],
            facts={
                "provider": "Anthropic",
                "model": "claude-sonnet-5",
                "request": {"bytes": 100},
                "response": {"bytes": 200},
            },
        ),
    )
    writer.record_finding(
        "flow-1",
        Finding(
            cls="agent_egress",
            label="WebSocket upgrade",
            confidence="signature",
            evidence=["status=101"],
            facts={"negotiated_extensions": "permessage-deflate"},
        ),
    )
    writer.record_finding(
        "flow-1",
        Finding(
            cls="x402",
            label="x402 payment offer",
            confidence="signature",
            evidence=["status=402"],
            facts={"amount": "10000", "asset": "0xabc", "network": "base-sepolia"},
        ),
    )
    writer.record_identity(value="shared-id", etld1="a.com", flow_id="flow-1")
    writer.record_flow(
        flow_id="flow-2",
        app_id=None,
        method="GET",
        host="b.com",
        path="/",
        status=200,
        request_bytes=None,
        response_bytes=None,
    )
    writer.record_identity(value="shared-id", etld1="b.com", flow_id="flow-2")
    writer.record_body(
        flow_id="flow-1",
        part="response",
        content=b"redacted stuff",
        truncated=False,
        redacted=True,
    )
    writer.close()

    reader = store.ReadOnlyStore(path)
    server._db = reader
    yield reader
    reader.close()
    server._db = None


class TestRequireDb:
    def test_raises_when_not_open(self):
        server._db = None
        with pytest.raises(RuntimeError):
            server._require_db()


class TestSessionOverview:
    def test_returns_report_dict(self, populated_db):
        overview = server.session_overview()
        assert overview["flow_count"] == 2
        assert overview["app_count"] == 1


class TestListApps:
    def test_returns_app_rows(self, populated_db):
        apps = server.list_apps()
        labels = {a["label"] for a in apps}
        assert "codex" in labels
        assert "unattributed" in labels


class TestQueryFlows:
    def test_no_filters_returns_all(self, populated_db):
        flows = server.query_flows()
        assert len(flows) == 2

    def test_filter_by_host(self, populated_db):
        flows = server.query_flows(host="api.anthropic.com")
        assert len(flows) == 1
        assert flows[0]["flow_id"] == "flow-1"

    def test_filter_by_cls(self, populated_db):
        flows = server.query_flows(cls="x402")
        assert [f["flow_id"] for f in flows] == ["flow-1"]

    def test_filter_by_app(self, populated_db):
        flows = server.query_flows(app="codex")
        assert [f["flow_id"] for f in flows] == ["flow-1"]

    def test_filter_by_status(self, populated_db):
        flows = server.query_flows(status=200)
        assert len(flows) == 2

    def test_limit_respected(self, populated_db):
        flows = server.query_flows(limit=1)
        assert len(flows) == 1

    def test_app_label_present(self, populated_db):
        flows = server.query_flows(host="api.anthropic.com")
        assert flows[0]["app"] == "codex"


class TestGetFindings:
    def test_no_filters_returns_all(self, populated_db):
        findings = server.get_findings()
        assert len(findings) == 3

    def test_filter_by_cls(self, populated_db):
        findings = server.get_findings(cls="x402")
        assert len(findings) == 1
        assert findings[0]["facts"]["amount"] == "10000"

    def test_evidence_and_facts_are_parsed_not_strings(self, populated_db):
        findings = server.get_findings(cls="x402")
        assert isinstance(findings[0]["evidence"], list)
        assert isinstance(findings[0]["facts"], dict)

    def test_filter_by_app(self, populated_db):
        findings = server.get_findings(app="codex")
        assert len(findings) == 3

    def test_filter_by_min_confidence_signature(self, populated_db):
        findings = server.get_findings(min_confidence="signature")
        assert len(findings) == 3  # all fixtures are signature-confidence


class TestExplainIdentityJoins:
    def test_returns_join_with_flow_ids(self, populated_db):
        joins = server.explain_identity_joins()
        assert len(joins) == 1
        assert set(joins[0]["etld1s"]) == {"a.com", "b.com"}
        assert set(joins[0]["flow_ids"]) == {"flow-1", "flow-2"}


class TestAgentActivity:
    def test_rollup_excludes_websocket_from_provider_counts(self, populated_db):
        activity = server.agent_activity()
        assert activity["providers"] == {"Anthropic": 1}
        assert activity["models"] == ["claude-sonnet-5"]
        assert activity["websocket_upgrades"] == 1
        assert activity["total_request_bytes"] == 100
        assert activity["total_response_bytes"] == 200

    def test_prompt_text_never_appears(self, populated_db):
        import json

        activity = server.agent_activity()
        assert "secret" not in json.dumps(activity)


class TestX402Offers:
    def test_returns_decoded_offers(self, populated_db):
        offers = server.x402_offers()
        assert len(offers) == 1
        assert offers[0]["amount"] == "10000"


class TestRedactionReport:
    def test_reports_body_access_and_rules(self, populated_db):
        report = server.redaction_report()
        assert report["body_access"] == "redacted"
        assert report["bodies_stored"] == 1
        assert report["bodies_redacted"] == 1
        assert len(report["rules"]) >= 8


class TestGetBody:
    def test_none_mode_refuses(self, populated_db):
        populated_db._audit_conn.execute(
            "UPDATE session SET body_access = 'none' WHERE id = 1"
        )
        populated_db._audit_conn.commit()
        result = server.get_body("flow-1", "response")
        assert "error" in result
        assert "firetoll_body_access" in result["error"]

    def test_redacted_mode_returns_stored_content(self, populated_db):
        result = server.get_body("flow-1", "response")
        assert result["content"] == "redacted stuff"
        assert result["content_bytes"] == len("redacted stuff")
        assert result["bytes_returned"] == len("redacted stuff")
        assert result["redacted"] is True
        assert "warning" not in result

    def test_body_reads_are_bounded(self, populated_db):
        result = server.get_body("flow-1", "response", limit=4)
        assert result["content"] == "reda"
        assert result["offset"] == 0
        assert result["bytes_returned"] == 4
        assert result["content_bytes"] == len("redacted stuff")
        assert result["has_more"] is True

    def test_body_range_reads_offset(self, populated_db):
        result = server.get_body_range("flow-1", "response", offset=4, limit=4)
        assert result["content"] == "cted"
        assert result["offset"] == 4

    def test_body_window_limits_are_validated(self, populated_db):
        with pytest.raises(ValueError):
            server.get_body("flow-1", "response", offset=-1)
        with pytest.raises(ValueError):
            server.get_body("flow-1", "response", limit=0)
        with pytest.raises(ValueError):
            server.get_body("flow-1", "response", limit=server.MAX_BODY_READ_BYTES + 1)

    def test_missing_body_returns_error(self, populated_db):
        result = server.get_body("flow-1", "request")
        assert "error" in result

    def test_full_mode_includes_warning(self, populated_db):
        populated_db._audit_conn.execute(
            "UPDATE session SET body_access = 'full' WHERE id = 1"
        )
        populated_db._audit_conn.commit()
        result = server.get_body("flow-1", "response")
        assert "warning" in result

    def test_every_call_is_logged(self, populated_db):
        server.get_body("flow-1", "response")
        server.get_body("flow-1", "request")
        log = server.access_log()
        assert len(log) == 2
        assert {entry["part"] for entry in log} == {"response", "request"}


class TestListBodies:
    def test_returns_metadata_without_content(self, populated_db):
        bodies = server.list_bodies()
        assert bodies == [
            {
                "flow_id": "flow-1",
                "part": "response",
                "content_bytes": len("redacted stuff"),
                "truncated": False,
                "redacted": True,
                "created_at": bodies[0]["created_at"],
            }
        ]

    def test_filters_by_flow(self, populated_db):
        assert server.list_bodies(flow_id="missing") == []


class TestAccessLog:
    def test_empty_by_default(self, populated_db):
        assert server.access_log() == []

    def test_records_after_get_body(self, populated_db):
        server.get_body("flow-1", "response")
        log = server.access_log()
        assert len(log) == 1
        assert log[0]["flow_id"] == "flow-1"
