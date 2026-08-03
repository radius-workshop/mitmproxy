import json
import runpy

from mitmproxy.firetoll import cli
from mitmproxy.firetoll import store
from mitmproxy.firetoll.finding import Finding


def _populated_store(path) -> None:
    db = store.Store(path)
    app_id = db.record_app(
        process="codex", path="/usr/local/bin/codex", parent="zsh", source="process"
    )
    db.record_flow(
        flow_id="flow-1",
        app_id=app_id,
        method="POST",
        host="ab.chatgpt.com",
        path="/otlp/v1/metrics",
        status=202,
        request_bytes=100,
        response_bytes=10,
    )
    db.record_finding(
        "flow-1",
        Finding(
            cls="telemetry",
            label="OTLP telemetry",
            confidence="signature",
            evidence=["host=ab.chatgpt.com"],
        ),
    )
    db.record_body(
        flow_id="flow-1",
        part="request",
        content=b'{"a": 1}',
        truncated=False,
        redacted=False,
    )
    db.close()


class TestPrintRows:
    def test_empty_json(self, capsys):
        cli._print_rows([], as_json=True)
        assert json.loads(capsys.readouterr().out) == []

    def test_empty_table(self, capsys):
        cli._print_rows([], as_json=False)
        assert capsys.readouterr().out.strip() == "(none)"

    def test_table_alignment(self, capsys):
        cli._print_rows([{"a": "x", "b": "yy"}, {"a": "xxxx", "b": "y"}], as_json=False)
        lines = capsys.readouterr().out.splitlines()
        assert lines[0].startswith("a")
        assert len(lines) == 3

    def test_json_rows(self, capsys):
        cli._print_rows([{"a": 1}], as_json=True)
        assert json.loads(capsys.readouterr().out) == [{"a": 1}]


class TestCmdSessions:
    def test_lists_session_with_is_live(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        cli.main(["--store-path", str(path), "sessions", "--json"])
        rows = json.loads(capsys.readouterr().out)
        assert len(rows) == 1
        assert rows[0]["flow_count"] == 1
        assert rows[0]["is_live"] is True

    def test_table_output(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        cli.main(["--store-path", str(path), "sessions"])
        out = capsys.readouterr().out
        assert "is_live" in out
        assert "True" in out


class TestCmdFlows:
    def test_no_filters(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        cli.main(["--store-path", str(path), "flows", "--json"])
        rows = json.loads(capsys.readouterr().out)
        assert len(rows) == 1
        assert rows[0]["app"] == "codex (via zsh)"

    def test_filter_by_host(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        cli.main(
            ["--store-path", str(path), "flows", "--host", "ab.chatgpt.com", "--json"]
        )
        rows = json.loads(capsys.readouterr().out)
        assert len(rows) == 1

        cli.main(
            ["--store-path", str(path), "flows", "--host", "no-such-host", "--json"]
        )
        assert json.loads(capsys.readouterr().out) == []

    def test_filter_by_status(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        cli.main(["--store-path", str(path), "flows", "--status", "202", "--json"])
        rows = json.loads(capsys.readouterr().out)
        assert len(rows) == 1

        cli.main(["--store-path", str(path), "flows", "--status", "404", "--json"])
        assert json.loads(capsys.readouterr().out) == []

    def test_table_output(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        cli.main(["--store-path", str(path), "flows"])
        assert "ab.chatgpt.com" in capsys.readouterr().out


class TestCmdBodies:
    def test_no_filter(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        cli.main(["--store-path", str(path), "bodies", "--json"])
        rows = json.loads(capsys.readouterr().out)
        assert len(rows) == 1
        assert rows[0]["content_type"] == "application/json"
        assert len(rows[0]["sha256"]) == 64

    def test_filter_by_flow_id(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        cli.main(
            ["--store-path", str(path), "bodies", "--flow-id", "flow-1", "--json"]
        )
        assert len(json.loads(capsys.readouterr().out)) == 1

        cli.main(
            ["--store-path", str(path), "bodies", "--flow-id", "missing", "--json"]
        )
        assert json.loads(capsys.readouterr().out) == []


class TestCmdAudit:
    def test_empty_by_default(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        cli.main(["--store-path", str(path), "audit", "--json"])
        assert json.loads(capsys.readouterr().out) == []

    def test_records_appear_and_survive_wipe(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        db = store.ReadOnlyStore(path)
        db.record_tool_call(
            tool="get_body",
            args={"flow_id": "flow-1", "part": "request"},
            flow_id="flow-1",
            part="request",
            mode="redacted",
            row_count=None,
            bytes_returned=8,
        )
        db.close()

        cli.main(["--store-path", str(path), "audit", "--json"])
        rows = json.loads(capsys.readouterr().out)
        assert len(rows) == 1
        assert rows[0]["tool"] == "get_body"
        assert rows[0]["args"] == {"flow_id": "flow-1", "part": "request"}
        assert rows[0]["bytes_returned"] == 8

    def test_table_output_serializes_args(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        db = store.ReadOnlyStore(path)
        db.record_tool_call(tool="list_apps", args={})
        db.close()

        cli.main(["--store-path", str(path), "audit"])
        out = capsys.readouterr().out
        assert "list_apps" in out

    def test_limit_is_forwarded(self, tmp_path, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        db = store.ReadOnlyStore(path)
        db.record_tool_call(tool="a", args={})
        db.record_tool_call(tool="b", args={})
        db.close()

        cli.main(["--store-path", str(path), "audit", "--limit", "1", "--json"])
        assert len(json.loads(capsys.readouterr().out)) == 1


class TestBuildParser:
    def test_requires_a_command(self):
        parser = cli.build_parser()
        assert parser.prog == "firetoll"

    def test_default_store_path(self):
        parser = cli.build_parser()
        args = parser.parse_args(["sessions"])
        assert args.store_path == str(store.DEFAULT_STORE_PATH)


class TestMain:
    def test_dunder_main_invokes_main(self, tmp_path, monkeypatch, capsys):
        path = tmp_path / "session.sqlite"
        _populated_store(path)
        monkeypatch.setattr(
            "sys.argv", ["firetoll", "--store-path", str(path), "sessions", "--json"]
        )
        runpy.run_path(cli.__file__, run_name="__main__")
        assert len(json.loads(capsys.readouterr().out)) == 1
