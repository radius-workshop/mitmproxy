import asyncio
import hashlib
import json
import os
import sqlite3
import stat
import time

import pytest

from mitmproxy.firetoll import options
from mitmproxy.firetoll import store
from mitmproxy.firetoll.finding import Finding
from mitmproxy.test import taddons


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class TestStorePermissions:
    @pytest.mark.skipif(os.name == "nt", reason="Skipping due to Windows")
    def test_directory_and_file_modes(self, tmp_path):
        db_path = tmp_path / "sub" / "session.sqlite"
        db = store.Store(db_path)
        try:
            assert _mode(db_path.parent) == 0o700
            assert _mode(db_path) == 0o600
        finally:
            db.close()


class TestStoreWrites:
    def test_record_app_is_idempotent(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            app_id_1 = db.record_app(
                process="codex",
                path="/usr/local/bin/codex",
                parent="zsh",
                source="process",
            )
            app_id_2 = db.record_app(
                process="codex",
                path="/usr/local/bin/codex",
                parent="zsh",
                source="process",
            )
            assert app_id_1 == app_id_2
        finally:
            db.close()

    def test_record_flow_and_finding_roundtrip(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            app_id = db.record_app(
                process="Claude.app",
                path="/Applications/Claude.app",
                parent=None,
                source="process",
            )
            db.record_flow(
                flow_id="flow-1",
                app_id=app_id,
                method="POST",
                host="api.anthropic.com",
                path="/v1/messages",
                status=200,
                request_bytes=100,
                response_bytes=200,
            )
            finding = Finding(
                cls="agent_egress",
                label="anthropic messages API",
                confidence="signature",
                evidence=["host=api.anthropic.com", "path=/v1/messages"],
                facts={"model": "claude"},
            )
            db.record_finding("flow-1", finding)

            rows = db.conn.execute(
                "SELECT cls, label, evidence, facts FROM findings"
            ).fetchall()
            assert len(rows) == 1
            cls, label, evidence, facts = rows[0]
            assert cls == "agent_egress"
            assert label == "anthropic messages API"
            assert "host=api.anthropic.com" in evidence
            assert "claude" in facts
        finally:
            db.close()

    def test_record_flow_upsert_updates_status(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_flow(
                flow_id="flow-1",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=None,
                request_bytes=10,
                response_bytes=None,
            )
            db.record_flow(
                flow_id="flow-1",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=10,
                response_bytes=50,
            )
            (status,) = db.conn.execute(
                "SELECT status FROM flows WHERE id = 'flow-1'"
            ).fetchone()
            assert status == 200
        finally:
            db.close()

    def test_identity_hash_never_stores_raw_value(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_flow(
                flow_id="flow-1",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            secret_value = "super-secret-tracking-id-abc123"
            db.record_identity(
                value=secret_value, etld1="example.com", flow_id="flow-1"
            )

            raw_dump = tmp_path.joinpath("session.sqlite").read_bytes()
            assert secret_value.encode() not in raw_dump

            value_hash, value_prefix = db.hash_identifier(secret_value)
            row = db.conn.execute(
                "SELECT value_hash, value_prefix, etld1 FROM identities"
            ).fetchone()
            assert row == (value_hash, value_prefix, "example.com")
        finally:
            db.close()

    def test_hash_is_stable_within_session_but_salted(self, tmp_path):
        db1 = store.Store(tmp_path / "a.sqlite")
        db2 = store.Store(tmp_path / "b.sqlite")
        try:
            h1, _ = db1.hash_identifier("same-value")
            h1_again, _ = db1.hash_identifier("same-value")
            h2, _ = db2.hash_identifier("same-value")
            assert h1 == h1_again
            assert h1 != h2  # different per-session salt
        finally:
            db1.close()
            db2.close()

    def test_salt_persists_across_reopen(self, tmp_path):
        db_path = tmp_path / "session.sqlite"
        db1 = store.Store(db_path)
        salt1 = db1._salt
        db1.close()

        db2 = store.Store(db_path)
        try:
            # Reopening an existing store must reuse the salt already
            # persisted in `meta`, not mint a new one.
            assert db2._salt == salt1
        finally:
            db2.close()

    def test_increment_counter_rejects_unknown_name(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            with pytest.raises(ValueError):
                db.increment_counter("not_a_real_counter")
        finally:
            db.close()

    def test_increment_and_read_counters(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.increment_counter("unattributed_flows")
            db.increment_counter("unattributed_flows", by=2)
            (value,) = db.conn.execute(
                "SELECT unattributed_flows FROM sessions WHERE id = ?",
                (db.session_id,),
            ).fetchone()
            assert value == 3
        finally:
            db.close()


class TestSessions:
    def test_open_creates_a_fresh_live_session(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            assert db.session_id is not None
            assert db.is_live() is True
        finally:
            db.close()

    def test_closing_a_session_does_not_leak_into_the_next_open(self, tmp_path):
        db_path = tmp_path / "session.sqlite"
        first = store.Store(db_path)
        first_session_id = first.session_id
        first.close_session()
        assert first.is_live() is False
        first.close()

        second = store.Store(db_path)
        try:
            # This is the bug a singleton session row caused: a new run must
            # never see the previous run's ended_at.
            assert second.session_id != first_session_id
            assert second.is_live() is True
        finally:
            second.close()

    def test_flows_are_scoped_to_the_session_that_wrote_them(self, tmp_path):
        db_path = tmp_path / "session.sqlite"
        first = store.Store(db_path)
        first.record_flow(
            flow_id="f-old",
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

        second = store.Store(db_path)
        try:
            second.record_flow(
                flow_id="f-new",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            (count,) = second.conn.execute(
                "SELECT COUNT(*) FROM flows WHERE session_id = ?",
                (second.session_id,),
            ).fetchone()
            assert count == 1
            (total,) = second.conn.execute("SELECT COUNT(*) FROM flows").fetchone()
            assert total == 2
        finally:
            second.close()

    def test_wipe_starts_a_new_session(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            original_session_id = db.session_id
            db.wipe()
            assert db.session_id != original_session_id
            assert db.is_live() is True
            (count,) = db.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
            assert count == 1
        finally:
            db.close()


class TestFindIdentityJoins:
    def test_value_under_two_etld1s_is_a_join(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_flow(
                flow_id="f1",
                app_id=None,
                method="GET",
                host="a.com",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            db.record_flow(
                flow_id="f2",
                app_id=None,
                method="GET",
                host="b.com",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            db.record_identity(value="same-value", etld1="a.com", flow_id="f1")
            db.record_identity(value="same-value", etld1="b.com", flow_id="f2")

            joins = db.find_identity_joins()
            assert len(joins) == 1
            value_hash, value_prefix, etlds, flow_ids = joins[0]
            expected_hash, expected_prefix = db.hash_identifier("same-value")
            assert value_hash == expected_hash
            assert value_prefix == expected_prefix
            assert etlds == ["a.com", "b.com"]
            assert set(flow_ids) == {"f1", "f2"}
        finally:
            db.close()

    def test_value_under_one_etld1_is_not_a_join(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_flow(
                flow_id="f1",
                app_id=None,
                method="GET",
                host="a.com",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            db.record_flow(
                flow_id="f2",
                app_id=None,
                method="GET",
                host="a.com",
                path="/other",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            db.record_identity(value="same-value", etld1="a.com", flow_id="f1")
            db.record_identity(value="same-value", etld1="a.com", flow_id="f2")

            assert db.find_identity_joins() == []
        finally:
            db.close()

    def test_no_identities_returns_empty(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            assert db.find_identity_joins() == []
        finally:
            db.close()

    def test_session_id_scopes_to_flows_from_that_session(self, tmp_path):
        db_path = tmp_path / "session.sqlite"
        first = store.Store(db_path)
        first.record_flow(
            flow_id="f1",
            app_id=None,
            method="GET",
            host="a.com",
            path="/",
            status=200,
            request_bytes=None,
            response_bytes=None,
        )
        first.record_flow(
            flow_id="f2",
            app_id=None,
            method="GET",
            host="b.com",
            path="/",
            status=200,
            request_bytes=None,
            response_bytes=None,
        )
        first.record_identity(value="same-value", etld1="a.com", flow_id="f1")
        first.record_identity(value="same-value", etld1="b.com", flow_id="f2")
        first_session_id = first.session_id
        first.close_session()
        first.close()

        second = store.Store(db_path)
        try:
            assert second.find_identity_joins(session_id=second.session_id) == []
            assert len(second.find_identity_joins(session_id=first_session_id)) == 1
            assert len(second.find_identity_joins()) == 1
        finally:
            second.close()


class TestRetention:
    def test_enforce_retention_deletes_old_flows_and_cascades(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            now = time.time()
            db.record_flow(
                flow_id="old",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
                created_at=now - 999_999,
            )
            db.record_finding(
                "old",
                Finding(
                    cls="telemetry", label="x", confidence="signature", evidence=["e"]
                ),
            )
            db.record_flow(
                flow_id="new",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
                created_at=now,
            )

            deleted = db.enforce_retention(retention_hours=24, now=now)
            assert deleted == 1

            remaining_ids = {
                row[0] for row in db.conn.execute("SELECT id FROM flows").fetchall()
            }
            assert remaining_ids == {"new"}
            assert db.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
        finally:
            db.close()


class TestBodiesAndAccessLog:
    def test_record_and_get_body_roundtrip(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_flow(
                flow_id="f1",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            db.record_body(
                flow_id="f1",
                part="response",
                content=b"hello",
                truncated=False,
                redacted=True,
            )
            content, truncated, redacted, sha256, content_type = db.get_body(
                "f1", "response"
            )
            assert content == b"hello"
            assert truncated is False
            assert redacted is True
            assert sha256 == hashlib.sha256(b"hello").hexdigest()
            assert content_type == "text/plain"
        finally:
            db.close()

    def test_get_body_missing_returns_none(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            assert db.get_body("nonexistent", "request") is None
        finally:
            db.close()

    def test_record_body_upsert_overwrites(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_flow(
                flow_id="f1",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            db.record_body(
                flow_id="f1",
                part="request",
                content=b"first",
                truncated=False,
                redacted=True,
            )
            db.record_body(
                flow_id="f1",
                part="request",
                content=b"second",
                truncated=True,
                redacted=False,
            )
            content, truncated, redacted, sha256, _content_type = db.get_body(
                "f1", "request"
            )
            assert content == b"second"
            assert truncated is True
            assert redacted is False
            assert sha256 == hashlib.sha256(b"second").hexdigest()
        finally:
            db.close()

    def test_get_body_window_returns_slice_and_total_length(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_flow(
                flow_id="f1",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            db.record_body(
                flow_id="f1",
                part="response",
                content=b"hello world",
                truncated=False,
                redacted=True,
            )
            content, truncated, redacted, total_bytes, sha256, content_type = (
                db.get_body_window("f1", "response", offset=6, limit=5)
            )
            assert content == b"world"
            assert truncated is False
            assert redacted is True
            assert total_bytes == len(b"hello world")
            assert sha256 == hashlib.sha256(b"hello world").hexdigest()
            assert content_type == "text/plain"
        finally:
            db.close()

    def test_get_body_window_missing_returns_none(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            assert db.get_body_window("nonexistent", "request", 0, 10) is None
        finally:
            db.close()

    def test_list_body_metadata_all_and_filtered_by_flow(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_flow(
                flow_id="f1",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
                created_at=100.0,
            )
            db.record_flow(
                flow_id="f2",
                app_id=None,
                method="GET",
                host="h",
                path="/other",
                status=200,
                request_bytes=None,
                response_bytes=None,
                created_at=200.0,
            )
            db.record_body(
                flow_id="f1",
                part="request",
                content=b"aaa",
                truncated=False,
                redacted=True,
            )
            db.record_body(
                flow_id="f2",
                part="response",
                content=b"bbbb",
                truncated=True,
                redacted=False,
            )

            all_rows = db.list_body_metadata()
            assert len(all_rows) == 2
            # newest flow first (ORDER BY f.created_at DESC)
            assert all_rows[0][0] == "f2"
            assert all_rows[1][0] == "f1"

            filtered = db.list_body_metadata(flow_id="f1")
            assert len(filtered) == 1
            (
                body_flow_id,
                part,
                content_bytes,
                truncated,
                redacted,
                created_at,
                sha256,
                content_type,
            ) = filtered[0]
            assert body_flow_id == "f1"
            assert part == "request"
            assert content_bytes == 3
            assert truncated is False
            assert redacted is True
            assert created_at == 100.0
            assert sha256 == hashlib.sha256(b"aaa").hexdigest()
            assert content_type == "text/plain"
        finally:
            db.close()

    def test_set_websocket_frames_captured(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.set_websocket_frames_captured(True)
            (value,) = db.conn.execute(
                "SELECT websocket_frames_captured FROM sessions WHERE id = ?",
                (db.session_id,),
            ).fetchone()
            assert value == 1

            db.set_websocket_frames_captured(False)
            (value,) = db.conn.execute(
                "SELECT websocket_frames_captured FROM sessions WHERE id = ?",
                (db.session_id,),
            ).fetchone()
            assert value == 0
        finally:
            db.close()

    def test_record_tool_call_and_list_tool_log(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_tool_call(
                tool="get_body",
                args={"flow_id": "f1"},
                flow_id="f1",
                part="response",
                mode="redacted",
            )
            db.record_tool_call(
                tool="get_body",
                args={"flow_id": "f2"},
                flow_id="f2",
                part="request",
                mode="full",
                row_count=1,
                bytes_returned=42,
            )
            rows = db.list_tool_log()
            assert len(rows) == 2
            tool, args_json, flow_id, part, mode, row_count, bytes_returned, session_id, called_at = rows[0]
            assert tool == "get_body"
            assert json.loads(args_json) == {"flow_id": "f2"}
            assert flow_id == "f2"  # most recent first
            assert row_count == 1
            assert bytes_returned == 42
            assert session_id == db.session_id
        finally:
            db.close()

    def test_record_tool_call_defaults_args_to_empty_dict(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_tool_call(tool="session_overview")
            (args_json,) = db.conn.execute(
                "SELECT args_json FROM tool_log"
            ).fetchone()
            assert json.loads(args_json) == {}
        finally:
            db.close()

    def test_body_access_defaults_to_redacted(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            assert db.get_body_access() == "redacted"
        finally:
            db.close()

    def test_set_and_get_body_access(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.set_body_access("full")
            assert db.get_body_access() == "full"
        finally:
            db.close()


class TestReadOnlyStore:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            store.ReadOnlyStore(tmp_path / "does-not-exist.sqlite")

    def test_reads_existing_data(self, tmp_path):
        path = tmp_path / "session.sqlite"
        writer = store.Store(path)
        writer.record_flow(
            flow_id="f1",
            app_id=None,
            method="GET",
            host="h",
            path="/",
            status=200,
            request_bytes=None,
            response_bytes=None,
        )
        writer.close()

        reader = store.ReadOnlyStore(path)
        try:
            rows = reader.conn.execute("SELECT id FROM flows").fetchall()
            assert rows == [("f1",)]
        finally:
            reader.close()

    def test_write_methods_are_disabled(self, tmp_path):
        path = tmp_path / "session.sqlite"
        store.Store(path).close()
        reader = store.ReadOnlyStore(path)
        try:
            with pytest.raises(PermissionError):
                reader.record_flow(
                    flow_id="f1",
                    app_id=None,
                    method="GET",
                    host="h",
                    path="/",
                    status=200,
                    request_bytes=None,
                    response_bytes=None,
                )
            with pytest.raises(PermissionError):
                reader.wipe()
            with pytest.raises(PermissionError):
                reader.enforce_retention(24)
        finally:
            reader.close()

    def test_record_tool_call_uses_separate_writable_connection(self, tmp_path):
        path = tmp_path / "session.sqlite"
        store.Store(path).close()
        reader = store.ReadOnlyStore(path)
        try:
            reader.record_tool_call(
                tool="get_body", flow_id="f1", part="response", mode="redacted"
            )
            rows = reader.list_tool_log()
            assert len(rows) == 1
            assert rows[0][2] == "f1"  # flow_id
        finally:
            reader.close()

    def test_defaults_to_the_most_recent_session(self, tmp_path):
        path = tmp_path / "session.sqlite"
        first = store.Store(path)
        first_session_id = first.session_id
        first.close_session()
        first.close()
        second = store.Store(path)
        second_session_id = second.session_id
        second.close()

        reader = store.ReadOnlyStore(path)
        try:
            assert reader.session_id == second_session_id
            assert reader.session_id != first_session_id
        finally:
            reader.close()

    def test_session_id_is_none_when_store_has_no_sessions_rows(self, tmp_path):
        path = tmp_path / "session.sqlite"
        store.Store(path).close()
        writable = sqlite3.connect(str(path))
        writable.execute("DELETE FROM sessions")
        writable.commit()
        writable.close()

        reader = store.ReadOnlyStore(path)
        try:
            assert reader.session_id is None
        finally:
            reader.close()

    def test_find_identity_joins_works_readonly(self, tmp_path):
        path = tmp_path / "session.sqlite"
        writer = store.Store(path)
        writer.record_flow(
            flow_id="f1",
            app_id=None,
            method="GET",
            host="a.com",
            path="/",
            status=200,
            request_bytes=None,
            response_bytes=None,
        )
        writer.record_flow(
            flow_id="f2",
            app_id=None,
            method="GET",
            host="b.com",
            path="/",
            status=200,
            request_bytes=None,
            response_bytes=None,
        )
        writer.record_identity(value="shared", etld1="a.com", flow_id="f1")
        writer.record_identity(value="shared", etld1="b.com", flow_id="f2")
        writer.close()

        reader = store.ReadOnlyStore(path)
        try:
            joins = reader.find_identity_joins()
            assert len(joins) == 1
        finally:
            reader.close()


class TestWipe:
    def test_wipe_clears_all_tables_and_resets_counters(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_flow(
                flow_id="flow-1",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            db.record_identity(value="v", etld1="example.com", flow_id="flow-1")
            db.increment_counter("unattributed_flows")

            db.wipe()

            assert db.conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 0
            assert db.conn.execute("SELECT COUNT(*) FROM identities").fetchone()[0] == 0
            (unattributed,) = db.conn.execute(
                "SELECT unattributed_flows FROM sessions WHERE id = ?", (db.session_id,)
            ).fetchone()
            assert unattributed == 0
        finally:
            db.close()

    def test_wipe_preserves_the_tool_log_audit_trail(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_flow(
                flow_id="flow-1",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            db.record_tool_call(tool="get_body", flow_id="flow-1", part="response")

            db.wipe()

            assert db.conn.execute("SELECT COUNT(*) FROM tool_log").fetchone()[0] == 1
        finally:
            db.close()


class TestFiretollStoreAddon:
    @pytest.mark.asyncio
    async def test_running_opens_store_and_wipe_command_works(self, tmp_path):
        db_path = tmp_path / "addon.sqlite"
        addon = store.FiretollStore()
        with taddons.context(options.FiretollOptions(), addon) as tctx:
            tctx.options.firetoll_store_path = str(db_path)
            addon.running()
            assert addon.db is not None
            assert db_path.exists()

            addon.db.record_flow(
                flow_id="flow-1",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
            )
            tctx.command(addon.wipe)
            assert (
                addon.db.conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 0
            )

            addon.done()
            assert addon.db is None

    @pytest.mark.asyncio
    async def test_running_is_noop_when_firetoll_disabled(self, tmp_path):
        addon = store.FiretollStore()
        with taddons.context(options.FiretollOptions(), addon) as tctx:
            tctx.options.firetoll = False
            tctx.options.firetoll_store_path = str(tmp_path / "should-not-exist.sqlite")
            addon.running()
            assert addon.db is None

    @pytest.mark.asyncio
    async def test_retention_loop_periodically_sweeps_old_flows(
        self, tmp_path, monkeypatch
    ):
        # Real sweeps are 15 minutes apart; make the loop tick immediately
        # so the test can observe a sweep happen without waiting.
        monkeypatch.setattr(store, "RETENTION_SWEEP_INTERVAL", 0)

        db_path = tmp_path / "addon.sqlite"
        addon = store.FiretollStore()
        with taddons.context(options.FiretollOptions(), addon) as tctx:
            tctx.options.firetoll_store_path = str(db_path)
            tctx.options.firetoll_retention_hours = 1
            addon.running()

            now = time.time()
            addon.db.record_flow(
                flow_id="old",
                app_id=None,
                method="GET",
                host="h",
                path="/",
                status=200,
                request_bytes=None,
                response_bytes=None,
                created_at=now - 999_999,
            )

            for _ in range(200):
                await asyncio.sleep(0)
                count = addon.db.conn.execute(
                    "SELECT COUNT(*) FROM flows"
                ).fetchone()[0]
                if count == 0:
                    break
            assert count == 0

            addon.done()
            assert addon.db is None

    @pytest.mark.asyncio
    async def test_wipe_command_warns_when_no_open_store(self, caplog):
        addon = store.FiretollStore()
        with taddons.context(options.FiretollOptions(), addon) as tctx:
            tctx.command(addon.wipe)
        assert addon.db is None
        assert "no open session store" in caplog.text


class TestGuessContentType:
    def test_empty_content_is_none(self):
        assert store._guess_content_type(b"") is None

    def test_json_object_prefix(self):
        assert store._guess_content_type(b'{"a": 1}') == "application/json"

    def test_json_array_prefix(self):
        assert store._guess_content_type(b"[1, 2, 3]") == "application/json"

    def test_sse_event_stream(self):
        assert store._guess_content_type(b"event: message\ndata: {}\n\n") == "text/event-stream"

    def test_plain_text(self):
        assert store._guess_content_type(b"hello world") == "text/plain"

    def test_binary_content(self):
        assert store._guess_content_type(b"\xff\xfe\x00\x01") == "application/octet-stream"


class TestSchemaMigration:
    def _legacy_store(self, path) -> None:
        """Build a store shaped like one from before sessions/tool_log/body
        digests existed, so migration has something real to do."""
        conn = sqlite3.connect(str(path))
        conn.executescript(
            """
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE session (
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
            CREATE TABLE apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process TEXT, path TEXT, parent TEXT, source TEXT NOT NULL,
                first_seen REAL NOT NULL,
                UNIQUE(process, path, parent, source)
            );
            CREATE TABLE flows (
                id TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                app_id INTEGER,
                method TEXT, host TEXT, path TEXT, status INTEGER,
                request_bytes INTEGER, response_bytes INTEGER,
                tls_profile_hash TEXT
            );
            CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT NOT NULL, cls TEXT NOT NULL, label TEXT NOT NULL,
                confidence TEXT NOT NULL, evidence TEXT NOT NULL, facts TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE identities (
                value_hash TEXT NOT NULL, value_prefix TEXT NOT NULL,
                etld1 TEXT NOT NULL, flow_id TEXT NOT NULL, seen_at REAL NOT NULL,
                PRIMARY KEY (value_hash, etld1, flow_id)
            );
            CREATE TABLE bodies (
                flow_id TEXT NOT NULL, part TEXT NOT NULL,
                content BLOB NOT NULL,
                truncated INTEGER NOT NULL DEFAULT 0,
                redacted INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (flow_id, part)
            );
            CREATE TABLE access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT NOT NULL, part TEXT NOT NULL, mode TEXT NOT NULL,
                accessed_at REAL NOT NULL
            );
            """
        )
        conn.execute(
            "INSERT INTO session (id, started_at, ended_at) VALUES (1, 100.0, 200.0)"
        )
        conn.execute(
            "INSERT INTO flows (id, created_at, host) VALUES ('legacy-flow', 100.0, 'h')"
        )
        conn.execute(
            "INSERT INTO bodies (flow_id, part, content) VALUES ('legacy-flow', 'request', ?)",
            (b'{"legacy": true}',),
        )
        conn.execute(
            "INSERT INTO access_log (flow_id, part, mode, accessed_at) "
            "VALUES ('legacy-flow', 'request', 'redacted', 150.0)"
        )
        conn.commit()
        conn.close()

    def test_migrates_a_pre_sessions_store_without_crashing(self, tmp_path):
        path = tmp_path / "session.sqlite"
        self._legacy_store(path)

        db = store.Store(path)
        try:
            # The old singleton `session` row described a stale, now-closed
            # session; a fresh run must not inherit it.
            assert db.is_live() is True
            assert db.session_id is not None

            # Pre-existing flows predate session tracking - session_id is
            # left NULL rather than fabricated, and the data is not lost.
            (session_id,) = db.conn.execute(
                "SELECT session_id FROM flows WHERE id = 'legacy-flow'"
            ).fetchone()
            assert session_id is None

            # Digests are backfilled since they're derivable from stored bytes.
            (sha256, content_type) = db.conn.execute(
                "SELECT sha256, content_type FROM bodies WHERE flow_id = 'legacy-flow'"
            ).fetchone()
            assert sha256 == hashlib.sha256(b'{"legacy": true}').hexdigest()
            assert content_type == "application/json"

            # The old audit trail is carried into tool_log, not discarded.
            rows = db.list_tool_log()
            assert len(rows) == 1
            tool, _args, flow_id, part, mode, _rc, _br, _sid, called_at = rows[0]
            assert tool == "get_body"
            assert flow_id == "legacy-flow"
            assert part == "request"
            assert mode == "redacted"
            assert called_at == 150.0
        finally:
            db.close()

    def test_migration_is_idempotent(self, tmp_path):
        path = tmp_path / "session.sqlite"
        self._legacy_store(path)

        store.Store(path).close()
        db = store.Store(path)
        try:
            assert db.conn.execute("SELECT COUNT(*) FROM tool_log").fetchone()[0] == 1
        finally:
            db.close()

    def test_legacy_session_table_is_dropped(self, tmp_path):
        path = tmp_path / "session.sqlite"
        self._legacy_store(path)
        store.Store(path).close()

        conn = sqlite3.connect(str(path))
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            assert "session" not in tables
            assert "access_log" not in tables
            assert "sessions" in tables
            assert "tool_log" in tables
        finally:
            conn.close()
