import asyncio
import os
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
                "SELECT unattributed_flows FROM session WHERE id = 1"
            ).fetchone()
            assert value == 3
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
            content, truncated, redacted = db.get_body("f1", "response")
            assert content == b"hello"
            assert truncated is False
            assert redacted is True
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
            content, truncated, redacted = db.get_body("f1", "request")
            assert content == b"second"
            assert truncated is True
            assert redacted is False
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
            content, truncated, redacted, total_bytes = db.get_body_window(
                "f1", "response", offset=6, limit=5
            )
            assert content == b"world"
            assert truncated is False
            assert redacted is True
            assert total_bytes == len(b"hello world")
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
            body_flow_id, part, content_bytes, truncated, redacted, created_at = (
                filtered[0]
            )
            assert body_flow_id == "f1"
            assert part == "request"
            assert content_bytes == 3
            assert truncated is False
            assert redacted is True
            assert created_at == 100.0
        finally:
            db.close()

    def test_set_websocket_frames_captured(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.set_websocket_frames_captured(True)
            (value,) = db.conn.execute(
                "SELECT websocket_frames_captured FROM session WHERE id = 1"
            ).fetchone()
            assert value == 1

            db.set_websocket_frames_captured(False)
            (value,) = db.conn.execute(
                "SELECT websocket_frames_captured FROM session WHERE id = 1"
            ).fetchone()
            assert value == 0
        finally:
            db.close()

    def test_record_access_and_list_access_log(self, tmp_path):
        db = store.Store(tmp_path / "session.sqlite")
        try:
            db.record_access(flow_id="f1", part="response", mode="redacted")
            db.record_access(flow_id="f2", part="request", mode="full")
            rows = db.list_access_log()
            assert len(rows) == 2
            assert rows[0][0] == "f2"  # most recent first
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

    def test_record_access_uses_separate_writable_connection(self, tmp_path):
        path = tmp_path / "session.sqlite"
        store.Store(path).close()
        reader = store.ReadOnlyStore(path)
        try:
            reader.record_access(flow_id="f1", part="response", mode="redacted")
            rows = reader.list_access_log()
            assert len(rows) == 1
            assert rows[0][0] == "f1"
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
                "SELECT unattributed_flows FROM session WHERE id = 1"
            ).fetchone()
            assert unattributed == 0
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
