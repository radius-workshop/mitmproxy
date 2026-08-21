import hashlib
import json

import pytest

from mitmproxy.firetoll import enrich
from mitmproxy.firetoll import options
from mitmproxy.firetoll import store
from mitmproxy.firetoll.finding import Finding
from mitmproxy.test import taddons
from mitmproxy.test import tflow
from mitmproxy.test import tutils


def _context(*addons):
    return taddons.context(options.FiretollOptions(), *addons)


class _StubDetector:
    name = "stub"

    def __init__(self, findings=None, raises=False):
        self._findings = findings or []
        self._raises = raises

    def detect(self, flow):
        if self._raises:
            raise RuntimeError("boom")
        return list(self._findings)


class TestEnrichOrchestrator:
    def test_findings_attached_to_flow_metadata(self):
        finding = Finding(
            cls="telemetry", label="x", confidence="signature", evidence=["e"]
        )
        a = enrich.Enrich()
        with _context(a) as tctx:
            tctx.configure(a)
            a.detectors = [_StubDetector([finding])]
            f = tflow.tflow(resp=True)
            a.response(f)
            assert f.metadata["firetoll.findings"] == [finding.to_dict()]

    def test_raising_detector_does_not_affect_flow_or_crash(self):
        good_finding = Finding(
            cls="telemetry", label="ok", confidence="signature", evidence=["e"]
        )
        a = enrich.Enrich()
        with _context(a) as tctx:
            tctx.configure(a)
            a.detectors = [
                _StubDetector(raises=True),
                _StubDetector([good_finding]),
            ]
            f = tflow.tflow(resp=True)
            a.response(f)  # must not raise
            assert f.metadata["firetoll.findings"] == [good_finding.to_dict()]
            assert f.error is None

    def test_disabled_option_skips_enrichment(self):
        a = enrich.Enrich()
        with _context(a) as tctx:
            tctx.configure(a)
            tctx.options.firetoll = False
            a.detectors = [
                _StubDetector(
                    [
                        Finding(
                            cls="telemetry",
                            label="x",
                            confidence="signature",
                            evidence=["e"],
                        )
                    ]
                )
            ]
            f = tflow.tflow(resp=True)
            a.response(f)
            assert "firetoll.findings" not in f.metadata

    def test_no_response_yet_is_skipped(self):
        a = enrich.Enrich()
        with _context(a) as tctx:
            tctx.configure(a)
            a.detectors = [
                _StubDetector(
                    [
                        Finding(
                            cls="telemetry",
                            label="x",
                            confidence="signature",
                            evidence=["e"],
                        )
                    ]
                )
            ]
            f = tflow.tflow(resp=False)
            a.response(f)
            assert "firetoll.findings" not in f.metadata

    def test_running_loads_default_detectors(self):
        a = enrich.Enrich()
        with _context(a) as tctx:
            tctx.configure(a)
            a.running()
            assert len(a.detectors) >= 1

    def test_running_skips_loading_detectors_when_disabled(self):
        a = enrich.Enrich()
        with _context(a) as tctx:
            tctx.configure(a)
            tctx.options.firetoll = False
            a.running()
            assert a.detectors == []

    def test_path_evidence_is_sanitized_before_metadata_attachment(self):
        token = "123456789:AAExampleTelegramBotToken_0123456789"
        finding = Finding(
            cls="telemetry",
            label="path-derived",
            confidence="signature",
            evidence=[f"path=/bot{token}/sendMessage?chat_id=987654321"],
        )
        a = enrich.Enrich()
        with _context(a) as tctx:
            tctx.configure(a)
            a.detectors = [_StubDetector([finding])]
            f = tflow.tflow(resp=True)
            a.response(f)

        evidence = f.metadata["firetoll.findings"][0]["evidence"]
        assert evidence == [
            "path=/bot<redacted:telegram-bot-token>/sendMessage"
            "?chat_id=<redacted:query-value>"
        ]
        assert token not in json.dumps(f.metadata["firetoll.findings"])
        assert evidence[0]


class _StubIdentifierDetector(_StubDetector):
    def __init__(self, values):
        super().__init__()
        self._values = values

    def extract_identifiers(self, flow):
        return list(self._values)


class _RaisingIdentifierDetector(_StubDetector):
    def extract_identifiers(self, flow):
        raise RuntimeError("boom")


class TestEnrichIdentifierExtraction:
    @pytest.mark.asyncio
    async def test_identifiers_recorded_with_request_host_etld1(self, tmp_path):
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            store_addon.running()
            enrich_addon.detectors = [_StubIdentifierDetector(["shared-value"])]

            f = tflow.tflow(
                req=tutils.treq(host="sub.example.com", path="/"), resp=True
            )
            enrich_addon.response(f)

            rows = store_addon.db.conn.execute(
                "SELECT etld1, flow_id FROM identities"
            ).fetchall()
            assert rows == [("example.com", f.id)]
            store_addon.done()


class TestEnrichTlsProfile:
    @pytest.mark.asyncio
    async def test_tls_profile_hash_recorded_when_tls_established(self, tmp_path):
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            store_addon.running()
            enrich_addon.detectors = []

            f = tflow.tflow(resp=True)  # tclient_conn() defaults to TLS established
            enrich_addon.response(f)

            (tls_profile_hash,) = store_addon.db.conn.execute(
                "SELECT tls_profile_hash FROM flows WHERE id = ?", (f.id,)
            ).fetchone()
            assert tls_profile_hash is not None
            store_addon.done()

    @pytest.mark.asyncio
    async def test_tls_profile_hash_none_without_tls(self, tmp_path):
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            store_addon.running()
            enrich_addon.detectors = []

            f = tflow.tflow(resp=True)
            f.client_conn.timestamp_tls_setup = None
            enrich_addon.response(f)

            (tls_profile_hash,) = store_addon.db.conn.execute(
                "SELECT tls_profile_hash FROM flows WHERE id = ?", (f.id,)
            ).fetchone()
            assert tls_profile_hash is None
            store_addon.done()

    @pytest.mark.asyncio
    async def test_raising_extractor_does_not_crash_or_block_other_detectors(
        self, tmp_path
    ):
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            store_addon.running()
            enrich_addon.detectors = [
                _RaisingIdentifierDetector(),
                _StubIdentifierDetector(["still-recorded"]),
            ]

            f = tflow.tflow(req=tutils.treq(host="example.com", path="/"), resp=True)
            enrich_addon.response(f)  # must not raise

            rows = store_addon.db.conn.execute(
                "SELECT etld1 FROM identities"
            ).fetchall()
            assert rows == [("example.com",)]
            store_addon.done()


class TestEnrichStoreIntegration:
    @pytest.mark.asyncio
    async def test_writes_flow_and_findings_to_store(self, tmp_path):
        finding = Finding(
            cls="telemetry",
            label="Segment telemetry",
            confidence="signature",
            evidence=["host=api.segment.io"],
            facts={"vendor": "Segment"},
        )
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            store_addon.running()
            enrich_addon.detectors = [_StubDetector([finding])]

            f = tflow.tflow(
                req=tutils.treq(host="api.segment.io", path="/v1/track"),
                resp=True,
            )
            f.metadata["firetoll.app"] = {
                "source": "process",
                "pid": 1,
                "process": "curl",
                "path": "/usr/bin/curl",
                "parent": None,
            }
            enrich_addon.response(f)

            rows = store_addon.db.conn.execute(
                "SELECT host, path, status FROM flows"
            ).fetchall()
            assert rows == [("api.segment.io", "/v1/track", 200)]

            finding_rows = store_addon.db.conn.execute(
                "SELECT cls, label FROM findings"
            ).fetchall()
            assert finding_rows == [("telemetry", "Segment telemetry")]

            store_addon.done()

    @pytest.mark.asyncio
    async def test_unattributed_flow_increments_counter(self, tmp_path):
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            store_addon.running()
            enrich_addon.detectors = []

            f = tflow.tflow(resp=True)
            f.metadata["firetoll.app"] = {
                "source": "unknown",
                "pid": None,
                "process": None,
                "path": None,
                "parent": None,
            }
            enrich_addon.response(f)

            (count,) = store_addon.db.conn.execute(
                "SELECT unattributed_flows FROM sessions WHERE id = ?",
                (store_addon.db.session_id,),
            ).fetchone()
            assert count == 1
            store_addon.done()

    @pytest.mark.asyncio
    async def test_flow_path_and_finding_evidence_are_sanitized_before_storage(
        self, tmp_path
    ):
        token = "123456789:AAExampleTelegramBotToken_0123456789"
        raw_path = f"/bot{token}/sendMessage?chat_id=987654321&text=private"
        finding = Finding(
            cls="telemetry",
            label="path-derived",
            confidence="signature",
            evidence=[f"path={raw_path}"],
        )
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            store_addon.running()
            enrich_addon.detectors = [_StubDetector([finding])]

            f = tflow.tflow(
                req=tutils.treq(host="api.telegram.org", path=raw_path), resp=True
            )
            enrich_addon.response(f)

            (stored_path,) = store_addon.db.conn.execute(
                "SELECT path FROM flows WHERE id = ?", (f.id,)
            ).fetchone()
            (stored_evidence,) = store_addon.db.conn.execute(
                "SELECT evidence FROM findings WHERE flow_id = ?", (f.id,)
            ).fetchone()
            assert stored_path == (
                "/bot<redacted:telegram-bot-token>/sendMessage"
                "?chat_id=<redacted:query-value>&text=<redacted:query-value>"
            )
            assert token not in stored_path
            assert "987654321" not in stored_path
            assert "private" not in stored_path
            assert token not in stored_evidence
            assert "987654321" not in stored_evidence
            assert "private" not in stored_evidence
            store_addon.done()


class TestEnrichBodyCapture:
    @pytest.mark.asyncio
    async def test_bodies_not_captured_by_default(self, tmp_path):
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            store_addon.running()
            enrich_addon.detectors = []

            f = tflow.tflow(resp=True)
            enrich_addon.response(f)

            assert (
                store_addon.db.conn.execute("SELECT COUNT(*) FROM bodies").fetchone()[0]
                == 0
            )
            store_addon.done()

    @pytest.mark.asyncio
    async def test_redacted_mode_stores_redacted_bytes(self, tmp_path):
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            tctx.options.firetoll_store_bodies = True
            store_addon.running()
            enrich_addon.detectors = []

            body = json.dumps({"prompt": "a secret prompt"}).encode()
            f = tflow.tflow(
                req=tutils.treq(host="example.com", path="/"),
                resp=tutils.tresp(content=body),
            )
            enrich_addon.response(f)

            content, truncated, redacted, sha256, content_type = store_addon.db.get_body(
                f.id, "response"
            )
            assert b"a secret prompt" not in content
            assert redacted is True
            assert truncated is False
            assert sha256 is not None
            assert content_type == "application/json"
            store_addon.done()

    @pytest.mark.asyncio
    async def test_full_access_stores_raw_bytes(self, tmp_path):
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            tctx.options.firetoll_store_bodies = True
            tctx.options.firetoll_body_access = "full"
            store_addon.running()
            enrich_addon.detectors = []

            body = json.dumps({"prompt": "a secret prompt"}).encode()
            f = tflow.tflow(
                req=tutils.treq(host="example.com", path="/"),
                resp=tutils.tresp(content=body),
            )
            enrich_addon.response(f)

            content, truncated, redacted, sha256, content_type = store_addon.db.get_body(
                f.id, "response"
            )
            assert content == body
            assert redacted is False
            assert sha256 == hashlib.sha256(body).hexdigest()
            assert content_type == "application/json"
            store_addon.done()

    @pytest.mark.asyncio
    async def test_oversized_body_is_truncated_and_counted(self, tmp_path):
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            tctx.options.firetoll_store_bodies = True
            tctx.options.firetoll_body_access = "full"
            store_addon.running()
            enrich_addon.detectors = []

            big_body = b"x" * (enrich.BODY_SIZE_CAP + 1000)
            f = tflow.tflow(
                req=tutils.treq(host="example.com", path="/"),
                resp=tutils.tresp(content=big_body),
            )
            enrich_addon.response(f)

            content, truncated, _redacted, _sha256, _content_type = (
                store_addon.db.get_body(f.id, "response")
            )
            assert len(content) == enrich.BODY_SIZE_CAP
            assert truncated is True
            (truncated_count,) = store_addon.db.conn.execute(
                "SELECT COUNT(*) FROM bodies WHERE truncated = 1"
            ).fetchone()
            assert truncated_count == 1
            store_addon.done()

    @pytest.mark.asyncio
    async def test_streamed_body_not_captured(self, tmp_path):
        store_addon = store.FiretollStore()
        enrich_addon = enrich.Enrich(store_addon)
        with _context(store_addon, enrich_addon) as tctx:
            tctx.options.firetoll_store_path = str(tmp_path / "s.sqlite")
            tctx.options.firetoll_store_bodies = True
            store_addon.running()
            enrich_addon.detectors = []

            f = tflow.tflow(resp=True)
            f.response.raw_content = None  # simulates a streamed body
            enrich_addon.response(f)

            assert store_addon.db.get_body(f.id, "response") is None
            store_addon.done()
