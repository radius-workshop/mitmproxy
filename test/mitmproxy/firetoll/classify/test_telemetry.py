import json

from mitmproxy.firetoll.classify import telemetry
from mitmproxy.test import tflow
from mitmproxy.test import tutils


class TestSignatureMatch:
    def test_known_host(self):
        detector = telemetry.TelemetryDetector()
        f = tflow.tflow(req=tutils.treq(host="api.segment.io", path="/v1/track"))
        findings = detector.detect(f)
        assert len(findings) == 1
        assert findings[0].cls == "telemetry"
        assert findings[0].confidence == "signature"
        assert findings[0].facts["vendor"] == "Segment"
        assert findings[0].evidence

    def test_host_suffix(self):
        detector = telemetry.TelemetryDetector()
        f = tflow.tflow(
            req=tutils.treq(host="events.something.statsig.com", path="/rgstr")
        )
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "Statsig"

    def test_path_pattern(self):
        detector = telemetry.TelemetryDetector()
        f = tflow.tflow(
            req=tutils.treq(host="otel-collector.internal", path="/v1/traces")
        )
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "OTLP"

    def test_no_match_returns_empty(self):
        detector = telemetry.TelemetryDetector()
        f = tflow.tflow(req=tutils.treq(host="example.com", path="/"))
        assert detector.detect(f) == []


class TestHeuristicMatch:
    def test_event_envelope_post(self):
        detector = telemetry.TelemetryDetector()
        body = json.dumps({"event": "signup", "distinct_id": "abc123"}).encode()
        f = tflow.tflow(
            req=tutils.treq(
                host="example.com",
                path="/analytics",
                method=b"POST",
                headers=[(b"content-type", b"application/json")],
                content=body,
            )
        )
        findings = detector.detect(f)
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"
        assert findings[0].facts["event"] == "signup"

    def test_non_json_post_no_match(self):
        detector = telemetry.TelemetryDetector()
        f = tflow.tflow(
            req=tutils.treq(
                host="example.com",
                path="/analytics",
                method=b"POST",
                headers=[(b"content-type", b"text/plain")],
                content=b"not json",
            )
        )
        assert detector.detect(f) == []

    def test_json_without_event_shape_no_match(self):
        detector = telemetry.TelemetryDetector()
        body = json.dumps({"foo": "bar"}).encode()
        f = tflow.tflow(
            req=tutils.treq(
                host="example.com",
                path="/api",
                method=b"POST",
                headers=[(b"content-type", b"application/json")],
                content=body,
            )
        )
        assert detector.detect(f) == []

    def test_malformed_json_post_no_match(self):
        detector = telemetry.TelemetryDetector()
        f = tflow.tflow(
            req=tutils.treq(
                host="example.com",
                path="/analytics",
                method=b"POST",
                headers=[(b"content-type", b"application/json")],
                content=b"{not valid json",
            )
        )
        assert detector.detect(f) == []

    def test_get_request_not_matched_by_heuristic(self):
        detector = telemetry.TelemetryDetector()
        body = json.dumps({"event": "signup", "distinct_id": "abc123"}).encode()
        f = tflow.tflow(
            req=tutils.treq(
                host="example.com",
                path="/analytics",
                method=b"GET",
                headers=[(b"content-type", b"application/json")],
                content=body,
            )
        )
        assert detector.detect(f) == []


class TestCorpusOverride:
    def test_extra_vendor_from_corpus_dir(self, tmp_path):
        (tmp_path / "telemetry.yaml").write_text(
            "vendors:\n"
            "  - name: InternalTelemetry\n"
            "    hosts: [telemetry.internal.example]\n"
        )
        detector = telemetry.TelemetryDetector(corpus_dir=str(tmp_path))
        f = tflow.tflow(
            req=tutils.treq(host="telemetry.internal.example", path="/collect")
        )
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "InternalTelemetry"

    def test_missing_corpus_file_does_not_raise(self, tmp_path):
        detector = telemetry.TelemetryDetector(corpus_dir=str(tmp_path))
        f = tflow.tflow(req=tutils.treq(host="example.com", path="/"))
        assert detector.detect(f) == []
