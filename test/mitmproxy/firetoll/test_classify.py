from mitmproxy.firetoll.classify import default_detectors
from mitmproxy.firetoll.classify import Detector
from mitmproxy.firetoll.classify.agent_egress import AgentEgressDetector
from mitmproxy.firetoll.classify.botdetect import BotDetectDetector
from mitmproxy.firetoll.classify.telemetry import TelemetryDetector
from mitmproxy.firetoll.classify.trackers import TrackerDetector
from mitmproxy.firetoll.x402 import X402Detector


class TestDefaultDetectors:
    def test_returns_expected_types_and_count(self):
        detectors = default_detectors()
        assert len(detectors) == 5
        types = [type(d) for d in detectors]
        assert types == [
            TelemetryDetector,
            AgentEgressDetector,
            TrackerDetector,
            BotDetectDetector,
            X402Detector,
        ]

    def test_without_corpus_dir(self):
        detectors = default_detectors()
        telemetry_detector = detectors[0]
        tracker_detector = detectors[2]
        assert isinstance(telemetry_detector, TelemetryDetector)
        assert isinstance(tracker_detector, TrackerDetector)
        # Should load the bundled corpus without error.
        assert telemetry_detector._vendors
        assert tracker_detector._vendors

    def test_with_corpus_dir(self, tmp_path):
        detectors = default_detectors(corpus_dir=str(tmp_path))
        telemetry_detector = detectors[0]
        tracker_detector = detectors[2]
        assert isinstance(telemetry_detector, TelemetryDetector)
        assert isinstance(tracker_detector, TrackerDetector)
        assert telemetry_detector._vendors
        assert tracker_detector._vendors


class TestDetectorProtocol:
    def test_default_detectors_satisfy_protocol(self):
        for detector in default_detectors():
            assert isinstance(detector, Detector)
