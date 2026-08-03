"""Detector protocol + default registry. A detector inspects one flow and
returns zero or more Findings; it must never raise for a flow it doesn't
understand - return an empty list instead. The orchestrator (`enrich.py`)
isolates detector exceptions anyway, but a well-behaved detector shouldn't
need that safety net.
"""

from __future__ import annotations

import typing

from mitmproxy import http
from mitmproxy.firetoll.finding import Finding


@typing.runtime_checkable
class Detector(typing.Protocol):
    name: str

    def detect(self, flow: http.HTTPFlow) -> list[Finding]: ...


def default_detectors(corpus_dir: str | None = None) -> list[Detector]:
    from mitmproxy.firetoll.classify.agent_egress import AgentEgressDetector
    from mitmproxy.firetoll.classify.botdetect import BotDetectDetector
    from mitmproxy.firetoll.classify.telemetry import TelemetryDetector
    from mitmproxy.firetoll.classify.trackers import TrackerDetector
    from mitmproxy.firetoll.x402 import X402Detector

    return [
        TelemetryDetector(corpus_dir),
        AgentEgressDetector(),
        TrackerDetector(corpus_dir),
        BotDetectDetector(),
        X402Detector(),
    ]
