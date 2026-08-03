"""Detector: telemetry & analytics sinks.

Signature match against the bundled corpus (`data/telemetry.yaml`, extendable
via `firetoll_corpus_dir`) first; falls back to a heuristic for POSTed JSON
that looks like an analytics event envelope (`event` + `properties`/
`distinct_id`/`anonymous_id`). Volume and cadence - not just "this is a
tracker" - are the interesting fact here, so callers should aggregate
`facts["vendor"]` across a session rather than treating each Finding in
isolation.
"""

from __future__ import annotations

import json

from mitmproxy import http
from mitmproxy.firetoll.classify._corpus import load_vendors
from mitmproxy.firetoll.finding import Finding

_EVENT_KEYS = {"event", "properties", "distinct_id", "anonymous_id"}


def _event_envelope(body: bytes) -> dict | None:
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    candidates = data if isinstance(data, list) else [data]
    for candidate in candidates:
        if (
            isinstance(candidate, dict)
            and "event" in candidate
            and _EVENT_KEYS & candidate.keys()
        ):
            return candidate
    return None


class TelemetryDetector:
    name = "telemetry"

    def __init__(self, corpus_dir: str | None = None) -> None:
        self._vendors = load_vendors("telemetry", corpus_dir)

    def detect(self, flow: http.HTTPFlow) -> list[Finding]:
        request = flow.request
        host = request.pretty_host
        path = request.path or "/"

        for vendor in self._vendors:
            if vendor.matches(host, path):
                return [
                    Finding(
                        cls="telemetry",
                        label=f"{vendor.name} telemetry",
                        confidence="signature",
                        evidence=[f"host={host}", f"path={path}"],
                        facts={"vendor": vendor.name},
                    )
                ]

        if request.method == "POST":
            content_type = request.headers.get("content-type", "")
            if "json" in content_type:
                body = request.get_content(strict=False)
                envelope = _event_envelope(body) if body else None
                if envelope is not None:
                    facts = {}
                    event_name = envelope.get("event")
                    if isinstance(event_name, str):
                        facts["event"] = event_name
                    return [
                        Finding(
                            cls="telemetry",
                            label="event-shaped POST",
                            confidence="heuristic",
                            evidence=[
                                f"host={host}",
                                f"content-type={content_type}",
                                "body has event + properties/distinct_id/anonymous_id",
                            ],
                            facts=facts,
                        )
                    ]
        return []
