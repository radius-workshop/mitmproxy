"""Layer 2 orchestrator: run every registered detector over each flow.

A detector that raises must never affect the flow - each is wrapped in its
own try/except and only logged. Findings land on
`flow.metadata["firetoll.findings"]` (so they survive `.mitm` save/load) and,
when a store is wired in, in the session store.
"""

from __future__ import annotations

import logging

from mitmproxy import ctx
from mitmproxy import http
from mitmproxy.firetoll import redact
from mitmproxy.firetoll.classify import default_detectors
from mitmproxy.firetoll.classify import Detector
from mitmproxy.firetoll.classify.botdetect import tls_client_profile
from mitmproxy.firetoll.classify.party import etld1
from mitmproxy.firetoll.finding import Finding
from mitmproxy.firetoll.store import FiretollStore

logger = logging.getLogger(__name__)

# Bodies are capped before storage regardless of redaction mode.
BODY_SIZE_CAP = 64 * 1024


class Enrich:
    def __init__(self, store_addon: FiretollStore | None = None) -> None:
        self.store_addon = store_addon
        self.detectors: list[Detector] = []

    def running(self) -> None:
        if not ctx.options.firetoll:
            return
        self.detectors = default_detectors(ctx.options.firetoll_corpus_dir or None)

    def _run_detectors(self, flow: http.HTTPFlow) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self.detectors:
            try:
                for finding in detector.detect(flow):
                    findings.append(
                        Finding(
                            cls=finding.cls,
                            label=finding.label,
                            confidence=finding.confidence,
                            evidence=[
                                redact.sanitize_path_evidence(item)
                                for item in finding.evidence
                            ],
                            facts=dict(finding.facts),
                        )
                    )
            except Exception:
                logger.exception(
                    f"firetoll: detector {getattr(detector, 'name', detector)!r} "
                    f"raised on flow {flow.id}; ignoring"
                )
        return findings

    def _extract_identifiers(self, flow: http.HTTPFlow) -> set[str]:
        values: set[str] = set()
        for detector in self.detectors:
            extract = getattr(detector, "extract_identifiers", None)
            if extract is None:
                continue
            try:
                values.update(extract(flow))
            except Exception:
                logger.exception(
                    f"firetoll: detector {getattr(detector, 'name', detector)!r} "
                    f"raised extracting identifiers on flow {flow.id}; ignoring"
                )
        return values

    def _capture_bodies(
        self,
        db,
        flow: http.HTTPFlow,
        request_body: bytes | None,
        response_body: bytes | None,
    ) -> None:
        """Persist redacted, size-capped bodies - unless the human running
        mitmproxy has explicitly set `firetoll_body_access=full`, in which
        case raw bodies are captured. This is the only place that decision
        is made: the MCP server (a separate, later process) only ever
        serves what was captured here, so it cannot retroactively widen
        access to a session captured under a stricter setting."""
        full_access = ctx.options.firetoll_body_access == "full"
        for part, body in (("request", request_body), ("response", response_body)):
            if body is None:
                continue
            content = body if full_access else redact.redact_bytes(body)
            content, truncated = redact.truncate(content, BODY_SIZE_CAP)
            db.record_body(
                flow_id=flow.id,
                part=part,
                content=content,
                truncated=truncated,
                redacted=not full_access,
            )

    def response(self, flow: http.HTTPFlow) -> None:
        if not ctx.options.firetoll or flow.response is None:
            return

        findings = self._run_detectors(flow)
        if findings:
            flow.metadata.setdefault("firetoll.findings", [])
            flow.metadata["firetoll.findings"].extend(f.to_dict() for f in findings)

        db = self.store_addon.db if self.store_addon else None
        if db is None:
            return

        app_info = flow.metadata.get("firetoll.app")
        app_id = None
        if app_info:
            app_id = db.record_app(
                process=app_info.get("process"),
                path=app_info.get("path"),
                parent=app_info.get("parent"),
                source=app_info["source"],
            )
            if app_info["source"] == "unknown":
                db.increment_counter("unattributed_flows")
        else:
            db.increment_counter("unattributed_flows")

        request_body = flow.request.get_content(strict=False)
        response_body = flow.response.get_content(strict=False)
        if request_body is None or response_body is None:
            db.increment_counter("streamed_bodies")

        tls_profile_hash = None
        if flow.client_conn.tls_established:
            tls_profile_hash = tls_client_profile(flow.client_conn)["tls_profile_hash"]

        db.record_flow(
            flow_id=flow.id,
            app_id=app_id,
            method=flow.request.method,
            host=flow.request.pretty_host,
            path=redact.sanitize_path(flow.request.path),
            status=flow.response.status_code,
            request_bytes=len(request_body) if request_body is not None else None,
            response_bytes=len(response_body) if response_body is not None else None,
            tls_profile_hash=tls_profile_hash,
        )
        for finding in findings:
            db.record_finding(flow.id, finding)

        if ctx.options.firetoll_store_bodies:
            self._capture_bodies(db, flow, request_body, response_body)

        host_etld1 = etld1(flow.request.pretty_host)
        for value in self._extract_identifiers(flow):
            db.record_identity(value=value, etld1=host_etld1, flow_id=flow.id)
