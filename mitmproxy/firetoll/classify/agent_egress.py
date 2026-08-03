"""Detector: AI-agent egress - the class no existing tool labels.

Provider inference calls, MCP JSON-RPC traffic, and WebSocket upgrade
handshakes are reported as byte counts and structural metadata (model id,
method name, tool name, negotiated extensions) - never as prompt or
completion text. That's what lets an agent reason about its own traffic
without this detector becoming the very leak it's supposed to reveal.
"""

from __future__ import annotations

import hashlib
import json
import re

from mitmproxy import http
from mitmproxy.firetoll.finding import Finding

# (provider label, path pattern) keyed by host. Bedrock/Vertex are matched by
# path shape since they're hosted on generic AWS/GCP domains.
_PROVIDER_HOSTS: dict[str, tuple[str, re.Pattern]] = {
    "api.anthropic.com": ("Anthropic", re.compile(r"^/v1/messages")),
    "api.openai.com": ("OpenAI", re.compile(r"^/v1/(chat/completions|responses)")),
    "chatgpt.com": ("OpenAI (Codex)", re.compile(r"^/backend-api/codex/responses")),
}
_BEDROCK_PATH = re.compile(
    r"^/model/[^/]+/(invoke|invoke-with-response-stream|converse)"
)
_VERTEX_PATH = re.compile(
    r"/publishers/[^/]+/models/[^/]+:(generateContent|streamGenerateContent)"
)

_MCP_METHODS = {
    "initialize",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
}


def _byte_summary(data: bytes | None) -> dict:
    if not data:
        return {"bytes": 0}
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()[:12]}


def _parse_json(body: bytes | None):
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None


class AgentEgressDetector:
    name = "agent_egress"

    def detect(self, flow: http.HTTPFlow) -> list[Finding]:
        findings: list[Finding] = []

        websocket_finding = self._detect_websocket_upgrade(flow)
        if websocket_finding:
            findings.append(websocket_finding)

        provider_finding = self._detect_provider(flow)
        if provider_finding:
            findings.append(provider_finding)
        elif (sse_finding := self._detect_sse(flow)) is not None:
            findings.append(sse_finding)

        mcp_finding = self._detect_mcp(flow)
        if mcp_finding:
            findings.append(mcp_finding)

        return findings

    def _detect_websocket_upgrade(self, flow: http.HTTPFlow) -> Finding | None:
        response = flow.response
        if response is None or response.status_code != 101:
            return None
        evidence = ["status=101", f"upgrade={response.headers.get('upgrade', '')}"]
        facts = {}
        extensions = response.headers.get("sec-websocket-extensions", "")
        if extensions:
            evidence.append(f"sec-websocket-extensions={extensions}")
            facts["negotiated_extensions"] = extensions
        return Finding(
            cls="agent_egress",
            label="WebSocket upgrade",
            confidence="signature",
            evidence=evidence,
            facts=facts,
        )

    def _provider_for(self, host: str, path: str) -> str | None:
        entry = _PROVIDER_HOSTS.get(host)
        if entry and entry[1].search(path):
            return entry[0]
        if _BEDROCK_PATH.search(path):
            return "AWS Bedrock"
        if _VERTEX_PATH.search(path):
            return "Google Vertex AI"
        return None

    def _detect_provider(self, flow: http.HTTPFlow) -> Finding | None:
        host = flow.request.pretty_host
        path = flow.request.path or "/"
        provider = self._provider_for(host, path)
        if provider is None:
            return None

        request_body = flow.request.get_content(strict=False)
        response_body = (
            flow.response.get_content(strict=False) if flow.response else None
        )
        facts = {
            "provider": provider,
            "request": _byte_summary(request_body),
            "response": _byte_summary(response_body),
        }
        model = self._extract_model(request_body)
        if model:
            facts["model"] = model

        return Finding(
            cls="agent_egress",
            label=f"{provider} inference call",
            confidence="signature",
            evidence=[f"host={host}", f"path={path}"],
            facts=facts,
        )

    def _extract_model(self, body: bytes | None) -> str | None:
        data = _parse_json(body)
        if isinstance(data, dict) and isinstance(data.get("model"), str):
            return data["model"]
        return None

    def _detect_sse(self, flow: http.HTTPFlow) -> Finding | None:
        response = flow.response
        if response is None:
            return None
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" not in content_type:
            return None
        return Finding(
            cls="agent_egress",
            label="server-sent events stream",
            confidence="heuristic",
            evidence=[
                f"host={flow.request.pretty_host}",
                f"content-type={content_type}",
            ],
            facts={},
        )

    def _detect_mcp(self, flow: http.HTTPFlow) -> Finding | None:
        request = flow.request
        if request.method != "POST" or "json" not in request.headers.get(
            "content-type", ""
        ):
            return None
        data = _parse_json(request.get_content(strict=False))
        candidates = data if isinstance(data, list) else [data]
        for candidate in candidates:
            if not isinstance(candidate, dict) or candidate.get("jsonrpc") != "2.0":
                continue
            method = candidate.get("method")
            if method not in _MCP_METHODS:
                continue
            facts = {"method": method}
            if method == "tools/call":
                params = candidate.get("params")
                if isinstance(params, dict) and isinstance(params.get("name"), str):
                    facts["tool"] = params["name"]
            return Finding(
                cls="agent_egress",
                label=f"MCP {method}",
                confidence="signature",
                evidence=["jsonrpc=2.0", f"method={method}"],
                facts=facts,
            )
        return None
