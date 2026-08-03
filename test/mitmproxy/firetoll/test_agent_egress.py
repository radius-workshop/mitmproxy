import json

from mitmproxy.firetoll.classify import agent_egress
from mitmproxy.test import tflow
from mitmproxy.test import tutils


def _flow(**req_kwargs):
    req_kwargs.setdefault("host", "example.com")
    req_kwargs.setdefault("path", "/")
    return tflow.tflow(req=tutils.treq(**req_kwargs), resp=True)


class TestWebSocketUpgrade:
    def test_101_with_permessage_deflate(self):
        detector = agent_egress.AgentEgressDetector()
        f = _flow(host="chatgpt.com", path="/ws")
        f.response = tutils.tresp(
            status_code=101,
            headers=[
                (b"upgrade", b"websocket"),
                (b"connection", b"Upgrade"),
                (b"sec-websocket-extensions", b"permessage-deflate"),
            ],
        )
        findings = detector.detect(f)
        ws_findings = [x for x in findings if x.label == "WebSocket upgrade"]
        assert len(ws_findings) == 1
        assert ws_findings[0].confidence == "signature"
        assert ws_findings[0].facts["negotiated_extensions"] == "permessage-deflate"
        assert any("status=101" in e for e in ws_findings[0].evidence)

    def test_no_upgrade_no_finding(self):
        detector = agent_egress.AgentEgressDetector()
        f = _flow()
        assert detector.detect(f) == []

    def test_no_response_no_finding(self):
        detector = agent_egress.AgentEgressDetector()
        f = tflow.tflow(req=tutils.treq(), resp=False)
        assert detector.detect(f) == []


class TestProviderDetection:
    def test_anthropic_messages(self):
        detector = agent_egress.AgentEgressDetector()
        body = json.dumps({"model": "claude-sonnet-5", "messages": []}).encode()
        f = _flow(
            host="api.anthropic.com",
            path="/v1/messages",
            method=b"POST",
            content=body,
        )
        findings = detector.detect(f)
        provider_findings = [x for x in findings if "inference call" in x.label]
        assert len(provider_findings) == 1
        finding = provider_findings[0]
        assert finding.confidence == "signature"
        assert finding.facts["provider"] == "Anthropic"
        assert finding.facts["model"] == "claude-sonnet-5"
        assert finding.facts["request"]["bytes"] == len(body)

    def test_openai_chat_completions(self):
        detector = agent_egress.AgentEgressDetector()
        body = json.dumps({"model": "gpt-5.6-sol"}).encode()
        f = _flow(
            host="api.openai.com",
            path="/v1/chat/completions",
            method=b"POST",
            content=body,
        )
        findings = detector.detect(f)
        assert findings[0].facts["provider"] == "OpenAI"
        assert findings[0].facts["model"] == "gpt-5.6-sol"

    def test_codex_backend(self):
        detector = agent_egress.AgentEgressDetector()
        f = _flow(
            host="chatgpt.com", path="/backend-api/codex/responses", method=b"POST"
        )
        findings = detector.detect(f)
        assert findings[0].facts["provider"] == "OpenAI (Codex)"

    def test_bedrock_invoke(self):
        detector = agent_egress.AgentEgressDetector()
        f = _flow(
            host="bedrock-runtime.us-east-1.amazonaws.com",
            path="/model/anthropic.claude-v2/invoke",
            method=b"POST",
        )
        findings = detector.detect(f)
        assert findings[0].facts["provider"] == "AWS Bedrock"

    def test_vertex_generate_content(self):
        detector = agent_egress.AgentEgressDetector()
        f = _flow(
            host="us-central1-aiplatform.googleapis.com",
            path="/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5:generateContent",
            method=b"POST",
        )
        findings = detector.detect(f)
        assert findings[0].facts["provider"] == "Google Vertex AI"

    def test_unrecognized_host_no_provider_finding(self):
        detector = agent_egress.AgentEgressDetector()
        f = _flow(host="example.com", path="/v1/messages", method=b"POST")
        provider_findings = [
            x for x in detector.detect(f) if "inference call" in x.label
        ]
        assert provider_findings == []

    def test_prompt_text_never_appears_in_facts(self):
        detector = agent_egress.AgentEgressDetector()
        body = json.dumps(
            {
                "model": "claude-sonnet-5",
                "messages": [{"role": "user", "content": "my secret prompt"}],
            }
        ).encode()
        f = _flow(
            host="api.anthropic.com", path="/v1/messages", method=b"POST", content=body
        )
        findings = detector.detect(f)
        finding = [x for x in findings if "inference call" in x.label][0]
        assert "my secret prompt" not in json.dumps(finding.facts)
        assert "my secret prompt" not in json.dumps(finding.evidence)


class TestSSEHeuristic:
    def test_event_stream_without_provider_match(self):
        detector = agent_egress.AgentEgressDetector()
        f = _flow(host="example.com", path="/stream")
        f.response.headers["content-type"] = "text/event-stream"
        findings = detector.detect(f)
        sse_findings = [x for x in findings if x.label == "server-sent events stream"]
        assert len(sse_findings) == 1
        assert sse_findings[0].confidence == "heuristic"

    def test_no_double_count_when_provider_matches(self):
        detector = agent_egress.AgentEgressDetector()
        body = json.dumps({"model": "claude-sonnet-5"}).encode()
        f = _flow(
            host="api.anthropic.com", path="/v1/messages", method=b"POST", content=body
        )
        f.response.headers["content-type"] = "text/event-stream"
        findings = detector.detect(f)
        assert [
            x.label for x in findings if "stream" in x.label or "inference" in x.label
        ] == ["Anthropic inference call"]


class TestMcpDetection:
    def test_tools_call_extracts_tool_name(self):
        detector = agent_egress.AgentEgressDetector()
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}},
            }
        ).encode()
        f = _flow(
            host="localhost",
            path="/mcp",
            method=b"POST",
            headers=[(b"content-type", b"application/json")],
            content=body,
        )
        findings = detector.detect(f)
        mcp_findings = [x for x in findings if x.label.startswith("MCP")]
        assert len(mcp_findings) == 1
        assert mcp_findings[0].facts["tool"] == "read_file"
        assert "/etc/passwd" not in json.dumps(mcp_findings[0].facts)

    def test_initialize_method(self):
        detector = agent_egress.AgentEgressDetector()
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode()
        f = _flow(
            host="localhost",
            path="/mcp",
            method=b"POST",
            headers=[(b"content-type", b"application/json")],
            content=body,
        )
        findings = detector.detect(f)
        assert any(x.facts.get("method") == "initialize" for x in findings)

    def test_non_mcp_json_post_no_finding(self):
        detector = agent_egress.AgentEgressDetector()
        body = json.dumps({"foo": "bar"}).encode()
        f = _flow(
            host="localhost",
            path="/api",
            method=b"POST",
            headers=[(b"content-type", b"application/json")],
            content=body,
        )
        assert [x for x in detector.detect(f) if x.label.startswith("MCP")] == []

    def test_get_request_not_matched(self):
        detector = agent_egress.AgentEgressDetector()
        body = json.dumps({"jsonrpc": "2.0", "method": "tools/list"}).encode()
        f = _flow(
            host="localhost",
            path="/mcp",
            method=b"GET",
            headers=[(b"content-type", b"application/json")],
            content=body,
        )
        assert [x for x in detector.detect(f) if x.label.startswith("MCP")] == []
