import hashlib
import json

from mitmproxy.firetoll import redact


class TestPromptRedaction:
    def test_content_field_replaced_wholesale(self):
        body = json.dumps(
            {"messages": [{"role": "user", "content": "my secret prompt"}]}
        ).encode()
        redacted = json.loads(redact.redact_bytes(body))
        content = redacted["messages"][0]["content"]
        assert "my secret prompt" not in content
        assert content.startswith("<redacted:prompt-text len=")

    def test_placeholder_carries_length_and_hash(self):
        value = "hello world"
        body = json.dumps({"prompt": value}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        digest = hashlib.sha256(value.encode()).hexdigest()[:12]
        assert (
            redacted["prompt"]
            == f"<redacted:prompt-text len={len(value)} sha256={digest}>"
        )

    def test_empty_prompt_left_alone(self):
        body = json.dumps({"prompt": ""}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert redacted["prompt"] == ""


class TestSecretKeyRedaction:
    def test_authorization_key_redacted(self):
        body = json.dumps({"authorization": "Bearer abc123"}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert redacted["authorization"] == "<redacted:secret-key>"

    def test_api_key_redacted_regardless_of_key_casing(self):
        body = json.dumps({"API_KEY": "sekrit"}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert redacted["API_KEY"] == "<redacted:secret-key>"

    def test_unrelated_key_untouched(self):
        body = json.dumps({"username": "alice"}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert redacted["username"] == "alice"


class TestPatternRedaction:
    def test_openai_api_key_shape(self):
        body = json.dumps({"note": "key is sk-abcdefghijklmnopqrstuvwx"}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert "sk-abcdefghijklmnopqrstuvwx" not in redacted["note"]
        assert "<redacted:openai-api-key>" in redacted["note"]

    def test_aws_key_shape(self):
        body = json.dumps({"note": "AKIAABCDEFGHIJKLMNOP"}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert "<redacted:aws-access-key-id>" in redacted["note"]

    def test_github_token_shape(self):
        token = "ghp_" + "a" * 36
        body = json.dumps({"note": token}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert token not in redacted["note"]
        assert "<redacted:github-token>" in redacted["note"]

    def test_jwt_shape(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ"
        body = json.dumps({"note": jwt}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert "<redacted:jwt>" in redacted["note"]

    def test_email_shape(self):
        body = json.dumps({"note": "contact me at a@example.com please"}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert "a@example.com" not in redacted["note"]
        assert "<redacted:email>" in redacted["note"]

    def test_ipv4_shape(self):
        body = json.dumps({"note": "client at 192.168.1.42"}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert "192.168.1.42" not in redacted["note"]
        assert "<redacted:ipv4>" in redacted["note"]

    def test_card_number_shape(self):
        body = json.dumps({"note": "card 4111 1111 1111 1111 on file"}).encode()
        redacted = json.loads(redact.redact_bytes(body))
        assert "4111 1111 1111 1111" not in redacted["note"]
        assert "<redacted:card-number>" in redacted["note"]


class TestNonJsonBodies:
    def test_sse_data_line_json_redacted(self):
        body = b'data: {"choices": [{"delta": {"content": "secret token stream"}}]}\n\n'
        redacted = redact.redact_bytes(body).decode()
        assert "secret token stream" not in redacted
        assert "<redacted:prompt-text" in redacted

    def test_sse_data_line_non_json_pattern_redacted(self):
        body = b"data: contact a@example.com\n\n"
        redacted = redact.redact_bytes(body).decode()
        assert "a@example.com" not in redacted
        assert "<redacted:email>" in redacted

    def test_plain_text_pattern_redacted(self):
        body = b"error from 10.0.0.5, contact ops@example.com"
        redacted = redact.redact_bytes(body).decode()
        assert "10.0.0.5" not in redacted
        assert "ops@example.com" not in redacted

    def test_binary_body_does_not_raise(self):
        body = bytes(range(256))
        redacted = redact.redact_bytes(body)
        assert b"redacted:binary-content" in redacted

    def test_empty_body_returned_as_is(self):
        assert redact.redact_bytes(b"") == b""


class TestTruncate:
    def test_under_cap_unchanged(self):
        data, truncated = redact.truncate(b"short", 100)
        assert data == b"short"
        assert truncated is False

    def test_over_cap_truncated(self):
        data, truncated = redact.truncate(b"x" * 200, 100)
        assert len(data) == 100
        assert truncated is True

    def test_exactly_at_cap_not_truncated(self):
        data, truncated = redact.truncate(b"x" * 100, 100)
        assert truncated is False


class TestPathRedaction:
    def test_query_names_retained_but_all_values_redacted(self):
        path = "/v1/messages?api_key=super-secret&email=alice%40example.com&debug"
        sanitized = redact.sanitize_path(path)
        assert sanitized == (
            "/v1/messages?api_key=<redacted:query-value>"
            "&email=<redacted:query-value>&<redacted:query-value>"
        )
        assert "super-secret" not in sanitized
        assert "alice" not in sanitized

    def test_email_and_identifier_segments_redacted(self):
        path = "/users/alice%40example.com/sessions/550e8400-e29b-41d4-a716-446655440000"
        assert redact.sanitize_path(path) == (
            "/users/<redacted:email>/sessions/<redacted:path-identifier>"
        )

    def test_telegram_bot_token_segment_redacted(self):
        token = "123456789:AAExampleTelegramBotToken_0123456789"
        sanitized = redact.sanitize_path(f"/bot{token}/sendMessage")
        assert sanitized == "/bot<redacted:telegram-bot-token>/sendMessage"
        assert token not in sanitized

    def test_high_entropy_and_credential_value_segments_redacted(self):
        path = "/downloads/aB3dE5fG7hJ9kL2mN4pQ6rS8/token/plain-looking-secret"
        assert redact.sanitize_path(path) == (
            "/downloads/<redacted:high-entropy-segment>/token/"
            "<redacted:path-credential>"
        )

    def test_ordinary_stable_path_is_unchanged(self):
        assert redact.sanitize_path("/v1/messages/batch-create") == (
            "/v1/messages/batch-create"
        )

    def test_path_redaction_is_idempotent(self):
        original = "/users/alice@example.com?token=secret#private"
        once = redact.sanitize_path(original)
        assert redact.sanitize_path(once) == once
        assert once.count("<redacted:email>") == 1
        assert once.count("<redacted:query-value>") == 1
        assert once.count("<redacted:fragment>") == 1

    def test_path_evidence_is_sanitized_without_changing_other_evidence(self):
        token = "123456789:AAExampleTelegramBotToken_0123456789"
        assert redact.sanitize_path_evidence(f"path=/bot{token}/sendMessage?q=x") == (
            "path=/bot<redacted:telegram-bot-token>/sendMessage"
            "?q=<redacted:query-value>"
        )
        assert redact.sanitize_path_evidence("host=api.telegram.org") == (
            "host=api.telegram.org"
        )


class TestRulesCatalog:
    def test_rules_have_names_and_descriptions(self):
        assert len(redact.RULES) >= 8
        for rule in redact.RULES:
            assert rule.name
            assert rule.description
