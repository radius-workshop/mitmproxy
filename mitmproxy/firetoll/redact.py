"""The redaction gate.

Applied at body-capture time (see `enrich.py`), so a redacted body is what
ever lands on disk unless the human running mitmproxy has explicitly set
`firetoll_body_access=full` *before* the body was captured - the MCP server
cannot widen this after the fact, it only serves whatever was already
stored.

Model prompt/completion text is never partially redacted: the whole field
becomes `<redacted:prompt-text len=N sha256=H>`. Length and hash let an
agent detect repeats, growth, and duplication across hosts without ever
reading the content - the single detail that best embodies the point of
this whole feature.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

_PROMPT_KEYS = {"content", "prompt", "input", "completion", "text", "message"}
_SECRET_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "token",
}

_PATTERNS = {
    "openai-api-key": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "aws-access-key-id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github-token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    # card-number must run before phone: both match digit-with-separator
    # runs, and a 13-19 digit grouping is more specifically card-shaped.
    "card-number": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "phone": re.compile(r"\+?\d[\d\-.\s]{7,}\d"),
}


@dataclass
class RedactionRule:
    name: str
    description: str


RULES = [
    RedactionRule(
        "prompt-text",
        "Model prompt/completion fields (messages[].content, input, prompt, "
        "completion, SSE data text) - replaced wholesale, never partially.",
    ),
    RedactionRule(
        "secret-key",
        "JSON keys that are secrets by name (authorization, cookie, api_key, "
        "token, password, ...) - value replaced regardless of shape.",
    ),
    RedactionRule("openai-api-key", "sk-... shaped API keys."),
    RedactionRule("aws-access-key-id", "AKIA... shaped AWS access key IDs."),
    RedactionRule("github-token", "ghp_... shaped GitHub personal access tokens."),
    RedactionRule("jwt", "JSON Web Tokens (three base64url segments)."),
    RedactionRule("email", "Email addresses."),
    RedactionRule("ipv4", "IPv4 addresses."),
    RedactionRule("phone", "Phone-number-shaped digit runs."),
    RedactionRule("card-number", "Card-number-shaped digit runs (13-19 digits)."),
]


def _prompt_placeholder(value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:12]
    return f"<redacted:prompt-text len={len(value)} sha256={digest}>"


def _redact_value(key: str, value):
    lowered_key = key.lower()
    if isinstance(value, str) and value:
        if lowered_key in _SECRET_KEYS:
            return "<redacted:secret-key>"
        if lowered_key in _PROMPT_KEYS:
            return _prompt_placeholder(value)
    return value


def _walk(value):
    if isinstance(value, dict):
        result = {}
        for key, val in value.items():
            replaced = _redact_value(key, val)
            result[key] = replaced if replaced is not val else _walk(val)
        return result
    if isinstance(value, list):
        return [_walk(v) for v in value]
    return value


def _apply_patterns(text: str) -> str:
    for name, pattern in _PATTERNS.items():
        text = pattern.sub(f"<redacted:{name}>", text)
    return text


_SSE_DATA_LINE = re.compile(rb"^data:[ \t]*(.*)$", re.MULTILINE)


def _redact_sse(data: bytes) -> bytes:
    def _redact_line(match: re.Match) -> bytes:
        payload = match.group(1)
        try:
            parsed = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            return (
                b"data: " + _apply_patterns(payload.decode(errors="replace")).encode()
            )
        return b"data: " + json.dumps(_walk(parsed), ensure_ascii=False).encode()

    return _SSE_DATA_LINE.sub(_redact_line, data)


def redact_bytes(data: bytes) -> bytes:
    """Redact a request/response body. JSON bodies are walked key-by-key
    (secret keys and prompt/completion fields replaced wholesale); anything
    else falls back to SSE `data:` line handling, then plain pattern
    substitution over the decoded text."""
    if not data:
        return data

    try:
        parsed = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        pass
    else:
        text = json.dumps(_walk(parsed), ensure_ascii=False)
        return _apply_patterns(text).encode()

    if _SSE_DATA_LINE.search(data):
        data = _redact_sse(data)

    try:
        text = data.decode()
    except UnicodeDecodeError:
        return f"<redacted:binary-content len={len(data)}>".encode()
    return _apply_patterns(text).encode()


def truncate(data: bytes, cap: int) -> tuple[bytes, bool]:
    if len(data) <= cap:
        return data, False
    return data[:cap], True
