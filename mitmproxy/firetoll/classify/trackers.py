"""Detector: third-party trackers, and the identity-join computation.

Signature ad/beacon-host matching lives here (`data/trackers.yaml`, same
loader as telemetry.py). The headline capability isn't that list, though -
it's `extract_identifiers()`: pull identifier-shaped values out of cookies,
query params, and JSON bodies so the orchestrator can hand them to the
session store. The store then flags any value seen under two or more
distinct eTLD+1s - a cross-site join computed from the reader's own traffic,
which a blocklist categorically cannot produce.
"""

from __future__ import annotations

import json
import re

from mitmproxy import http
from mitmproxy.firetoll.classify._corpus import load_vendors
from mitmproxy.firetoll.finding import Finding

# Known tracker query/cookie param names - these count as identifiers
# regardless of shape, since they're semantically identifiers by convention.
KNOWN_ID_PARAMS = frozenset(
    {
        "_ga",
        "_gac",
        "_gcl_au",
        "_fbp",
        "_fbc",
        "fbclid",
        "gclid",
        "gbraid",
        "wbraid",
        "msclkid",
        "ttclid",
        "twclid",
        "epik",
    }
)

# UUID / hex / base64url-shaped, at least 16 chars.
_ID_SHAPE = re.compile(r"^[A-Za-z0-9_\-\.]{16,512}$")
_TRIVIAL_SHAPE = re.compile(r"^(?:[0-9]+|[a-z]+|[A-Z]+)$")

_MAX_JSON_DEPTH = 4
_MAX_JSON_VALUES = 100


def looks_like_identifier(value: str) -> bool:
    """A conservative shape check: long enough, character-set matches a
    UUID/hex/base64url token, and not a trivial all-digit or all-one-case
    run (which is more likely a sentence fragment than an identifier)."""
    if not _ID_SHAPE.match(value):
        return False
    return not _TRIVIAL_SHAPE.match(value)


def _walk_json_strings(value, depth: int = 0, budget: list[int] | None = None):
    if budget is None:
        budget = [_MAX_JSON_VALUES]
    if depth > _MAX_JSON_DEPTH or budget[0] <= 0:
        return
    if isinstance(value, str):
        budget[0] -= 1
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _walk_json_strings(v, depth + 1, budget)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_json_strings(v, depth + 1, budget)


def _json_identifier_strings(body: bytes | None):
    if not body:
        return []
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return []
    return [v for v in _walk_json_strings(data) if looks_like_identifier(v)]


def extract_identifiers(flow: http.HTTPFlow) -> list[str]:
    """Candidate identifier values carried by this flow - from query params,
    request/response cookies, and JSON bodies. Named tracker params
    (`KNOWN_ID_PARAMS`) are included regardless of shape; everything else
    must pass `looks_like_identifier`."""
    values: set[str] = set()

    for name, value in flow.request.query.items(multi=True):
        if not value:
            continue
        if name in KNOWN_ID_PARAMS or looks_like_identifier(value):
            values.add(value)

    for name, value in flow.request.cookies.items(multi=True):
        if not value:
            continue
        if name in KNOWN_ID_PARAMS or looks_like_identifier(value):
            values.add(value)

    if flow.response is not None:
        for name, (value, _attrs) in flow.response.cookies.items(multi=True):
            if not value:
                continue
            if name in KNOWN_ID_PARAMS or looks_like_identifier(value):
                values.add(value)

    values.update(_json_identifier_strings(flow.request.get_content(strict=False)))
    if flow.response is not None:
        values.update(_json_identifier_strings(flow.response.get_content(strict=False)))

    return sorted(values)


class TrackerDetector:
    name = "tracker"

    def __init__(self, corpus_dir: str | None = None) -> None:
        self._vendors = load_vendors("trackers", corpus_dir)

    def detect(self, flow: http.HTTPFlow) -> list[Finding]:
        request = flow.request
        host = request.pretty_host
        path = request.path or "/"

        for vendor in self._vendors:
            if vendor.matches(host, path):
                return [
                    Finding(
                        cls="tracker",
                        label=f"{vendor.name} tracker",
                        confidence="signature",
                        evidence=[f"host={host}", f"path={path}"],
                        facts={"vendor": vendor.name},
                    )
                ]
        return []

    def extract_identifiers(self, flow: http.HTTPFlow) -> list[str]:
        return extract_identifiers(flow)
