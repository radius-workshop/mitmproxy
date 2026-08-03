"""Detector: bot-detection & fingerprinting challenges, plus a TLS client
profile hash.

Response-side signatures for the major challenge/fingerprinting vendors;
request-side signatures for known JS fingerprinting libraries and challenge
widgets. `tls_client_profile()` is a separate, connection-level fact (stored
on the flow row, not emitted as a Finding) - deliberately NOT called JA3,
and deliberately excluding `cipher_list`: that field is "ciphers accepted by
the proxy server" (mitmproxy/connection.py), i.e. our own configured cipher
list from `--ciphers-client`, not anything derived from the client's
ClientHello - hashing it would imply a per-client signal that isn't there.
`alpn_offers`, by contrast, genuinely is "the ALPN offers as sent in the
ClientHello" and does vary by client, so that's what the profile uses.
"""

from __future__ import annotations

import hashlib

from mitmproxy import connection
from mitmproxy import http
from mitmproxy.firetoll.finding import Finding

_COOKIE_EXACT = {
    "_abck": "Akamai Bot Manager",
    "ak_bmsc": "Akamai Bot Manager",
    "datadome": "DataDome",
}
_COOKIE_PREFIXES = {
    "_px": "PerimeterX",
    "visid_incap": "Imperva/Incapsula",
    "incap_ses": "Imperva/Incapsula",
}

_FINGERPRINT_REQUEST_PATTERNS = (
    "fingerprintjs",
    "fp.min.js",
    "fp.js",
    "px.js",
    "/cdn-cgi/challenge-platform/",
)
_CHALLENGE_WIDGET_HOSTS = {
    "hcaptcha.com": "hCaptcha",
    "js.hcaptcha.com": "hCaptcha",
    "challenges.cloudflare.com": "Cloudflare Turnstile",
}


def _cookie_vendor(name: str) -> str | None:
    if name in _COOKIE_EXACT:
        return _COOKIE_EXACT[name]
    for prefix, vendor in _COOKIE_PREFIXES.items():
        if name.startswith(prefix):
            return vendor
    return None


class BotDetectDetector:
    name = "botdetect"

    def detect(self, flow: http.HTTPFlow) -> list[Finding]:
        findings: list[Finding] = []
        response_finding = self._detect_response(flow)
        if response_finding:
            findings.append(response_finding)
        request_finding = self._detect_request(flow)
        if request_finding:
            findings.append(request_finding)
        return findings

    def _detect_response(self, flow: http.HTTPFlow) -> Finding | None:
        response = flow.response
        if response is None:
            return None

        cf_ray = response.headers.get("cf-ray")
        cf_mitigated = response.headers.get("cf-mitigated")
        if cf_mitigated or (cf_ray and response.status_code in (403, 503)):
            evidence = [f"status={response.status_code}"]
            if cf_ray:
                evidence.append(f"cf-ray={cf_ray}")
            if cf_mitigated:
                evidence.append(f"cf-mitigated={cf_mitigated}")
            return self._finding("Cloudflare", evidence, response.status_code)

        body = response.get_content(strict=False) or b""
        if b"__cf_chl" in body:
            return self._finding(
                "Cloudflare", ["body contains __cf_chl"], response.status_code
            )
        if b"challenges.cloudflare.com" in body:
            return self._finding(
                "Cloudflare Turnstile",
                ["body references challenges.cloudflare.com"],
                response.status_code,
            )

        for name, (_value, _attrs) in response.cookies.items(multi=True):
            vendor = _cookie_vendor(name)
            if vendor:
                return self._finding(
                    vendor, [f"set-cookie={name}"], response.status_code
                )

        return None

    def _finding(self, vendor: str, evidence: list[str], status: int) -> Finding:
        return Finding(
            cls="botdetect",
            label=f"{vendor} challenge",
            confidence="signature",
            evidence=evidence,
            facts={"vendor": vendor, "status": status},
        )

    def _detect_request(self, flow: http.HTTPFlow) -> Finding | None:
        host = flow.request.pretty_host
        path = (flow.request.path or "").lower()

        vendor = _CHALLENGE_WIDGET_HOSTS.get(host)
        if vendor:
            return Finding(
                cls="botdetect",
                label=f"{vendor} widget load",
                confidence="heuristic",
                evidence=[f"host={host}"],
                facts={"vendor": vendor},
            )

        for pattern in _FINGERPRINT_REQUEST_PATTERNS:
            if pattern in path:
                return Finding(
                    cls="botdetect",
                    label="fingerprinting script request",
                    confidence="heuristic",
                    evidence=[f"path={flow.request.path}"],
                    facts={"pattern": pattern},
                )
        return None


def tls_client_profile(client_conn: connection.Client) -> dict:
    """A stable hash of the TLS handshake fields that actually vary per
    client (tls_version, sni, negotiated alpn, and the client's ALPN
    offers) - see module docstring for why cipher_list is excluded."""
    alpn_offers = sorted(
        o.decode(errors="replace") for o in (client_conn.alpn_offers or ())
    )
    parts = "|".join(
        [
            client_conn.tls_version or "",
            client_conn.sni or "",
            (client_conn.alpn or b"").decode(errors="replace"),
            ",".join(alpn_offers),
        ]
    )
    digest = hashlib.sha256(parts.encode()).hexdigest()[:16]
    return {
        "tls_profile_hash": digest,
        "tls_version": client_conn.tls_version,
        "sni": client_conn.sni,
        "alpn_offers": alpn_offers,
    }
