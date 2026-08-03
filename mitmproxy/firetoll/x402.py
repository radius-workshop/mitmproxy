"""x402 payment-required offers: observe, decode, and quote - never sign.

x402 (https://github.com/coinbase/x402) is an emerging convention for using
HTTP 402 Payment Required to advertise an on-chain micropayment a client
could make to get a resource. The wire format has moved during
standardization (`maxAmountRequired` -> `amount`, plain network names ->
CAIP-2 `eip155:<id>`), so this decoder is deliberately tolerant of
field-name variants rather than pinned to one draft.

No wallet, no key, no signing here - `dry_run_quote()` computes what a
payment would cost, never how to make one. That is a separate project with
a separate safety model outside this package.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from mitmproxy import http
from mitmproxy.firetoll.finding import Finding

# Network name (as commonly seen in x402 responses) -> CAIP-2 chain id.
# Extend as new networks show up in real captures.
_NETWORK_TO_CAIP2 = {
    "ethereum": "eip155:1",
    "base": "eip155:8453",
    "base-sepolia": "eip155:84532",
    "polygon": "eip155:137",
    "avalanche": "eip155:43114",
    "optimism": "eip155:10",
    "arbitrum": "eip155:42161",
}

# (chain id, lowercased asset address) -> (symbol, decimals). Deliberately
# small and best-effort: an unrecognized asset is quoted in raw units rather
# than guessed at.
_KNOWN_ASSETS: dict[tuple[str, str], tuple[str, int]] = {
    ("eip155:8453", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"): ("USDC", 6),
    ("eip155:84532", "0x036cbd53842c5426634e7929541ec2318f3dcf7e"): ("USDC", 6),
}


def to_caip2(network: str | None) -> str | None:
    """`"base-sepolia"` -> `"eip155:84532"`. Already-CAIP-2 values pass
    through unchanged; unrecognized network names return `None` rather than
    a guess."""
    if not network:
        return None
    if network.startswith("eip155:"):
        return network
    return _NETWORK_TO_CAIP2.get(network.lower())


def _amount_of(entry: dict) -> str | None:
    for key in ("maxAmountRequired", "amount"):
        if key in entry:
            return str(entry[key])
    return None


@dataclass
class X402Offer:
    scheme: str | None
    network: str | None
    chain_id: str | None
    amount: str | None
    asset: str | None
    pay_to: str | None
    resource: str | None
    extra: dict[str, Any] = field(default_factory=dict)

    def dry_run_quote(self) -> str:
        """A human-readable estimate of what accepting this offer would
        cost - computed from the offer alone, with no key and no signature."""
        if self.amount is None:
            return "amount unknown"

        symbol: str | None = None
        decimals: int | None = None
        if self.chain_id and self.asset:
            symbol, decimals = _KNOWN_ASSETS.get(
                (self.chain_id, self.asset.lower()), (None, None)
            )

        network_label = self.network or self.chain_id or "unknown network"
        if symbol and decimals is not None:
            try:
                display = int(self.amount) / (10**decimals)
            except ValueError:
                symbol = None
            else:
                resource = f" for {self.resource}" if self.resource else ""
                return f"{display:g} {symbol} on {network_label}{resource}"

        return f"{self.amount} raw units of {self.asset or 'unknown asset'} on {network_label}"

    def to_facts(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "network": self.network,
            "chain_id": self.chain_id,
            "amount": self.amount,
            "asset": self.asset,
            "pay_to": self.pay_to,
            "resource": self.resource,
            "extra": self.extra,
            "dry_run_quote": self.dry_run_quote(),
        }


def parse_offers(body: bytes) -> list[X402Offer]:
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    entries = data.get("accepts")
    if not isinstance(entries, list):
        # some early drafts put a single offer at the top level instead of
        # wrapping it in "accepts".
        entries = [data] if _amount_of(data) is not None else []

    offers = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        network = entry.get("network")
        extra = entry.get("extra")
        offers.append(
            X402Offer(
                scheme=entry.get("scheme"),
                network=network,
                chain_id=to_caip2(network),
                amount=_amount_of(entry),
                asset=entry.get("asset"),
                pay_to=entry.get("payTo"),
                resource=entry.get("resource") or data.get("resource"),
                extra=extra if isinstance(extra, dict) else {},
            )
        )
    return offers


class X402Detector:
    name = "x402"

    def detect(self, flow: http.HTTPFlow) -> list[Finding]:
        response = flow.response
        if response is None or response.status_code != 402:
            return []
        body = response.get_content(strict=False)
        if not body:
            return []
        offers = parse_offers(body)
        if not offers:
            return []

        return [
            Finding(
                cls="x402",
                label="x402 payment offer",
                confidence="signature",
                evidence=[
                    "status=402",
                    f"host={flow.request.pretty_host}",
                    f"path={flow.request.path}",
                ],
                facts=offer.to_facts(),
            )
            for offer in offers
        ]
