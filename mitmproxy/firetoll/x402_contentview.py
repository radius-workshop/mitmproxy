"""The x402 contentview, split out of x402.py to avoid a circular import:
mitmproxy/contentviews/__init__.py needs this module, and this module needs
mitmproxy.contentviews._api, so it must not be reachable via any path that
mitmproxy.contentviews itself passes through before it (in particular, it
must not be imported by mitmproxy/firetoll/classify - the detector registry
imports x402.X402Detector directly instead, which has no contentviews
dependency at all).
"""

from __future__ import annotations

from mitmproxy import http
from mitmproxy.contentviews._api import Contentview
from mitmproxy.contentviews._api import Metadata
from mitmproxy.firetoll.x402 import parse_offers


class X402Contentview(Contentview):
    syntax_highlight = "yaml"

    def prettify(self, data: bytes, metadata: Metadata) -> str:
        offers = parse_offers(data)
        if not offers:
            raise ValueError("not an x402 offer body")

        lines = []
        for i, offer in enumerate(offers):
            if i:
                lines.append("")
            lines.append(f"scheme:   {offer.scheme}")
            lines.append(f"network:  {offer.network} ({offer.chain_id or 'unmapped'})")
            lines.append(f"amount:   {offer.amount}")
            lines.append(f"asset:    {offer.asset}")
            lines.append(f"pay to:   {offer.pay_to}")
            lines.append(f"resource: {offer.resource}")
            lines.append(f"quote:    {offer.dry_run_quote()}")
        return "\n".join(lines)

    def render_priority(self, data: bytes, metadata: Metadata) -> float:
        if not data:
            return 0
        is_402 = (
            isinstance(metadata.http_message, http.Response)
            and metadata.http_message.status_code == 402
        )
        if not is_402:
            return 0
        return 1.0 if parse_offers(data) else 0.0


x402_view = X402Contentview()
