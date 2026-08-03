import json

import pytest

from mitmproxy.contentviews._api import Metadata
from mitmproxy.firetoll import x402_contentview
from mitmproxy.test import tutils

V1_BODY = json.dumps(
    {
        "x402Version": 1,
        "accepts": [
            {
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "10000",
                "resource": "https://api.example.com/resource",
                "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "payTo": "0xPayeeAddress",
                "extra": {"name": "USDC", "version": "2"},
            }
        ],
    }
).encode()

TWO_OFFERS_BODY = json.dumps(
    {
        "accepts": [
            {
                "scheme": "exact",
                "network": "base-sepolia",
                "amount": "10000",
                "resource": "https://api.example.com/resource",
                "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "payTo": "0xPayeeAddress",
            },
            {
                "scheme": "exact",
                "network": "base",
                "amount": "42",
                "resource": "https://api.example.com/other",
                "asset": "0xdeadbeef",
                "payTo": "0xOtherPayee",
            },
        ]
    }
).encode()


class TestX402Contentview:
    def test_name_is_inferred(self):
        assert x402_contentview.x402_view.name == "X402"

    def test_prettify_renders_offer_fields(self):
        text = x402_contentview.x402_view.prettify(V1_BODY, Metadata())
        assert "network:" in text
        assert "base-sepolia" in text
        assert "quote:" in text

    def test_prettify_separates_multiple_offers_with_blank_line(self):
        text = x402_contentview.x402_view.prettify(TWO_OFFERS_BODY, Metadata())
        # a blank line is inserted between offers (but not before the first)
        assert "\n\nscheme:" in text
        assert text.count("scheme:") == 2

    def test_prettify_raises_on_non_offer_body(self):
        with pytest.raises(ValueError):
            x402_contentview.x402_view.prettify(b"not an offer", Metadata())

    def test_render_priority_high_for_402_response(self):
        resp = tutils.tresp(status_code=402, content=V1_BODY)
        metadata = Metadata(http_message=resp)
        assert x402_contentview.x402_view.render_priority(V1_BODY, metadata) == 1.0

    def test_render_priority_zero_for_200_response(self):
        resp = tutils.tresp(status_code=200, content=V1_BODY)
        metadata = Metadata(http_message=resp)
        assert x402_contentview.x402_view.render_priority(V1_BODY, metadata) == 0

    def test_render_priority_zero_for_empty_data(self):
        assert x402_contentview.x402_view.render_priority(b"", Metadata()) == 0
