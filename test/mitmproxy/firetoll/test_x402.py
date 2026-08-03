import json

from mitmproxy.firetoll import x402
from mitmproxy.test import tflow
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

V2_STYLE_BODY = json.dumps(
    {
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xPayeeAddress",
                "resource": "https://api.example.com/other",
            }
        ]
    }
).encode()

UNKNOWN_NETWORK_BODY = json.dumps(
    {
        "accepts": [
            {
                "scheme": "exact",
                "network": "some-new-l2",
                "amount": "1",
                "asset": "0xdeadbeef",
                "payTo": "0xPayeeAddress",
            }
        ]
    }
).encode()

BARE_OFFER_BODY = json.dumps(
    {
        "scheme": "exact",
        "network": "base",
        "amount": "42",
        "resource": "https://api.example.com/bare",
    }
).encode()


class TestToCaip2:
    def test_known_network_name(self):
        assert x402.to_caip2("base-sepolia") == "eip155:84532"

    def test_already_caip2(self):
        assert x402.to_caip2("eip155:999") == "eip155:999"

    def test_unknown_network(self):
        assert x402.to_caip2("some-new-l2") is None

    def test_none_network(self):
        assert x402.to_caip2(None) is None


class TestParseOffers:
    def test_v1_max_amount_required(self):
        offers = x402.parse_offers(V1_BODY)
        assert len(offers) == 1
        offer = offers[0]
        assert offer.amount == "10000"
        assert offer.network == "base-sepolia"
        assert offer.chain_id == "eip155:84532"
        assert offer.pay_to == "0xPayeeAddress"
        assert offer.extra == {"name": "USDC", "version": "2"}

    def test_v2_amount_field_and_caip2_network(self):
        offers = x402.parse_offers(V2_STYLE_BODY)
        assert offers[0].amount == "5000"
        assert offers[0].chain_id == "eip155:8453"

    def test_unknown_network_yields_none_chain_id(self):
        offers = x402.parse_offers(UNKNOWN_NETWORK_BODY)
        assert offers[0].chain_id is None
        assert offers[0].network == "some-new-l2"

    def test_bare_offer_without_accepts_wrapper(self):
        offers = x402.parse_offers(BARE_OFFER_BODY)
        assert len(offers) == 1
        assert offers[0].amount == "42"
        assert offers[0].resource == "https://api.example.com/bare"

    def test_non_json_body_returns_empty(self):
        assert x402.parse_offers(b"not json") == []

    def test_json_without_offer_shape_returns_empty(self):
        assert (
            x402.parse_offers(json.dumps({"error": "payment required"}).encode()) == []
        )

    def test_non_dict_entries_in_accepts_are_skipped(self):
        body = json.dumps({"accepts": ["not-a-dict", 123]}).encode()
        assert x402.parse_offers(body) == []

    def test_json_top_level_list_returns_empty(self):
        # valid JSON, but not an object at all - `isinstance(data, dict)`
        # must reject it rather than crash on `.get(...)`.
        assert x402.parse_offers(b"[1, 2, 3]") == []

    def test_json_top_level_scalar_returns_empty(self):
        assert x402.parse_offers(b"42") == []


class TestDryRunQuote:
    def test_known_asset_shows_symbol_and_decimals(self):
        offer = x402.parse_offers(V1_BODY)[0]
        quote = offer.dry_run_quote()
        assert "USDC" in quote
        assert "0.01" in quote  # 10000 / 10**6

    def test_unknown_asset_shows_raw_units(self):
        offer = x402.parse_offers(UNKNOWN_NETWORK_BODY)[0]
        quote = offer.dry_run_quote()
        assert "raw units" in quote
        assert "0xdeadbeef" in quote

    def test_known_asset_with_non_numeric_amount_falls_back_to_raw_units(self):
        # chain/asset match a known entry, but the amount itself can't be
        # parsed as an int - must fall back to the raw-units message rather
        # than raising.
        offer = x402.X402Offer(
            scheme="exact",
            network="base",
            chain_id="eip155:8453",
            amount="not-a-number",
            asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            pay_to="0xPayeeAddress",
            resource=None,
        )
        quote = offer.dry_run_quote()
        assert "raw units" in quote
        assert "not-a-number" in quote

    def test_no_amount_is_explicit(self):
        offer = x402.X402Offer(
            scheme=None,
            network=None,
            chain_id=None,
            amount=None,
            asset=None,
            pay_to=None,
            resource=None,
        )
        assert offer.dry_run_quote() == "amount unknown"

    def test_quote_never_requires_a_key_or_signature(self):
        # dry_run_quote takes no wallet/signer argument at all - this test
        # exists to make that contract explicit and catch any regression
        # that tries to add one.
        import inspect

        sig = inspect.signature(x402.X402Offer.dry_run_quote)
        assert list(sig.parameters) == ["self"]


class TestX402Detector:
    def test_402_response_yields_finding(self):
        detector = x402.X402Detector()
        f = tflow.tflow(
            req=tutils.treq(host="api.example.com", path="/resource"),
            resp=tutils.tresp(status_code=402, content=V1_BODY),
        )
        findings = detector.detect(f)
        assert len(findings) == 1
        assert findings[0].cls == "x402"
        assert findings[0].confidence == "signature"
        assert findings[0].facts["amount"] == "10000"
        assert findings[0].evidence

    def test_non_402_status_no_finding(self):
        detector = x402.X402Detector()
        f = tflow.tflow(
            req=tutils.treq(host="api.example.com", path="/resource"),
            resp=tutils.tresp(status_code=200, content=V1_BODY),
        )
        assert detector.detect(f) == []

    def test_402_with_non_offer_body_no_finding(self):
        detector = x402.X402Detector()
        f = tflow.tflow(
            req=tutils.treq(host="api.example.com", path="/resource"),
            resp=tutils.tresp(status_code=402, content=b"plain text error"),
        )
        assert detector.detect(f) == []

    def test_402_empty_body_no_finding(self):
        detector = x402.X402Detector()
        f = tflow.tflow(
            req=tutils.treq(host="api.example.com", path="/resource"),
            resp=tutils.tresp(status_code=402, content=b""),
        )
        assert detector.detect(f) == []

    def test_no_response_no_finding(self):
        detector = x402.X402Detector()
        f = tflow.tflow(req=tutils.treq(), resp=False)
        assert detector.detect(f) == []
