import json

from mitmproxy.firetoll.classify import trackers
from mitmproxy.test import tflow
from mitmproxy.test import tutils


class TestLooksLikeIdentifier:
    def test_hex_uuid_shaped(self):
        assert trackers.looks_like_identifier("8f3a1c2d9e4b5f6a7c8d9e0f1a2b3c4d")

    def test_base64url_shaped(self):
        assert trackers.looks_like_identifier("AbCdEf123456_-.ZzYyXxWw")

    def test_too_short_rejected(self):
        assert not trackers.looks_like_identifier("short123")

    def test_all_digits_rejected(self):
        assert not trackers.looks_like_identifier("12345678901234567890")

    def test_all_lowercase_word_rejected(self):
        assert not trackers.looks_like_identifier("abcdefghijklmnopqrstuvwxyz")

    def test_contains_space_rejected(self):
        assert not trackers.looks_like_identifier("this is definitely not an id")


class TestSignatureMatch:
    def test_known_tracker_host(self):
        detector = trackers.TrackerDetector()
        f = tflow.tflow(req=tutils.treq(host="doubleclick.net", path="/ad"))
        findings = detector.detect(f)
        assert len(findings) == 1
        assert findings[0].cls == "tracker"
        assert findings[0].facts["vendor"] == "DoubleClick / Google Ads"

    def test_host_suffix(self):
        detector = trackers.TrackerDetector()
        f = tflow.tflow(req=tutils.treq(host="ads.g.doubleclick.net", path="/x"))
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "DoubleClick / Google Ads"

    def test_no_match(self):
        detector = trackers.TrackerDetector()
        f = tflow.tflow(req=tutils.treq(host="example.com", path="/"))
        assert detector.detect(f) == []


class TestExtractIdentifiers:
    def test_known_param_included_regardless_of_shape(self):
        f = tflow.tflow(req=tutils.treq(host="example.com", path="/?gclid=short"))
        assert "short" in trackers.extract_identifiers(f)

    def test_unnamed_short_query_param_excluded(self):
        f = tflow.tflow(req=tutils.treq(host="example.com", path="/?foo=short"))
        assert "short" not in trackers.extract_identifiers(f)

    def test_long_shaped_query_param_included(self):
        value = "8f3a1c2d9e4b5f6a7c8d9e0f1a2b3c4d"
        f = tflow.tflow(
            req=tutils.treq(host="example.com", path=f"/?tracker_id={value}")
        )
        assert value in trackers.extract_identifiers(f)

    def test_request_cookie_shaped_value_included(self):
        value = "8f3a1c2d9e4b5f6a7c8d9e0f1a2b3c4d"
        f = tflow.tflow(
            req=tutils.treq(
                host="example.com",
                path="/",
                headers=[(b"cookie", f"sid={value}".encode())],
            )
        )
        assert value in trackers.extract_identifiers(f)

    def test_response_set_cookie_shaped_value_included(self):
        value = "8f3a1c2d9e4b5f6a7c8d9e0f1a2b3c4d"
        f = tflow.tflow(
            req=tutils.treq(host="example.com", path="/"),
            resp=tutils.tresp(
                headers=[(b"set-cookie", f"uid={value}; Path=/".encode())]
            ),
        )
        assert value in trackers.extract_identifiers(f)

    def test_json_body_shaped_string_included(self):
        value = "8f3a1c2d9e4b5f6a7c8d9e0f1a2b3c4d"
        body = json.dumps({"user": {"tracking_id": value}}).encode()
        f = tflow.tflow(
            req=tutils.treq(
                host="example.com",
                path="/",
                method=b"POST",
                headers=[(b"content-type", b"application/json")],
                content=body,
            )
        )
        assert value in trackers.extract_identifiers(f)

    def test_no_identifiers_returns_empty(self):
        f = tflow.tflow(req=tutils.treq(host="example.com", path="/"))
        assert trackers.extract_identifiers(f) == []

    def test_json_body_list_of_shaped_strings_included(self):
        value = "8f3a1c2d9e4b5f6a7c8d9e0f1a2b3c4d"
        body = json.dumps({"ids": [value]}).encode()
        f = tflow.tflow(
            req=tutils.treq(
                host="example.com",
                path="/",
                method=b"POST",
                headers=[(b"content-type", b"application/json")],
                content=body,
            )
        )
        assert value in trackers.extract_identifiers(f)

    def test_json_deeply_nested_value_ignored_past_depth_limit(self):
        value = "8f3a1c2d9e4b5f6a7c8d9e0f1a2b3c4d"
        body = json.dumps({"a": {"b": {"c": {"d": {"e": value}}}}}).encode()
        f = tflow.tflow(
            req=tutils.treq(
                host="example.com",
                path="/",
                method=b"POST",
                headers=[(b"content-type", b"application/json")],
                content=body,
            )
        )
        assert trackers.extract_identifiers(f) == []

    def test_empty_body_yields_no_json_identifiers(self):
        f = tflow.tflow(
            req=tutils.treq(host="example.com", path="/", content=b""),
            resp=False,
        )
        assert trackers.extract_identifiers(f) == []

    def test_empty_query_param_value_skipped(self):
        f = tflow.tflow(req=tutils.treq(host="example.com", path="/?foo="))
        assert trackers.extract_identifiers(f) == []

    def test_empty_request_cookie_value_skipped(self):
        f = tflow.tflow(
            req=tutils.treq(
                host="example.com",
                path="/",
                headers=[(b"cookie", b"sid=")],
            )
        )
        assert trackers.extract_identifiers(f) == []

    def test_empty_response_cookie_value_skipped(self):
        f = tflow.tflow(
            req=tutils.treq(host="example.com", path="/"),
            resp=tutils.tresp(headers=[(b"set-cookie", b"uid=; Path=/")]),
        )
        assert trackers.extract_identifiers(f) == []

    def test_detector_extract_identifiers_delegates(self):
        detector = trackers.TrackerDetector()
        value = "8f3a1c2d9e4b5f6a7c8d9e0f1a2b3c4d"
        f = tflow.tflow(req=tutils.treq(host="example.com", path=f"/?tid={value}"))
        assert value in detector.extract_identifiers(f)
