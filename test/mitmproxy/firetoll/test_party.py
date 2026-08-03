from mitmproxy.firetoll.classify import party


class TestEtld1:
    def test_subdomain(self):
        assert party.etld1("sub.example.com") == "example.com"

    def test_multi_part_tld(self):
        assert party.etld1("sub.example.co.uk") == "example.co.uk"

    def test_bare_domain(self):
        assert party.etld1("example.com") == "example.com"

    def test_ipv4_literal_returned_as_is(self):
        assert party.etld1("127.0.0.1") == "127.0.0.1"

    def test_ipv6_literal_returned_as_is(self):
        assert party.etld1("::1") == "::1"

    def test_empty_host(self):
        assert party.etld1("") == ""


class TestClassifyParty:
    def test_matching_origin_is_first_party(self):
        result = party.classify_party(
            "api.example.com", origin="https://app.example.com"
        )
        assert result == "first-party"

    def test_mismatched_origin_is_third_party(self):
        result = party.classify_party(
            "api.example.com", origin="https://tracker.other.com"
        )
        assert result == "third-party"

    def test_referer_used_when_no_origin(self):
        result = party.classify_party(
            "api.example.com", referer="https://app.example.com/page"
        )
        assert result == "first-party"

    def test_origin_takes_precedence_over_referer(self):
        result = party.classify_party(
            "api.example.com",
            origin="https://tracker.other.com",
            referer="https://app.example.com/page",
        )
        assert result == "third-party"

    def test_no_signal_is_unknown(self):
        assert party.classify_party("api.example.com") == "unknown"
