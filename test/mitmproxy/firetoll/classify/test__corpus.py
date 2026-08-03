import logging

from mitmproxy.firetoll.classify import _corpus


class TestVendorMatches:
    def test_matches_exact_host(self):
        vendor = _corpus.Vendor(name="Acme", hosts=frozenset({"api.acme.com"}))
        assert vendor.matches("api.acme.com", "/anything")

    def test_matches_host_suffix(self):
        vendor = _corpus.Vendor(name="Acme", host_suffixes=("acme.com",))
        assert vendor.matches("sub.acme.com", "/anything")

    def test_matches_path_pattern(self):
        import re

        vendor = _corpus.Vendor(name="Acme", path_patterns=(re.compile(r"/track$"),))
        assert vendor.matches("unrelated.example.com", "/v1/track")

    def test_no_match(self):
        vendor = _corpus.Vendor(name="Acme", hosts=frozenset({"api.acme.com"}))
        assert not vendor.matches("other.example.com", "/nope")


class TestParse:
    def test_parse_full_entry(self):
        text = """
vendors:
  - name: Acme
    hosts:
      - api.acme.com
    host_suffixes:
      - acme.net
    path_patterns:
      - "/track$"
"""
        vendors = _corpus._parse(text)
        assert len(vendors) == 1
        vendor = vendors[0]
        assert vendor.name == "Acme"
        assert vendor.hosts == frozenset({"api.acme.com"})
        assert vendor.host_suffixes == ("acme.net",)
        assert len(vendor.path_patterns) == 1
        assert vendor.path_patterns[0].search("/v1/track")

    def test_parse_minimal_entry(self):
        text = """
vendors:
  - name: Bare
"""
        vendors = _corpus._parse(text)
        assert len(vendors) == 1
        vendor = vendors[0]
        assert vendor.name == "Bare"
        assert vendor.hosts == frozenset()
        assert vendor.host_suffixes == ()
        assert vendor.path_patterns == ()

    def test_parse_empty_document(self):
        assert _corpus._parse("") == []

    def test_parse_no_vendors_key(self):
        assert _corpus._parse("other_key: 1\n") == []


class TestLoadVendors:
    def test_loads_bundled_telemetry_corpus(self):
        vendors = _corpus.load_vendors("telemetry")
        assert vendors
        assert any(v.name == "Segment" for v in vendors)

    def test_loads_bundled_trackers_corpus(self):
        vendors = _corpus.load_vendors("trackers")
        assert vendors

    def test_no_corpus_dir_argument(self):
        # corpus_dir defaults to None and no extension is attempted.
        vendors = _corpus.load_vendors("telemetry", None)
        assert vendors

    def test_merges_with_extra_corpus_dir(self, tmp_path):
        extra = tmp_path / "telemetry.yaml"
        extra.write_text(
            """
vendors:
  - name: CustomCo
    hosts:
      - telemetry.customco.example
"""
        )
        vendors = _corpus.load_vendors("telemetry", str(tmp_path))
        names = {v.name for v in vendors}
        assert "Segment" in names
        assert "CustomCo" in names

    def test_missing_corpus_file_in_dir_logs_warning(self, tmp_path, caplog):
        # tmp_path has no telemetry.yaml in it, so the override is skipped
        # and a warning is logged instead of raising.
        with caplog.at_level(logging.WARNING):
            vendors = _corpus.load_vendors("telemetry", str(tmp_path))
        assert vendors
        assert any(
            "no telemetry.yaml in corpus dir" in message for message in caplog.messages
        )
