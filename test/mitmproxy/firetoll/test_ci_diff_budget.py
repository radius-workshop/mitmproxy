from mitmproxy.firetoll import ci_diff_budget


class TestOffendingFiles:
    def test_firetoll_package_is_excluded(self):
        files = [
            "mitmproxy/firetoll/enrich.py",
            "mitmproxy/firetoll/classify/telemetry.py",
            "test/mitmproxy/firetoll/test_enrich.py",
        ]
        assert ci_diff_budget.offending_files(files) == []

    def test_allowlisted_wiring_files_are_excluded(self):
        files = [
            "mitmproxy/addons/__init__.py",
            "mitmproxy/contentviews/__init__.py",
            "pyproject.toml",
            "README.md",
            ".github/workflows/main.yml",
        ]
        assert ci_diff_budget.offending_files(files) == []

    def test_unrelated_core_file_is_flagged(self):
        files = ["mitmproxy/proxy/layers/http/__init__.py"]
        assert ci_diff_budget.offending_files(files) == [
            "mitmproxy/proxy/layers/http/__init__.py"
        ]

    def test_mixed_list_only_flags_offenders(self):
        files = [
            "mitmproxy/firetoll/store.py",
            "mitmproxy/addons/__init__.py",
            "mitmproxy/http.py",
        ]
        assert ci_diff_budget.offending_files(files) == ["mitmproxy/http.py"]

    def test_empty_diff_is_clean(self):
        assert ci_diff_budget.offending_files([]) == []
