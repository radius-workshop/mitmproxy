import subprocess

import pytest

from mitmproxy.firetoll import ci_diff_budget


class TestChangedFiles:
    def test_parses_git_diff_output(self, monkeypatch):
        def fake_run(cmd, capture_output, text, check):
            assert cmd == ["git", "diff", "--name-only", "some-ref...HEAD"]
            assert capture_output is True
            assert text is True
            assert check is True
            return subprocess.CompletedProcess(cmd, 0, stdout="a.py\nb.py\n\n", stderr="")

        monkeypatch.setattr(ci_diff_budget.subprocess, "run", fake_run)
        assert ci_diff_budget.changed_files("some-ref") == ["a.py", "b.py"]

    def test_raises_on_git_failure(self, monkeypatch):
        def fake_run(*args, **kwargs):
            raise subprocess.CalledProcessError(1, ["git", "diff"])

        monkeypatch.setattr(ci_diff_budget.subprocess, "run", fake_run)
        with pytest.raises(subprocess.CalledProcessError):
            ci_diff_budget.changed_files("some-ref")


class TestMain:
    def test_clean_diff_prints_ok_and_returns_zero(self, monkeypatch, capsys):
        monkeypatch.setattr(
            ci_diff_budget,
            "changed_files",
            lambda base_ref: ["mitmproxy/firetoll/store.py"],
        )
        exit_code = ci_diff_budget.main([])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "firetoll diff budget OK" in captured.out
        assert captured.err == ""

    def test_offenders_found_prints_to_stderr_and_returns_one(self, monkeypatch, capsys):
        monkeypatch.setattr(
            ci_diff_budget,
            "changed_files",
            lambda base_ref: ["mitmproxy/http.py"],
        )
        exit_code = ci_diff_budget.main([])
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "firetoll upstream diff budget exceeded" in captured.err
        assert "mitmproxy/http.py" in captured.err
        assert captured.out == ""

    def test_base_ref_argument_is_forwarded(self, monkeypatch):
        received = {}

        def fake_changed_files(base_ref):
            received["base_ref"] = base_ref
            return []

        monkeypatch.setattr(ci_diff_budget, "changed_files", fake_changed_files)
        exit_code = ci_diff_budget.main(["--base-ref", "custom-ref"])
        assert exit_code == 0
        assert received["base_ref"] == "custom-ref"

    def test_default_base_ref_is_used_when_not_given(self, monkeypatch):
        received = {}

        def fake_changed_files(base_ref):
            received["base_ref"] = base_ref
            return []

        monkeypatch.setattr(ci_diff_budget, "changed_files", fake_changed_files)
        ci_diff_budget.main([])
        assert received["base_ref"] == ci_diff_budget.DEFAULT_BASE_REF


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
