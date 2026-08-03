from mitmproxy.firetoll import options
from mitmproxy.test import taddons


def _context():
    return taddons.context(options.FiretollOptions())


class TestFiretollOptionsDefaults:
    def test_firetoll_defaults_to_enabled(self):
        with _context() as tctx:
            assert tctx.options.firetoll is True

    def test_firetoll_attribution_defaults_to_enabled(self):
        with _context() as tctx:
            assert tctx.options.firetoll_attribution is True

    def test_firetoll_store_bodies_defaults_to_disabled(self):
        with _context() as tctx:
            assert tctx.options.firetoll_store_bodies is False

    def test_firetoll_body_access_defaults_to_redacted(self):
        with _context() as tctx:
            assert tctx.options.firetoll_body_access == "redacted"

    def test_firetoll_retention_hours_defaults_to_24(self):
        with _context() as tctx:
            assert tctx.options.firetoll_retention_hours == 24

    def test_firetoll_corpus_dir_defaults_to_empty_string(self):
        with _context() as tctx:
            assert tctx.options.firetoll_corpus_dir == ""

    def test_firetoll_report_defaults_to_disabled(self):
        with _context() as tctx:
            assert tctx.options.firetoll_report is False

    def test_firetoll_report_path_defaults_to_empty_string(self):
        with _context() as tctx:
            assert tctx.options.firetoll_report_path == ""

    def test_firetoll_store_path_defaults_to_empty_string(self):
        with _context() as tctx:
            assert tctx.options.firetoll_store_path == ""


class TestFiretollOptionsTypes:
    def test_bool_options_accept_bool_values(self):
        with _context() as tctx:
            tctx.options.firetoll = False
            tctx.options.firetoll_attribution = False
            tctx.options.firetoll_store_bodies = True
            tctx.options.firetoll_report = True
            assert tctx.options.firetoll is False
            assert tctx.options.firetoll_attribution is False
            assert tctx.options.firetoll_store_bodies is True
            assert tctx.options.firetoll_report is True

    def test_str_options_accept_str_values(self):
        with _context() as tctx:
            tctx.options.firetoll_corpus_dir = "/tmp/corpus"
            tctx.options.firetoll_report_path = "/tmp/report"
            tctx.options.firetoll_store_path = "/tmp/session.sqlite"
            assert tctx.options.firetoll_corpus_dir == "/tmp/corpus"
            assert tctx.options.firetoll_report_path == "/tmp/report"
            assert tctx.options.firetoll_store_path == "/tmp/session.sqlite"

    def test_firetoll_retention_hours_accepts_int(self):
        with _context() as tctx:
            tctx.options.firetoll_retention_hours = 48
            assert tctx.options.firetoll_retention_hours == 48

    def test_firetoll_body_access_accepts_each_choice(self):
        with _context() as tctx:
            for value in ("none", "redacted", "full"):
                tctx.options.firetoll_body_access = value
                assert tctx.options.firetoll_body_access == value


class TestFiretollOptionsChoices:
    def test_firetoll_body_access_choices_are_registered(self):
        with _context() as tctx:
            opt = tctx.options._options["firetoll_body_access"]
            assert opt.choices == ["none", "redacted", "full"]

    def test_other_options_have_no_choices(self):
        with _context() as tctx:
            for name in (
                "firetoll",
                "firetoll_attribution",
                "firetoll_store_bodies",
                "firetoll_retention_hours",
                "firetoll_corpus_dir",
                "firetoll_report",
                "firetoll_report_path",
                "firetoll_store_path",
            ):
                assert tctx.options._options[name].choices is None


class TestFiretollOptionsHelp:
    def test_all_options_have_non_empty_help_text(self):
        with _context() as tctx:
            for name in (
                "firetoll",
                "firetoll_attribution",
                "firetoll_store_bodies",
                "firetoll_body_access",
                "firetoll_retention_hours",
                "firetoll_corpus_dir",
                "firetoll_report",
                "firetoll_report_path",
                "firetoll_store_path",
            ):
                assert tctx.options._options[name].help
