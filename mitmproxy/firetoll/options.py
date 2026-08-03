"""All firetoll_* option definitions, in one place so `loader.add_option` is
only ever called once per name (mitmproxy asserts on duplicate registration).
"""

from __future__ import annotations

from mitmproxy.addonmanager import Loader


class FiretollOptions:
    def load(self, loader: Loader) -> None:
        loader.add_option(
            "firetoll",
            bool,
            True,
            """
            Enable Firetoll traffic enrichment (process attribution, classification,
            session store, and the firetoll.report command).
            """,
        )
        loader.add_option(
            "firetoll_attribution",
            bool,
            True,
            """
            Attribute each client connection to the owning local process (PID/name),
            degrading to User-Agent when the lookup fails or is unavailable.
            """,
        )
        loader.add_option(
            "firetoll_store_bodies",
            bool,
            False,
            """
            Persist redacted, size-capped request/response bodies in the Firetoll
            session store. Off by default: only metadata and findings are stored.
            """,
        )
        loader.add_option(
            "firetoll_body_access",
            str,
            "redacted",
            """
            What the Firetoll MCP server may return for a flow body: "none" refuses
            all body access, "redacted" applies redact.py first, "full" returns raw
            bytes with a warning and an access-log entry. This is a proxy-side
            setting - the MCP server cannot change it, only read it.
            """,
            choices=["none", "redacted", "full"],
        )
        loader.add_option(
            "firetoll_retention_hours",
            int,
            24,
            """
            Delete Firetoll session-store rows older than this many hours. Enforced
            on startup and periodically, not just documented.
            """,
        )
        loader.add_option(
            "firetoll_corpus_dir",
            str,
            "",
            """
            Directory of additional/overriding detector corpus YAML files, merged
            over the bundled corpora in mitmproxy/firetoll/data/.
            """,
        )
        loader.add_option(
            "firetoll_report",
            bool,
            False,
            """
            Emit a Firetoll session report to the terminal when mitmproxy/mitmdump
            exits. Off by default so that Firetoll's background attribution and
            classification never change existing scripts' terminal output; the
            session is enriched either way, and "firetoll.report" can always be
            run on demand.
            """,
        )
        loader.add_option(
            "firetoll_report_path",
            str,
            "",
            """
            If set, also write the Firetoll session report as JSON and Markdown
            next to this path (suffixes are added/replaced).
            """,
        )
        loader.add_option(
            "firetoll_store_path",
            str,
            "",
            """
            Override the Firetoll SQLite session-store path. Defaults to
            ~/.mitmproxy/firetoll/session.sqlite.
            """,
        )
