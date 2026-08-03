import os

import pytest

from mitmproxy.firetoll import attribution
from mitmproxy.firetoll import options
from mitmproxy.test import taddons
from mitmproxy.test import tflow


def _context(*addons):
    return taddons.context(options.FiretollOptions(), *addons)


class TestPortFromAddress:
    def test_ipv4(self):
        assert attribution.port_from_address("127.0.0.1:51820") == 51820

    def test_ipv6(self):
        assert attribution.port_from_address("[::1]:51820") == 51820

    def test_garbage(self):
        assert attribution.port_from_address("not-an-address") is None


class TestCollapseMacosApp:
    def test_app_bundle(self):
        path = "/Applications/Claude.app/Contents/MacOS/Claude"
        assert attribution.collapse_macos_app(path) == "Claude.app"

    def test_plain_binary(self):
        assert attribution.collapse_macos_app("/usr/bin/curl") == "curl"


class TestSnapshotMacos:
    def test_parses_bulk_lsof_output(self, monkeypatch):
        my_pid = os.getpid()
        fake_stdout = (
            "p123\n"
            "cnode\n"
            "n127.0.0.1:51820->127.0.0.1:8080\n"
            f"p{my_pid}\n"
            "cmitmdump\n"
            "n127.0.0.1:9999->127.0.0.1:80\n"  # excluded: our own pid
            "p456\n"
            "ccodex\n"
            "n[::1]:51821->[::1]:443\n"
        )

        class FakeProc:
            stdout = fake_stdout

        monkeypatch.setattr(attribution.subprocess, "run", lambda *a, **k: FakeProc())
        table = attribution._snapshot_macos()
        assert table == {51820: 123, 51821: 456}

    def test_lsof_missing_returns_empty(self, monkeypatch):
        def raise_oserror(*a, **k):
            raise OSError("no lsof")

        monkeypatch.setattr(attribution.subprocess, "run", raise_oserror)
        assert attribution._snapshot_macos() == {}


class TestSnapshotLinux:
    def test_parses_proc_net_tcp(self, tmp_path):
        proc_root = tmp_path
        my_pid = os.getpid()
        other_pid = (
            my_pid + 1
        )  # guaranteed not to collide with a real /proc entry we scan

        (proc_root / "net").mkdir()
        # local_address is hex IP:hex port; 0x CA48 == 51784; state 01 == ESTABLISHED
        (proc_root / "net" / "tcp").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:CA48 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
        )
        (proc_root / "net" / "tcp6").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        )

        pid_dir = proc_root / str(other_pid)
        (pid_dir / "fd").mkdir(parents=True)
        (pid_dir / "fd" / "3").symlink_to("socket:[12345]")

        table = attribution._snapshot_linux(proc_root=str(proc_root))
        assert table == {51784: other_pid}

    def test_no_proc_net_tcp_returns_empty(self, tmp_path):
        assert attribution._snapshot_linux(proc_root=str(tmp_path)) == {}


class TestAttributionAddon:
    @pytest.mark.asyncio
    async def test_process_attribution_stamped_on_flow(self, monkeypatch):
        monkeypatch.setattr(attribution, "snapshot_port_table", lambda: {22: 4242})
        monkeypatch.setattr(
            attribution,
            "process_info",
            lambda pid: ("codex", "/usr/local/bin/codex", 1, "zsh"),
        )
        attribution._process_cache.clear()

        a = attribution.Attribution()
        with _context(a) as tctx:
            tctx.configure(a)
            f = tflow.tflow()
            await a.client_connected(f.client_conn)
            a.requestheaders(f)

            assert f.metadata["firetoll.app"] == {
                "source": "process",
                "pid": 4242,
                "process": "codex",
                "path": "/usr/local/bin/codex",
                "parent": "zsh",
            }

    @pytest.mark.asyncio
    async def test_degrades_to_user_agent_on_lookup_miss(self, monkeypatch):
        monkeypatch.setattr(attribution, "snapshot_port_table", lambda: {})

        a = attribution.Attribution()
        with _context(a) as tctx:
            tctx.configure(a)
            f = tflow.tflow()
            f.request.headers["user-agent"] = "curl/8.0"
            await a.client_connected(f.client_conn)
            a.requestheaders(f)

            assert f.metadata["firetoll.app"] == {
                "source": "user-agent",
                "pid": None,
                "process": "curl/8.0",
                "path": None,
                "parent": None,
            }

    @pytest.mark.asyncio
    async def test_degrades_to_unknown_with_no_user_agent(self, monkeypatch):
        monkeypatch.setattr(attribution, "snapshot_port_table", lambda: {})

        a = attribution.Attribution()
        with _context(a) as tctx:
            tctx.configure(a)
            f = tflow.tflow()
            assert "user-agent" not in f.request.headers
            await a.client_connected(f.client_conn)
            a.requestheaders(f)

            assert f.metadata["firetoll.app"]["source"] == "unknown"

    @pytest.mark.asyncio
    async def test_client_disconnected_clears_cache(self, monkeypatch):
        monkeypatch.setattr(attribution, "snapshot_port_table", lambda: {22: 4242})
        monkeypatch.setattr(
            attribution, "process_info", lambda pid: ("codex", "/bin/codex", None, None)
        )
        attribution._process_cache.clear()

        a = attribution.Attribution()
        with _context(a) as tctx:
            tctx.configure(a)
            f = tflow.tflow()
            await a.client_connected(f.client_conn)
            assert f.client_conn.id in a._by_client
            a.client_disconnected(f.client_conn)
            assert f.client_conn.id not in a._by_client

    @pytest.mark.asyncio
    async def test_disabled_option_skips_attribution(self, monkeypatch):
        called = False

        def fail(*a, **k):
            nonlocal called
            called = True
            return {}

        monkeypatch.setattr(attribution, "snapshot_port_table", fail)

        a = attribution.Attribution()
        with _context(a) as tctx:
            tctx.configure(a)
            tctx.options.firetoll_attribution = False
            f = tflow.tflow()
            await a.client_connected(f.client_conn)
            assert not called
            assert f.client_conn.id not in a._by_client
