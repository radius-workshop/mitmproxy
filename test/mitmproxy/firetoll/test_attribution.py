import os
import subprocess

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


class TestSnapshotPortTable:
    def test_dispatches_to_macos(self, monkeypatch):
        monkeypatch.setattr(attribution.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(attribution, "_snapshot_macos", lambda: {1: 2})
        assert attribution.snapshot_port_table() == {1: 2}

    def test_dispatches_to_linux(self, monkeypatch):
        monkeypatch.setattr(attribution.platform, "system", lambda: "Linux")
        monkeypatch.setattr(attribution, "_snapshot_linux", lambda: {3: 4})
        assert attribution.snapshot_port_table() == {3: 4}

    def test_unsupported_platform_returns_empty(self, monkeypatch):
        monkeypatch.setattr(attribution.platform, "system", lambda: "Windows")
        assert attribution.snapshot_port_table() == {}


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

    def test_subprocess_error_returns_empty(self, monkeypatch):
        def raise_subprocess_error(*a, **k):
            raise subprocess.TimeoutExpired(cmd="lsof", timeout=2)

        monkeypatch.setattr(attribution.subprocess, "run", raise_subprocess_error)
        assert attribution._snapshot_macos() == {}

    def test_skips_blank_lines_and_malformed_pid(self, monkeypatch):
        fake_stdout = (
            "\n"  # blank line: skipped entirely
            "pnot-a-number\n"  # malformed pid -> pid reset to None
            "n127.0.0.1:51820->127.0.0.1:8080\n"  # ignored: pid is None
            "p789\n"
            "csomeproc\n"
            "n127.0.0.1:6000->127.0.0.1:80\n"
        )

        class FakeProc:
            stdout = fake_stdout

        monkeypatch.setattr(attribution.subprocess, "run", lambda *a, **k: FakeProc())
        table = attribution._snapshot_macos()
        assert table == {6000: 789}


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

    def test_skips_short_and_non_established_lines(self, tmp_path):
        proc_root = tmp_path
        my_pid = os.getpid()
        other_pid = my_pid + 1

        (proc_root / "net").mkdir()
        (proc_root / "net" / "tcp").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:CA48 01\n"  # too few fields: skipped
            "   1: 0100007F:CA49 0100007F:0050 06 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0\n"  # not ESTABLISHED: skipped
            "   2: 0100007F:CA4A 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0\n"
        )
        (proc_root / "net" / "tcp6").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        )

        pid_dir = proc_root / str(other_pid)
        (pid_dir / "fd").mkdir(parents=True)
        (pid_dir / "fd" / "3").symlink_to("socket:[12347]")

        table = attribution._snapshot_linux(proc_root=str(proc_root))
        assert table == {51786: other_pid}  # 0xCA4A == 51786

    def test_skips_invalid_port_hex(self, tmp_path):
        proc_root = tmp_path
        (proc_root / "net").mkdir()
        (proc_root / "net" / "tcp").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:ZZZZ 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
        )
        (proc_root / "net" / "tcp6").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        )
        assert attribution._snapshot_linux(proc_root=str(proc_root)) == {}

    def test_listdir_proc_root_oserror_returns_empty(self, tmp_path, monkeypatch):
        proc_root = tmp_path
        (proc_root / "net").mkdir()
        (proc_root / "net" / "tcp").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:CA48 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
        )
        (proc_root / "net" / "tcp6").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        )

        real_listdir = attribution.os.listdir

        def selective_raise(path):
            if path == str(proc_root):
                raise OSError("permission denied")
            return real_listdir(path)

        monkeypatch.setattr(attribution.os, "listdir", selective_raise)
        assert attribution._snapshot_linux(proc_root=str(proc_root)) == {}

    def test_skips_own_pid(self, tmp_path):
        proc_root = tmp_path
        my_pid = os.getpid()

        (proc_root / "net").mkdir()
        (proc_root / "net" / "tcp").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:CA48 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
        )
        (proc_root / "net" / "tcp6").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        )

        pid_dir = proc_root / str(my_pid)
        (pid_dir / "fd").mkdir(parents=True)
        (pid_dir / "fd" / "3").symlink_to("socket:[12345]")

        table = attribution._snapshot_linux(proc_root=str(proc_root))
        assert table == {}  # our own pid is never attributed

    def test_pid_missing_fd_dir_is_skipped(self, tmp_path):
        proc_root = tmp_path
        my_pid = os.getpid()
        other_pid = my_pid + 1

        (proc_root / "net").mkdir()
        (proc_root / "net" / "tcp").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:CA48 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
        )
        (proc_root / "net" / "tcp6").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        )

        # pid directory exists but has no "fd" subdirectory -> os.listdir(fd) raises
        (proc_root / str(other_pid)).mkdir()

        assert attribution._snapshot_linux(proc_root=str(proc_root)) == {}

    def test_unreadable_fd_symlink_is_skipped(self, tmp_path):
        proc_root = tmp_path
        my_pid = os.getpid()
        other_pid = my_pid + 1

        (proc_root / "net").mkdir()
        (proc_root / "net" / "tcp").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:CA48 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
        )
        (proc_root / "net" / "tcp6").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        )

        pid_dir = proc_root / str(other_pid)
        (pid_dir / "fd").mkdir(parents=True)
        # a regular file, not a symlink -> os.readlink() raises OSError
        (pid_dir / "fd" / "3").write_text("not a symlink")

        assert attribution._snapshot_linux(proc_root=str(proc_root)) == {}


class TestPsPpidAndComm:
    def test_subprocess_error_returns_none_none(self, monkeypatch):
        def raise_oserror(*a, **k):
            raise OSError("no ps")

        monkeypatch.setattr(attribution.subprocess, "run", raise_oserror)
        assert attribution._ps_ppid_and_comm(123) == (None, None)

    def test_subprocess_timeout_returns_none_none(self, monkeypatch):
        def raise_timeout(*a, **k):
            raise subprocess.TimeoutExpired(cmd="ps", timeout=2)

        monkeypatch.setattr(attribution.subprocess, "run", raise_timeout)
        assert attribution._ps_ppid_and_comm(123) == (None, None)

    def test_no_match_returns_none_none(self, monkeypatch):
        class FakeProc:
            stdout = ""  # no process with this pid -> ps prints nothing

        monkeypatch.setattr(attribution.subprocess, "run", lambda *a, **k: FakeProc())
        assert attribution._ps_ppid_and_comm(123) == (None, None)

    def test_parses_ppid_and_comm(self, monkeypatch):
        class FakeProc:
            stdout = "  123 zsh\n"

        monkeypatch.setattr(attribution.subprocess, "run", lambda *a, **k: FakeProc())
        assert attribution._ps_ppid_and_comm(456) == (123, "zsh")

    def test_malformed_ppid_falls_back_to_none(self, monkeypatch):
        # _PS_LINE's own \d+ group can never fail int(), so exercise the
        # defensive except-branch directly by faking the compiled pattern.
        class FakeMatch:
            def group(self, n):
                return "not-a-number" if n == 1 else "somecomm"

        class FakePattern:
            def match(self, s):
                return FakeMatch()

        class FakeProc:
            stdout = "garbage\n"

        monkeypatch.setattr(attribution.subprocess, "run", lambda *a, **k: FakeProc())
        monkeypatch.setattr(attribution, "_PS_LINE", FakePattern())
        assert attribution._ps_ppid_and_comm(789) == (None, "somecomm")


class TestProcessInfo:
    def test_returns_none_when_path_missing(self, monkeypatch):
        monkeypatch.setattr(
            attribution, "_ps_ppid_and_comm", lambda pid: (5, None)
        )
        assert attribution.process_info(1) == (None, None, 5, None)

    def test_darwin_collapses_app_bundles_for_self_and_parent(self, monkeypatch):
        monkeypatch.setattr(attribution.platform, "system", lambda: "Darwin")

        def fake_ps(pid):
            if pid == 1:
                return 10, "/Applications/Foo.app/Contents/MacOS/Foo"
            if pid == 10:
                return None, "/Applications/Bar.app/Contents/MacOS/Bar"
            raise AssertionError(f"unexpected pid {pid}")

        monkeypatch.setattr(attribution, "_ps_ppid_and_comm", fake_ps)
        assert attribution.process_info(1) == (
            "Foo.app",
            "/Applications/Foo.app/Contents/MacOS/Foo",
            10,
            "Bar.app",
        )

    def test_non_darwin_uses_basename_for_self_and_parent(self, monkeypatch):
        monkeypatch.setattr(attribution.platform, "system", lambda: "Linux")

        def fake_ps(pid):
            if pid == 1:
                return 20, "/usr/bin/foo"
            if pid == 20:
                return None, "/usr/bin/bash"
            raise AssertionError(f"unexpected pid {pid}")

        monkeypatch.setattr(attribution, "_ps_ppid_and_comm", fake_ps)
        assert attribution.process_info(1) == ("foo", "/usr/bin/foo", 20, "bash")

    def test_no_ppid_skips_parent_lookup(self, monkeypatch):
        monkeypatch.setattr(attribution.platform, "system", lambda: "Linux")
        calls = []

        def fake_ps(pid):
            calls.append(pid)
            return None, "/usr/bin/foo"

        monkeypatch.setattr(attribution, "_ps_ppid_and_comm", fake_ps)
        assert attribution.process_info(1) == ("foo", "/usr/bin/foo", None, None)
        assert calls == [1]  # parent lookup never attempted

    def test_ppid_present_but_parent_path_missing(self, monkeypatch):
        monkeypatch.setattr(attribution.platform, "system", lambda: "Linux")

        def fake_ps(pid):
            if pid == 1:
                return 30, "/usr/bin/foo"
            if pid == 30:
                return None, None
            raise AssertionError(f"unexpected pid {pid}")

        monkeypatch.setattr(attribution, "_ps_ppid_and_comm", fake_ps)
        assert attribution.process_info(1) == ("foo", "/usr/bin/foo", 30, None)


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

    @pytest.mark.asyncio
    async def test_pid_found_but_process_info_unresolved_is_unknown(self, monkeypatch):
        # port lookup hits a pid, but /proc or ps couldn't resolve a name for
        # it (e.g. the process exited between snapshot and lookup).
        monkeypatch.setattr(attribution, "snapshot_port_table", lambda: {22: 4242})
        monkeypatch.setattr(
            attribution, "process_info", lambda pid: (None, None, None, None)
        )
        attribution._process_cache.clear()

        a = attribution.Attribution()
        with _context(a) as tctx:
            tctx.configure(a)
            f = tflow.tflow()
            await a.client_connected(f.client_conn)
            assert a._by_client[f.client_conn.id] == attribution.AppInfo(
                source="unknown", pid=4242
            )

    @pytest.mark.asyncio
    async def test_requestheaders_noop_when_firetoll_disabled(self, monkeypatch):
        monkeypatch.setattr(attribution, "snapshot_port_table", lambda: {})

        a = attribution.Attribution()
        with _context(a) as tctx:
            tctx.configure(a)
            f = tflow.tflow()
            await a.client_connected(f.client_conn)
            tctx.options.firetoll = False
            a.requestheaders(f)
            assert "firetoll.app" not in f.metadata
