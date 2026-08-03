"""Layer 1: attribute each client connection to the local process that made it.

Resolution happens at `client_connected`, never later - ephemeral source ports
get reused, and attributing at `response` time is how you get confidently
wrong app labels (the worst failure mode for this feature). The result is
cached per-client and copied onto each flow's metadata at `requestheaders`.

Platform notes:
- macOS: a bulk `lsof` snapshot of the whole established-connection table,
  measured at ~57ms vs ~189ms for a single targeted lookup - so we always
  snapshot everything and cache it briefly, never query one port at a time.
- Linux: pure-Python /proc/net/tcp{,6} + /proc/*/fd parse, no lsof dependency.
- Windows: unsupported in v1; degrades straight to User-Agent.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Literal

from mitmproxy import connection
from mitmproxy import ctx
from mitmproxy import http

logger = logging.getLogger(__name__)

AttributionSource = Literal["process", "user-agent", "unknown"]

SNAPSHOT_TTL = 0.25  # seconds


@dataclass
class AppInfo:
    source: AttributionSource
    pid: int | None = None
    process: str | None = None
    path: str | None = None
    parent: str | None = None

    def as_metadata(self) -> dict:
        return {
            "source": self.source,
            "pid": self.pid,
            "process": self.process,
            "path": self.path,
            "parent": self.parent,
        }


def collapse_macos_app(path: str) -> str:
    match = re.search(r"/([^/]+\.app)/Contents/MacOS/", path)
    if match:
        return match.group(1)
    return path.rsplit("/", 1)[-1]


def port_from_address(address: str) -> int | None:
    """`"127.0.0.1:51820"` / `"[::1]:51820"` -> `51820`."""
    if address.startswith("["):
        _, _, port_str = address.rpartition("]:")
    else:
        _, _, port_str = address.rpartition(":")
    try:
        return int(port_str)
    except ValueError:
        return None


def snapshot_port_table() -> dict[int, int]:
    """Local TCP port -> owning pid, for every established connection on this
    host. Runs on a thread; must never be called from the event loop directly.
    """
    system = platform.system()
    if system == "Darwin":
        return _snapshot_macos()
    elif system == "Linux":
        return _snapshot_linux()
    return {}


def _snapshot_macos() -> dict[int, int]:
    try:
        proc = subprocess.run(
            ["lsof", "-nP", "-w", "-iTCP", "-sTCP:ESTABLISHED", "-Fpcn"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return {}

    table: dict[int, int] = {}
    pid: int | None = None
    my_pid = os.getpid()
    for line in proc.stdout.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            try:
                pid = int(value)
            except ValueError:
                pid = None
        elif tag == "n" and pid is not None and pid != my_pid:
            local, _, _remote = value.partition("->")
            port = port_from_address(local)
            if port is not None:
                table[port] = pid
    return table


def _snapshot_linux(proc_root: str = "/proc") -> dict[int, int]:
    inode_to_port: dict[str, int] = {}
    for name in ("tcp", "tcp6"):
        try:
            with open(f"{proc_root}/net/{name}") as f:
                lines = f.readlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "01":  # 01 == TCP_ESTABLISHED
                continue
            _, _, port_hex = fields[1].rpartition(":")
            try:
                inode_to_port[fields[9]] = int(port_hex, 16)
            except ValueError:
                continue

    if not inode_to_port:
        return {}

    my_pid = os.getpid()
    table: dict[int, int] = {}
    try:
        pids = [int(p) for p in os.listdir(proc_root) if p.isdigit()]
    except OSError:
        return {}
    for pid in pids:
        if pid == my_pid:
            continue
        try:
            fds = os.listdir(f"{proc_root}/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{proc_root}/{pid}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                port = inode_to_port.get(target[8:-1])
                if port is not None:
                    table[port] = pid
    return table


_PS_LINE = re.compile(r"^\s*(\d+)\s+(.+?)\s*$")


def process_info(pid: int) -> tuple[str | None, str | None, int | None, str | None]:
    """(process_name, full_path, ppid, parent_name) for `pid`. Callers should
    cache this forever per pid - measured at ~158ms per call."""
    ppid, path = _ps_ppid_and_comm(pid)
    if path is None:
        return None, None, ppid, None
    name = (
        collapse_macos_app(path)
        if platform.system() == "Darwin"
        else os.path.basename(path)
    )
    parent_name = None
    if ppid is not None:
        _, parent_path = _ps_ppid_and_comm(ppid)
        if parent_path is not None:
            parent_name = (
                collapse_macos_app(parent_path)
                if platform.system() == "Darwin"
                else os.path.basename(parent_path)
            )
    return name, path, ppid, parent_name


def _ps_ppid_and_comm(pid: int) -> tuple[int | None, str | None]:
    try:
        proc = subprocess.run(
            ["ps", "-o", "ppid=,comm=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    match = _PS_LINE.match(proc.stdout)
    if not match:
        return None, None
    try:
        ppid = int(match.group(1))
    except ValueError:
        ppid = None
    return ppid, match.group(2)


class _PortTable:
    """A cached, refreshed-on-demand snapshot. One bulk syscall beats N
    targeted ones - see module docstring."""

    def __init__(self) -> None:
        self._by_port: dict[int, int] = {}
        self._last_refresh = 0.0
        self._lock = asyncio.Lock()

    async def pid_for_port(self, port: int) -> int | None:
        async with self._lock:
            now = time.monotonic()
            if now - self._last_refresh > SNAPSHOT_TTL:
                await self._refresh()
            pid = self._by_port.get(port)
            if pid is None:
                # one immediate re-snapshot on miss (connection may have raced
                # the last snapshot), then give up.
                await self._refresh()
                pid = self._by_port.get(port)
            return pid

    async def _refresh(self) -> None:
        self._by_port = await asyncio.to_thread(snapshot_port_table)
        self._last_refresh = time.monotonic()


_process_cache: dict[int, tuple[str | None, str | None, int | None, str | None]] = {}


async def _cached_process_info(
    pid: int,
) -> tuple[str | None, str | None, int | None, str | None]:
    if pid not in _process_cache:
        _process_cache[pid] = await asyncio.to_thread(process_info, pid)
    return _process_cache[pid]


class Attribution:
    """L1 addon: resolves and caches per-client process attribution, and
    stamps it onto every flow's metadata."""

    def __init__(self) -> None:
        self._table = _PortTable()
        self._by_client: dict[str, AppInfo] = {}

    async def client_connected(self, client: connection.Client) -> None:
        if not (ctx.options.firetoll and ctx.options.firetoll_attribution):
            return
        pid = await self._table.pid_for_port(client.peername[1])
        if pid is None:
            self._by_client[client.id] = AppInfo(source="unknown")
            return
        name, path, _ppid, parent_name = await _cached_process_info(pid)
        if name is None:
            self._by_client[client.id] = AppInfo(source="unknown", pid=pid)
            return
        self._by_client[client.id] = AppInfo(
            source="process", pid=pid, process=name, path=path, parent=parent_name
        )

    def client_disconnected(self, client: connection.Client) -> None:
        self._by_client.pop(client.id, None)

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        if not ctx.options.firetoll:
            return
        info = self._by_client.get(flow.client_conn.id)
        if info is None or info.source == "unknown":
            user_agent = flow.request.headers.get("user-agent")
            if user_agent:
                info = AppInfo(source="user-agent", process=user_agent)
            else:
                info = AppInfo(source="unknown")
        flow.metadata["firetoll.app"] = info.as_metadata()
