"""Observe new outbound network connections per process.

Complements the proxy: even traffic that never passes through the proxy (e.g. a
raw socket) shows up here as "process X connected to A.B.C.D:port", giving the
activity log a fuller picture of what each app did on the network.
"""
from __future__ import annotations

import threading
from typing import Any

import psutil


class NetstatWatcher:
    def __init__(self, ctx, interval: float = 3.0) -> None:
        self.ctx = ctx
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: set[tuple[int, str, int]] = set()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="netstat-watch", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        # baseline: record existing connections without reporting them
        self._collect(report=False)
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break
            try:
                self._collect(report=True)
            except Exception:
                continue

    def _collect(self, report: bool) -> None:
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return
        for c in conns:
            if not c.raddr or not c.pid:
                continue
            # only established / outbound connections with a remote peer
            if c.status not in ("ESTABLISHED", "SYN_SENT", "NONE"):
                continue
            key = (c.pid, c.raddr.ip, c.raddr.port)
            if key in self._seen:
                continue
            self._seen.add(key)
            if len(self._seen) > 20000:  # bound memory
                self._seen.clear()
                self._seen.add(key)
            if not report:
                continue
            info = self.ctx.attribution.process_info(c.pid)
            event: dict[str, Any] = {
                "type": "connection",
                "pid": c.pid,
                "name": info.get("name", "unknown"),
                "exe": info.get("exe", ""),
                "remote_ip": c.raddr.ip,
                "remote_port": c.raddr.port,
            }
            self.ctx.activity_log.log(event)
