"""Map network connections back to the process that made them.

Two jobs:
  * ``attribute(ip, port)`` - given the proxy client's source endpoint, find the
    PID / process name that opened it (so each request is tagged with its app).
  * ``foreground_pid()`` - the PID of the window the user is currently looking at
    (drives the "current app only" focus mode).

Both use short-lived caches: ``psutil.net_connections`` is comparatively
expensive, and the foreground window is polled far more often than it changes.

Caveat: very short-lived connections may close before we snapshot them, so
attribution is best-effort.  The connection table is rebuilt on a cache miss.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any, Optional

import psutil

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    try:
        import win32gui  # type: ignore
        import win32process  # type: ignore
    except Exception:  # pragma: no cover - pywin32 not installed
        win32gui = None
        win32process = None
else:  # pragma: no cover - non-Windows dev
    win32gui = None
    win32process = None


class Attribution:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._port_map: dict[int, int] = {}     # local port -> pid
        self._port_map_ts = 0.0
        self._proc_cache: dict[int, dict[str, Any]] = {}
        self._fg_cache: tuple[float, Optional[dict[str, Any]]] = (0.0, None)

    # -- connection -> pid -------------------------------------------------- #
    def _refresh_ports(self) -> None:
        mapping: dict[int, int] = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.laddr and c.pid:
                    mapping[c.laddr.port] = c.pid
        except Exception:
            pass
        self._port_map = mapping
        self._port_map_ts = time.time()

    def _pid_for_port(self, port: int) -> Optional[int]:
        with self._lock:
            if time.time() - self._port_map_ts > 1.0:
                self._refresh_ports()
            pid = self._port_map.get(port)
            if pid is None:
                # miss: force a fresh snapshot once, in case it's a new conn
                self._refresh_ports()
                pid = self._port_map.get(port)
            return pid

    def process_info(self, pid: Optional[int]) -> dict[str, Any]:
        if not pid:
            return {"pid": None, "name": "unknown", "exe": ""}
        cached = self._proc_cache.get(pid)
        if cached:
            return cached
        info: dict[str, Any] = {"pid": pid, "name": "unknown", "exe": ""}
        try:
            p = psutil.Process(pid)
            info["name"] = p.name()
            try:
                info["exe"] = p.exe()
            except Exception:
                info["exe"] = ""
        except Exception:
            pass
        self._proc_cache[pid] = info
        return info

    def attribute(self, ip: Optional[str], port: Optional[int]) -> dict[str, Any]:
        if not port:
            return {"pid": None, "name": "unknown", "exe": ""}
        pid = self._pid_for_port(port)
        return self.process_info(pid)

    # -- foreground window -> pid ------------------------------------------ #
    def foreground_pid(self) -> Optional[int]:
        info = self.foreground_info()
        return info.get("pid") if info else None

    def foreground_info(self) -> Optional[dict[str, Any]]:
        ts, cached = self._fg_cache
        if time.time() - ts < 0.5:
            return cached
        info: Optional[dict[str, Any]] = None
        if win32gui and win32process:
            try:
                hwnd = win32gui.GetForegroundWindow()
                if hwnd:
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    if pid:
                        info = self.process_info(pid)
                        try:
                            info = dict(info)
                            info["title"] = win32gui.GetWindowText(hwnd)
                        except Exception:
                            pass
            except Exception:
                info = None
        self._fg_cache = (time.time(), info)
        return info
