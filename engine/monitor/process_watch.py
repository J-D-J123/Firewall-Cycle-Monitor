"""Watch for application launches (and exits) system-wide.

Polls ``psutil.process_iter`` and diffs the PID set - no admin rights required.
New processes are logged to the activity log and pushed to the live feed so the
UI can show "app X started at HH:MM".  The first snapshot is treated as the
baseline (already-running apps are not reported as launches).
"""
from __future__ import annotations

import threading
import time
from typing import Any

import psutil


class ProcessWatcher:
    def __init__(self, ctx, interval: float = 1.5) -> None:
        self.ctx = ctx
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._known: dict[int, dict[str, Any]] = {}

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="process-watch", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _snapshot(self) -> dict[int, dict[str, Any]]:
        out: dict[int, dict[str, Any]] = {}
        for p in psutil.process_iter(["pid", "name", "exe", "create_time"]):
            try:
                info = p.info
                out[info["pid"]] = {
                    "pid": info["pid"],
                    "name": info.get("name") or "unknown",
                    "exe": info.get("exe") or "",
                    "create_time": info.get("create_time"),
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return out

    def _run(self) -> None:
        self._known = self._snapshot()  # baseline
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break
            try:
                current = self._snapshot()
            except Exception:
                continue
            new_pids = current.keys() - self._known.keys()
            gone_pids = self._known.keys() - current.keys()

            for pid in new_pids:
                proc = current[pid]
                event = {
                    "type": "app_launch",
                    "pid": pid,
                    "name": proc["name"],
                    "exe": proc["exe"],
                }
                self.ctx.bus.publish(event)
                self.ctx.activity_log.log(event)

            for pid in gone_pids:
                proc = self._known.get(pid, {})
                event = {
                    "type": "app_exit",
                    "pid": pid,
                    "name": proc.get("name", "unknown"),
                }
                # exits are logged but kept out of the live feed to reduce noise
                self.ctx.activity_log.log(event)

            self._known = current
