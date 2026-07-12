"""Local logging: monitor sessions + system-wide activity.

Session logs: one file per engine run (``logs/sessions/session-<ts>.jsonl``)
containing every request / response / block / modify event as JSON lines, plus a
summary written on shutdown.

Activity logs: appended per day (``logs/activity/<date>.jsonl``) recording app
launches and new network connections observed across the whole system.
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

import paths


def _ts() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


class SessionLogger:
    """Per-run structured log of everything the proxy saw/did."""

    def __init__(self) -> None:
        paths.ensure_dirs()
        self.session_id = _ts()
        self.path = paths.SESSION_LOG_DIR / f"session-{self.session_id}.jsonl"
        self._lock = threading.Lock()
        self._fh = open(self.path, "a", encoding="utf-8")
        self.counts: dict[str, int] = {"requests": 0, "responses": 0,
                                       "blocked": 0, "modified": 0}
        self.started_at = _iso()
        self.log({"type": "session_start", "ts": self.started_at,
                  "session_id": self.session_id})

    def log(self, event: dict[str, Any]) -> None:
        event.setdefault("ts", _iso())
        etype = event.get("type", "")
        with self._lock:
            if etype in ("request",):
                self.counts["requests"] += 1
            elif etype == "response":
                self.counts["responses"] += 1
            if event.get("blocked"):
                self.counts["blocked"] += 1
            if event.get("modified"):
                self.counts["modified"] += 1
            try:
                self._fh.write(json.dumps(event, default=str) + "\n")
                self._fh.flush()
            except Exception:
                pass

    def close(self) -> None:
        with self._lock:
            try:
                summary = {
                    "type": "session_end",
                    "ts": _iso(),
                    "session_id": self.session_id,
                    "started_at": self.started_at,
                    "counts": dict(self.counts),
                }
                self._fh.write(json.dumps(summary) + "\n")
                self._fh.flush()
                self._fh.close()
            except Exception:
                pass


class ActivityLogger:
    """System-wide activity log (app launches + new connections), one file per day."""

    def __init__(self) -> None:
        paths.ensure_dirs()
        self._lock = threading.Lock()

    def _path_for_today(self):
        return paths.ACTIVITY_LOG_DIR / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"

    def log(self, event: dict[str, Any]) -> None:
        event.setdefault("ts", _iso())
        line = json.dumps(event, default=str) + "\n"
        with self._lock:
            try:
                with open(self._path_for_today(), "a", encoding="utf-8") as fh:
                    fh.write(line)
            except Exception:
                pass


# -- readers used by the API to render the Logs / Activity tabs -------------- #
def list_sessions() -> list[dict[str, Any]]:
    paths.ensure_dirs()
    out = []
    for p in sorted(paths.SESSION_LOG_DIR.glob("session-*.jsonl"), reverse=True):
        try:
            stat = p.stat()
            out.append({"name": p.name, "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()})
        except Exception:
            continue
    return out


def read_jsonl(path, limit: int = 2000, tail: bool = True) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    if tail:
        lines = lines[-limit:]
    else:
        lines = lines[:limit]
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    return out


def read_session(name: str, limit: int = 2000) -> list[dict[str, Any]]:
    # Guard against path traversal - only allow plain session file names.
    safe = "".join(c for c in name if c.isalnum() or c in "-_.")
    if not safe.startswith("session-") or not safe.endswith(".jsonl"):
        return []
    return read_jsonl(paths.SESSION_LOG_DIR / safe, limit=limit)


def read_activity(date: Optional[str] = None, limit: int = 2000) -> list[dict[str, Any]]:
    if date:
        safe = "".join(c for c in date if c.isalnum() or c == "-")
        path = paths.ACTIVITY_LOG_DIR / f"{safe}.jsonl"
    else:
        path = paths.ACTIVITY_LOG_DIR / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"
    return read_jsonl(path, limit=limit)


def list_activity_days() -> list[str]:
    paths.ensure_dirs()
    return sorted(
        (p.stem for p in paths.ACTIVITY_LOG_DIR.glob("*.jsonl")), reverse=True
    )
