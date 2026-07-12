"""Shared runtime context passed to the addon, monitors and API server."""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Optional

import paths
from api.bus import EventBus
from storage.config import Settings, RuleStore, save_settings
from storage.logs import SessionLogger, ActivityLogger
from proxy.blocklists import Blocklists
from proxy.attribution import Attribution
from proxy.rules import RuleEngine


class AppContext:
    """Container for everything the running engine shares."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.bus = EventBus()
        self.rules = RuleStore()
        self.blocklists = Blocklists(settings)
        self.attribution = Attribution()
        self.session_log = SessionLogger()
        self.activity_log = ActivityLogger()
        self.rule_engine = RuleEngine(self)

        # runtime status flags (mutable, read from many threads)
        self._lock = threading.Lock()
        self.proxy_active = False          # is the mitmproxy listener up?
        self.system_proxy_active = False   # is the Windows system proxy pointed at us?
        self.proxy_error: Optional[str] = None

        # counters surfaced in /state
        self.stats = {"requests": 0, "responses": 0, "blocked": 0, "modified": 0}

        # per-app proxy activity for the Apps dashboard: name(lower) -> stats
        self._app_lock = threading.Lock()
        self.app_stats: dict[str, dict[str, Any]] = {}

        # seed the counters from disk so the activity summary is all-time
        self._load_stats()

        # apps auto-blocked by the new-app guard, awaiting a user decision.
        # Runtime-only: on restart an un-approved app is simply re-quarantined
        # the next time it tries to connect. name(lower) -> {name, exe, pid, ...}
        self._pending_lock = threading.Lock()
        self.pending_apps: dict[str, dict[str, Any]] = {}

    def record_app(self, name: str, host: str, blocked: bool) -> None:
        if not name:
            return
        key = name.lower()
        with self._app_lock:
            e = self.app_stats.get(key)
            if e is None:
                e = {"name": name, "requests": 0, "blocked": 0, "hosts": {}}
                self.app_stats[key] = e
            e["requests"] += 1
            if blocked:
                e["blocked"] += 1
            if host:
                e["hosts"][host] = e["hosts"].get(host, 0) + 1
                if len(e["hosts"]) > 200:  # bound memory
                    e["hosts"].pop(next(iter(e["hosts"])))

    def app_stats_for(self, name: str) -> dict[str, Any]:
        with self._app_lock:
            e = self.app_stats.get((name or "").lower())
            if not e:
                return {"requests": 0, "blocked": 0, "hosts": {}}
            return {"requests": e["requests"], "blocked": e["blocked"],
                    "hosts": dict(e["hosts"])}

    def top_apps(self, limit: int = 6) -> list[dict[str, Any]]:
        """The busiest apps by request count, for the activity summary."""
        with self._app_lock:
            items = sorted(self.app_stats.values(),
                           key=lambda e: -e["requests"])[:limit]
            return [{"name": e["name"], "requests": e["requests"],
                     "blocked": e["blocked"]} for e in items]

    # -- all-time counter persistence -------------------------------------- #
    def _load_stats(self) -> None:
        """Seed counters from stats.json (best-effort) so they accumulate over
        the lifetime of the tool rather than resetting each launch."""
        try:
            data = json.loads(paths.STATS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return
        for k in list(self.stats):
            v = (data.get("totals") or {}).get(k)
            if isinstance(v, int) and v >= 0:
                self.stats[k] = v
        for e in (data.get("apps") or []):
            name = e.get("name")
            if not name:
                continue
            self.app_stats[name.lower()] = {
                "name": name,
                "requests": int(e.get("requests", 0) or 0),
                "blocked": int(e.get("blocked", 0) or 0),
                "hosts": {},  # hosts are session-scoped; they repopulate live
            }

    def persist_stats(self) -> None:
        """Flush the all-time counters to disk (called periodically + on exit)."""
        with self._lock:
            totals = dict(self.stats)
        with self._app_lock:
            apps = sorted(
                ({"name": e["name"], "requests": e["requests"],
                  "blocked": e["blocked"]} for e in self.app_stats.values()),
                key=lambda a: -a["requests"],
            )[:500]  # bound the file; distinct exe names are naturally limited
        try:
            paths.ensure_dirs()
            paths.STATS_FILE.write_text(
                json.dumps({"totals": totals, "apps": apps}, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    # -- new-app guard ------------------------------------------------------ #
    def quarantine_app(self, name: str, exe: str = "",
                       pid: Optional[int] = None, reason: str = "") -> bool:
        """Mark an un-approved app as blocked-pending-decision.

        Returns True and emits one ``app_quarantined`` event the first time the
        app is seen; subsequent calls for the same app are no-ops so the popup
        isn't re-fired on every request. ``reason`` is a human-readable phrase
        (surfaced in the notification as "blocked because <reason>").
        """
        if not name:
            return False
        key = name.lower()
        with self._pending_lock:
            if key in self.pending_apps:
                return False
            info = {"name": name, "exe": exe or "", "pid": pid,
                    "reason": reason or "it's a new app you haven't allowed yet",
                    "first_seen": time.time()}
            self.pending_apps[key] = info
        self.bus.publish({"type": "app_quarantined", **info})
        return True

    def resolve_app(self, name: str) -> None:
        """Drop an app from quarantine once the user has decided about it."""
        if not name:
            return
        with self._pending_lock:
            self.pending_apps.pop(name.lower(), None)

    def is_pending(self, name: str) -> bool:
        with self._pending_lock:
            return (name or "").lower() in self.pending_apps

    def pending_list(self) -> list[dict[str, Any]]:
        with self._pending_lock:
            return list(self.pending_apps.values())

    # -- convenience -------------------------------------------------------- #
    @property
    def paused(self) -> bool:
        return self.settings.paused

    @property
    def current_app_only(self) -> bool:
        return self.settings.current_app_only

    def bump(self, key: str) -> None:
        with self._lock:
            self.stats[key] = self.stats.get(key, 0) + 1

    def persist_settings(self) -> None:
        save_settings(self.settings)

    def state_dict(self) -> dict[str, Any]:
        return {
            "proxy_active": self.proxy_active,
            "system_proxy_active": self.system_proxy_active,
            "proxy_error": self.proxy_error,
            "settings": self.settings.to_dict(),
            "stats": dict(self.stats),
            "rules_version": self.rules.version,
            "blocklist_categories": self.blocklists.category_summary(),
            "foreground": self.attribution.foreground_info(),
            "ws_clients": self.bus.subscriber_count(),
            "pending_apps": self.pending_list(),
            "top_apps": self.top_apps(),
        }
