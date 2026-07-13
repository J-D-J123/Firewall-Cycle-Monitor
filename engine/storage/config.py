"""Persistent settings and user rules.

Two JSON files under ``config/``:
  * ``settings.json`` - engine-wide preferences (ports, modes, blocklist toggles)
  * ``rules.json``    - the user's request-modification / blocking rules

Both are loaded at startup and saved whenever the UI changes them.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

import paths


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
@dataclass
class Settings:
    api_port: int = 8788
    proxy_port: int = 8080
    # When True, blocking/modification rules only apply to the foreground app.
    current_app_only: bool = False
    # "enforce" -> only apply rules to the foreground app (others pass through)
    # "monitor" -> only log the foreground app (others are ignored in the feed)
    focus_mode: str = "enforce"
    # Master switch: when paused, traffic passes through untouched (still logged).
    paused: bool = False
    # Point the Windows system proxy at us on startup. On by default (per user
    # preference). Note: until the CA is trusted, HTTPS sites will show cert
    # warnings - install the certificate from Settings on first run.
    proxy_enabled: bool = True
    # Categories from blocklists.py that are active.
    enabled_blocklists: list[str] = field(
        default_factory=lambda: ["windows-telemetry", "ads-trackers"]
    )
    # Extra hosts the user wants blocked, on top of the enabled categories.
    custom_blocked_hosts: list[str] = field(default_factory=list)
    # Per-app network policy (matched by exe name, case-insensitive):
    #   blocked_apps - these apps are denied all network (via the proxy)
    #   solo_app     - if set, ONLY this app may use the network; all others blocked
    blocked_apps: list[str] = field(default_factory=list)
    # Full exe paths of blocked apps, for Windows Firewall enforcement.
    blocked_app_paths: list[str] = field(default_factory=list)
    solo_app: str = ""
    # New-app guard: when True, an app we've never approved is blocked the moment
    # it tries to use the network, and a prompt asks the user to allow or block it.
    guard_new_apps: bool = True
    # Exe names (case-insensitive) the user has explicitly allowed. Apps listed
    # here are never quarantined by the new-app guard.
    allowed_apps: list[str] = field(default_factory=list)
    # Send privacy signals (Do-Not-Track / Global Privacy Control) on requests.
    add_privacy_headers: bool = False
    # --- Firewall (non-HTTP) blocking, all needs admin -------------------
    # Block outbound ping (ICMP echo) from the whole PC.
    block_ping: bool = False
    # Strict mode: default-deny outbound; only traffic through the monitor
    # (plus DNS/DHCP) is allowed. Blocks ping, QUIC, raw UDP/TCP, etc.
    strict_mode: bool = False
    # Per-app protocol blocks from the request-blocker popup:
    #   [{"name": "chrome.exe", "exe": "C:\\...\\chrome.exe", "proto": "icmp"|"quic"}]
    app_proto_blocks: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_settings() -> Settings:
    paths.ensure_dirs()
    if paths.SETTINGS_FILE.exists():
        try:
            data = json.loads(paths.SETTINGS_FILE.read_text(encoding="utf-8"))
            known = {f for f in Settings().__dict__}
            return Settings(**{k: v for k, v in data.items() if k in known})
        except Exception:
            pass
    s = Settings()
    save_settings(s)
    return s


def save_settings(settings: Settings) -> None:
    paths.ensure_dirs()
    paths.SETTINGS_FILE.write_text(
        json.dumps(settings.to_dict(), indent=2), encoding="utf-8"
    )


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    """A single user rule.

    match:
        host        - glob against destination host (e.g. "*.doubleclick.net")
        url_pattern - optional regex against the full URL
        method      - optional HTTP method (GET/POST/...), "" = any
        app_scope   - {"type": "all"|"exe"|"current", "value": "chrome.exe"}
    action:
        type   - "block" | "modify_headers" | "modify_body" | "redirect" | "delay"
        params - action-specific parameters (see proxy/rules.py)
    """
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = "Untitled rule"
    enabled: bool = True
    match: dict[str, Any] = field(default_factory=dict)
    action: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RuleStore:
    """Thread-safe collection of rules persisted to ``rules.json``."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rules: list[Rule] = []
        self._version = 0
        self.load()

    # -- persistence -------------------------------------------------------- #
    def load(self) -> None:
        paths.ensure_dirs()
        with self._lock:
            if paths.RULES_FILE.exists():
                try:
                    raw = json.loads(paths.RULES_FILE.read_text(encoding="utf-8"))
                    self._rules = [Rule(**r) for r in raw]
                except Exception:
                    self._rules = []
            else:
                self._rules = list(_default_rules())
                self._save_locked()
            self._version += 1

    def _save_locked(self) -> None:
        paths.RULES_FILE.write_text(
            json.dumps([r.to_dict() for r in self._rules], indent=2),
            encoding="utf-8",
        )
        self._version += 1

    # -- accessors ---------------------------------------------------------- #
    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self._rules]

    def snapshot(self) -> list[Rule]:
        """A shallow copy for the rule engine to evaluate without holding the lock."""
        with self._lock:
            return list(self._rules)

    def add(self, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            data.pop("id", None)
            rule = Rule(**{k: v for k, v in data.items() if k in Rule().__dict__})
            self._rules.append(rule)
            self._save_locked()
            return rule.to_dict()

    def update(self, rule_id: str, data: dict[str, Any]) -> Optional[dict[str, Any]]:
        with self._lock:
            for i, r in enumerate(self._rules):
                if r.id == rule_id:
                    merged = {**r.to_dict(), **data, "id": rule_id}
                    self._rules[i] = Rule(
                        **{k: v for k, v in merged.items() if k in Rule().__dict__}
                    )
                    self._save_locked()
                    return self._rules[i].to_dict()
            return None

    def delete(self, rule_id: str) -> bool:
        with self._lock:
            n = len(self._rules)
            self._rules = [r for r in self._rules if r.id != rule_id]
            if len(self._rules) != n:
                self._save_locked()
                return True
            return False


def _default_rules() -> list[Rule]:
    """A couple of illustrative rules so the UI isn't empty on first launch."""
    return [
        Rule(
            name="Strip cross-site tracking cookies (example, disabled)",
            enabled=False,
            match={"host": "*", "app_scope": {"type": "all"}},
            action={"type": "modify_headers", "params": {"remove": ["Cookie"]}},
        ),
        Rule(
            name="Block example tracker",
            enabled=False,
            match={"host": "*.doubleclick.net", "app_scope": {"type": "all"}},
            action={"type": "block", "params": {"status": 403}},
        ),
    ]
