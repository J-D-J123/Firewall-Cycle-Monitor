"""Rule evaluation: combine block lists + user rules into a decision.

The addon builds a plain ``ReqInfo`` (no mitmproxy types leak in here), asks the
engine for a :class:`Decision`, then applies it to the live flow.  Keeping the
decision logic pure makes it easy to reason about and unit-test.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from context import AppContext


# Core Windows / OS executables the new-app guard never quarantines. They make
# background network requests constantly (so prompting for them would flood the
# user) and cutting them off can break the machine. Their telemetry is still
# handled by the block lists; the user can also block them from the Apps tab.
SYSTEM_APP_ALLOWLIST = frozenset({
    "", "unknown", "system", "system idle process", "registry",
    "memory compression", "svchost.exe", "services.exe", "lsass.exe",
    "wininit.exe", "winlogon.exe", "csrss.exe", "smss.exe", "explorer.exe",
    "dllhost.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe",
    "runtimebroker.exe", "backgroundtaskhost.exe", "searchapp.exe",
    "searchhost.exe", "searchindexer.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "textinputhost.exe", "wmiprvse.exe",
    "conhost.exe", "spoolsv.exe", "fontdrvhost.exe", "audiodg.exe",
    "smartscreen.exe", "securityhealthservice.exe", "securityhealthsystray.exe",
    "msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe",
    "trustedinstaller.exe", "wuauclt.exe", "usocoreworker.exe", "mousocoreworker.exe",
    "dwm.exe", "lockapp.exe", "widgets.exe", "widgetservice.exe",
})


@dataclass
class ReqInfo:
    method: str
    host: str
    url: str
    pid: Optional[int]
    proc_name: str
    exe: str


@dataclass
class Decision:
    block: bool = False
    block_status: int = 403
    block_reason: str = ""
    redirect_url: Optional[str] = None
    delay_ms: int = 0
    # header ops applied to the request
    req_header_set: dict[str, str] = field(default_factory=dict)
    req_header_remove: list[str] = field(default_factory=list)
    # header ops applied to the response
    resp_header_set: dict[str, str] = field(default_factory=dict)
    resp_header_remove: list[str] = field(default_factory=list)
    # body find/replace, each: (find, replace, is_regex)
    req_body_replace: list[tuple[str, str, bool]] = field(default_factory=list)
    resp_body_replace: list[tuple[str, str, bool]] = field(default_factory=list)
    matched: list[str] = field(default_factory=list)

    @property
    def modifies(self) -> bool:
        return bool(
            self.redirect_url or self.delay_ms or self.req_header_set
            or self.req_header_remove or self.resp_header_set
            or self.resp_header_remove or self.req_body_replace
            or self.resp_body_replace
        )


class RuleEngine:
    def __init__(self, ctx: "AppContext") -> None:
        self.ctx = ctx

    # -- scope gate --------------------------------------------------------- #
    def _in_focus(self, info: ReqInfo) -> bool:
        """True if this request is in scope given the global current-app setting."""
        if not self.ctx.settings.current_app_only:
            return True
        if self.ctx.settings.focus_mode != "enforce":
            return True  # "monitor" only affects the feed, not enforcement
        fg = self.ctx.attribution.foreground_pid()
        return fg is not None and info.pid == fg

    def _scope_matches(self, scope: dict[str, Any], info: ReqInfo) -> bool:
        stype = (scope or {}).get("type", "all")
        if stype == "all":
            return True
        if stype == "exe":
            want = str(scope.get("value", "")).lower()
            return bool(want) and info.proc_name.lower() == want
        if stype == "current":
            fg = self.ctx.attribution.foreground_pid()
            return fg is not None and info.pid == fg
        return True

    def _rule_matches(self, match: dict[str, Any], info: ReqInfo) -> bool:
        host_glob = match.get("host") or "*"
        if not fnmatch.fnmatch(info.host.lower(), host_glob.lower()):
            return False
        method = (match.get("method") or "").upper()
        if method and info.method.upper() != method:
            return False
        url_pat = match.get("url_pattern")
        if url_pat:
            try:
                if not re.search(url_pat, info.url):
                    return False
            except re.error:
                return False
        if not self._scope_matches(match.get("app_scope", {"type": "all"}), info):
            return False
        return True

    # -- evaluation --------------------------------------------------------- #
    def evaluate(self, info: ReqInfo) -> Decision:
        decision = Decision()
        if self.ctx.paused:
            return decision

        name = (info.proc_name or "").lower()
        blocked_apps = {a.lower() for a in self.ctx.settings.blocked_apps}
        allowed_apps = {a.lower() for a in self.ctx.settings.allowed_apps}

        # Explicit per-app decisions are enforced regardless of the current-app
        # focus scope: a solo/block/allow choice about a specific program should
        # hold whether or not that program is the window you're looking at. Only
        # the general block lists and user rules further down are limited by focus
        # mode. (Without this, turning on "current app only" silently stops your
        # saved app blocks from applying to anything running in the background.)

        # 1) solo: if set, only that one app may use the network.
        solo = (self.ctx.settings.solo_app or "").lower()
        if solo and name != solo:
            decision.block = True
            decision.block_reason = f"solo:{self.ctx.settings.solo_app}"
            decision.matched.append(decision.block_reason)
            return decision

        # 2) apps the user explicitly blocked (from the Apps dashboard).
        if name and name in blocked_apps:
            decision.block = True
            decision.block_reason = "app-blocked"
            decision.matched.append(f"app-blocked:{info.proc_name}")
            return decision

        # 3) new-app guard: an app we've never approved (and isn't a core OS
        #    process) is blocked and quarantined the instant it touches the
        #    network so the UI can prompt to allow or block it.
        if (self.ctx.settings.guard_new_apps
                and name not in SYSTEM_APP_ALLOWLIST
                and name not in allowed_apps):
            self.ctx.quarantine_app(
                info.proc_name, info.exe, info.pid,
                reason="it's a new app you haven't allowed yet",
            )
            decision.block = True
            decision.block_reason = "new-app"
            decision.matched.append(f"new-app:{info.proc_name}")
            return decision

        # Everything below is scoped by the current-app focus setting.
        if not self._in_focus(info):
            return decision

        # 4) block lists (cheap, high-value)
        blocked, reason = self.ctx.blocklists.is_blocked(info.host)
        if blocked:
            decision.block = True
            decision.block_reason = reason
            decision.matched.append(reason)
            return decision

        # 5) user rules
        for rule in self.ctx.rules.snapshot():
            if not rule.enabled:
                continue
            if not self._rule_matches(rule.match, info):
                continue
            self._apply_action(rule.name, rule.action, decision)
            if decision.block:
                break
        return decision

    def _apply_action(self, name: str, action: dict[str, Any], d: Decision) -> None:
        atype = action.get("type")
        params = action.get("params", {}) or {}
        d.matched.append(name)
        if atype == "block":
            d.block = True
            d.block_status = int(params.get("status", 403))
            d.block_reason = f"rule:{name}"
        elif atype == "redirect":
            url = params.get("url")
            if url:
                d.redirect_url = url
        elif atype == "delay":
            d.delay_ms = int(params.get("ms", 0))
        elif atype == "modify_headers":
            target = params.get("target", "request")
            setmap = params.get("set", {}) or {}
            remove = params.get("remove", []) or []
            if target == "response":
                d.resp_header_set.update(setmap)
                d.resp_header_remove.extend(remove)
            else:
                d.req_header_set.update(setmap)
                d.req_header_remove.extend(remove)
        elif atype == "modify_body":
            target = params.get("target", "request")
            repl = (params.get("find"), params.get("replace", ""),
                    bool(params.get("regex", False)))
            if repl[0] is not None:
                if target == "response":
                    d.resp_body_replace.append(repl)
                else:
                    d.req_body_replace.append(repl)
