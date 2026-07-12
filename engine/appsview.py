"""Build the per-app dashboard shown in the Apps tab.

Aggregates live network connections (from psutil, so it works even when the
proxy is off) by process, merges in proxy request/block counts, and annotates
each app with its current policy (allowed / blocked / solo).
"""
from __future__ import annotations

from typing import Any

import psutil

import appmeta
from proxy.rules import SYSTEM_APP_ALLOWLIST


def _categorize(name: str, exe: str) -> str:
    """Bucket a process for the dashboard: 'app', 'system' or 'unknown'.

    'system' = a core OS process (allowlisted name or an executable that lives
    under the Windows directory); 'unknown' = traffic we couldn't attribute to a
    named executable; everything else is a normal 'app'.
    """
    low = (name or "").lower()
    if low in ("", "unknown"):
        return "unknown"          # traffic we couldn't attribute to a named exe
    if low in SYSTEM_APP_ALLOWLIST:
        return "system"
    path = (exe or "").replace("/", "\\").lower()
    if "\\windows\\" in path:
        return "system"
    return "app"                  # a named process is an app even without a path


def build_apps(ctx) -> dict[str, Any]:
    settings = ctx.settings
    blocked = {a.lower() for a in settings.blocked_apps}
    allowed = {a.lower() for a in settings.allowed_apps}
    pending = {p["name"].lower() for p in ctx.pending_list()}
    solo = (settings.solo_app or "").lower()
    fg_pid = ctx.attribution.foreground_pid()

    # pid -> aggregate
    apps: dict[int, dict[str, Any]] = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []
    for c in conns:
        if not c.pid:
            continue
        entry = apps.get(c.pid)
        if entry is None:
            info = ctx.attribution.process_info(c.pid)
            entry = {
                "pid": c.pid,
                "name": info.get("name", "unknown"),
                "exe": info.get("exe", ""),
                "connections": 0,
                "established": 0,
                "remotes": [],
                "_remset": set(),
            }
            apps[c.pid] = entry
        if c.raddr:
            entry["connections"] += 1
            if c.status == "ESTABLISHED":
                entry["established"] += 1
            key = f"{c.raddr.ip}:{c.raddr.port}"
            if key not in entry["_remset"] and len(entry["remotes"]) < 12:
                entry["_remset"].add(key)
                entry["remotes"].append(key)

    # merge proxy stats + policy, drop the internal set
    out = []
    for entry in apps.values():
        name = entry["name"]
        low = name.lower()
        stats = ctx.app_stats_for(name)
        top_hosts = sorted(stats["hosts"].items(), key=lambda kv: -kv[1])[:6]
        is_pending = low in pending
        is_blocked = low in blocked or is_pending or (bool(solo) and low != solo)
        out.append({
            "pid": entry["pid"],
            "name": name,
            "exe": entry["exe"],
            "connections": entry["connections"],
            "established": entry["established"],
            "remotes": entry["remotes"],
            "requests": stats["requests"],
            "blocked_count": stats["blocked"],
            "top_hosts": [{"host": h, "count": n} for h, n in top_hosts],
            "foreground": entry["pid"] == fg_pid,
            "policy_blocked": low in blocked,
            "allowed": low in allowed,
            "pending": is_pending,
            "is_solo": bool(solo) and low == solo,
            "effectively_blocked": is_blocked,
            "category": _categorize(name, entry["exe"]),
            "group": appmeta.vendor(entry["exe"]),
        })

    # also include apps we've seen through the proxy that have no live socket now
    live_names = {a["name"].lower() for a in out}
    for low, e in list(ctx.app_stats.items()):
        if low in live_names:
            continue
        top_hosts = sorted(e["hosts"].items(), key=lambda kv: -kv[1])[:6]
        is_pending = low in pending
        out.append({
            "pid": None, "name": e["name"], "exe": "",
            "connections": 0, "established": 0, "remotes": [],
            "requests": e["requests"], "blocked_count": e["blocked"],
            "top_hosts": [{"host": h, "count": n} for h, n in top_hosts],
            "foreground": False,
            "policy_blocked": low in blocked,
            "allowed": low in allowed,
            "pending": is_pending,
            "is_solo": bool(solo) and low == solo,
            "effectively_blocked": low in blocked or is_pending or (bool(solo) and low != solo),
            "category": _categorize(e["name"], ""),
            "group": "",
        })

    # Always surface saved-blocked apps, even if they aren't running right now,
    # so the user can see and un-block them after a restart.
    present = {a["name"].lower() for a in out}
    path_by_name: dict[str, str] = {}
    for p in settings.blocked_app_paths:
        base = p.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        path_by_name.setdefault(base, p)
    for nm in settings.blocked_apps:
        low = nm.lower()
        if low in present:
            continue
        present.add(low)
        out.append({
            "pid": None, "name": nm, "exe": path_by_name.get(low, ""),
            "connections": 0, "established": 0, "remotes": [],
            "requests": 0, "blocked_count": 0, "top_hosts": [],
            "foreground": False, "policy_blocked": True,
            "allowed": low in allowed, "pending": False,
            "is_solo": bool(solo) and low == solo,
            "effectively_blocked": True, "offline": True,
            "category": _categorize(nm, path_by_name.get(low, "")),
            "group": appmeta.vendor(path_by_name.get(low, "")),
        })

    # sort: foreground first, then most active
    out.sort(key=lambda a: (not a["foreground"], -(a["established"] * 100 + a["requests"] + a["connections"])))
    return {
        "apps": out,
        "solo_app": settings.solo_app,
        "blocked_apps": settings.blocked_apps,
        "allowed_apps": settings.allowed_apps,
        "proxy_active": ctx.system_proxy_active,
    }
