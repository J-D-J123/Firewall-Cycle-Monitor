"""Preset security profiles.

Each profile is a one-click bundle of block-list categories (+ a privacy-header
toggle) ranging from "just watch" to "block everything known-bad". Applying a
profile just rewrites the relevant settings; the user can still fine-tune the
individual block lists afterwards (which shows up as the "Custom" profile).
"""
from __future__ import annotations

from typing import Any

# Order matters: shown low-to-high protection in the UI.
PROFILES: dict[str, dict[str, Any]] = {
    "off": {
        "label": "Off — monitor only",
        "description": "Nothing is blocked. Just watch what your apps do.",
        "blocklists": [],
        "privacy_headers": False,
    },
    "balanced": {
        "label": "Balanced (recommended)",
        "description": "Block Windows/Microsoft telemetry and ad networks & "
                       "trackers. Safe for everyday use.",
        "blocklists": ["windows-telemetry", "ads-trackers"],
        "privacy_headers": False,
    },
    "strict": {
        "label": "Strict",
        "description": "Everything in Balanced, plus social-media trackers, and "
                       "sends Do-Not-Track / GPC privacy signals.",
        "blocklists": ["windows-telemetry", "ads-trackers", "social-trackers"],
        "privacy_headers": True,
    },
    "lockdown": {
        "label": "Lockdown",
        "description": "All known telemetry, ad, tracker and third-party "
                       "app-analytics hosts are blocked, plus privacy signals. "
                       "Most aggressive; may affect apps that rely on analytics.",
        "blocklists": ["windows-telemetry", "ads-trackers",
                       "social-trackers", "app-telemetry"],
        "privacy_headers": True,
    },
}


def list_profiles(ctx) -> dict[str, Any]:
    return {
        "profiles": [
            {"key": k, "label": v["label"], "description": v["description"]}
            for k, v in PROFILES.items()
        ],
        "current": current_profile(ctx),
    }


def current_profile(ctx) -> str:
    s = ctx.settings
    cur = set(s.enabled_blocklists)
    for key, spec in PROFILES.items():
        if cur == set(spec["blocklists"]) and s.add_privacy_headers == spec["privacy_headers"]:
            return key
    return "custom"


def apply_profile(ctx, name: str) -> dict[str, Any]:
    spec = PROFILES.get(name)
    if not spec:
        return {"ok": False, "error": f"unknown profile {name!r}"}
    ctx.settings.enabled_blocklists = list(spec["blocklists"])
    ctx.settings.add_privacy_headers = bool(spec["privacy_headers"])
    ctx.persist_settings()
    return {"ok": True, "current": current_profile(ctx),
            "blocklist_categories": ctx.blocklists.category_summary()}
