"""Curated block lists for spyware / telemetry / ads plus user-added hosts.

The bundled lists are intentionally modest and well-known; the point is a sane
default the user can extend from the UI, not an exhaustive filter list.  Hosts
are matched by exact host or by parent-domain suffix (``a.b.example.com`` matches
``example.com``).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from storage.config import Settings


BUILTIN: dict[str, dict[str, Any]] = {
    "windows-telemetry": {
        "label": "Windows / Microsoft telemetry",
        "hosts": [
            "vortex.data.microsoft.com",
            "vortex-win.data.microsoft.com",
            "telecommand.telemetry.microsoft.com",
            "telemetry.microsoft.com",
            "watson.telemetry.microsoft.com",
            "watson.microsoft.com",
            "settings-win.data.microsoft.com",
            "v10.vortex-win.data.microsoft.com",
            "v20.vortex-win.data.microsoft.com",
            "browser.events.data.msn.com",
            "self.events.data.microsoft.com",
            "eu-mobile.events.data.microsoft.com",
            "us-mobile.events.data.microsoft.com",
        ],
    },
    "ads-trackers": {
        "label": "Ad networks & trackers",
        "hosts": [
            "doubleclick.net",
            "googlesyndication.com",
            "googleadservices.com",
            "google-analytics.com",
            "analytics.google.com",
            "adservice.google.com",
            "scorecardresearch.com",
            "quantserve.com",
            "criteo.com",
            "adnxs.com",
            "taboola.com",
            "outbrain.com",
            "moatads.com",
        ],
    },
    "social-trackers": {
        "label": "Social-media trackers",
        "hosts": [
            "connect.facebook.net",
            "graph.facebook.com",
            "analytics.tiktok.com",
            "ads-api.tiktok.com",
            "ads.linkedin.com",
            "px.ads.linkedin.com",
        ],
    },
    "app-telemetry": {
        "label": "Third-party app telemetry",
        "hosts": [
            "app-measurement.com",
            "firebaseinstallations.googleapis.com",
            "crashlytics.com",
            "sentry.io",
            "bugsnag.com",
            "mixpanel.com",
            "segment.io",
            "amplitude.com",
        ],
    },
}


def _host_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    return host == pattern or host.endswith("." + pattern)


class Blocklists:
    def __init__(self, settings: "Settings") -> None:
        self._settings = settings

    # -- lookup ------------------------------------------------------------- #
    def is_blocked(self, host: str) -> tuple[bool, str]:
        """Return (blocked, reason) for a destination host."""
        host = (host or "").lower()
        for cat in self._settings.enabled_blocklists:
            spec = BUILTIN.get(cat)
            if not spec:
                continue
            for pattern in spec["hosts"]:
                if _host_matches(host, pattern):
                    return True, f"blocklist:{cat}"
        for pattern in self._settings.custom_blocked_hosts:
            if pattern and _host_matches(host, pattern):
                return True, "blocklist:custom"
        return False, ""

    # -- introspection for the UI ------------------------------------------ #
    def category_summary(self) -> list[dict[str, Any]]:
        out = []
        enabled = set(self._settings.enabled_blocklists)
        for key, spec in BUILTIN.items():
            out.append({
                "key": key,
                "label": spec["label"],
                "count": len(spec["hosts"]),
                "enabled": key in enabled,
            })
        out.append({
            "key": "custom",
            "label": "Custom hosts",
            "count": len(self._settings.custom_blocked_hosts),
            "enabled": True,
            "hosts": list(self._settings.custom_blocked_hosts),
        })
        return out
