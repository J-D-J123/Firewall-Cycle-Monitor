"""Central path resolution for the engine.

The engine lives in ``<project>/engine`` and reads/writes runtime data in
``<project>/config`` and ``<project>/logs``.  Everything is resolved relative to
this file so the engine works regardless of the current working directory.
"""
from __future__ import annotations

import os
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = ENGINE_DIR.parent

CONFIG_DIR = PROJECT_ROOT / "config"
LOG_DIR = PROJECT_ROOT / "logs"
SESSION_LOG_DIR = LOG_DIR / "sessions"
ACTIVITY_LOG_DIR = LOG_DIR / "activity"

SETTINGS_FILE = CONFIG_DIR / "settings.json"
RULES_FILE = CONFIG_DIR / "rules.json"
# All-time activity counters (total/blocked requests + per-app rollup), so the
# activity summary survives restarts.
STATS_FILE = CONFIG_DIR / "stats.json"
# Snapshot of the system proxy state before we changed it, so a crash cannot
# leave the machine pointing at a dead proxy.
PROXY_BACKUP_FILE = CONFIG_DIR / "proxy_backup.json"


def ensure_dirs() -> None:
    for d in (CONFIG_DIR, LOG_DIR, SESSION_LOG_DIR, ACTIVITY_LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)


def mitmproxy_ca_cert() -> Path:
    """Location of the auto-generated mitmproxy CA (created on first proxy run)."""
    home = Path(os.path.expanduser("~"))
    return home / ".mitmproxy" / "mitmproxy-ca-cert.cer"
