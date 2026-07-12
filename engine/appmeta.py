"""Read a program's vendor/product from its executable's version resource.

Used by the Apps dashboard to group related processes under one heading — e.g.
Norton's several background services (``VpnSvc.exe``, ``NortonUI.exe`` …) all
carry the same CompanyName, so they collapse into a single "Norton" group.

Windows-only (uses pywin32's version-info reader); results are cached by path.
On any other platform, or when the resource is missing, ``vendor()`` returns "".
"""
from __future__ import annotations

import sys
import threading

_IS_WINDOWS = sys.platform == "win32"
if _IS_WINDOWS:
    try:
        import win32api  # type: ignore
    except Exception:  # pragma: no cover - pywin32 not installed
        win32api = None  # type: ignore
else:  # pragma: no cover - non-Windows dev
    win32api = None  # type: ignore

_cache: dict[str, str] = {}
_lock = threading.Lock()

# Trailing corporate boilerplate stripped so "Google LLC" and "Google" group
# together. Order matters: longer/more-specific suffixes first.
_SUFFIXES = (
    ", incorporated", " incorporated", ", inc.", ", inc", " inc.", " inc",
    " corporation", " corp.", " corp", ", llc", " l.l.c.", " llc",
    " ltd.", " ltd", " limited", " co., ltd.", " co.", " gmbh", " s.a.",
    " s.r.l.", " a.g.", " ag", " pvt. ltd.", " software", " technologies",
)


def _clean(name: str) -> str:
    n = " ".join((name or "").split()).strip()
    low = n.lower()
    for suf in _SUFFIXES:
        if low.endswith(suf):
            n = n[: len(n) - len(suf)].rstrip(" ,.")
            break
    return n.strip()


def _read_version_string(exe: str) -> str:
    """Return the exe's CompanyName (falling back to ProductName), or ""."""
    if not win32api:
        return ""
    try:
        trans = win32api.GetFileVersionInfo(exe, "\\VarFileInfo\\Translation")
    except Exception:
        return ""
    if not trans:
        return ""
    lang, codepage = trans[0]
    for key in ("CompanyName", "ProductName"):
        try:
            val = win32api.GetFileVersionInfo(
                exe, "\\StringFileInfo\\%04X%04X\\%s" % (lang, codepage, key)
            )
        except Exception:
            continue
        if val and val.strip():
            return val.strip()
    return ""


def _from_path(exe: str) -> str:
    """Fallback: the folder directly under Program Files / (x86)."""
    parts = [p for p in (exe or "").replace("/", "\\").split("\\") if p]
    for i, seg in enumerate(parts):
        if seg.lower().startswith("program files") and i + 1 < len(parts):
            return parts[i + 1]
    return ""


def vendor(exe: str) -> str:
    """Best-effort vendor/product name for grouping, or "" if unknown."""
    if not exe:
        return ""
    with _lock:
        if exe in _cache:
            return _cache[exe]
    v = _clean(_read_version_string(exe)) or _from_path(exe)
    with _lock:
        _cache[exe] = v
    return v
