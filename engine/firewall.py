"""Real per-app network blocking via Windows Firewall (needs admin).

The proxy can only drop traffic that routes through it; to actually stop an app
(e.g. Chrome, which uses QUIC/HTTP-3 and can bypass an HTTP proxy) we add a
Windows Firewall rule that blocks that program's inbound + outbound traffic
entirely. All rules are tagged with the group "RequestCycleMonitor" so we can
clean them all up on shutdown and never leave the machine blocked.

Requires administrator privileges (creating firewall rules always does).
"""
from __future__ import annotations

import binascii
import ctypes
import subprocess
import sys

_IS_WINDOWS = sys.platform == "win32"
GROUP = "RequestCycleMonitor"


def is_admin() -> bool:
    if not _IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _ps(script: str, timeout: int = 25) -> dict:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if _IS_WINDOWS else 0
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout, creationflags=flags,
        )
        return {"code": p.returncode, "out": p.stdout or "", "err": p.stderr or ""}
    except Exception as e:
        return {"code": -1, "out": "", "err": str(e)}


def _token(exe: str) -> str:
    base = exe.replace("/", "\\").rsplit("\\", 1)[-1]
    crc = binascii.crc32(exe.lower().encode("utf-8", "ignore")) & 0xFFFFFFFF
    return f"{base}#{crc:08x}"


def _q(s: str) -> str:
    """Quote for a PowerShell single-quoted string."""
    return "'" + s.replace("'", "''") + "'"


def block_app(exe: str) -> dict:
    if not _IS_WINDOWS:
        return {"ok": False, "error": "windows only"}
    if not exe:
        return {"ok": False, "error": "no executable path"}
    tok = _token(exe)
    dn = f"RCM-block {tok}"
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"Remove-NetFirewallRule -DisplayName {_q(dn + '*')} 2>$null;"
        f"New-NetFirewallRule -DisplayName {_q(dn + ' out')} -Group {_q(GROUP)} "
        f"-Direction Outbound -Program {_q(exe)} -Action Block -Profile Any | Out-Null;"
        f"New-NetFirewallRule -DisplayName {_q(dn + ' in')} -Group {_q(GROUP)} "
        f"-Direction Inbound -Program {_q(exe)} -Action Block -Profile Any | Out-Null;"
        f"if (Get-NetFirewallRule -DisplayName {_q(dn + ' out')}) {{'OK'}} else {{'FAIL'}}"
    )
    r = _ps(script)
    ok = "OK" in r["out"]
    return {"ok": ok, "needs_admin": (not ok and not is_admin()),
            "detail": (r["out"] + r["err"])[:400]}


def unblock_app(exe: str) -> dict:
    if not _IS_WINDOWS or not exe:
        return {"ok": True}
    tok = _token(exe)
    r = _ps(
        "$ErrorActionPreference='SilentlyContinue';"
        f"Remove-NetFirewallRule -DisplayName {_q('RCM-block ' + tok + '*')} 2>$null;'OK'"
    )
    return {"ok": "OK" in r["out"]}


def clear_all() -> dict:
    """Remove every rule we created (called on startup cleanup and on shutdown)."""
    if not _IS_WINDOWS:
        return {"ok": True}
    r = _ps(
        "$ErrorActionPreference='SilentlyContinue';"
        f"Get-NetFirewallRule -Group {_q(GROUP)} 2>$null | Remove-NetFirewallRule 2>$null;'OK'"
    )
    return {"ok": "OK" in r["out"]}


def reapply(paths: list[str]) -> None:
    """Re-create firewall blocks for the persisted blocked paths (startup)."""
    for p in paths:
        if p:
            block_app(p)
