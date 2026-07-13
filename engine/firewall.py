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

import paths

_IS_WINDOWS = sys.platform == "win32"
GROUP = "RequestCycleMonitor"
# Separate groups so each feature can be applied/removed independently.
LOCKDOWN_GROUP = "RequestCycleMonitorLockdown"   # startup kill-switch (all out)
ICMP_GROUP = "RequestCycleMonitorICMP"           # global ping (ICMP) block
PROTO_GROUP = "RequestCycleMonitorProto"         # per-app protocol blocks
STRICT_GROUP = "RequestCycleMonitorStrict"       # strict-mode allow-list rules
# Where we stash the pre-strict default outbound action so we can restore it.
STRICT_BACKUP = paths.CONFIG_DIR / "firewall_strict_backup.json"


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


# --------------------------------------------------------------------------- #
# Startup kill-switch (fail-closed): block ALL outbound until the proxy is up.
# --------------------------------------------------------------------------- #
def lockdown_on() -> dict:
    """Block every outbound connection until :func:`lockdown_off` is called.

    Windows Firewall never filters loopback (127.0.0.1 / ::1), so the local
    proxy, the engine's API and the UI keep working - only real internet egress
    is blocked. This is the fail-closed guard used at auto-start so nothing can
    phone home before the proxy is actually intercepting. Needs admin.
    """
    if not _IS_WINDOWS:
        return {"ok": False, "error": "windows only"}
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"Remove-NetFirewallRule -Group {_q(LOCKDOWN_GROUP)} 2>$null;"
        "New-NetFirewallRule -DisplayName 'RCM-lockdown all out' "
        f"-Group {_q(LOCKDOWN_GROUP)} -Direction Outbound -Action Block "
        "-Profile Any -Enabled True | Out-Null;"
        f"if (Get-NetFirewallRule -Group {_q(LOCKDOWN_GROUP)}) {{'OK'}} else {{'FAIL'}}"
    )
    r = _ps(script)
    ok = "OK" in r["out"]
    return {"ok": ok, "needs_admin": (not ok and not is_admin()),
            "detail": (r["out"] + r["err"])[:400]}


def lockdown_off() -> dict:
    """Remove the kill-switch, restoring normal (default-allow) outbound."""
    if not _IS_WINDOWS:
        return {"ok": True}
    r = _ps(
        "$ErrorActionPreference='SilentlyContinue';"
        f"Remove-NetFirewallRule -Group {_q(LOCKDOWN_GROUP)} 2>$null;'OK'"
    )
    return {"ok": "OK" in r["out"]}


# --------------------------------------------------------------------------- #
# Global ping (ICMP) block
# --------------------------------------------------------------------------- #
def block_icmp() -> dict:
    """Block outbound ping (ICMP echo requests, v4 + v6) from the whole PC."""
    if not _IS_WINDOWS:
        return {"ok": False, "error": "windows only"}
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"Remove-NetFirewallRule -Group {_q(ICMP_GROUP)} 2>$null;"
        "New-NetFirewallRule -DisplayName 'RCM-block ping v4' "
        f"-Group {_q(ICMP_GROUP)} -Direction Outbound -Protocol ICMPv4 "
        "-IcmpType 8 -Action Block -Profile Any | Out-Null;"
        "New-NetFirewallRule -DisplayName 'RCM-block ping v6' "
        f"-Group {_q(ICMP_GROUP)} -Direction Outbound -Protocol ICMPv6 "
        "-IcmpType 128 -Action Block -Profile Any | Out-Null;"
        f"if (Get-NetFirewallRule -Group {_q(ICMP_GROUP)}) {{'OK'}} else {{'FAIL'}}"
    )
    r = _ps(script)
    ok = "OK" in r["out"]
    return {"ok": ok, "needs_admin": (not ok and not is_admin()),
            "detail": (r["out"] + r["err"])[:400]}


def unblock_icmp() -> dict:
    if not _IS_WINDOWS:
        return {"ok": True}
    r = _ps(
        "$ErrorActionPreference='SilentlyContinue';"
        f"Remove-NetFirewallRule -Group {_q(ICMP_GROUP)} 2>$null;'OK'"
    )
    return {"ok": "OK" in r["out"]}


# --------------------------------------------------------------------------- #
# Per-app protocol blocks (ping / QUIC) — used by the request blocker popup
# --------------------------------------------------------------------------- #
def _proto_rules(exe: str, proto: str) -> str:
    tok = _token(exe)
    if proto == "icmp":
        return (
            f"New-NetFirewallRule -DisplayName {_q('RCM-proto ' + tok + ' icmp4')} "
            f"-Group {_q(PROTO_GROUP)} -Direction Outbound -Program {_q(exe)} "
            "-Protocol ICMPv4 -IcmpType 8 -Action Block -Profile Any | Out-Null;"
            f"New-NetFirewallRule -DisplayName {_q('RCM-proto ' + tok + ' icmp6')} "
            f"-Group {_q(PROTO_GROUP)} -Direction Outbound -Program {_q(exe)} "
            "-Protocol ICMPv6 -IcmpType 128 -Action Block -Profile Any | Out-Null;"
        )
    if proto == "quic":
        # QUIC / HTTP-3 is UDP:443. Blocking it forces the app to fall back to
        # TCP, which the HTTP proxy can then see.
        return (
            f"New-NetFirewallRule -DisplayName {_q('RCM-proto ' + tok + ' quic')} "
            f"-Group {_q(PROTO_GROUP)} -Direction Outbound -Program {_q(exe)} "
            "-Protocol UDP -RemotePort 443 -Action Block -Profile Any | Out-Null;"
        )
    return ""


def block_app_proto(exe: str, proto: str) -> dict:
    if not _IS_WINDOWS:
        return {"ok": False, "error": "windows only"}
    if not exe:
        return {"ok": False, "error": "no executable path"}
    rules = _proto_rules(exe, proto)
    if not rules:
        return {"ok": False, "error": f"unknown proto {proto!r}"}
    tok = _token(exe)
    r = _ps(
        "$ErrorActionPreference='SilentlyContinue';"
        f"Remove-NetFirewallRule -DisplayName {_q('RCM-proto ' + tok + ' ' + proto + '*')} 2>$null;"
        + rules +
        f"if (Get-NetFirewallRule -DisplayName {_q('RCM-proto ' + tok + ' ' + proto + '*')}) {{'OK'}} else {{'FAIL'}}"
    )
    ok = "OK" in r["out"]
    return {"ok": ok, "needs_admin": (not ok and not is_admin()),
            "detail": (r["out"] + r["err"])[:400]}


def unblock_app_proto(exe: str, proto: str) -> dict:
    if not _IS_WINDOWS or not exe:
        return {"ok": True}
    tok = _token(exe)
    r = _ps(
        "$ErrorActionPreference='SilentlyContinue';"
        f"Remove-NetFirewallRule -DisplayName {_q('RCM-proto ' + tok + ' ' + proto + '*')} 2>$null;'OK'"
    )
    return {"ok": "OK" in r["out"]}


def reapply_protos(blocks: list[dict]) -> None:
    """Re-create per-app protocol blocks on startup: [{'exe','proto'}, ...]."""
    for b in blocks:
        exe, proto = b.get("exe"), b.get("proto")
        if exe and proto:
            block_app_proto(exe, proto)


# --------------------------------------------------------------------------- #
# Strict mode: default-deny outbound, allow only the monitor + DNS/DHCP.
# --------------------------------------------------------------------------- #
def strict_on(allow_paths: list[str]) -> dict:
    """Flip the firewall to default-deny outbound so nothing leaves the PC
    except what goes through the monitor. Loopback is auto-exempt (so apps can
    still reach the local proxy); we add allow rules for the engine itself plus
    DNS and DHCP so name resolution and addressing keep working. Everything else
    — ping, QUIC, raw UDP/TCP that bypasses the proxy — is dropped.
    Needs admin. Fully reversed by :func:`strict_off`.
    """
    if not _IS_WINDOWS:
        return {"ok": False, "error": "windows only"}
    # Back up the current per-profile default outbound action once, so we can
    # put it back exactly (a crash is recovered on next launch / on quit).
    try:
        if not STRICT_BACKUP.exists():
            cur = _ps("(Get-NetFirewallProfile | ForEach-Object "
                      "{ \"$($_.Name)=$($_.DefaultOutboundAction)\" }) -join ';'")
            STRICT_BACKUP.parent.mkdir(parents=True, exist_ok=True)
            STRICT_BACKUP.write_text((cur["out"] or "").strip(), encoding="utf-8")
    except Exception:
        pass
    allow = ""
    for p in allow_paths:
        if p:
            allow += (
                f"New-NetFirewallRule -DisplayName {_q('RCM-strict allow ' + _token(p))} "
                f"-Group {_q(STRICT_GROUP)} -Direction Outbound -Program {_q(p)} "
                "-Action Allow -Profile Any | Out-Null;"
            )
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"Remove-NetFirewallRule -Group {_q(STRICT_GROUP)} 2>$null;"
        "New-NetFirewallRule -DisplayName 'RCM-strict allow DNS UDP' "
        f"-Group {_q(STRICT_GROUP)} -Direction Outbound -Protocol UDP -RemotePort 53 "
        "-Action Allow -Profile Any | Out-Null;"
        "New-NetFirewallRule -DisplayName 'RCM-strict allow DNS TCP' "
        f"-Group {_q(STRICT_GROUP)} -Direction Outbound -Protocol TCP -RemotePort 53 "
        "-Action Allow -Profile Any | Out-Null;"
        "New-NetFirewallRule -DisplayName 'RCM-strict allow DHCP' "
        f"-Group {_q(STRICT_GROUP)} -Direction Outbound -Protocol UDP -RemotePort 67,68 "
        "-Action Allow -Profile Any | Out-Null;"
        + allow +
        "Set-NetFirewallProfile -DefaultOutboundAction Block;'OK'"
    )
    r = _ps(script, timeout=40)
    ok = "OK" in r["out"]
    return {"ok": ok, "needs_admin": (not ok and not is_admin()),
            "detail": (r["out"] + r["err"])[:400]}


def strict_off() -> dict:
    """Undo strict mode: restore the previous default outbound action (Allow if
    we have no backup) and drop the strict allow-list."""
    if not _IS_WINDOWS:
        return {"ok": True}
    restore = "Set-NetFirewallProfile -DefaultOutboundAction Allow;"
    try:
        if STRICT_BACKUP.exists():
            data = STRICT_BACKUP.read_text(encoding="utf-8").strip()
            cmds = []
            for part in data.split(";"):
                if "=" not in part:
                    continue
                name, val = part.split("=", 1)
                val = val.strip()
                if val in ("Allow", "Block", "NotConfigured") and name.strip():
                    cmds.append(f"Set-NetFirewallProfile -Name {name.strip()} "
                                f"-DefaultOutboundAction {val};")
            if cmds:
                restore = "".join(cmds)
    except Exception:
        pass
    r = _ps(
        "$ErrorActionPreference='SilentlyContinue';"
        + restore +
        f"Remove-NetFirewallRule -Group {_q(STRICT_GROUP)} 2>$null;'OK'",
        timeout=40,
    )
    try:
        STRICT_BACKUP.unlink(missing_ok=True)
    except Exception:
        pass
    return {"ok": "OK" in r["out"]}
