"""Point the Windows system proxy at our local proxy and restore it safely.

We edit ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings``
(per-user, no admin required) and notify WinINET so the change takes effect
immediately.  The previous values are written to ``config/proxy_backup.json``
*before* we change anything, so a crash can be recovered on the next launch
(see :func:`recover`).
"""
from __future__ import annotations

import json
import sys
from typing import Any, Optional

import paths

_IS_WINDOWS = sys.platform == "win32"
_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# Hosts that should never route through the proxy (localhost + our own API).
_BYPASS = "localhost;127.*;10.*;172.16.*;192.168.*;<local>"


def _read_current() -> dict[str, Any]:
    import winreg
    result = {"ProxyEnable": 0, "ProxyServer": "", "ProxyOverride": ""}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH) as key:
            for name in list(result.keys()):
                try:
                    val, _ = winreg.QueryValueEx(key, name)
                    result[name] = val
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass
    return result


def _write(enable: int, server: Optional[str], override: Optional[str]) -> None:
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _REG_PATH) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(enable))
        if server is not None:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
        if override is not None:
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, override)
    _refresh()


def _refresh() -> None:
    """Tell WinINET the proxy settings changed (INTERNET_OPTION_SETTINGS_CHANGED=39,
    INTERNET_OPTION_REFRESH=37)."""
    try:
        import ctypes
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)
        wininet.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass


class SystemProxy:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    @property
    def available(self) -> bool:
        return _IS_WINDOWS

    def enable(self) -> dict[str, Any]:
        if not _IS_WINDOWS:
            return {"ok": False, "error": "system proxy only supported on Windows"}
        # Save current state first (only if we haven't already, to avoid
        # clobbering the real backup with our own values on re-enable).
        if not paths.PROXY_BACKUP_FILE.exists():
            current = _read_current()
            paths.ensure_dirs()
            paths.PROXY_BACKUP_FILE.write_text(
                json.dumps(current, indent=2), encoding="utf-8"
            )
        server = f"127.0.0.1:{self.ctx.settings.proxy_port}"
        try:
            _write(1, server, _BYPASS)
            self.ctx.system_proxy_active = True
            return {"ok": True, "server": server}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def disable(self) -> dict[str, Any]:
        """Restore the pre-monitor proxy settings and remove the backup."""
        if not _IS_WINDOWS:
            self.ctx.system_proxy_active = False
            return {"ok": True}
        try:
            if paths.PROXY_BACKUP_FILE.exists():
                data = json.loads(paths.PROXY_BACKUP_FILE.read_text(encoding="utf-8"))
                _write(
                    int(data.get("ProxyEnable", 0)),
                    data.get("ProxyServer", ""),
                    data.get("ProxyOverride", ""),
                )
                paths.PROXY_BACKUP_FILE.unlink(missing_ok=True)
            else:
                _write(0, "", None)
            self.ctx.system_proxy_active = False
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def status(self) -> dict[str, Any]:
        if not _IS_WINDOWS:
            return {"available": False, "enabled": False, "server": ""}
        cur = _read_current()
        return {
            "available": True,
            "enabled": bool(cur.get("ProxyEnable")),
            "server": cur.get("ProxyServer", ""),
            "pointing_at_us": cur.get("ProxyServer", "").endswith(
                str(self.ctx.settings.proxy_port)
            ),
        }


def recover() -> Optional[dict[str, Any]]:
    """Called at startup: if a backup exists, a previous run crashed while the
    system proxy was redirected. Restore it before we do anything else."""
    if not _IS_WINDOWS or not paths.PROXY_BACKUP_FILE.exists():
        return None
    try:
        data = json.loads(paths.PROXY_BACKUP_FILE.read_text(encoding="utf-8"))
        _write(
            int(data.get("ProxyEnable", 0)),
            data.get("ProxyServer", ""),
            data.get("ProxyOverride", ""),
        )
        paths.PROXY_BACKUP_FILE.unlink(missing_ok=True)
        return {"recovered": True, "restored": data}
    except Exception as e:
        return {"recovered": False, "error": str(e)}
