"""Manage trust for the mitmproxy root CA (required to decrypt HTTPS).

Installs/removes the CA in the *current-user* Root store via ``certutil`` - no
admin required.  Installing a root certificate is the one genuinely sensitive
step, so it is only ever done in response to an explicit UI action, and Windows
shows its own confirmation dialog which the user must accept.
"""
from __future__ import annotations

import subprocess
import sys
from typing import Any

import paths

_IS_WINDOWS = sys.platform == "win32"
# Common name of the mitmproxy CA, used to find it in the store for status/removal.
_CERT_CN = "mitmproxy"


def _run(args: list[str], timeout: int = 30) -> dict[str, Any]:
    creationflags = 0
    if _IS_WINDOWS:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=creationflags,
        )
        return {"code": proc.returncode, "out": proc.stdout, "err": proc.stderr}
    except Exception as e:
        return {"code": -1, "out": "", "err": str(e)}


class CertManager:
    def ca_path(self):
        return paths.mitmproxy_ca_cert()

    def status(self) -> dict[str, Any]:
        path = self.ca_path()
        exists = path.exists()
        trusted = False
        if _IS_WINDOWS and exists:
            res = _run(["certutil", "-user", "-store", "Root"])
            trusted = _CERT_CN.lower() in (res.get("out", "") or "").lower()
        return {
            "available": _IS_WINDOWS,
            "exists": exists,
            "path": str(path),
            "trusted": trusted,
        }

    def install(self) -> dict[str, Any]:
        if not _IS_WINDOWS:
            return {"ok": False, "error": "certificate install only on Windows"}
        path = self.ca_path()
        if not path.exists():
            return {
                "ok": False,
                "error": "CA not found yet. Start the proxy once so mitmproxy "
                         "generates its certificate, then try again.",
            }
        res = _run(["certutil", "-user", "-addstore", "Root", str(path)])
        ok = res["code"] == 0
        return {
            "ok": ok,
            "code": res["code"],
            "detail": (res["out"] or "") + (res["err"] or ""),
        }

    def uninstall(self) -> dict[str, Any]:
        if not _IS_WINDOWS:
            return {"ok": False, "error": "certificate uninstall only on Windows"}
        res = _run(["certutil", "-user", "-delstore", "Root", _CERT_CN])
        ok = res["code"] == 0
        return {
            "ok": ok,
            "code": res["code"],
            "detail": (res["out"] or "") + (res["err"] or ""),
        }
