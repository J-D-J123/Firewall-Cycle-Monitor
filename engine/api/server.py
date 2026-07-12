"""FastAPI app: REST control plane + WebSocket live feed.

Bound to 127.0.0.1 only (see main.py). The Electron UI is the sole client.
"""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from storage import logs as logstore
from storage.config import save_settings


def create_app(ctx, system_proxy, cert_manager, proxy_controller) -> FastAPI:
    app = FastAPI(title="Request Cycle Monitor Engine")

    # Local-only tool; the renderer runs from file:// so allow any origin.
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    async def _startup() -> None:
        ctx.bus.set_loop(asyncio.get_running_loop())
        import sys
        import json as _json
        print(_json.dumps({
            "event": "ready",
            "api_port": ctx.settings.api_port,
            "proxy_port": ctx.settings.proxy_port,
            "proxy_active": ctx.proxy_active,
            "proxy_error": ctx.proxy_error,
        }), flush=True)
        sys.stdout.flush()

    # ------------------------------------------------------------------ #
    # State & live feed
    # ------------------------------------------------------------------ #
    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"ok": True}

    @app.get("/state")
    async def state() -> dict[str, Any]:
        import firewall
        s = ctx.state_dict()
        s["system_proxy"] = system_proxy.status()
        s["cert"] = cert_manager.status()
        s["is_admin"] = firewall.is_admin()
        return s

    @app.get("/events")
    async def events(limit: int = 200) -> list[dict[str, Any]]:
        return ctx.bus.recent(limit)

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        await websocket.accept()
        q = ctx.bus.subscribe()
        try:
            for evt in ctx.bus.recent(100):
                await websocket.send_json(evt)
            while True:
                evt = await q.get()
                await websocket.send_json(evt)
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            ctx.bus.unsubscribe(q)

    # ------------------------------------------------------------------ #
    # Rules
    # ------------------------------------------------------------------ #
    @app.get("/rules")
    async def get_rules() -> list[dict[str, Any]]:
        return ctx.rules.list()

    @app.post("/rules")
    async def add_rule(request: Request) -> dict[str, Any]:
        data = await request.json()
        return ctx.rules.add(data)

    @app.put("/rules/{rule_id}")
    async def update_rule(rule_id: str, request: Request):
        data = await request.json()
        r = ctx.rules.update(rule_id, data)
        if r is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return r

    @app.delete("/rules/{rule_id}")
    async def delete_rule(rule_id: str) -> dict[str, Any]:
        return {"deleted": ctx.rules.delete(rule_id)}

    # ------------------------------------------------------------------ #
    # Block lists
    # ------------------------------------------------------------------ #
    @app.get("/blocklists")
    async def get_blocklists() -> list[dict[str, Any]]:
        return ctx.blocklists.category_summary()

    @app.post("/blocklists")
    async def update_blocklists(request: Request) -> dict[str, Any]:
        data = await request.json()
        if "enabled_categories" in data:
            ctx.settings.enabled_blocklists = list(data["enabled_categories"])
        if "custom_hosts" in data:
            ctx.settings.custom_blocked_hosts = [
                h.strip() for h in data["custom_hosts"] if h and h.strip()
            ]
        save_settings(ctx.settings)
        return {"ok": True, "categories": ctx.blocklists.category_summary()}

    # ------------------------------------------------------------------ #
    # Control (pause, proxy on/off, focus mode)
    # ------------------------------------------------------------------ #
    @app.post("/control")
    async def control(request: Request) -> dict[str, Any]:
        data = await request.json()
        action = data.get("action")
        result: dict[str, Any] = {"ok": True}
        if action == "pause":
            ctx.settings.paused = True
        elif action == "resume":
            ctx.settings.paused = False
        elif action == "set_current_app_only":
            ctx.settings.current_app_only = bool(data.get("value"))
        elif action == "set_focus_mode":
            mode = data.get("value")
            if mode in ("enforce", "monitor"):
                ctx.settings.focus_mode = mode
        elif action == "set_guard_new_apps":
            ctx.settings.guard_new_apps = bool(data.get("value"))
        elif action == "proxy_on":
            ctx.settings.proxy_enabled = True
            result["system_proxy"] = system_proxy.enable()
        elif action == "proxy_off":
            ctx.settings.proxy_enabled = False
            result["system_proxy"] = system_proxy.disable()
        else:
            result = {"ok": False, "error": f"unknown action {action!r}"}
        save_settings(ctx.settings)
        result["settings"] = ctx.settings.to_dict()
        return result

    # ------------------------------------------------------------------ #
    # Security profiles (presets)
    # ------------------------------------------------------------------ #
    @app.get("/profiles")
    async def get_profiles() -> dict[str, Any]:
        import profiles
        return profiles.list_profiles(ctx)

    @app.post("/profiles/apply")
    async def apply_profile(request: Request) -> dict[str, Any]:
        import profiles
        data = await request.json()
        return profiles.apply_profile(ctx, data.get("name", ""))

    # ------------------------------------------------------------------ #
    # Apps dashboard + per-app network policy
    # ------------------------------------------------------------------ #
    @app.get("/apps")
    async def apps() -> dict[str, Any]:
        import appsview
        return await asyncio.to_thread(appsview.build_apps, ctx)

    @app.get("/icon")
    async def icon(path: str):
        import icon_extract
        png = await asyncio.to_thread(icon_extract.png_for, path)
        if not png:
            return Response(status_code=404)
        return Response(content=png, media_type="image/png",
                        headers={"Cache-Control": "max-age=86400"})

    @app.post("/apps/policy")
    async def apps_policy(request: Request) -> dict[str, Any]:
        import firewall
        data = await request.json()
        action = data.get("action")
        name = (data.get("name") or "").strip()
        exe = (data.get("exe") or "").strip()
        s = ctx.settings
        blocked = {a.lower(): a for a in s.blocked_apps}
        allowed = {a.lower(): a for a in s.allowed_apps}
        paths = {p.lower(): p for p in s.blocked_app_paths}
        fw: dict[str, Any] = {}
        if action == "block" and name:
            blocked[name.lower()] = name
            allowed.pop(name.lower(), None)
            ctx.resolve_app(name)  # decided -> leave quarantine
            if exe:
                paths[exe.lower()] = exe
                fw = await asyncio.to_thread(firewall.block_app, exe)
        elif action in ("unblock", "allow") and name:
            blocked.pop(name.lower(), None)
            # Remember the approval so the new-app guard won't re-quarantine it.
            allowed[name.lower()] = name
            ctx.resolve_app(name)
            # drop every stored path whose file name matches, and unblock it
            for key, p in list(paths.items()):
                if p.replace("/", "\\").rsplit("\\", 1)[-1].lower() == name.lower():
                    paths.pop(key, None)
                    await asyncio.to_thread(firewall.unblock_app, p)
            if exe:
                paths.pop(exe.lower(), None)
                await asyncio.to_thread(firewall.unblock_app, exe)
        elif action == "solo" and name:
            s.solo_app = name
        elif action == "unsolo":
            s.solo_app = ""
        else:
            return {"ok": False, "error": f"unknown action {action!r}"}
        s.blocked_apps = list(blocked.values())
        s.allowed_apps = list(allowed.values())
        s.blocked_app_paths = list(paths.values())
        save_settings(s)
        return {"ok": True, "solo_app": s.solo_app, "blocked_apps": s.blocked_apps,
                "allowed_apps": s.allowed_apps, "firewall": fw,
                "is_admin": firewall.is_admin()}

    # ------------------------------------------------------------------ #
    # Certificate
    # ------------------------------------------------------------------ #
    @app.get("/cert")
    async def cert_status() -> dict[str, Any]:
        return cert_manager.status()

    @app.post("/cert/install")
    async def cert_install() -> dict[str, Any]:
        result = cert_manager.install()
        # If the cert is now trusted and the user wants the proxy on, turn it on
        # right away so there's nothing else to click.
        if result.get("ok") and ctx.settings.proxy_enabled and not ctx.system_proxy_active:
            result["system_proxy"] = system_proxy.enable()
        return result

    @app.post("/cert/uninstall")
    async def cert_uninstall() -> dict[str, Any]:
        return cert_manager.uninstall()

    # ------------------------------------------------------------------ #
    # Logs
    # ------------------------------------------------------------------ #
    @app.get("/logs/sessions")
    async def sessions() -> list[dict[str, Any]]:
        return logstore.list_sessions()

    @app.get("/logs/sessions/{name}")
    async def session_detail(name: str, limit: int = 2000) -> list[dict[str, Any]]:
        return logstore.read_session(name, limit=limit)

    @app.get("/logs/activity")
    async def activity(date: str | None = None, limit: int = 2000):
        return {
            "days": logstore.list_activity_days(),
            "date": date,
            "entries": logstore.read_activity(date, limit=limit),
        }

    # ------------------------------------------------------------------ #
    # Replay a (possibly edited) request through our own proxy
    # ------------------------------------------------------------------ #
    @app.post("/replay")
    async def replay(request: Request) -> dict[str, Any]:
        data = await request.json()
        return await asyncio.to_thread(_do_replay, ctx, data)

    # ------------------------------------------------------------------ #
    # Shutdown (called by Electron on quit)
    # ------------------------------------------------------------------ #
    @app.post("/shutdown")
    async def shutdown() -> dict[str, Any]:
        server = getattr(app.state, "server", None)
        if server is not None:
            server.should_exit = True
        return {"ok": True}

    return app


def _do_replay(ctx, data: dict[str, Any]) -> dict[str, Any]:
    """Send a request back through the local proxy so rules re-apply and it shows
    up in the feed. Best-effort; HTTPS verification is disabled for replay."""
    import ssl
    import urllib.request

    method = (data.get("method") or "GET").upper()
    url = data.get("url")
    if not url:
        return {"ok": False, "error": "url required"}
    headers = data.get("headers") or {}
    body = data.get("body")
    body_bytes = body.encode("utf-8") if isinstance(body, str) and body else None

    proxy = f"http://127.0.0.1:{ctx.settings.proxy_port}"
    handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    ctx_ssl = ssl._create_unverified_context()
    https_handler = urllib.request.HTTPSHandler(context=ctx_ssl)
    opener = urllib.request.build_opener(handler, https_handler)

    req = urllib.request.Request(url, data=body_bytes, method=method)
    for k, v in headers.items():
        try:
            req.add_header(k, v)
        except Exception:
            pass
    try:
        with opener.open(req, timeout=20) as resp:
            payload = resp.read(8192)
            return {
                "ok": True,
                "status": resp.status,
                "body_preview": payload.decode("utf-8", errors="replace"),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)}
