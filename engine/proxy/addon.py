"""mitmproxy addon: the heart of the monitor/modifier.

For every flow we:
  1. attribute it to the app that made the request,
  2. ask the rule engine for a :class:`Decision`,
  3. apply it (block / redirect / delay / header & body edits),
  4. emit a structured event to the live feed + session log.

Hooks are async so a "delay" action can ``await asyncio.sleep`` without blocking
the proxy's event loop.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from mitmproxy import http

from proxy.rules import ReqInfo, Decision

_MAX_PREVIEW = 4096  # bytes of body kept for the detail view


def _headers_list(headers) -> list[list[str]]:
    out = []
    try:
        for k, v in headers.items():
            out.append([k, v])
    except Exception:
        pass
    return out


def _body_preview(message) -> dict[str, Any]:
    try:
        content = message.get_content(strict=False)
    except Exception:
        content = None
    if not content:
        return {"size": 0, "text": "", "truncated": False}
    size = len(content)
    chunk = content[:_MAX_PREVIEW]
    try:
        text = chunk.decode("utf-8", errors="replace")
    except Exception:
        text = f"<{size} bytes binary>"
    return {"size": size, "text": text, "truncated": size > _MAX_PREVIEW}


def _apply_body_replace(message, replacements) -> bool:
    """Apply (find, replace, regex) edits to a message body. Returns True if changed."""
    if not replacements:
        return False
    try:
        text = message.get_text(strict=False)
    except Exception:
        text = None
    if text is None:
        return False
    original = text
    import re as _re
    for find, replace, is_regex in replacements:
        try:
            if is_regex:
                text = _re.sub(find, replace, text)
            else:
                text = text.replace(find, replace)
        except Exception:
            continue
    if text != original:
        try:
            message.set_text(text)
            return True
        except Exception:
            return False
    return False


class MonitorAddon:
    def __init__(self, ctx) -> None:
        self.ctx = ctx
        # decision + timing carried from request hook to response hook
        self._pending: dict[str, dict[str, Any]] = {}

    # -- lifecycle ---------------------------------------------------------- #
    def running(self) -> None:
        """Called by mitmproxy once the listener is actually bound and serving."""
        self.ctx.proxy_active = True
        self.ctx.proxy_error = None

    # -- request ------------------------------------------------------------ #
    async def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        peer = getattr(flow.client_conn, "peername", None)
        src_port = peer[1] if peer and len(peer) >= 2 else None
        src_ip = peer[0] if peer and len(peer) >= 1 else None
        app = self.ctx.attribution.attribute(src_ip, src_port)

        info = ReqInfo(
            method=req.method, host=req.pretty_host, url=req.pretty_url,
            pid=app.get("pid"), proc_name=app.get("name", "unknown"),
            exe=app.get("exe", ""),
        )

        # Focus "monitor" mode: only surface the foreground app in the feed.
        emit = True
        if (self.ctx.settings.current_app_only
                and self.ctx.settings.focus_mode == "monitor"):
            fg = self.ctx.attribution.foreground_pid()
            emit = fg is not None and info.pid == fg

        decision = self.ctx.rule_engine.evaluate(info)
        modified = False

        # apply request-side modifications
        if decision.redirect_url:
            try:
                req.url = decision.redirect_url
                modified = True
            except Exception:
                pass
        for name in decision.req_header_remove:
            if name in req.headers:
                del req.headers[name]
                modified = True
        for k, v in decision.req_header_set.items():
            req.headers[k] = v
            modified = True
        if _apply_body_replace(req, decision.req_body_replace):
            modified = True

        # Privacy signals from Strict/Lockdown profiles. Applied quietly (not
        # counted as a "modification") so they don't flood the feed.
        if self.ctx.settings.add_privacy_headers and not decision.block:
            req.headers["DNT"] = "1"
            req.headers["Sec-GPC"] = "1"

        if decision.delay_ms > 0:
            await asyncio.sleep(min(decision.delay_ms, 30000) / 1000.0)

        self.ctx.bump("requests")

        event: dict[str, Any] = {
            "type": "request",
            "flow_id": flow.id,
            "app": {"pid": info.pid, "name": info.proc_name, "exe": info.exe},
            "method": info.method,
            "scheme": req.scheme,
            "host": info.host,
            "path": req.path,
            "url": info.url,
            "matched": decision.matched,
            "blocked": False,
            "modified": modified,
            "action": "pass",
            "req_headers": _headers_list(req.headers),
            "req_body": _body_preview(req),
        }

        if decision.block:
            flow.response = http.Response.make(
                decision.block_status,
                b"Blocked by Request Cycle Monitor",
                {"Content-Type": "text/plain",
                 "X-Blocked-By": "request-cycle-monitor"},
            )
            event["blocked"] = True
            event["action"] = "blocked"
            event["reason"] = decision.block_reason
            # Surface the status we return so the live feed can show it (e.g. 403)
            # right away, even though a blocked flow makes no upstream request.
            event["status"] = decision.block_status
            self.ctx.bump("blocked")
        elif modified:
            event["action"] = "modified"
            self.ctx.bump("modified")

        # feed the per-app dashboard
        self.ctx.record_app(info.proc_name, info.host, decision.block)

        # stash for response hook
        self._pending[flow.id] = {
            "decision": decision,
            "t0": time.time(),
            "emit": emit,
            "app": event["app"],
            "method": info.method,
            "host": info.host,
            "path": req.path,
            "url": info.url,
        }

        if emit:
            self.ctx.bus.publish(event)
        self.ctx.session_log.log(event)

    # -- response ----------------------------------------------------------- #
    async def response(self, flow: http.HTTPFlow) -> None:
        pend = self._pending.pop(flow.id, None)
        decision: Optional[Decision] = pend["decision"] if pend else None
        emit = pend["emit"] if pend else True
        resp = flow.response
        if resp is None:
            return

        modified = False
        if decision:
            for name in decision.resp_header_remove:
                if name in resp.headers:
                    del resp.headers[name]
                    modified = True
            for k, v in decision.resp_header_set.items():
                resp.headers[k] = v
                modified = True
            if _apply_body_replace(resp, decision.resp_body_replace):
                modified = True

        self.ctx.bump("responses")
        if modified:
            self.ctx.bump("modified")

        latency = None
        if pend:
            latency = round((time.time() - pend["t0"]) * 1000)

        event = {
            "type": "response",
            "flow_id": flow.id,
            "app": pend["app"] if pend else {},
            "method": pend["method"] if pend else flow.request.method,
            "host": pend["host"] if pend else flow.request.pretty_host,
            "path": pend["path"] if pend else flow.request.path,
            "url": pend["url"] if pend else flow.request.pretty_url,
            "status": resp.status_code,
            "reason": resp.reason,
            "latency_ms": latency,
            "modified": modified,
            "content_type": resp.headers.get("content-type", ""),
            "resp_headers": _headers_list(resp.headers),
            "resp_body": _body_preview(resp),
        }
        if emit:
            self.ctx.bus.publish(event)
        self.ctx.session_log.log(event)

    # -- cleanup on error --------------------------------------------------- #
    def error(self, flow: http.HTTPFlow) -> None:
        self._pending.pop(flow.id, None)
