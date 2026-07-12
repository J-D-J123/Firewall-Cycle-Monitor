"""Run mitmproxy in a dedicated thread with its own asyncio loop.

Kept separate from the addon so that ``main.py`` can import this lazily and the
rest of the engine (API server, monitors) still starts even if mitmproxy is not
installed yet.
"""
from __future__ import annotations

import asyncio
import threading
import time
from typing import Optional


class ProxyController:
    def __init__(self, ctx) -> None:
        self.ctx = ctx
        self.port = ctx.settings.proxy_port
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._master = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="mitmproxy", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        # Import here so a missing mitmproxy only disables the proxy, not the app.
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster
        from proxy.addon import MonitorAddon

        async def _serve() -> None:
            # mitmproxy 11/12 must be constructed inside a running loop.
            opts = options.Options(
                listen_host="127.0.0.1",
                listen_port=self.port,
            )
            try:
                master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            except TypeError:  # older mitmproxy signatures
                master = DumpMaster(opts)
            # The addon's running() hook flips ctx.proxy_active once we're bound.
            master.addons.add(MonitorAddon(self.ctx))
            self._master = master
            await master.run()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(_serve())
        except Exception as e:  # bind failure, missing dep, etc.
            self.ctx.proxy_error = f"{type(e).__name__}: {e}"
        finally:
            self.ctx.proxy_active = False
            try:
                loop.close()
            except Exception:
                pass

    def wait_ready(self, timeout: float = 8.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.ctx.proxy_active:
                return True
            if self.ctx.proxy_error:
                return False
            time.sleep(0.1)
        return self.ctx.proxy_active

    def stop(self) -> None:
        if self._master and self._loop:
            try:
                self._loop.call_soon_threadsafe(self._master.shutdown)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
