"""Engine entrypoint.

Boot order:
  1. Crash-recovery: restore the system proxy if a previous run died mid-flight.
  2. Load settings, build the shared context.
  3. Start the mitmproxy listener (generates the CA on first run).
  4. If the proxy came up and is enabled, point the Windows system proxy at it.
  5. Start the process / netstat monitors.
  6. Serve the FastAPI control plane on 127.0.0.1 (blocks until /shutdown).
  7. Tear everything down and restore the system proxy.

Run standalone:  python engine/main.py --api-port 8788 --proxy-port 8080
"""
from __future__ import annotations

import argparse
import atexit
import sys

import uvicorn

import paths
from context import AppContext
from storage.config import load_settings
from system import proxy_config
from system.proxy_config import SystemProxy
from system.cert import CertManager
from proxy.runner import ProxyController
from monitor.process_watch import ProcessWatcher
from monitor.netstat import NetstatWatcher
from api.server import create_app


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Request Cycle Monitor engine")
    ap.add_argument("--api-port", type=int, default=None)
    ap.add_argument("--proxy-port", type=int, default=None)
    ap.add_argument(
        "--no-system-proxy", action="store_true",
        help="Run the local proxy but do not change the Windows system proxy.",
    )
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    paths.ensure_dirs()

    # 1) crash-recovery of a possibly-hijacked system proxy
    rec = proxy_config.recover()
    if rec:
        print(f"[startup] system proxy recovered: {rec}", file=sys.stderr)

    # 2) settings + context
    settings = load_settings()
    if args.api_port:
        settings.api_port = args.api_port
    if args.proxy_port:
        settings.proxy_port = args.proxy_port

    ctx = AppContext(settings)
    system_proxy = SystemProxy(ctx)
    cert_manager = CertManager()
    proxy_controller = ProxyController(ctx)
    watchers = [ProcessWatcher(ctx), NetstatWatcher(ctx)]

    # 3) start the proxy listener
    proxy_controller.start()
    ready = proxy_controller.wait_ready(timeout=8.0)
    if not ready:
        print(f"[startup] proxy not ready: {ctx.proxy_error}", file=sys.stderr)

    # 4) redirect the system proxy only if the listener is up AND the CA is
    #    already trusted (so we never break HTTPS before the cert is installed).
    if args.no_system_proxy:
        print("[startup] --no-system-proxy: leaving Windows proxy untouched",
              file=sys.stderr)
    elif ready and settings.proxy_enabled:
        cert_trusted = False
        try:
            cert_trusted = bool(cert_manager.status().get("trusted"))
        except Exception:
            pass
        if cert_trusted:
            res = system_proxy.enable()
            print(f"[startup] system proxy enable: {res}", file=sys.stderr)
        else:
            print("[startup] proxy is enabled but the certificate isn't trusted "
                  "yet; leaving the system proxy off. Install & trust it from "
                  "Settings and it will turn on automatically.", file=sys.stderr)

    # 5) monitors
    for w in watchers:
        w.start()

    # 5b) firewall reconciliation runs in a background thread so the (sometimes
    #     slow) first-run PowerShell calls never delay the API/GUI from coming up.
    import firewall
    import threading as _threading

    def _firewall_startup() -> None:
        try:
            if firewall.is_admin():
                firewall.clear_all()
                firewall.reapply(settings.blocked_app_paths)
                print(f"[startup] firewall enforcement active (admin); "
                      f"{len(settings.blocked_app_paths)} app(s) blocked",
                      file=sys.stderr)
            else:
                print("[startup] not elevated: per-app blocking limited to the "
                      "proxy. Run as administrator for full blocking.",
                      file=sys.stderr)
        except Exception as e:
            print(f"[startup] firewall init error: {e}", file=sys.stderr)

    _threading.Thread(target=_firewall_startup, daemon=True,
                      name="fw-startup").start()

    # 5c) periodically flush the all-time activity counters to disk so they
    #     survive a restart (and aren't lost between shutdowns).
    def _stats_flusher() -> None:
        import time as _time
        while True:
            _time.sleep(20)
            ctx.persist_stats()

    _threading.Thread(target=_stats_flusher, daemon=True,
                      name="stats-flush").start()

    # cleanup is idempotent and also wired to atexit as a safety net
    cleaned = {"done": False}

    def cleanup() -> None:
        if cleaned["done"]:
            return
        cleaned["done"] = True
        try:
            ctx.persist_stats()
        except Exception:
            pass
        try:
            import firewall
            if firewall.is_admin():
                firewall.clear_all()
        except Exception:
            pass
        try:
            for w in watchers:
                w.stop()
        except Exception:
            pass
        try:
            system_proxy.disable()
        except Exception:
            pass
        try:
            proxy_controller.stop()
        except Exception:
            pass
        try:
            ctx.session_log.close()
        except Exception:
            pass

    atexit.register(cleanup)

    # 6) serve
    app = create_app(ctx, system_proxy, cert_manager, proxy_controller)
    config = uvicorn.Config(
        app, host="127.0.0.1", port=settings.api_port, log_level="warning"
    )
    server = uvicorn.Server(config)
    app.state.server = server
    try:
        server.run()
    finally:
        # 7) teardown
        cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
