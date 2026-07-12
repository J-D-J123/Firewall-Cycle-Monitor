"""Thread-safe event bus bridging producer threads to the WebSocket.

Producers (the mitmproxy addon thread, the monitor threads) call
``publish(event)`` from arbitrary threads.  Consumers are WebSocket connections
living on the uvicorn asyncio loop; each gets its own ``asyncio.Queue`` and is
fed via ``loop.call_soon_threadsafe`` so we never touch asyncio objects from the
wrong thread.  A bounded ``deque`` keeps the most recent events for the REST
``/events`` endpoint and late-joining clients.
"""
from __future__ import annotations

import asyncio
import threading
from collections import deque
from typing import Any, Optional


class EventBus:
    def __init__(self, history: int = 500) -> None:
        self._lock = threading.Lock()
        self._recent: deque[dict[str, Any]] = deque(maxlen=history)
        self._subscribers: set[asyncio.Queue] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._seq = 0

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Called from the uvicorn startup hook once the serving loop exists."""
        self._loop = loop

    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._seq += 1
            event["seq"] = self._seq
            self._recent.append(event)
            subs = list(self._subscribers)
            loop = self._loop
        if loop is None:
            return
        for q in subs:
            try:
                loop.call_soon_threadsafe(_safe_put, q, event)
            except RuntimeError:
                # loop is shutting down
                pass

    def recent(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._recent)
        return items[-limit:]

    # -- subscription (called on the asyncio loop) -------------------------- #
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            self._subscribers.discard(q)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


def _safe_put(q: asyncio.Queue, event: dict[str, Any]) -> None:
    try:
        q.put_nowait(event)
    except asyncio.QueueFull:
        # Drop oldest to keep the stream live rather than blocking producers.
        try:
            q.get_nowait()
            q.put_nowait(event)
        except Exception:
            pass
