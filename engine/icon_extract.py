"""Extract an application's icon from its .exe as a PNG (Windows only).

Uses pywin32 to pull the icon resource, draws it onto a white background (to
match the dashboard's avatar box), and encodes a PNG with the standard library
so no image dependency is required. Results are cached by exe path.
"""
from __future__ import annotations

import struct
import sys
import threading
import zlib
from typing import Optional

_IS_WINDOWS = sys.platform == "win32"
if _IS_WINDOWS:
    try:
        import win32gui  # type: ignore
        import win32ui  # type: ignore
        import win32con  # type: ignore
        import win32api  # type: ignore
    except Exception:  # pragma: no cover
        win32gui = None  # type: ignore
else:  # pragma: no cover
    win32gui = None  # type: ignore

SIZE = 32
_cache: dict[str, Optional[bytes]] = {}
_lock = threading.Lock()


def _encode_png(rgba: bytes, w: int, h: int) -> bytes:
    raw = bytearray()
    stride = w * 4
    for y in range(h):
        raw.append(0)  # filter byte 0 per scanline
        raw.extend(rgba[y * stride:(y + 1) * stride])

    def chunk(typ: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + typ + data
                + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(raw), 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _extract(exe: str) -> Optional[bytes]:
    if not win32gui:
        return None
    try:
        large, small = win32gui.ExtractIconEx(exe, 0)
    except Exception:
        return None
    icons = list(large or []) + list(small or [])
    if not icons:
        return None
    hicon = (large or small)[0]
    hdc_screen = memdc = hdc = None
    try:
        hdc_screen = win32gui.GetDC(0)
        hdc = win32ui.CreateDCFromHandle(hdc_screen)
        memdc = hdc.CreateCompatibleDC()
        bmp = win32ui.CreateBitmap()
        bmp.CreateCompatibleBitmap(hdc, SIZE, SIZE)
        memdc.SelectObject(bmp)
        # white background so transparent icon areas match the avatar box
        brush = win32gui.CreateSolidBrush(win32api.RGB(255, 255, 255))
        win32gui.FillRect(memdc.GetSafeHdc(), (0, 0, SIZE, SIZE), brush)
        win32gui.DeleteObject(brush)
        win32gui.DrawIconEx(memdc.GetSafeHdc(), 0, 0, hicon,
                            SIZE, SIZE, 0, None, win32con.DI_NORMAL)
        bgra = bmp.GetBitmapBits(True)  # top-down BGRA
        out = bytearray(len(bgra))
        for i in range(0, len(bgra), 4):
            out[i] = bgra[i + 2]      # R <- from B position (BGRA -> RGBA)
            out[i + 1] = bgra[i + 1]  # G
            out[i + 2] = bgra[i]      # B
            out[i + 3] = 255          # opaque
        return _encode_png(bytes(out), SIZE, SIZE)
    except Exception:
        return None
    finally:
        for h in icons:
            try:
                win32gui.DestroyIcon(h)
            except Exception:
                pass
        try:
            if memdc:
                memdc.DeleteDC()
        except Exception:
            pass
        try:
            if hdc:
                hdc.DeleteDC()
        except Exception:
            pass
        try:
            if hdc_screen:
                win32gui.ReleaseDC(0, hdc_screen)
        except Exception:
            pass


def png_for(exe: str) -> Optional[bytes]:
    """Return PNG bytes for an exe's icon, or None. Cached by path."""
    if not exe or not win32gui:
        return None
    with _lock:
        if exe in _cache:
            return _cache[exe]
    png = _extract(exe)
    with _lock:
        _cache[exe] = png
    return png
