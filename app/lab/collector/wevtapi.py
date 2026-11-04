"""Reads the Windows Event Log through wevtapi.dll (built into Windows) with ctypes: no extra
package and no child process per query.

``query(channel, xpath, reverse, limit)`` returns the matching events as ``<Events><Event>...``
XML, the shape ``parsers.winevent_from_xml`` reads. Errors (no such channel, access denied) raise
OSError with Windows' own message.
"""
from __future__ import annotations

import ctypes
import sys

EVT_QUERY_CHANNEL_PATH = 0x1
EVT_QUERY_FORWARD = 0x100
EVT_QUERY_REVERSE = 0x200
EVT_RENDER_EVENT_XML = 1
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_MORE_ITEMS = 259
ERROR_TIMEOUT = 1460
BATCH = 64
WAIT_MS = 2000

_api = None


def _wevtapi():
    global _api
    if _api is None:
        if sys.platform != "win32":
            raise OSError("the Windows Event Log is only on Windows")
        from ctypes import wintypes

        api = ctypes.WinDLL("wevtapi.dll", use_last_error=True)
        api.EvtQuery.restype = wintypes.HANDLE
        api.EvtQuery.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        api.EvtNext.restype = wintypes.BOOL
        api.EvtNext.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                                wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        api.EvtRender.restype = wintypes.BOOL
        api.EvtRender.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
        api.EvtClose.restype = wintypes.BOOL
        api.EvtClose.argtypes = [wintypes.HANDLE]
        _api = api
    return _api


def _error(what: str) -> OSError:
    code = ctypes.get_last_error()
    return OSError(code, f"{what}: {ctypes.FormatError(code).strip()}")  # type: ignore[attr-defined]


def _render(api, handle) -> str | None:
    from ctypes import wintypes

    used, props = wintypes.DWORD(), wintypes.DWORD()
    if not api.EvtRender(None, handle, EVT_RENDER_EVENT_XML, 0, None, ctypes.byref(used), ctypes.byref(props)):
        if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
            return None
    buf = ctypes.create_unicode_buffer(used.value // ctypes.sizeof(ctypes.c_wchar) + 1)
    if not api.EvtRender(None, handle, EVT_RENDER_EVENT_XML, ctypes.sizeof(buf), buf, ctypes.byref(used),
                         ctypes.byref(props)):
        return None
    return buf.value


def query(channel: str, xpath: str, reverse: bool = False, limit: int = 500) -> str:
    """Up to ``limit`` events of ``channel`` matching ``xpath``, oldest first (newest first with
    ``reverse``), as one ``<Events>`` XML document."""
    from ctypes import wintypes

    api = _wevtapi()
    flags = EVT_QUERY_CHANNEL_PATH | (EVT_QUERY_REVERSE if reverse else EVT_QUERY_FORWARD)
    q = api.EvtQuery(None, channel, xpath, flags)
    if not q:
        raise _error(f"cannot query {channel}")
    events: list[str] = []
    handles = (wintypes.HANDLE * BATCH)()
    try:
        while len(events) < limit:
            got = wintypes.DWORD()
            if not api.EvtNext(q, min(BATCH, limit - len(events)), handles, WAIT_MS, 0, ctypes.byref(got)):
                if ctypes.get_last_error() in (ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT):
                    break
                raise _error(f"cannot read {channel}")
            for i in range(got.value):
                try:
                    if (xml := _render(api, handles[i])) is not None:
                        events.append(xml)
                finally:
                    api.EvtClose(handles[i])
    finally:
        api.EvtClose(q)
    return "<Events>" + "".join(events) + "</Events>"
