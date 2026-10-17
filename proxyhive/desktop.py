"""The ProxyHive desktop window: the dashboard inside a native app window, with no browser tab and no terminal.

It uses the Microsoft Edge WebView2 engine that ships with Windows 10 and 11, through pywebview. The window has the
normal minimize / maximize / close buttons and the ProxyHive icon. Closing it stops the dashboard server cleanly (a running
scan is ended, the gateway is disconnected and your Windows proxy settings are put back).

Author: B3hnamR  |  Telegram https://t.me/B3hnamR  |  GitHub https://github.com/B3hnamR
"""
from __future__ import annotations

import json
import socket
import time
import urllib.request
import webbrowser
from datetime import datetime

from . import paths, server

TITLE = "ProxyHive"
LOG_FILE = paths.APP_DIR / "proxyhive.log"
BACKGROUND = "#090c12"


def log(message: str) -> None:
    """Append a line to proxyhive.log next to the program. Never raises."""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {message}\n")
    except OSError:
        pass


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _is_proxyhive(port: int) -> bool:
    """Is a ProxyHive dashboard already answering on this port?"""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/init", timeout=2) as r:
            data = json.load(r)
        return isinstance(data, dict) and "pool" in data and "settings" in data
    except Exception:  # noqa: BLE001
        return False


class Api:
    """Small bridge the page can call: links open in your normal browser instead of inside the app."""

    def open_external(self, url: str) -> bool:
        if isinstance(url, str) and url.lower().startswith(("http://", "https://")):
            webbrowser.open(url)
            return True
        return False


def _dark_title_bar(window) -> None:
    """Make the Windows title bar dark so it matches the dashboard (Windows 10 2004+ / 11). Purely cosmetic."""
    try:
        import ctypes
        hwnd = window.native.Handle.ToInt64()
        on = ctypes.c_int(1)
        for attribute in (20, 19):          # DWMWA_USE_IMMERSIVE_DARK_MODE (20 on current builds, 19 on older ones)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(on), ctypes.sizeof(on))
    except Exception as e:  # noqa: BLE001
        log(f"dark title bar not applied: {e}")


def _message_box(text: str) -> None:
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text, TITLE, 0x40)
    except Exception:  # noqa: BLE001
        pass


def run(port: int = 8765, frozen: bool = False) -> int:
    """Open the app window. Returns a process exit code."""
    paths.ensure_default_files()
    try:
        import webview
    except Exception as e:  # noqa: BLE001
        log(f"pywebview is not available: {e}")
        if frozen:
            _message_box("ProxyHive could not open its window (the window component is missing).")
            return 1
        print("pywebview is not installed (pip install pywebview): opening the dashboard in your browser instead.")
        server.serve(port)
        return 0

    own = None
    if _is_proxyhive(port):                         # already running: open another window on the same dashboard
        url_port = port
    else:
        try:
            own = server.start_background(port if _port_free(port) else 0)
        except Exception as e:  # noqa: BLE001
            log(f"could not start the dashboard server: {e}")
            _message_box(f"ProxyHive could not start its dashboard server:\n\n{e}")
            return 1
        url_port = own.port
    log(f"window opening on port {url_port} ({'own server' if own else 'existing server'})")

    icon = paths.BUNDLE_DIR / "assets" / "proxyhive.ico"
    window = webview.create_window(TITLE, f"http://127.0.0.1:{url_port}/", js_api=Api(), width=1400, height=900,
                                   min_size=(1000, 660), background_color=BACKGROUND)
    window.events.shown += lambda: _dark_title_bar(window)
    code = 0
    try:
        for key, value in (("ALLOW_DOWNLOADS", True), ("OPEN_EXTERNAL_LINKS_IN_BROWSER", True)):
            try:
                webview.settings[key] = value
            except Exception:  # noqa: BLE001 - older pywebview without this switch
                pass
        # the web view keeps its own files (saved tab, filters) next to the program, so a copied folder stays self-contained
        storage = paths.DATA_DIR / "webview"
        storage.mkdir(parents=True, exist_ok=True)
        webview.start(gui="edgechromium", private_mode=False, storage_path=str(storage),
                      icon=str(icon) if icon.exists() else None)
    except Exception as e:  # noqa: BLE001 - most likely the WebView2 runtime is missing
        log(f"the window could not start: {type(e).__name__}: {e}")
        code = 1
        if frozen:
            _message_box("ProxyHive needs the Microsoft Edge WebView2 runtime to show its window.\n\n"
                         "It is built into Windows 11 and recent Windows 10. Install it from\n"
                         "https://developer.microsoft.com/microsoft-edge/webview2/\n\n"
                         "Or run  ProxyHive.exe --server  and open http://127.0.0.1:8765 in a browser.")
    finally:
        if own:
            started = time.time()
            server.stop_background(own)
            log(f"server stopped in {time.time() - started:.1f}s")
    return code
