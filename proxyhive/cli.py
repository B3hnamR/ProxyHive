"""ProxyHive command line: what the double-clicked program does.

  ProxyHive.exe                    opens the app window (the dashboard inside its own window, no browser, no terminal)
  ProxyHive.exe --server           runs the dashboard in a terminal and opens it in your browser instead
  ProxyHive.exe --server --no-browser --port 9000     the same without opening a tab, on another port
  ProxyHive.exe --version          prints the version
  ProxyHive.exe --limit 3000 ...   any scanner option (see --help) runs the terminal scanner

Author: B3hnamR  |  Telegram https://t.me/B3hnamR  |  GitHub https://github.com/B3hnamR
"""
import os
import sys

from . import stdio

stdio.install()                                         # a windowed .exe has no console

import argparse  # noqa: E402
import socket  # noqa: E402
import webbrowser  # noqa: E402

from . import __version__, desktop, engine, paths, server  # noqa: E402

SERVER_FLAGS = ("--server", "--no-browser", "--port", "--ui", "ui")


def _attach_parent_console() -> None:
    """The windowed .exe has no console of its own. When it is started from a terminal with command-line options,
    print into that terminal."""
    if os.name == "nt" and paths.FROZEN:
        try:
            import ctypes
            if ctypes.windll.kernel32.AttachConsole(-1):          # ATTACH_PARENT_PROCESS
                sys.stdout = sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
        except Exception:  # noqa: BLE001
            pass


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def main() -> int:
    args = sys.argv[1:]
    if not args or args == ["--gui"]:
        return desktop.run(int(os.environ.get("PROXYHIVE_PORT", "8765")), frozen=paths.FROZEN)
    _attach_parent_console()
    if args in (["--version"], ["-V"]):
        print(f"ProxyHive {__version__}")
        return 0
    if args[0] not in SERVER_FLAGS:
        engine.main()                            # terminal scanner
        return 0
    ap = argparse.ArgumentParser(prog="ProxyHive", description="ProxyHive dashboard in your browser", epilog=paths.banner())
    ap.add_argument("--server", action="store_true", help="run the dashboard here and open it in the browser")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    ap.add_argument("--ui", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("ui_word", nargs="?", help=argparse.SUPPRESS)
    a = ap.parse_args(args)
    if _port_in_use(a.port):                     # already running: just show it
        print(f"ProxyHive is already running on port {a.port}. Opening it.")
        if not a.no_browser:
            webbrowser.open(f"http://127.0.0.1:{a.port}")
        return 0
    server.serve(a.port, open_browser=not a.no_browser)
    return 0


if __name__ == "__main__":
    sys.exit(main())
