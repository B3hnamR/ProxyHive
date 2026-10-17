"""Where files live. Works both from source and from the PyInstaller .exe.

APP_DIR     writable data next to the program: settings.json, pool.json, results/, sources.txt ...
BUNDLE_DIR  read-only files shipped inside the .exe (the dashboard page, the default source list)
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False))
ROOT = Path(__file__).resolve().parent.parent          # the project folder when running from source
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", ROOT))
# PROXYHIVE_HOME lets you keep all data somewhere else (a USB stick, a test folder, ...)
APP_DIR = (Path(os.environ["PROXYHIVE_HOME"]).resolve() if os.environ.get("PROXYHIVE_HOME")
           else Path(sys.executable).parent if FROZEN else ROOT)
DATA_DIR = APP_DIR / "data"

AUTHOR = "B3hnamR"
TELEGRAM = "https://t.me/B3hnamR"
GITHUB = "https://github.com/B3hnamR"


def ensure_default_files() -> None:
    """First run of the .exe: copy the bundled source list next to it so the user can edit it."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    dst, src = APP_DIR / "sources.txt", BUNDLE_DIR / "sources.txt"
    if not dst.exists() and src.exists() and src != dst:
        shutil.copy(src, dst)


def banner() -> str:
    from . import __version__
    return f"ProxyHive {__version__} by {AUTHOR}  |  Telegram {TELEGRAM}  |  GitHub {GITHUB}"
