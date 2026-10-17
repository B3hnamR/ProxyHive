"""Launcher: python app.py  (this is also the entry point PyInstaller builds ProxyHive.exe from)."""
import sys

from proxyhive.cli import main

if __name__ == "__main__":
    sys.exit(main())
