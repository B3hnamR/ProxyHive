"""stdout/stderr for a program that has no console (the windowed .exe)."""
import sys


class LazyLog:
    """Text written here goes to proxyhive.log next to the program; the file is created only if something is written."""

    def __init__(self):
        self._f = None

    def write(self, text):
        try:
            if self._f is None:
                from . import paths
                self._f = open(paths.APP_DIR / "proxyhive.log", "a", encoding="utf-8", buffering=1)
            self._f.write(text)
        except Exception:  # noqa: BLE001
            pass
        return len(text)

    def flush(self):
        pass

    def isatty(self):
        return False


def install() -> None:
    if sys.stdout is None or sys.stderr is None:
        sys.stdout = sys.stderr = LazyLog()
