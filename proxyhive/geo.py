"""Offline city / ASN / organization lookup for a proxy's exit IP.

Uses the free "IP to City Lite" and "IP to ASN Lite" databases from DB-IP.com (CC BY 4.0, no account or key).
They are downloaded only when the user asks (about 60 MB + 5 MB), stored in data/, and then every lookup is local:
no per-proxy API calls.  Attribution: IP geolocation by DB-IP (https://db-ip.com).
"""
from __future__ import annotations

import asyncio
import time
import zlib
from pathlib import Path

import aiohttp

try:
    import maxminddb
except ImportError:  # the library is optional; geo features just stay off
    maxminddb = None

BASE_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"
FILES = {"city": "geo-city.mmdb", "asn": "geo-asn.mmdb"}
LABELS = {"city": "City database (~60 MB)", "asn": "ASN / organization database (~5 MB)"}


def _months() -> list[str]:
    """This month and the previous one (DB-IP publishes a new file early each month)."""
    t = time.gmtime()
    prev = (t.tm_year, t.tm_mon - 1) if t.tm_mon > 1 else (t.tm_year - 1, 12)
    return [f"{t.tm_year}-{t.tm_mon:02d}", f"{prev[0]}-{prev[1]:02d}"]


class GeoDB:
    def __init__(self, data_dir: Path):
        self.dir = data_dir
        self.readers: dict[str, object] = {}
        self.progress: dict[str, dict] = {}
        self.task: asyncio.Task | None = None
        self.url_override: dict[str, str] = {}      # used by tests
        self.load()

    # ----------------------------------------------------------------- reading
    @property
    def library(self) -> bool:
        return maxminddb is not None

    def load(self) -> None:
        for kind, name in FILES.items():
            path = self.dir / name
            if maxminddb is not None and path.exists() and kind not in self.readers:
                try:
                    self.readers[kind] = maxminddb.open_database(str(path))
                except Exception:  # noqa: BLE001 - corrupt file: ignore it, user can download again
                    pass

    @property
    def ready(self) -> bool:
        return bool(self.readers)

    def lookup(self, ip: str) -> dict:
        """Return {"city": str, "asn": "AS123", "org": str}; empty strings when unknown."""
        out = {"city": "", "asn": "", "org": ""}
        try:
            if "city" in self.readers:
                rec = self.readers["city"].get(ip) or {}
                names = (rec.get("city") or {}).get("names") or {}
                out["city"] = str(names.get("en") or next(iter(names.values()), ""))[:60]
            if "asn" in self.readers:
                rec = self.readers["asn"].get(ip) or {}
                if rec.get("autonomous_system_number"):
                    out["asn"] = f"AS{rec['autonomous_system_number']}"
                out["org"] = str(rec.get("autonomous_system_organization") or "")[:80]
        except (ValueError, TypeError, KeyError):
            pass
        return out

    def status(self) -> dict:
        files = {}
        for kind, name in FILES.items():
            path = self.dir / name
            files[kind] = {"label": LABELS[kind], "installed": kind in self.readers,
                           "size": path.stat().st_size if path.exists() else 0,
                           "progress": self.progress.get(kind)}
        return {"library": self.library, "ready": self.ready, "files": files,
                "busy": bool(self.task and not self.task.done())}

    # ----------------------------------------------------------------- downloading
    async def _download_one(self, session: aiohttp.ClientSession, kind: str) -> None:
        urls = [self.url_override[kind]] if kind in self.url_override else \
            [BASE_URL.format(kind=kind, ym=ym) for ym in _months()]
        prog = self.progress[kind] = {"state": "starting", "bytes": 0, "total": 0, "error": ""}
        last_err = "not found"
        for url in urls:
            part = self.dir / (FILES[kind] + ".part")
            try:
                async with session.get(url) as r:
                    if r.status != 200:
                        last_err = f"HTTP {r.status}"
                        continue
                    prog.update(state="downloading", total=int(r.headers.get("Content-Length", 0)))
                    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    with part.open("wb") as f:
                        async for chunk in r.content.iter_chunked(1 << 16):
                            f.write(dec.decompress(chunk))
                            prog["bytes"] += len(chunk)
                        f.write(dec.flush())
                part.replace(self.dir / FILES[kind])
                self.readers.pop(kind, None)
                self.load()
                prog["state"] = "done" if kind in self.readers else "error"
                if prog["state"] == "error":
                    prog["error"] = "downloaded file could not be read (is the maxminddb library installed?)"
                    (self.dir / FILES[kind]).unlink(missing_ok=True)
                return
            except Exception as e:  # noqa: BLE001
                last_err = f"{type(e).__name__}: {e}"
            finally:
                part.unlink(missing_ok=True)
        prog.update(state="error", error=last_err)

    async def _download(self, kinds: list[str]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=1800, sock_connect=20)) as s:
            for kind in kinds:
                await self._download_one(s, kind)

    def start_download(self, kinds: list[str]) -> bool:
        if self.task and not self.task.done():
            return False
        kinds = [k for k in kinds if k in FILES]
        self.task = asyncio.create_task(self._download(kinds))
        return True
