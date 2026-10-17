"""Persistent proxy pool with health scoring (the idea behind jhao104/proxy_pool).

Every working proxy a scan finds is stored in pool.json, so nothing is lost when the server restarts.
Each proxy has a failure score: a failed re-check adds 1, a successful one removes 1, and the proxy is
dropped once the score goes above `max_fails`. That lets a good proxy survive one bad moment, while
dead ones disappear after a few checks.
"""
from __future__ import annotations

import json
import os
import random
import time
from pathlib import Path
from urllib.parse import quote

MAX_SIZE = 20_000
FIELDS = ("proto", "host", "port", "latency_ms", "country", "city", "asn", "org", "exit_ip", "anonymity",
          "speed_mbps", "https", "auth")


def quality(e: dict) -> tuple:
    """Lower is better: fewest failures first, then fastest."""
    return (e["fails"], e["latency_ms"])


def full_url(e: dict) -> str:
    """proto://[user:pass@]host:port, including the proxy's own login when it has one."""
    if not e.get("auth"):
        return e["url"]
    user, _, pw = e["auth"].partition(":")
    return f"{e['proto']}://{quote(user, safe='')}:{quote(pw, safe='')}@{e['host']}:{e['port']}"


def public_entry(e: dict) -> dict:
    """A pool entry without the login, safe to show in the dashboard."""
    d = {k: v for k, v in e.items() if k != "auth"}
    d["has_auth"] = bool(e.get("auth"))
    return d


def to_result(e: dict):
    """Rebuild a proxyhive.Result from a pool entry (used for exporting and the gateway)."""
    from . import engine as pt
    return pt.Result(e["proto"], e["host"], e["port"], e["latency_ms"], e["country"], e["exit_ip"], e["anonymity"],
                     e.get("speed_mbps"), e.get("https", True), e.get("auth", ""), e.get("city", ""),
                     e.get("asn", ""), e.get("org", ""))


class Pool:
    def __init__(self, path: Path):
        self.path = path
        self.items: dict[str, dict] = {}
        self.dirty = False
        self.load()

    def __len__(self) -> int:
        return len(self.items)

    # ----------------------------------------------------------------- persistence
    def load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.items = {e["url"]: e for e in data if isinstance(e, dict) and "url" in e and "fails" in e}
        except (OSError, ValueError, TypeError, KeyError):
            self.items = {}

    def save(self) -> None:
        if not self.dirty:
            return
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(list(self.items.values())), encoding="utf-8")
        os.replace(tmp, self.path)           # atomic: a crash never leaves half a file
        self.dirty = False

    # ----------------------------------------------------------------- scoring
    def add_success(self, r, now: float | None = None) -> None:
        """Store or refresh a proxy that just passed a check (r is a proxyhive.Result)."""
        now = now or time.time()
        e = self.items.get(r.url)
        if e is None:
            e = self.items[r.url] = {"url": r.url, "first_seen": int(now), "checks": 0, "fails": 0}
        e.update({k: getattr(r, k) for k in FIELDS})
        e["fails"] = max(0, e["fails"] - 1)
        e["checks"] += 1
        e["last_ok"] = e["last_check"] = int(now)
        self.dirty = True

    def add_failure(self, url: str, max_fails: int, now: float | None = None) -> bool:
        """A check failed. Returns True if the proxy was dropped from the pool."""
        e = self.items.get(url)
        if e is None:
            return False
        e["fails"] += 1
        e["checks"] += 1
        e["last_check"] = int((now or time.time()))
        self.dirty = True
        if e["fails"] > max_fails:
            del self.items[url]
            return True
        return False

    def apply_scan(self, results, tested: set[str], max_fails: int) -> dict:
        """Merge a finished scan: refresh the proxies that passed, penalise pool members that were tested
        and failed. Proxies that were not tested (e.g. the scan was stopped early) are left alone."""
        ok = {r.url for r in results}
        for r in results:
            self.add_success(r)
        dropped = sum(self.add_failure(u, max_fails) for u in tested - ok if u in self.items)
        self._trim()
        return {"added_or_refreshed": len(ok), "dropped": dropped, "size": len(self.items)}

    def _trim(self) -> None:
        if len(self.items) > MAX_SIZE:
            keep = sorted(self.items.values(), key=quality)[:MAX_SIZE]
            self.items = {e["url"]: e for e in keep}
            self.dirty = True

    def report(self, url: str, ok: bool, max_fails: int) -> bool:
        """A script using the pool reports whether a proxy worked. Returns True if the proxy was dropped."""
        e = self.items.get(url)
        if e is None:
            return False
        if ok:
            e["fails"] = max(0, e["fails"] - 1)
            e["last_ok"] = e["last_check"] = int(time.time())
            self.dirty = True
            return False
        return self.add_failure(url, max_fails)

    def remove(self, url: str) -> bool:
        if self.items.pop(url, None) is not None:
            self.dirty = True
            return True
        return False

    def last_checked(self) -> float:
        return max((e.get("last_check", 0) for e in self.items.values()), default=0)

    # ----------------------------------------------------------------- queries
    def select(self, f: dict | None = None) -> list[dict]:
        """Filter by type (http|socks4|socks5|https), country, anonymity, max_latency, min_speed, max_fails,
        https_only. Sorted best first."""
        f = f or {}
        typ = (f.get("type") or "").lower()
        countries = {c.upper() for c in f.get("country") or []}
        anons = {a.lower() for a in f.get("anonymity") or []}
        out = []
        for e in self.items.values():
            if typ in ("http", "socks4", "socks5") and e["proto"] != typ:
                continue
            if (typ == "https" or f.get("https_only")) and not e.get("https", True):
                continue
            if countries and e["country"] not in countries:
                continue
            if anons and e["anonymity"] not in anons:
                continue
            if f.get("max_latency") and e["latency_ms"] > f["max_latency"]:
                continue
            if f.get("min_speed") and (e.get("speed_mbps") or 0) < f["min_speed"]:
                continue
            if f.get("max_fails") is not None and e["fails"] > f["max_fails"]:
                continue
            if f.get("exclude") and e["url"] in f["exclude"]:
                continue
            out.append(e)
        out.sort(key=quality)
        return out

    def pick(self, f: dict | None = None, strategy: str = "random") -> dict | None:
        rows = self.select(f)
        if not rows:
            return None
        if strategy == "best":
            return rows[0]
        # random, but never from the failing half: healthy proxies only when there are enough of them
        healthy = [e for e in rows if e["fails"] == 0] or rows
        return random.choice(healthy)

    def stats(self) -> dict:
        by_proto, by_anon = {}, {}
        for e in self.items.values():
            by_proto[e["proto"]] = by_proto.get(e["proto"], 0) + 1
            by_anon[e["anonymity"]] = by_anon.get(e["anonymity"], 0) + 1
        return {"count": len(self.items), "healthy": sum(1 for e in self.items.values() if e["fails"] == 0),
                "by_proto": by_proto, "by_anonymity": by_anon, "https_capable": sum(1 for e in self.items.values() if e.get("https", True))}
