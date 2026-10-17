"""Persistent state: validated settings, dead-proxy cache, scan history, custom proxy list."""
from __future__ import annotations

import copy
import json
import time

from . import engine as pt
from . import exports, paths

HERE = paths.APP_DIR
SETTINGS_FILE = HERE / "settings.json"
CACHE_FILE = HERE / "dead_cache.json"
HISTORY_FILE = HERE / "history.json"
CUSTOM_FILE = HERE / "custom_proxies.txt"

DEFAULT_SETTINGS: dict = {
    # scan
    "_v": 2,                      # settings version (2 = defaults tuned by measurement, see README "Why these defaults")
    "protocols": list(pt.PROTOCOLS),
    "timeout": 10,                # 6 s found 2.5x fewer working proxies than 12 s: free proxies are slow, not dead
    "concurrency": 400,           # 1000 parallel found ~15-20% fewer than 400 on a home connection
    "probe_timeout": 3,
    "probe_concurrency": 300,     # 1500 parallel port probes silently missed about half of the live hosts
    "retry_failed": True,         # second chance for proxies that timed out or dropped: recovers ~30% more
    "retry_max": 5000,
    "prefilter": True,
    "max_latency": 0,
    "limit": 0,
    "dead_cache_hours": 0,
    "include_custom": True,
    "fetch_timeout": 30,
    "max_per_source": 150_000,
    # checks
    "allow_http_only": True,
    "geo_enrich": True,
    "test_url": pt.DEFAULT_TEST_URL,
    "extra_presets": [],
    "extra_urls": [],
    "anonymity": True,
    "judge_urls": list(pt.DEFAULT_JUDGES),
    "speed": False,
    "speed_bytes": 300_000,
    "speed_timeout": 10,
    # automation
    "auto_refresh_min": 0,
    "auto_save": True,
    "disabled_sources": [],
    # persistent pool (kept in pool.json, survives restarts)
    "pool_enabled": False,        # background upkeep: re-check on a schedule, refill when it gets small
    "pool_recheck_min": 10,
    "pool_min_size": 50,
    "pool_max_fails": 3,
    # saving
    "save": {
        "dir": "results",
        "formats": ["url", "csv", "json"],
        "filters": {"protocols": list(pt.PROTOCOLS), "anonymity": list(exports.ANON_RANK), "countries": [],
                    "max_latency": 0, "max_count": 0, "https_only": False},
        "sort": "anon_country",
        "split": "protocol",
        "prefix": "working",
        "template": "{proto}://{host}:{port}",
        "user": "",
        "pass": "",
        "timestamp": False,
    },
    # local gateway
    "gateway": {"port": 8082, "mode": "single", "order": "round_robin", "rotate_secs": 0, "rotate_requests": 0,
                "pool_size": 20, "max_errors": 3, "auto_refill": True, "bind": "127.0.0.1",
                "auth_user": "", "auth_pass": "", "system_proxy": False},
    # dashboard
    "ui": {"sort": "anonymity"},
    # Site check tab: the last values used
    "target": {"url": "", "source": "pool", "contains": "", "expect": "ok", "timeout": 10, "concurrency": 200,
               "limit": 0},
}


# --------------------------------------------------------------------------- validation

def _num(lo, hi):
    def f(v):
        n = float(v)
        if n != n:
            raise ValueError
        n = max(lo, min(hi, n))
        return int(n) if n == int(n) else n
    return f


def _bool(v):
    if not isinstance(v, bool):
        raise ValueError
    return v


def _text(maxlen):
    def f(v):
        if not isinstance(v, str):
            raise ValueError
        return v.strip()[:maxlen]
    return f


def _choice(options):
    options = list(options)

    def f(v):
        if v not in options:
            raise ValueError
        return v
    return f


def _subset(options):
    options = list(options)

    def f(v):
        if not isinstance(v, list):
            raise ValueError
        return [x for x in options if x in v]
    return f


def _urls(prefixes, maxn=10):
    def f(v):
        if not isinstance(v, list):
            raise ValueError
        out = [s.strip() for s in v if isinstance(s, str) and s.strip().lower().startswith(prefixes)]
        return out[:maxn]
    return f


def _url(prefixes):
    def f(v):
        v = _text(500)(v)
        if not v.lower().startswith(prefixes):
            raise ValueError
        return v
    return f


def _countries(v):
    if not isinstance(v, list):
        raise ValueError
    return [c.strip().upper() for c in v if isinstance(c, str) and len(c.strip()) == 2 and c.strip().isalpha()][:300]


def _strlist(v):
    if not isinstance(v, list):
        raise ValueError
    return [s for s in v if isinstance(s, str)][:1000]


ANON_LEVELS = list(exports.ANON_RANK)
SCHEMA: dict = {
    "protocols": _subset(pt.PROTOCOLS), "timeout": _num(1, 60), "concurrency": _num(10, 5000),
    "retry_failed": _bool, "retry_max": _num(0, 200_000),
    "probe_timeout": _num(1, 30), "probe_concurrency": _num(10, 5000), "prefilter": _bool,
    "max_latency": _num(0, 120_000), "limit": _num(0, 2_000_000), "dead_cache_hours": _num(0, 720),
    "include_custom": _bool, "fetch_timeout": _num(5, 120), "max_per_source": _num(0, 5_000_000),
    "allow_http_only": _bool, "geo_enrich": _bool, "pool_enabled": _bool, "pool_recheck_min": _num(1, 1440),
    "pool_min_size": _num(0, 100_000), "pool_max_fails": _num(0, 50),
    "test_url": _url(("http://", "https://")), "extra_presets": _subset(pt.EXTRA_PRESETS),
    "extra_urls": _urls(("http://", "https://")), "anonymity": _bool, "judge_urls": _urls(("http://",), 5),
    "speed": _bool, "speed_bytes": _num(50_000, 20_000_000), "speed_timeout": _num(2, 120),
    "auto_refresh_min": _num(0, 10_080), "auto_save": _bool, "disabled_sources": _strlist,
    "save": {
        "dir": _text(260), "formats": _subset(exports.FORMATS),
        "filters": {"protocols": _subset(pt.PROTOCOLS), "anonymity": _subset(ANON_LEVELS), "countries": _countries,
                    "max_latency": _num(0, 120_000), "max_count": _num(0, 1_000_000), "https_only": _bool},
        "sort": _choice(exports.SORT_PRESETS), "split": _choice(["none", "protocol", "country", "anonymity"]),
        "prefix": _text(60), "template": _text(200), "user": _text(100), "pass": _text(100), "timestamp": _bool,
    },
    "gateway": {"port": _num(1024, 65535), "mode": _choice(["single", "rotate"]),
                "order": _choice(["round_robin", "random"]), "rotate_secs": _num(0, 86_400),
                "rotate_requests": _num(0, 1_000_000), "pool_size": _num(1, 500), "max_errors": _num(0, 100),
                "auto_refill": _bool, "bind": _choice(["127.0.0.1", "0.0.0.0"]), "auth_user": _text(64),
                "auth_pass": _text(64), "system_proxy": _bool},
    "ui": {"sort": _choice(exports.SORT_PRESETS)},
    "target": {"url": _text(500), "source": _choice(["pool", "scan", "sources"]), "contains": _text(200),
               "expect": _choice(["ok", "200"]), "timeout": _num(2, 60), "concurrency": _num(10, 1000),
               "limit": _num(0, 200_000)},
}


def _merge(base: dict, incoming: dict, schema: dict) -> None:
    for key, rule in schema.items():
        if key not in incoming:
            continue
        if isinstance(rule, dict):
            if isinstance(incoming[key], dict):
                _merge(base[key], incoming[key], rule)
            continue
        try:
            base[key] = rule(incoming[key])
        except (ValueError, TypeError):
            pass  # keep the previous value for anything invalid


def sanitize(incoming: dict, current: dict) -> dict:
    out = copy.deepcopy(current)
    if isinstance(incoming, dict):
        _merge(out, incoming, SCHEMA)
    return out


def load_settings() -> dict:
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if isinstance(data, dict) and data.get("_v", 1) < 2:
        # settings saved by an older version carry the old scan defaults, which measured worse: take the new ones
        for key in ("timeout", "concurrency", "probe_timeout", "probe_concurrency"):
            data.pop(key, None)
    return sanitize(data, copy.deepcopy(DEFAULT_SETTINGS))


def save_settings(settings: dict) -> None:
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- dead-proxy cache

class DeadCache:
    """Remembers hosts/proxies that recently failed so repeat scans can skip them."""

    KEEP_SECONDS = 7 * 86400

    def __init__(self) -> None:
        self.ep: dict[str, int] = {}   # "host:port" that refused/timed out a TCP connect
        self.px: dict[str, int] = {}   # "proto://host:port" that failed the real check
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            self.ep, self.px = dict(data.get("ep", {})), dict(data.get("px", {}))
        except (OSError, ValueError, AttributeError):
            pass

    def __len__(self) -> int:
        return len(self.ep) + len(self.px)

    def dead_endpoint(self, host: str, port: int, hours: float) -> bool:
        ts = self.ep.get(f"{host}:{port}")
        return ts is not None and time.time() - ts < hours * 3600

    def dead_proxy(self, proto: str, host: str, port: int, hours: float) -> bool:
        ts = self.px.get(f"{proto}://{host}:{port}")
        return ts is not None and time.time() - ts < hours * 3600

    def mark_endpoint(self, host: str, port: int) -> None:
        self.ep[f"{host}:{port}"] = int(time.time())

    def mark_proxy(self, proto: str, host: str, port: int) -> None:
        self.px[f"{proto}://{host}:{port}"] = int(time.time())

    def forget(self, proto: str, host: str, port: int) -> None:
        self.ep.pop(f"{host}:{port}", None)
        self.px.pop(f"{proto}://{host}:{port}", None)

    def clear(self) -> None:
        self.ep.clear()
        self.px.clear()
        self.save()

    def save(self) -> None:
        cutoff = time.time() - self.KEEP_SECONDS
        self.ep = {k: v for k, v in self.ep.items() if v > cutoff}
        self.px = {k: v for k, v in self.px.items() if v > cutoff}
        CACHE_FILE.write_text(json.dumps({"ep": self.ep, "px": self.px}), encoding="utf-8")


# --------------------------------------------------------------------------- history / custom list

def load_history() -> list[dict]:
    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def add_history(entry: dict, keep: int = 100) -> None:
    history = load_history()
    history.insert(0, entry)
    HISTORY_FILE.write_text(json.dumps(history[:keep]), encoding="utf-8")


def load_custom() -> str:
    try:
        return CUSTOM_FILE.read_text(encoding="utf-8")
    except OSError:
        return ""


def save_custom(text: str) -> None:
    CUSTOM_FILE.write_text(text[:5_000_000], encoding="utf-8")
