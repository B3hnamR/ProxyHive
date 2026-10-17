"""Web dashboard for proxyhive.   python -m proxyhive --server

Serves web/index.html on 127.0.0.1 and streams live job state to it over Server-Sent Events.
Also exposes the saved proxy pool to your own scripts under /api/pool/*  (localhost only).

Author: B3hnamR  |  Telegram https://t.me/B3hnamR  |  GitHub https://github.com/B3hnamR
"""
from __future__ import annotations

import asyncio
import atexit
import copy
import json
import random
import re
import socket
import struct
import time
import webbrowser
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web
from aiohttp_socks import ProxyConnector, ProxyType

from . import __version__, config, exports, paths
from . import engine as pt
from . import gateway as gw
from . import geo as geo_mod
from . import pool as pool_mod

HERE = paths.APP_DIR
INDEX = paths.BUNDLE_DIR / "web" / "index.html"
SAVE_SUFFIXES = {".txt", ".csv", ".json", ".conf", ".pac"}
PROXY_URL_RE = re.compile(r"(http|socks4|socks5)://(?:[^\s/@]+@)?(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}")
KEY_RE = re.compile(r"(http|socks4|socks5)://(?:[^\s/@]+@)?((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})")


class Job:
    def __init__(self, settings: dict, kind: str = "scan"):
        self.id = int(time.time() * 1000)
        self.settings = settings
        self.kind = kind                    # scan | file | pool
        self.sources: list[dict] = []
        self.src_index: dict[tuple, list[int]] = {}
        self.creds: dict[tuple, tuple[str, str]] = {}       # proxies that need a login
        self.counts = {"candidates": 0, "skipped": 0, "endpoints": 0, "tcp_done": 0, "tcp_open": 0,
                       "check_total": 0, "check_done": 0}
        self.fails: dict[str, int] = {}     # failure reason -> count
        self.retry_n = 0                    # proxies given a second chance
        self.recovered = 0                  # ...and how many of them passed
        self.in_retry = False
        self.tested: set[str] = set()       # proxy URLs actually checked (pool scoring only counts these)
        self.results: list[pt.Result] = []
        self.by_url: dict[str, pt.Result] = {}
        self.phase = "scrape"
        self.message = ""
        self.saved: list[str] = []
        self.pool_note: dict = {}
        self.t0 = time.time()
        self.scan_t0: float | None = None
        self.t_end: float | None = None
        self.task: asyncio.Task | None = None

    def set_phase(self, phase: str) -> None:
        self.phase = phase
        if phase == "scan":
            self.scan_t0 = time.time()

    @property
    def active(self) -> bool:
        return self.phase in ("scrape", "prepare", "scan")

    def rates(self) -> tuple[float, float, float | None]:
        """(probe/s, check/s, eta seconds). The probe and check stages overlap, so the ETA is whichever is slower."""
        if self.phase != "scan" or not self.scan_t0:
            return 0.0, 0.0, None
        el = max(time.time() - self.scan_t0, 0.001)
        c = self.counts
        probe_rate, check_rate = c["tcp_done"] / el, c["check_done"] / el
        probe_left = c["endpoints"] - c["tcp_done"]
        per_endpoint = c["check_total"] / max(c["tcp_done"], 1)
        checks_left = (c["check_total"] - c["check_done"]) + probe_left * per_endpoint
        eta = None
        if el > 3 and probe_rate > 0 and (check_rate > 0 or checks_left < 1):
            eta = max(probe_left / probe_rate, checks_left / check_rate if check_rate > 0 else 0)
        return probe_rate, check_rate, eta

    def snapshot(self) -> dict:
        probe_rate, rate, eta = self.rates()
        return {"job": self.id, "kind": self.kind, "phase": self.phase, "message": self.message,
                "sources": self.sources, "counts": self.counts, "fails": self.fails, "retry": self.retry_n,
                "in_retry": self.in_retry, "recovered": self.recovered, "rate": rate,
                "probe_rate": probe_rate, "eta": eta, "elapsed": (self.t_end or time.time()) - self.t0,
                "saved": self.saved, "pool_note": self.pool_note,
                "cfg": {k: self.settings[k] for k in ("timeout", "concurrency", "anonymity", "speed")}}


class TargetSession:
    """One Site check: test many proxies against a single URL. Runs independently of the main scan."""

    def __init__(self, url: str, source: str, cfg: dict):
        self.id = int(time.time() * 1000)
        self.url, self.source, self.cfg = url, source, cfg
        self.phase = "prepare"
        self.message = ""
        self.counts = {"candidates": 0, "skipped": 0, "tcp_done": 0, "tcp_open": 0, "checked": 0, "total": 0}
        self.fails: dict[str, int] = {}
        self.results: list[pt.Result] = []
        self.extra: dict[str, dict] = {}            # proxy url -> {"status", "size"}
        self.by_url: dict[str, pt.Result] = {}
        self.t0 = time.time()
        self.t_end: float | None = None
        self.task: asyncio.Task | None = None

    @property
    def active(self) -> bool:
        return self.phase in ("prepare", "scan")

    def row(self, r: pt.Result) -> dict:
        return {**result_dict(r), **self.extra.get(r.url, {})}

    def snapshot(self, since: int = 0) -> dict:
        return {"id": self.id, "url": self.url, "source": self.source, "phase": self.phase, "message": self.message,
                "counts": self.counts, "fails": self.fails, "elapsed": (self.t_end or time.time()) - self.t0,
                "total": len(self.results), "since": since, "rows": [self.row(r) for r in self.results[since:]],
                "cfg": {k: self.cfg[k] for k in ("timeout", "expect", "contains")}}


class State:
    """Everything that changes while the server runs. aiohttp warns when keys of a started Application are
    reassigned, so the Application holds this one mutable object instead."""

    def __init__(self, sources_path: Path):
        self.sources_path = sources_path
        self.settings: dict = config.load_settings()
        self.job: Job | None = None
        self.target: TargetSession | None = None
        self.cache = config.DeadCache()
        self.pool = pool_mod.Pool(paths.APP_DIR / "pool.json")
        self.geo = geo_mod.GeoDB(paths.DATA_DIR)
        self.gateway = gw.Gateway()
        self.next_auto: float | None = None
        self.next_what = ""
        self.last_scan_end = time.time()
        self.last_pool_check = self.pool.last_checked()
        self.scheduler: asyncio.Task | None = None


STATE_KEY: "web.AppKey[State]" = web.AppKey("state", State)


# --------------------------------------------------------------------------- the scan itself

def add_source(job: Job, proto: str, url: str, kind: str, label: str | None = None) -> int:
    job.sources.append({"proto": proto, "url": url, "label": label, "kind": kind,
                        "status": "pending", "count": 0, "working": 0, "error": ""})
    return len(job.sources) - 1


def register(job: Job, i: int, found: set) -> None:
    job.sources[i]["count"] = len(found)
    job.sources[i]["status"] = "ok" if found else "failed"
    for key in found:
        job.src_index.setdefault(key, []).append(i)


async def gather_candidates(app: web.Application, job: Job, file_name: str | None,
                            include_pool: bool, import_data: dict | None = None) -> set[tuple]:
    """Fill job.sources / job.src_index with every candidate proxy. Returns the keys that must always be
    checked (they bypass the dead-proxy cache)."""
    state: State = app[STATE_KEY]
    st = job.settings
    forced: set[tuple] = set()
    pool_keys = {(e["proto"], e["host"], e["port"]): e for e in state.pool.items.values()}

    def from_pool() -> set[tuple]:
        for key, e in pool_keys.items():
            if e.get("auth"):
                u, _, p = e["auth"].partition(":")
                job.creds[key] = (u, p)
        return set(pool_keys)

    if job.kind == "pool":
        register(job, add_source(job, "all", "pool:", "pool", "Saved pool"), from_pool())
        return set(pool_keys)
    if job.kind == "import" and import_data:
        proto = import_data["proto"]
        for n, (label, doc) in enumerate(import_data["docs"]):
            i = add_source(job, proto, f"doc:{n}", "import", label)
            register(job, i, await asyncio.to_thread(pt.parse_proxies, doc, proto, job.creds))
        if import_data["urls"]:
            def on_err(url: str, msg: str) -> None:
                for src in job.sources:
                    if src["url"] == url:
                        src["error"] = msg

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=st["fetch_timeout"]),
                                             headers=pt.HEADERS) as session:
                async def grab(i, url):
                    job.sources[i]["status"] = "loading"
                    _, _, found = await pt.fetch_source(session, proto, url, creds=job.creds,
                                                        max_proxies=st["max_per_source"], on_error=on_err)
                    register(job, i, found)

                await asyncio.gather(*(grab(add_source(job, proto, u, "import"), u) for u in import_data["urls"]))
        return set(job.src_index)           # everything you hand over is always checked (the dead cache is bypassed)
    if job.kind == "file":
        text = saved_file_path(app, file_name).read_text(encoding="utf-8", errors="ignore")
        i = add_source(job, "all", f"file:{file_name}", "file", f"file: {file_name}")
        register(job, i, await asyncio.to_thread(pt.parse_proxies, text, "all", job.creds))
        return forced

    disabled = set(st["disabled_sources"])
    entries = [(add_source(job, p, u, "source"), p, u)
               for p, u in pt.load_sources(state.sources_path) if u not in disabled]

    def on_error(url: str, msg: str) -> None:
        for s in job.sources:
            if s["url"] == url:
                s["error"] = msg

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=st["fetch_timeout"]),
                                     headers=pt.HEADERS) as session:
        async def fetch(i, proto, url):
            job.sources[i]["status"] = "loading"
            _, _, found = await pt.fetch_source(session, proto, url, creds=job.creds,
                                                max_proxies=st["max_per_source"], on_error=on_error)
            register(job, i, found)

        await asyncio.gather(*(fetch(*e) for e in entries))
    custom = config.load_custom() if st["include_custom"] else ""
    if custom.strip():
        register(job, add_source(job, "all", "custom:", "custom", "Custom list"),
                 await asyncio.to_thread(pt.parse_proxies, custom, "all", job.creds))
    if include_pool and pool_keys:
        forced = from_pool()
        register(job, add_source(job, "all", "pool:", "pool", "Saved pool"), set(forced))
    return forced


async def run_job(app: web.Application, job: Job, file_name: str | None = None,
                  include_pool: bool = False, import_data: dict | None = None) -> None:
    state: State = app[STATE_KEY]
    st, c, cache, geo = job.settings, job.counts, state.cache, state.geo
    check_tasks: list[asyncio.Task] = []
    final = "done"
    try:
        forced = await gather_candidates(app, job, file_name, include_pool, import_data)
        # a scan follows the protocol chips in Settings; a list you handed over is checked as a whole
        protos = set(st["protocols"]) if job.kind == "scan" else set(pt.PROTOCOLS)
        keys = sorted(k for k in job.src_index if k[0] in protos)
        if st["limit"] and job.kind == "scan":
            keys = random.sample(keys, min(st["limit"], len(keys)))
        hours = st["dead_cache_hours"]
        if hours and job.kind == "scan":
            before = len(keys)
            keys = [k for k in keys if k in forced or not (cache.dead_proxy(*k, hours)
                                                           or cache.dead_endpoint(k[1], k[2], hours))]
            c["skipped"] = before - len(keys)
        c["candidates"] = len(keys)
        if not keys:
            job.message = ("No proxies were found in what you provided. Check the format "
                           "(ip:port, scheme://ip:port, user:pass@ip:port)." if job.kind in ("import", "file")
                           else "Nothing to check: every source came back empty or was filtered out.")
            return                                # the finally block below closes the job cleanly
        by_ep: dict[tuple, list[tuple]] = {}
        for k in keys:
            by_ep.setdefault((k[1], k[2]), []).append(k)
        endpoints = list(by_ep)
        random.shuffle(endpoints)
        c["endpoints"] = len(endpoints)

        job.set_phase("prepare")
        extra = [pt.EXTRA_PRESETS[p][1] for p in st["extra_presets"]] + st["extra_urls"]
        opts = pt.CheckOptions(url=st["test_url"], timeout=st["timeout"], extra_urls=tuple(dict.fromkeys(extra)),
                               anonymity=st["anonymity"], speed=st["speed"], speed_bytes=st["speed_bytes"],
                               speed_timeout=st["speed_timeout"], allow_http_only=st["allow_http_only"],
                               plain_url=st["test_url"] if st["test_url"].startswith("http://") else pt.PLAIN_TEST_URL)
        notes = await pt.prepare(opts, st["judge_urls"])
        if st["concurrency"] > 1000 or st["probe_concurrency"] > 1500:
            notes.append(f"{st['concurrency']} parallel checks and {st['probe_concurrency']} probes at once can "
                         "overwhelm some home routers (NAT table). If your internet stalls, lower them in Settings.")
        job.message = "; ".join(notes)

        job.set_phase("scan")
        queue: asyncio.Queue = asyncio.Queue()
        retry_on = st["retry_failed"] and st["retry_max"] > 0
        retry: list[tuple] = []                 # failed once for a reason that may just be a bad moment
        first_reason: dict[tuple, str] = {}     # key -> why it failed the first time (already counted in job.fails)
        second = False

        def fail(reason: str, n: int = 1) -> None:
            job.fails[reason] = job.fails.get(reason, 0) + n

        def accept(res: pt.Result) -> None:
            if st["max_latency"] and res.latency_ms > st["max_latency"]:
                job.tested.discard(res.url)      # alive, just too slow for this scan: do not penalise it in the pool
                fail("too_slow")
                return
            if st["geo_enrich"] and geo.ready:
                info = geo.lookup(res.exit_ip)
                res.city, res.asn, res.org = info["city"], info["asn"], info["org"]
            job.results.append(res)
            job.by_url[res.url] = res
            for i in job.src_index.get((res.proto, res.host, res.port), ()):
                job.sources[i]["working"] += 1
            cache.forget(res.proto, res.host, res.port)

        async def checker() -> None:
            while (key := await queue.get()) is not None:
                try:
                    res, reason = await pt.check_detailed(*key, opts, job.creds.get(key))
                except Exception:  # noqa: BLE001 - one odd proxy must never kill a worker or lose a candidate
                    res, reason = None, "other"
                c["check_done"] += 1
                job.tested.add(f"{key[0]}://{key[1]}:{key[2]}")
                if res:
                    if key in first_reason:      # recovered on its second chance: undo the first failure
                        job.recovered += 1
                        old = first_reason[key]
                        job.fails[old] = job.fails.get(old, 1) - 1
                        if job.fails[old] <= 0:
                            job.fails.pop(old, None)
                    try:
                        accept(res)
                    except Exception:  # noqa: BLE001
                        job.results.append(res)
                        job.by_url[res.url] = res
                elif not second and retry_on and reason in pt.RETRY_REASONS:
                    retry.append(key)
                    first_reason[key] = reason
                    fail(reason)
                else:
                    if key not in first_reason:  # on the second pass the first failure is already counted
                        fail(reason)
                    if reason != "local_limit":
                        cache.mark_proxy(*key)

        async def probe(ep: tuple) -> None:
            alive = True
            if st["prefilter"]:
                for attempt in range(3):
                    try:
                        _, w = await asyncio.wait_for(asyncio.open_connection(*ep), st["probe_timeout"])
                        sock = w.get_extra_info("socket")
                        if sock is not None:     # abortive close: leaves no TIME_WAIT behind (100k probes would exhaust ports)
                            try:
                                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                            except OSError:
                                pass
                        w.close()
                        alive = True
                        break
                    except Exception as e:  # noqa: BLE001
                        reason = pt.tcp_reason(e)
                        if reason == "local_limit" and attempt < 2:      # our own PC is out of ports: wait, try again
                            await asyncio.sleep(0.5 * (attempt + 1))
                            continue
                        alive = False
                        fail(reason, len(by_ep[ep]))
                        if reason != "local_limit":
                            cache.mark_endpoint(*ep)
                            for k in by_ep[ep]:
                                job.tested.add(f"{k[0]}://{k[1]}:{k[2]}")
                        break
            c["tcp_done"] += 1
            if alive:
                c["tcp_open"] += 1
                for key in by_ep[ep]:
                    c["check_total"] += 1
                    queue.put_nowait(key)

        check_tasks = [asyncio.create_task(checker()) for _ in range(st["concurrency"])]
        it = iter(endpoints)

        async def probe_worker() -> None:
            for ep in it:
                try:
                    await probe(ep)
                except Exception:  # noqa: BLE001 - never lose the worker
                    c["tcp_done"] += 1
                    fail("tcp_unreachable", len(by_ep[ep]))

        await asyncio.gather(*(probe_worker() for _ in range(st["probe_concurrency"])))
        for _ in check_tasks:
            queue.put_nowait(None)
        await asyncio.gather(*check_tasks)

        if retry_on and retry:                   # second chance for the flaky ones, once, at the end
            batch = retry if len(retry) <= st["retry_max"] else random.sample(retry, st["retry_max"])
            for k in set(retry) - set(batch):     # too many to retry: these failures are final
                cache.mark_proxy(*k)
            second, job.retry_n, job.in_retry = True, len(batch), True
            c["check_total"] += len(batch)
            queue = asyncio.Queue()
            for k in batch:
                queue.put_nowait(k)
            check_tasks = [asyncio.create_task(checker()) for _ in range(min(st["concurrency"], max(20, len(batch))))]
            for _ in check_tasks:
                queue.put_nowait(None)
            await asyncio.gather(*check_tasks)
            job.in_retry = False
    except asyncio.CancelledError:
        final = "stopped"
    except Exception as e:  # noqa: BLE001
        job.message = f"{type(e).__name__}: {e}"
        final = "error"
    finally:
        for t in check_tasks:
            t.cancel()
        finish_job(app, job, final)


def finish_job(app: web.Application, job: Job, final: str) -> None:
    state: State = app[STATE_KEY]
    job.t_end = time.time()
    state.last_scan_end = job.t_end
    try:
        state.cache.save()
    except OSError:
        pass
    # keep what we learned: refresh/penalise pool members, add new finds
    try:
        job.pool_note = state.pool.apply_scan(job.results, job.tested, job.settings["pool_max_fails"])
        state.pool.save()
        state.last_pool_check = job.t_end
    except OSError as e:
        job.message = f"could not save the pool: {e}"
    if job.results and job.settings["auto_save"]:
        try:
            job.saved = [str(p) for p in exports.save_files(job.results, job.settings["save"], HERE)]
        except Exception as e:  # noqa: BLE001
            job.message = f"auto-save failed: {e}"
    if job.counts["candidates"] or job.results:
        r = job.results
        config.add_history({
            "id": job.id, "ts": int(job.t0), "duration": round(job.t_end - job.t0), "phase": final, "kind": job.kind,
            "counts": dict(job.counts), "working": len(r), "best_ms": min((x.latency_ms for x in r), default=None),
            "by_proto": {p: sum(x.proto == p for x in r) for p in pt.PROTOCOLS},
            "by_anon": {a: sum(x.anonymity == a for x in r) for a in exports.ANON_RANK},
            "http_only": sum(not x.https for x in r), "fails": dict(job.fails),
            "sources": [{"label": s["label"] or s["url"], "proto": s["proto"], "found": s["count"],
                         "working": s["working"]} for s in job.sources]})
    job.set_phase(final)


def start_job(app: web.Application, kind: str = "scan", file_name: str | None = None,
              include_pool: bool = False, import_data: dict | None = None) -> Job:
    state: State = app[STATE_KEY]
    job = Job(copy.deepcopy(state.settings), kind)
    state.job = job
    job.task = asyncio.create_task(run_job(app, job, file_name, include_pool, import_data))
    return job


async def scheduler(app: web.Application) -> None:
    """Background upkeep. With the pool maintenance switch on: re-check the pool every N minutes and run a full
    scan when it has shrunk below the minimum size. Otherwise: the optional 'scan every N minutes' timer."""
    state: State = app[STATE_KEY]
    started = time.time()
    while True:
        await asyncio.sleep(5)
        st, job, now = state.settings, state.job, time.time()
        if job and job.active:
            state.next_auto = None
            continue
        if st["pool_enabled"]:
            recheck_at = (state.last_pool_check or started) + st["pool_recheck_min"] * 60
            refill_at = state.last_scan_end + 600           # never full-scan more than every 10 minutes
            if len(state.pool) < st["pool_min_size"]:
                state.next_auto, state.next_what = refill_at, "pool refill scan"
                if now >= refill_at:
                    start_job(app, "scan", include_pool=True)
            else:
                state.next_auto, state.next_what = recheck_at, "pool re-check"
                if now >= recheck_at and len(state.pool):
                    start_job(app, "pool")
        elif st["auto_refresh_min"]:
            state.next_auto, state.next_what = state.last_scan_end + st["auto_refresh_min"] * 60, "auto-scan"
            if now >= state.next_auto:
                start_job(app, "scan", include_pool=True)
        else:
            state.next_auto = None


# --------------------------------------------------------------------------- site check (target session)

def normalize_url(raw: str | None) -> str | None:
    """'example.com/page' -> 'https://example.com/page'. Returns None if it is not a usable web address."""
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    try:
        u = urlsplit(raw)
        host, _ = u.hostname, u.port            # .port raises ValueError for things like "host:abc"
    except ValueError:
        return None
    ok_host = host and (re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?", host) or ":" in host)
    return raw if u.scheme in ("http", "https") and ok_host else None


async def run_target(app: web.Application, sess: TargetSession) -> None:
    state: State = app[STATE_KEY]
    st, cfg, c = state.settings, sess.cfg, sess.counts
    workers: list[asyncio.Task] = []
    final = "done"
    try:
        known: dict[tuple, pt.Result] = {}         # proxies we already know details about
        creds: dict[tuple, tuple[str, str]] = {}
        fresh = sess.source == "sources"
        if sess.source == "pool":
            known = {(r.proto, r.host, r.port): r for r in map(pool_mod.to_result, state.pool.items.values())}
        elif sess.source == "scan":
            known = {(r.proto, r.host, r.port): r for r in (state.job.results if state.job else [])}
        if known:
            for key, r in known.items():
                if r.auth:
                    u, _, p = r.auth.partition(":")
                    creds[key] = (u, p)
            keys = sorted(known)
        else:                                      # fresh from the sources: nothing is known yet
            tmp = Job(copy.deepcopy(st), "scan")
            await gather_candidates(app, tmp, None, False)
            creds = tmp.creds
            keys = sorted(k for k in tmp.src_index if k[0] in set(st["protocols"]))
        if sess.url.lower().startswith("https://") and known:      # HTTP-only proxies cannot reach https sites
            before = len(keys)
            keys = [k for k in keys if known[k].https]
            c["skipped"] = before - len(keys)
        limit = cfg["limit"] or (2000 if fresh else 0)
        if limit and len(keys) > limit:
            keys = random.sample(keys, limit)
        c["candidates"] = c["total"] = len(keys)
        opts = pt.TargetOptions(url=sess.url, timeout=cfg["timeout"], expect=cfg["expect"], contains=cfg["contains"])

        sess.phase = "scan"
        queue: asyncio.Queue = asyncio.Queue()

        def fail(reason: str, n: int = 1) -> None:
            sess.fails[reason] = sess.fails.get(reason, 0) + n

        async def checker() -> None:
            while (key := await queue.get()) is not None:
                info, reason = await pt.check_target(*key, opts, creds.get(key))
                c["checked"] += 1
                if info is None:
                    fail(reason)
                    continue
                base = known.get(key)
                auth = f"{creds[key][0]}:{creds[key][1]}" if key in creds else ""
                r = (replace(base, latency_ms=info["latency_ms"]) if base else
                     pt.Result(key[0], key[1], key[2], info["latency_ms"], "??", "", "unknown", None, True, auth))
                sess.extra[r.url] = {"status": info["status"], "size": info["size"]}
                sess.by_url[r.url] = r
                sess.results.append(r)

        workers = [asyncio.create_task(checker()) for _ in range(cfg["concurrency"])]
        if fresh and st["prefilter"]:              # unchecked lists: drop dead ports first, then test the rest
            by_ep: dict[tuple, list[tuple]] = {}
            for k in keys:
                by_ep.setdefault((k[1], k[2]), []).append(k)
            it = iter(list(by_ep))

            async def probe_worker() -> None:
                for ep in it:
                    try:
                        _, w = await asyncio.wait_for(asyncio.open_connection(*ep), st["probe_timeout"])
                        w.close()
                        c["tcp_open"] += 1
                        for k in by_ep[ep]:
                            queue.put_nowait(k)
                    except Exception as e:  # noqa: BLE001
                        fail(pt.tcp_reason(e), len(by_ep[ep]))
                        c["checked"] += len(by_ep[ep])
                    c["tcp_done"] += 1

            await asyncio.gather(*(probe_worker() for _ in range(min(st["probe_concurrency"], 800))))
        else:
            for k in keys:
                queue.put_nowait(k)
        for _ in workers:
            queue.put_nowait(None)
        await asyncio.gather(*workers)
    except asyncio.CancelledError:
        final = "stopped"
    except Exception as e:  # noqa: BLE001
        sess.message = f"{type(e).__name__}: {e}"
        final = "error"
    finally:
        for t in workers:
            t.cancel()
        sess.t_end = time.time()
        sess.phase = final


# --------------------------------------------------------------------------- helpers

def find_row(state: State, key: str) -> pt.Result | None:
    """A proxy by its URL key (proto://host:port): this scan first, then the last site check, then the pool."""
    if state.job and key in state.job.by_url:
        return state.job.by_url[key]
    if state.target and key in state.target.by_url:
        return state.target.by_url[key]
    entry = state.pool.items.get(key)
    return pool_mod.to_result(entry) if entry else None


def bad(msg: str, status: int = 400) -> web.Response:
    return web.json_response({"error": msg}, status=status)


def result_dict(r: pt.Result) -> dict:
    return {**r.as_dict(), "url": r.url}


def save_dir(state: State) -> Path:
    return exports.resolve_dir(state.settings["save"]["dir"], HERE)


def saved_file_path(app: web.Application, name: str | None) -> Path:
    if not name or Path(name).name != name or Path(name).suffix.lower() not in SAVE_SUFFIXES:
        raise ValueError("invalid file name")
    path = save_dir(app[STATE_KEY]) / name
    if not path.is_file():
        raise ValueError("file not found")
    return path


def source_rows(state: State) -> list[dict]:
    return [{"proto": p, "url": u, "label": None, "kind": "source", "status": "pending", "count": 0, "working": 0,
             "error": ""} for p, u in pt.load_sources(state.sources_path)]


def resolve_rows(state: State, urls: list[str]) -> list[pt.Result]:
    """Turn the proxy URLs the page shows back into full Result objects (this scan first, then the pool)."""
    return [r for r in (find_row(state, u) for u in urls) if r is not None]


PROXY_LINE_RE = re.compile(r"https?://(?:[^/@\s]+@)?\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?:\d{1,5}/?")


def split_import(text: str) -> tuple[str, list[str]]:
    """Pasted text may mix proxies (1.2.3.4:80, http://1.2.3.4:80, user:pass@...) with links to lists
    (https://example.com/proxies.txt). A line that is just a web address and not a proxy is a link to download."""
    proxy_lines, urls = [], []
    for line in text.splitlines():
        t = line.strip()
        if re.fullmatch(r"https?://\S+", t, re.I) and not PROXY_LINE_RE.fullmatch(t):
            if t not in urls and len(urls) < 50:
                urls.append(t)
        else:
            proxy_lines.append(line)
    return "\n".join(proxy_lines), urls


def split_csv(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def pool_filters(q) -> dict:
    def num(key, cast=int):
        try:
            return cast(q[key]) if key in q else None
        except ValueError:
            return None
    return {"type": q.get("type"), "country": split_csv(q.get("country")), "anonymity": split_csv(q.get("anonymity")),
            "max_latency": num("max_latency"), "min_speed": num("min_speed", float), "max_fails": num("max_fails"),
            "https_only": q.get("https") in ("1", "true", "yes")}


# --------------------------------------------------------------------------- HTTP handlers

async def index(request: web.Request) -> web.Response:
    return web.Response(body=INDEX.read_bytes(), content_type="text/html", charset="utf-8",
                        headers={"Cache-Control": "no-store"})


async def init(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    return web.json_response({
        "settings": s.settings, "sources": source_rows(s), "protocols": list(pt.PROTOCOLS),
        "presets": [{"id": k, "label": v[0], "url": v[1]} for k, v in pt.EXTRA_PRESETS.items()],
        "formats": {k: v[0] for k, v in exports.FORMATS.items()}, "sorts": exports.SORT_PRESETS,
        "anon_levels": list(exports.ANON_RANK), "custom": config.load_custom(), "history": config.load_history()[:40],
        "fail_labels": {k: {"label": v[0], "tip": v[1]} for k, v in pt.FAIL_LABELS.items()},
        "save_dir": str(save_dir(s)), "cache_size": len(s.cache), "windows": gw.os.name == "nt",
        "pool": s.pool.stats(), "geo": s.geo.status(),
        "version": __version__,
        "author": {"name": paths.AUTHOR, "telegram": paths.TELEGRAM, "github": paths.GITHUB}})


async def post_settings(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    s.settings = config.sanitize(await request.json(), s.settings)
    config.save_settings(s.settings)
    return web.json_response({"settings": s.settings, "save_dir": str(save_dir(s))})


async def start(request: web.Request) -> web.Response:
    app, s = request.app, request.app[STATE_KEY]
    if s.job and s.job.active:
        return bad("a job is already running", 409)
    body = await request.json() if request.can_read_body else {}
    file_name, kind, import_data = body.get("file"), "scan", None
    if isinstance(body.get("import"), dict):
        imp = body["import"]
        raw_docs = [("Your pasted list", str(imp.get("text") or ""))]
        raw_docs += [(f"file: {str(d.get('name') or 'file')[:80]}", str(d.get("text") or ""))
                     for d in (imp.get("docs") or [])[:50] if isinstance(d, dict)]
        if sum(len(t) for _, t in raw_docs) > 20_000_000:
            return bad("that is more than 20 MB of text; split it into smaller files")
        docs, urls = [], []
        for label, text in raw_docs:             # each file stays its own document (a JSON file must stay valid JSON)
            proxy_text, links = split_import(text)
            urls += [u for u in links if u not in urls]
            if proxy_text.strip():
                docs.append((label, proxy_text))
        if not docs and not urls:
            return bad("paste some proxies or links to lists first, or load a file")
        proto = imp.get("proto") if imp.get("proto") in ("all", *pt.SCHEME_ALIASES) else "all"
        kind, import_data = "import", {"docs": docs, "urls": urls[:50], "proto": proto}
    elif body.get("pool"):
        if not len(s.pool):
            return bad("the pool is empty, run a scan first")
        kind = "pool"
    elif file_name:
        kind = "file"
        try:
            saved_file_path(app, file_name)
        except ValueError as e:
            return bad(str(e))
    elif kind == "import":
        pass
    else:
        disabled = set(s.settings["disabled_sources"])
        has_source = any(u not in disabled for _, u in pt.load_sources(s.sources_path))
        has_custom = s.settings["include_custom"] and config.load_custom().strip()
        if not has_source and not has_custom:
            return bad("enable at least one source (or add a custom list)")
    if kind == "scan" and not s.settings["protocols"]:
        return bad("pick at least one protocol")
    job = start_job(app, kind, file_name, import_data=import_data)
    return web.json_response({"ok": True, "job": job.id})


async def stop(request: web.Request) -> web.Response:
    job = request.app[STATE_KEY].job
    if job and job.active and job.task:
        job.task.cancel()
    return web.json_response({"ok": True})


async def events(request: web.Request) -> web.StreamResponse:
    s: State = request.app[STATE_KEY]
    resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-store",
                                       "X-Accel-Buffering": "no"})
    await resp.prepare(request)
    seen_job, cursor = None, 0
    try:
        while True:
            job = s.job
            extra = {"gw": s.gateway.status(), "next_auto": s.next_auto, "next_what": s.next_what,
                     "cache_size": len(s.cache), "pool": s.pool.stats(), "geo": s.geo.status()}
            if job is None:
                payload = {"job": None, "phase": "idle", "new": [], "reset": False, "total": 0, **extra}
            else:
                reset = job.id != seen_job
                if reset:
                    seen_job, cursor = job.id, 0
                batch = job.results[cursor:]
                cursor += len(batch)
                payload = {**job.snapshot(), "new": [result_dict(r) for r in batch], "reset": reset,
                           "total": len(job.results), **extra}
            await resp.write(f"data: {json.dumps(payload)}\n\n".encode())
            await asyncio.sleep(0.3)
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    return resp


async def export(request: web.Request) -> web.Response:
    """Render the proxies the page is currently showing (sent as a list of URLs) in the requested format."""
    s: State = request.app[STATE_KEY]
    body = await request.json()
    fmt = body.get("fmt", "url")
    if fmt not in exports.FORMATS:
        return bad("unknown format")
    rows = resolve_rows(s, body.get("urls", []))
    try:
        text = exports.render(rows, fmt, template=str(body.get("template") or "{proto}://{host}:{port}"),
                              user=str(body.get("user") or ""), pw=str(body.get("pass") or ""))
    except (ValueError, KeyError, IndexError) as e:
        return bad(f"template error: {e}")
    ext = exports.FORMATS[fmt][1]
    return web.Response(text=text, content_type="text/plain", charset="utf-8",
                        headers={"Content-Disposition": f'attachment; filename="proxies.{ext}"'})


async def save_now(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    body = await request.json() if request.can_read_body else {}
    cfg = copy.deepcopy(s.settings["save"])
    if body.get("urls") is not None:      # "save what I see": explicit rows, so skip the saved filters
        rows, cfg["filters"] = resolve_rows(s, body["urls"]), {}
    elif s.job and s.job.results:
        rows = s.job.results
    else:
        rows = [pool_mod.to_result(e) for e in s.pool.items.values()]
    if not rows:
        return bad("nothing to save yet")
    try:
        files = exports.save_files(rows, cfg, HERE)
    except (OSError, ValueError, KeyError, IndexError) as e:
        return bad(f"could not save: {e}", 500)
    if not files:
        return bad("no proxies match the save filters")
    return web.json_response({"files": [str(p) for p in files], "dir": str(save_dir(s))})


_COUNT_CACHE: dict[tuple, int] = {}


def _count_file(p: Path, size: int, mtime: float) -> int:
    key = (str(p), size, mtime)
    if key not in _COUNT_CACHE:
        found = pt.parse_proxies(p.read_text(encoding="utf-8", errors="ignore"), "all")
        _COUNT_CACHE[key] = len({(h, port) for _, h, port in found})
    return _COUNT_CACHE[key]


async def list_saves(request: web.Request) -> web.Response:
    d = save_dir(request.app[STATE_KEY])
    files = []
    if d.is_dir():
        for p in sorted((x for x in d.iterdir() if x.is_file() and x.suffix.lower() in SAVE_SUFFIXES),
                        key=lambda x: x.stat().st_mtime, reverse=True)[:200]:
            stat = p.stat()
            count = 0
            if stat.st_size < 8_000_000:            # parsed in a thread so a big file cannot freeze the dashboard
                count = await asyncio.to_thread(_count_file, p, stat.st_size, stat.st_mtime)
            files.append({"name": p.name, "size": stat.st_size, "mtime": int(stat.st_mtime), "count": count})
    return web.json_response({"dir": str(d), "files": files})


async def download_save(request: web.Request) -> web.StreamResponse:
    try:
        path = saved_file_path(request.app, request.query.get("name"))
    except ValueError as e:
        return bad(str(e), 404)
    return web.FileResponse(path, headers={"Content-Disposition": f'attachment; filename="{path.name}"'})


async def add_source_route(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    body = await request.json()
    proto, url = str(body.get("proto", "")).lower(), str(body.get("url", "")).strip()
    if proto not in (*pt.SCHEME_ALIASES, "all") or not re.fullmatch(r"https?://\S+", url):
        return bad("need a protocol and an http(s) URL")
    if any(u == url for _, u in pt.load_sources(s.sources_path)):
        return bad("that source is already in the list")
    path: Path = s.sources_path
    text = path.read_text(encoding="utf-8")
    path.write_text(text + ("" if text.endswith("\n") else "\n") + f"{proto} {url}\n", encoding="utf-8")
    return web.json_response({"sources": source_rows(s)})


async def remove_source_route(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    url = str((await request.json()).get("url", "")).strip()
    path: Path = s.sources_path
    kept = [ln for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip().startswith("#") or not ln.strip() or ln.strip().partition(" ")[2].strip() != url]
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return web.json_response({"sources": source_rows(s)})


async def custom_route(request: web.Request) -> web.Response:
    if request.method == "POST":
        config.save_custom(str((await request.json()).get("text", "")))
    text = config.load_custom()
    found = await asyncio.to_thread(pt.parse_proxies, text, "all")
    return web.json_response({"text": text, "count": len({(h, p) for _, h, p in found})})


async def history_route(request: web.Request) -> web.Response:
    return web.json_response({"history": config.load_history()[:40]})


async def clear_cache(request: web.Request) -> web.Response:
    request.app[STATE_KEY].cache.clear()
    return web.json_response({"cache_size": 0})


async def geo_download(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    if not s.geo.library:
        return bad("the 'maxminddb' Python package is not installed (pip install maxminddb)")
    body = await request.json() if request.can_read_body else {}
    kinds = [k for k in body.get("which", ["asn", "city"]) if k in geo_mod.FILES]
    if not s.geo.start_download(kinds):
        return bad("a download is already running", 409)
    return web.json_response({"ok": True})


# ---- the pool: for the dashboard and for your own scripts ----

def pool_rows_json(rows: list[dict], secret: bool) -> list[dict]:
    out = []
    for e in rows:
        d = pool_mod.public_entry(e)
        if secret:
            d["proxy"] = pool_mod.full_url(e)       # includes the proxy's own login, for scripts
        out.append(d)
    return out


async def pool_get(request: web.Request) -> web.Response:
    """One proxy for a script. ?type=socks5|http|socks4|https &country=US,NL &anonymity=elite &max_latency=2000
    &https=1 &strategy=random|best &format=json|text"""
    s: State = request.app[STATE_KEY]
    q = request.query
    e = s.pool.pick(pool_filters(q), "best" if q.get("strategy") == "best" else "random")
    if not e:
        return bad("no proxy in the pool matches", 404)
    if q.get("format") == "text":
        return web.Response(text=pool_mod.full_url(e), content_type="text/plain")
    return web.json_response(pool_rows_json([e], True)[0])


async def pool_all(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    q = request.query
    rows = s.pool.select(pool_filters(q))
    try:
        rows = rows[: int(q["limit"])] if "limit" in q else rows
    except ValueError:
        pass
    if q.get("format") == "text":
        return web.Response(text="\n".join(pool_mod.full_url(e) for e in rows), content_type="text/plain")
    return web.json_response(pool_rows_json(rows, True))


async def pool_count(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    return web.json_response({"count": len(s.pool.select(pool_filters(request.query))), "pool": s.pool.stats()})


async def pool_rows(request: web.Request) -> web.Response:
    """Pool contents for the dashboard table (no logins)."""
    return web.json_response({"rows": pool_rows_json(request.app[STATE_KEY].pool.select({}), False)})


async def pool_delete(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    body = await request.json() if request.can_read_body else {}
    url = str(body.get("proxy") or request.query.get("proxy") or "")
    m = KEY_RE.fullmatch(url)
    key = f"{m[1]}://{m[2]}:{m[3]}" if m else url
    removed = s.pool.remove(key)
    s.pool.save()
    return web.json_response({"removed": removed, "size": len(s.pool)})


async def pool_report(request: web.Request) -> web.Response:
    """A script tells us whether a proxy worked: POST {"proxy": "socks5://1.2.3.4:1080", "ok": false}."""
    s: State = request.app[STATE_KEY]
    body = await request.json()
    m = KEY_RE.fullmatch(str(body.get("proxy") or ""))
    if not m:
        return bad("proxy must look like socks5://1.2.3.4:1080")
    dropped = s.pool.report(f"{m[1]}://{m[2]}:{m[3]}", bool(body.get("ok")), s.settings["pool_max_fails"])
    s.pool.save()
    return web.json_response({"dropped": dropped, "size": len(s.pool)})


async def pool_clear(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    s.pool.items.clear()
    s.pool.dirty = True
    s.pool.save()
    return web.json_response({"size": 0})


# ---- gateway ----

def gateway_callbacks(s: State, auto_refill: bool):
    def on_drop(url: str) -> None:
        s.pool.add_failure(url, s.settings["pool_max_fails"])

    def refill(exclude: set[str]) -> str | None:
        e = s.pool.pick({"https_only": True, "exclude": exclude, "max_fails": 0}, "best")
        return pool_mod.full_url(e) if e else None

    return on_drop, (refill if auto_refill else None)


async def gw_start(request: web.Request) -> web.Response:
    s: State = request.app[STATE_KEY]
    g = s.gateway
    body = await request.json()
    keys = ("port", "mode", "order", "rotate_secs", "rotate_requests", "max_errors", "auto_refill", "bind",
            "auth_user", "auth_pass", "system_proxy")
    gs = config.sanitize({"gateway": {k: body[k] for k in keys if k in body}}, s.settings)["gateway"]
    # the page sends proxy URLs without logins; look the logins (and HTTP-only flags) up on our side
    urls, http_only = [], set()
    for u in [u for u in body.get("urls", []) if isinstance(u, str)][:500]:
        m = KEY_RE.fullmatch(u)
        if not m:
            continue
        row = find_row(s, f"{m[1]}://{m[2]}:{m[3]}")
        full = row.full_url if row else u
        urls.append(full)
        if row is not None and not row.https:
            http_only.add(full)
    auth = (gs["auth_user"], gs["auth_pass"]) if gs["auth_user"] else None
    if gs["system_proxy"] and auth:
        return bad("the Windows system proxy cannot be combined with a gateway password (Windows would prompt for it)")
    on_drop, refill = gateway_callbacks(s, gs["auto_refill"])
    try:
        await g.start(gs["port"], urls, gs["mode"], gs["rotate_secs"], order=gs["order"],
                      rotate_requests=gs["rotate_requests"], max_errors=gs["max_errors"], bind=gs["bind"], auth=auth,
                      refill=refill, on_drop=on_drop, http_only=http_only)
    except ValueError as e:
        return bad(str(e))
    except OSError as e:
        return bad(f"cannot listen on port {gs['port']}: {e.strerror or e}", 409)
    warning = ""
    if gs["system_proxy"]:
        try:
            gw.enable_system_proxy(gs["port"])
            applied = await asyncio.to_thread(gw.verify_system_proxy, gs["port"])
            if applied is False:       # we wrote it, but Windows itself does not see it (sandboxed host)
                gw.restore_system_proxy()
                warning = (f"The gateway is running on 127.0.0.1:{gs['port']}, but Windows did not accept the system "
                           "proxy: this copy of ProxyHive runs inside a sandbox (for example an app's preview pane) "
                           "that redirects registry changes. Start ProxyHive from start-ui.bat or ProxyHive.exe "
                           "instead, or set your browser's HTTP proxy to that address by hand.")
            else:
                g.system_proxy = True
        except Exception as e:  # noqa: BLE001
            warning = f"gateway is running, but the Windows proxy was not set: {e}"
    elif http_only and len(http_only) == len(urls):
        warning = "all selected proxies are HTTP-only: they can serve plain http:// sites but not https:// ones"
    s.settings["gateway"] = gs
    config.save_settings(s.settings)
    return web.json_response({"ok": True, "warning": warning, "status": g.status()})


async def gw_stop(request: web.Request) -> web.Response:
    await request.app[STATE_KEY].gateway.stop()
    return web.json_response({"ok": True})


async def gw_test(request: web.Request) -> web.Response:
    """Fetch the trace page through our own gateway to prove the outgoing IP changed."""
    s: State = request.app[STATE_KEY]
    g = s.gateway
    if not g.running:
        return bad("gateway is not running", 409)
    url = s.settings["test_url"]
    own = await pt.get_own_ip(url, 10)
    t0 = time.perf_counter()
    kw = {"username": g.auth[0], "password": g.auth[1]} if g.auth else {}
    try:
        connector = ProxyConnector(proxy_type=ProxyType.HTTP, host="127.0.0.1", port=g.port, **kw)
        async with aiohttp.ClientSession(connector=connector, headers=pt.HEADERS,
                                         timeout=aiohttp.ClientTimeout(total=20)) as sess:
            async with sess.get(url) as r:
                info = pt.parse_trace(await r.text(errors="ignore"))
    except Exception as e:  # noqa: BLE001
        return bad(f"request through the gateway failed: {type(e).__name__}: {e}", 502)
    ip = info.get("ip", "")
    if not pt.IP_RE.fullmatch(ip):
        return bad("the test page did not return an IP", 502)
    country = info.get("loc", "??").upper()
    return web.json_response({"ip": ip, "country": country if re.fullmatch(r"[A-Z]{2}", country) else "??",
                              "own_ip": own, "changed": own is not None and own != ip,
                              "ms": int((time.perf_counter() - t0) * 1000), "upstream": g.current})


# ---- site check ----

async def target_start(request: web.Request) -> web.Response:
    app, s = request.app, request.app[STATE_KEY]
    body = await request.json()
    url = normalize_url(body.get("url"))
    if not url:
        return bad("type a web address such as https://example.com/page")
    keys = ("source", "contains", "expect", "timeout", "concurrency", "limit")
    cfg = config.sanitize({"target": {k: body[k] for k in keys if k in body}}, s.settings)["target"]
    cfg["url"] = url
    if cfg["source"] == "pool" and not len(s.pool):
        return bad("the saved pool is empty. Run a scan first, or choose 'Fresh from sources'")
    if cfg["source"] == "scan" and not (s.job and s.job.results):
        return bad("there are no scan results yet. Run a scan first, or choose the saved pool")
    if s.target and s.target.active and s.target.task:     # a new check replaces the one in progress
        s.target.task.cancel()
        await asyncio.wait([s.target.task], timeout=3)
    s.settings["target"] = cfg
    config.save_settings(s.settings)
    sess = TargetSession(url, cfg["source"], cfg)
    s.target = sess
    sess.task = asyncio.create_task(run_target(app, sess))
    return web.json_response({"ok": True, "id": sess.id, "url": url})


async def target_status(request: web.Request) -> web.Response:
    sess = request.app[STATE_KEY].target
    if sess is None:
        return web.json_response({"phase": "idle"})
    try:
        since = max(0, int(request.query.get("since", 0)))
    except ValueError:
        since = 0
    if request.query.get("id") not in (None, str(sess.id)):      # the page is following an older session
        since = 0
    return web.json_response(sess.snapshot(since))


async def target_stop(request: web.Request) -> web.Response:
    sess = request.app[STATE_KEY].target
    if sess and sess.active and sess.task:
        sess.task.cancel()
    return web.json_response({"ok": True})


@web.middleware
async def same_origin_only(request: web.Request, handler):
    """The server only listens on localhost, but block other websites from driving it via the browser."""
    origin = request.headers.get("Origin")
    if origin and origin.split("://", 1)[-1] != request.host:
        raise web.HTTPForbidden(text="cross-origin request blocked")
    return await handler(request)


async def on_startup(app: web.Application) -> None:
    asyncio.get_running_loop().set_exception_handler(pt.quiet_connection_resets)
    app[STATE_KEY].scheduler = asyncio.create_task(scheduler(app))


async def on_cleanup(app: web.Application) -> None:
    s: State = app[STATE_KEY]
    if s.scheduler:
        s.scheduler.cancel()
    if s.job and s.job.active and s.job.task:
        s.job.task.cancel()
        await asyncio.wait([s.job.task], timeout=5)
    await s.gateway.stop()
    try:
        s.pool.save()
    except OSError:
        pass


def make_app(sources_path: Path, out: Path | None = None) -> web.Application:
    app = web.Application(middlewares=[same_origin_only])
    state = State(sources_path)
    if out is not None:
        state.settings["save"]["dir"] = str(out)
    app[STATE_KEY] = state
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.add_routes([
        web.get("/", index), web.get("/api/init", init), web.get("/api/events", events),
        web.post("/api/settings", post_settings), web.post("/api/start", start), web.post("/api/stop", stop),
        web.post("/api/export", export), web.post("/api/save", save_now),
        web.get("/api/saves", list_saves), web.get("/api/saves/download", download_save),
        web.post("/api/sources/add", add_source_route), web.post("/api/sources/remove", remove_source_route),
        web.get("/api/custom", custom_route), web.post("/api/custom", custom_route),
        web.get("/api/history", history_route), web.post("/api/cache/clear", clear_cache),
        web.post("/api/geo/download", geo_download),
        web.get("/api/pool/get", pool_get), web.get("/api/pool/all", pool_all), web.get("/api/pool/count", pool_count),
        web.get("/api/pool/rows", pool_rows), web.post("/api/pool/delete", pool_delete),
        web.post("/api/pool/report", pool_report), web.post("/api/pool/clear", pool_clear),
        web.post("/api/gateway/start", gw_start), web.post("/api/gateway/stop", gw_stop),
        web.post("/api/gateway/test", gw_test),
        web.post("/api/target/start", target_start), web.get("/api/target/status", target_status),
        web.post("/api/target/stop", target_stop),
    ])
    return app


class BackgroundServer:
    """The dashboard server running in its own thread, for the desktop window (which needs the main thread)."""

    def __init__(self, loop: asyncio.AbstractEventLoop, runner: web.AppRunner, port: int, thread):
        self.loop, self.runner, self.port, self.thread = loop, runner, port, thread


def start_background(port: int = 8765, sources_path: Path | None = None, out: Path | None = None) -> BackgroundServer:
    """Start the dashboard on 127.0.0.1 in a thread and return once it accepts connections. port=0 picks a free one."""
    import threading
    paths.ensure_default_files()
    if gw.restore_system_proxy():
        print("Restored your Windows proxy settings (a previous session was closed without disconnecting).")
    atexit.register(gw.restore_system_proxy)
    loop = asyncio.new_event_loop()
    ready, box = threading.Event(), {}

    def run() -> None:
        asyncio.set_event_loop(loop)

        async def boot() -> None:
            runner = web.AppRunner(make_app(sources_path or HERE / "sources.txt", out))
            await runner.setup()
            await web.TCPSite(runner, "127.0.0.1", port).start()
            box["runner"], box["port"] = runner, runner.addresses[0][1]

        try:
            loop.run_until_complete(boot())
        except Exception as e:  # noqa: BLE001 - reported to the caller
            box["error"] = e
            ready.set()
            return
        ready.set()
        loop.run_forever()

    thread = threading.Thread(target=run, name="proxyhive-server", daemon=True)
    thread.start()
    if not ready.wait(30) or "error" in box:
        raise RuntimeError(f"the dashboard server did not start: {box.get('error', 'timed out')}")
    return BackgroundServer(loop, box["runner"], box["port"], thread)


def stop_background(bs: BackgroundServer) -> None:
    """Graceful stop: ends a running scan, disconnects the gateway (restoring the Windows proxy), saves the pool."""
    try:
        asyncio.run_coroutine_threadsafe(bs.runner.cleanup(), bs.loop).result(20)
    except Exception:  # noqa: BLE001 - we are quitting anyway
        pass
    bs.loop.call_soon_threadsafe(bs.loop.stop)


def serve(port: int = 8765, sources_path: Path | None = None, out: Path | None = None,
          open_browser: bool = True) -> None:
    paths.ensure_default_files()
    if gw.restore_system_proxy():
        print("Restored your Windows proxy settings (a previous session was closed without disconnecting).")
    atexit.register(gw.restore_system_proxy)
    url = f"http://127.0.0.1:{port}"
    print(paths.banner())
    print(f"Dashboard -> {url}   (Ctrl+C to quit)")
    if open_browser:
        webbrowser.open(url)
    web.run_app(make_app(sources_path or HERE / "sources.txt", out), host="127.0.0.1", port=port, print=None)

