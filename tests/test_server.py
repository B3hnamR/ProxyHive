"""End-to-end server tests. A local fake 'internet' (trace page, source list, fake proxies) stands in for the real
one, so a whole scan runs in seconds without network access and without touching your real settings or pool."""
import asyncio
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from proxyhive import config, paths, server
from proxyhive import engine as pt
from proxyhive import pool as pool_mod


# ----------------------------------------------------------------------------- fake internet
class Net:
    """trace page + a source list + three fake HTTP proxies: good (tunnels), httponly (403 on CONNECT), dead."""

    def __init__(self):
        self.runners, self.servers, self.hits, self.flaky_hits = [], [], 0, 0
        self.ports = {}

    async def start(self):
        async def trace(request):
            self.hits += 1       # first hit is our own IP probe, later hits come through a proxy
            ip = "198.51.100.1" if self.hits == 1 else f"203.0.113.{self.hits % 250}"
            return web.Response(text=f"ip={ip}\nloc=NL\n")

        async def flaky_source(request):
            return web.Response(text=f"127.0.0.1:{self.ports['flaky']}")

        async def source(request):
            body = "\n".join(f"127.0.0.1:{self.ports[n]}" for n in ("good", "httponly", "dead"))
            return web.Response(text=body)

        async def page(request):
            return web.Response(text="<html>hello from the target site</html>")

        async def blocked(request):
            return web.Response(status=403, text="access denied")

        async def hop(request):
            raise web.HTTPFound("/page")

        app = web.Application()
        app.router.add_get("/trace", trace)
        app.router.add_get("/source.txt", source)
        app.router.add_get("/flaky.txt", flaky_source)
        app.router.add_get("/page", page)
        app.router.add_get("/blocked", blocked)
        app.router.add_get("/hop", hop)
        runner = web.AppRunner(app)
        await runner.setup()
        self.runners.append(runner)
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        self.http_port = site._server.sockets[0].getsockname()[1]
        for name in ("good", "httponly", "flaky"):
            srv = await asyncio.start_server(self._proxy(name), "127.0.0.1", 0)
            self.servers.append(srv)
            self.ports[name] = srv.sockets[0].getsockname()[1]
        probe = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        self.ports["dead"] = probe.sockets[0].getsockname()[1]
        probe.close()
        await probe.wait_closed()           # nothing listens on this port any more: connection refused
        return self

    def _proxy(self, kind):
        async def pipe(r, w):
            try:
                while data := await r.read(65536):
                    w.write(data)
                    await w.drain()
            except Exception:
                pass
            finally:
                w.close()

        async def handle(r, w):
            try:
                head = await r.readuntil(b"\r\n\r\n")
                if kind == "flaky":
                    self.flaky_hits += 1
                    if self.flaky_hits == 1:          # the very first connection is dropped, later ones work
                        return w.close()
                first = head.split(b"\r\n")[0].decode()
                if first.startswith("CONNECT"):
                    if kind == "httponly":
                        w.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                        await w.drain()
                        return w.close()
                    host, _, port = first.split()[1].rpartition(":")
                    ur, uw = await asyncio.open_connection(host, int(port))
                    w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    await w.drain()
                    await asyncio.gather(pipe(r, uw), pipe(ur, w))
                else:                                           # absolute-URI request: forward it
                    from urllib.parse import urlsplit
                    u = urlsplit(first.split()[1])
                    ur, uw = await asyncio.open_connection(u.hostname, u.port or 80)
                    uw.write(f"GET {u.path} HTTP/1.1\r\nHost: {u.hostname}\r\nConnection: close\r\n\r\n".encode())
                    await uw.drain()
                    await pipe(ur, w)
            except Exception:
                w.close()
        return handle

    async def close(self):
        for s in self.servers:
            s.close()
        for r in self.runners:
            await r.cleanup()


@pytest.fixture
async def srv(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXYHIVE_ALLOW_LOOPBACK", "1")
    for name in ("SETTINGS_FILE", "CACHE_FILE", "HISTORY_FILE", "CUSTOM_FILE"):
        monkeypatch.setattr(config, name, tmp_path / f"{name.lower()}.json")
    monkeypatch.setattr(paths, "APP_DIR", tmp_path)
    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(server, "HERE", tmp_path)
    net = await Net().start()
    (tmp_path / "sources.txt").write_text(f"http http://127.0.0.1:{net.http_port}/source.txt\n", encoding="utf-8")
    app = server.make_app(tmp_path / "sources.txt")
    client = TestClient(TestServer(app))
    await client.start_server()
    state = app[server.STATE_KEY]
    state.settings.update(test_url=f"http://127.0.0.1:{net.http_port}/trace", timeout=5, concurrency=10,
                          probe_concurrency=10, anonymity=False, geo_enrich=False, auto_save=False,
                          protocols=["http"], prefilter=True)
    yield client, state, net, tmp_path
    await client.close()
    await net.close()


async def wait_done(state, timeout=40):
    for _ in range(timeout * 10):
        if state.job and not state.job.active:
            return state.job
        await asyncio.sleep(0.1)
    raise AssertionError("job did not finish")


# ----------------------------------------------------------------------------- tests
async def test_scan_finds_good_and_http_only_and_explains_the_dead_one(srv):
    client, state, net, tmp = srv
    r = await client.post("/api/start", json={})
    assert r.status == 200, await r.text()
    job = await wait_done(state)
    assert job.phase == "done", job.message
    by = {x.port: x for x in job.results}
    good, ho = by[net.ports["good"]], by[net.ports["httponly"]]
    assert good.https is True and good.country == "NL"
    assert ho.https is False, "an HTTP proxy that refuses CONNECT must be kept and labelled HTTP-only"
    assert net.ports["dead"] not in by
    assert job.fails.get("tcp_refused") == 1, job.fails          # the failure reason is recorded
    assert job.counts["candidates"] == 3 and job.counts["tcp_open"] == 2


async def test_scan_results_survive_a_restart_through_the_pool(srv):
    client, state, net, tmp = srv
    await client.post("/api/start", json={})
    await wait_done(state)
    assert len(state.pool) == 2 and (tmp / "pool.json").exists()
    reloaded = pool_mod.Pool(tmp / "pool.json")
    assert {e["host"] for e in reloaded.items.values()} == {"127.0.0.1"}
    assert sorted(e["https"] for e in reloaded.items.values()) == [False, True]


async def test_pool_recheck_penalises_a_proxy_that_died_and_drops_it_eventually(srv):
    client, state, net, tmp = srv
    await client.post("/api/start", json={})
    await wait_done(state)
    good_url = f"http://127.0.0.1:{net.ports['good']}"
    state.pool.items[good_url]["auth"] = ""
    net.servers[0].close()                                          # the good proxy goes away
    await net.servers[0].wait_closed()
    state.settings["pool_max_fails"] = 2
    for expected in (1, 2):
        r = await client.post("/api/start", json={"pool": True})
        assert r.status == 200, await r.text()
        await wait_done(state)
        assert state.pool.items[good_url]["fails"] == expected
    await client.post("/api/start", json={"pool": True})
    await wait_done(state)
    assert good_url not in state.pool.items, "dropped after failing more than pool_max_fails times"


async def test_pool_api_filters_and_scores(srv):
    client, state, net, tmp = srv
    def mk(host, proto, ms, cc, anon, https=True, auth=""):
        return pt.Result(proto, host, 1080, ms, cc, "9.9.9.9", anon, None, https, auth)
    for r in (mk("1.1.1.1", "socks5", 800, "US", "elite"), mk("2.2.2.2", "socks5", 300, "NL", "elite"),
              mk("3.3.3.3", "http", 500, "US", "anonymous", https=False), mk("4.4.4.4", "http", 900, "DE", "elite", True, "u:p w")):
        state.pool.add_success(r)
    j = lambda path: client.get(path)
    assert (await (await j("/api/pool/count")).json())["count"] == 4
    assert (await (await j("/api/pool/count?type=socks5")).json())["count"] == 2
    assert (await (await j("/api/pool/count?type=https")).json())["count"] == 3          # HTTP-only excluded
    assert (await (await j("/api/pool/count?country=us&anonymity=anonymous")).json())["count"] == 1
    best = await (await j("/api/pool/get?type=socks5&strategy=best")).json()
    assert best["proxy"] == "socks5://2.2.2.2:1080" and "auth" not in best
    text = await (await j("/api/pool/get?country=DE&format=text")).text()
    assert text == "http://u:p%20w@4.4.4.4:1080", "scripts get the proxy's own login in the URL"
    assert (await j("/api/pool/get?country=ZZ")).status == 404
    allt = (await (await j("/api/pool/all?format=text&max_latency=600")).text()).split("\n")
    assert sorted(allt) == ["http://3.3.3.3:1080", "socks5://2.2.2.2:1080"]
    # scripts report back; enough failures drop the proxy
    for _ in range(4):
        rep = await (await client.post("/api/pool/report", json={"proxy": "socks5://1.1.1.1:1080", "ok": False})).json()
    assert rep["dropped"] is True and (await (await j("/api/pool/count")).json())["count"] == 3
    rep = await (await client.post("/api/pool/delete", json={"proxy": "http://3.3.3.3:1080"})).json()
    assert rep["removed"] is True and rep["size"] == 2
    # the dashboard table endpoint never leaks logins
    rows = (await (await j("/api/pool/rows")).json())["rows"]
    assert all("auth" not in r and "proxy" not in r for r in rows) and any(r["has_auth"] for r in rows)


async def test_cross_origin_requests_are_blocked(srv):
    client, *_ = srv
    r = await client.get("/api/pool/count", headers={"Origin": "https://evil.example"})
    assert r.status == 403
    assert (await client.get("/api/pool/count")).status == 200      # scripts (no Origin header) are fine


async def test_gateway_uses_the_proxys_login_but_never_shows_it(srv):
    client, state, net, tmp = srv
    state.pool.add_success(pt.Result("socks5", "5.5.5.5", 1080, 400, "US", "9.9.9.9", "elite", None, True, "bob:s3cret"))
    r = await client.post("/api/gateway/start", json={"urls": ["socks5://5.5.5.5:1080"], "port": 18555})
    body = await r.json()
    assert r.status == 200, body
    assert state.gateway.pool == ["socks5://bob:s3cret@5.5.5.5:1080"]                  # the real login is used
    assert "s3cret" not in json.dumps(state.gateway.status())                           # but never reported
    await client.post("/api/gateway/stop", json={})


async def test_gateway_start_validates_network_binding_and_system_proxy(srv):
    client, state, net, tmp = srv
    url = "socks5://5.5.5.5:1080"
    r = await client.post("/api/gateway/start", json={"urls": [url], "port": 18556, "bind": "0.0.0.0"})
    assert r.status == 400 and "password" in (await r.json())["error"]
    r = await client.post("/api/gateway/start", json={"urls": [url], "port": 18556, "auth_user": "u",
                                                       "auth_pass": "p", "system_proxy": True})
    assert r.status == 400 and "system proxy" in (await r.json())["error"].lower()
    r = await client.post("/api/gateway/start", json={"urls": ["not a proxy"], "port": 18556})
    assert r.status == 400


async def test_export_includes_the_proxys_login_and_new_columns(srv):
    client, state, net, tmp = srv
    state.pool.add_success(pt.Result("http", "6.6.6.6", 8080, 700, "FR", "9.9.9.9", "elite", None, False, "ann:pw",
                                      "Paris", "AS123", "Example Net"))
    r = await client.post("/api/export", json={"urls": ["http://6.6.6.6:8080"], "fmt": "csv"})
    csv_text = await r.text()
    assert "Paris" in csv_text and "AS123" in csv_text and "ann:pw" in csv_text and "False" in csv_text
    r = await client.post("/api/export", json={"urls": ["http://6.6.6.6:8080"], "fmt": "url"})
    assert (await r.text()) == "http://ann:pw@6.6.6.6:8080"


async def test_settings_are_validated_and_persisted(srv):
    client, state, net, tmp = srv
    r = await client.post("/api/settings", json={"timeout": "abc", "concurrency": 999999, "gateway": {"bind": "8.8.8.8"},
                                                  "pool_min_size": 5})
    s = (await r.json())["settings"]
    assert s["concurrency"] == 5000 and s["gateway"]["bind"] == "127.0.0.1" and s["pool_min_size"] == 5
    assert json.loads(config.SETTINGS_FILE.read_text())["pool_min_size"] == 5


async def test_scheduler_runs_a_pool_recheck_when_maintenance_is_on(srv, monkeypatch):
    client, state, net, tmp = srv
    await client.post("/api/start", json={})
    await wait_done(state)
    first = state.job.id
    state.settings.update(pool_enabled=True, pool_recheck_min=1, pool_min_size=1)
    state.last_pool_check = __import__('time').time() - 3600      # last checked an hour ago
    state.settings["pool_recheck_min"] = 1
    real_sleep = asyncio.sleep
    monkeypatch.setattr(server.asyncio, "sleep", lambda s: real_sleep(0.01))
    # the scheduler loop is already running on the real sleep(5); run one iteration by hand instead
    task = asyncio.create_task(server.scheduler(client.app))
    for _ in range(200):
        await asyncio.sleep(0.05)
        if state.job.id != first:
            break
    task.cancel()
    assert state.job.id != first and state.job.kind == "pool"
    await wait_done(state)


# ----------------------------------------------------------------------------- site check
async def wait_target(state, timeout=30):
    for _ in range(timeout * 10):
        if state.target and not state.target.active:
            return state.target
        await asyncio.sleep(0.1)
    raise AssertionError("site check did not finish")


def seed_pool(state, net):
    for name in ("good", "httponly", "dead"):
        state.pool.add_success(pt.Result("http", "127.0.0.1", net.ports[name], 500, "NL", "1.1.1.1", "elite", None,
                                         name != "httponly"))


async def test_site_check_lists_the_proxies_that_can_load_the_page(srv):
    client, state, net, tmp = srv
    seed_pool(state, net)
    url = f"http://127.0.0.1:{net.http_port}/page"
    r = await client.post("/api/target/start", json={"url": url, "source": "pool", "contains": "hello",
                                                      "timeout": 5, "concurrency": 10})
    assert r.status == 200, await r.text()
    sess = await wait_target(state)
    assert sess.phase == "done", sess.message
    ports = {x.port for x in sess.results}
    assert ports == {net.ports["good"], net.ports["httponly"]}, "HTTP-only proxies can still fetch a plain http:// page"
    assert sess.fails == {"refused": 1} or sess.fails.get("refused") == 1, sess.fails
    snap = await (await client.get(f"/api/target/status?id={sess.id}&since=0")).json()
    assert snap["total"] == 2 and all(row["status"] == 200 and row["size"] > 0 for row in snap["rows"])
    later = await (await client.get(f"/api/target/status?id={sess.id}&since=2")).json()
    assert later["rows"] == [], "only rows after `since` are sent"


async def test_site_check_follows_redirects_and_reports_blocks_and_missing_text(srv):
    client, state, net, tmp = srv
    seed_pool(state, net)
    base = f"http://127.0.0.1:{net.http_port}"
    await client.post("/api/target/start", json={"url": base + "/hop", "source": "pool", "timeout": 5})
    assert len((await wait_target(state)).results) == 2                      # /hop redirects to /page
    await client.post("/api/target/start", json={"url": base + "/blocked", "source": "pool", "timeout": 5})
    sess = await wait_target(state)
    assert not sess.results and sess.fails.get("blocked") == 2, sess.fails
    await client.post("/api/target/start", json={"url": base + "/page", "source": "pool", "contains": "zzz-not-there",
                                                  "timeout": 5})
    sess = await wait_target(state)
    assert not sess.results and sess.fails.get("no_match") == 2, sess.fails
    await client.post("/api/target/start", json={"url": base + "/page", "source": "pool", "expect": "200",
                                                  "contains": "HELLO", "timeout": 5})
    assert len((await wait_target(state)).results) == 2, "text match ignores case"


async def test_site_check_skips_http_only_proxies_for_https_sites_and_validates_input(srv):
    client, state, net, tmp = srv
    seed_pool(state, net)
    await client.post("/api/target/start", json={"url": f"https://127.0.0.1:{net.http_port}/", "source": "pool",
                                                      "timeout": 3})
    sess = await wait_target(state)
    assert sess.counts["skipped"] == 1 and sess.counts["candidates"] == 2
    assert (await client.post("/api/target/start", json={"url": "ftp://x.test"})).status == 400
    assert (await client.post("/api/target/start", json={"url": "  "})).status == 400
    assert pool_mod and server.normalize_url("example.com/a?b=1") == "https://example.com/a?b=1"
    assert server.normalize_url("http://x.test") == "http://x.test" and server.normalize_url("javascript:alert(1)") is None
    state.pool.items.clear()
    assert (await client.post("/api/target/start", json={"url": "https://x.test", "source": "pool"})).status == 400
    assert (await client.post("/api/target/start", json={"url": "https://x.test", "source": "scan"})).status == 400


async def test_site_check_from_fresh_sources_and_results_can_be_exported_and_used(srv):
    client, state, net, tmp = srv
    url = f"http://127.0.0.1:{net.http_port}/page"
    r = await client.post("/api/target/start", json={"url": url, "source": "sources", "timeout": 5, "concurrency": 10})
    assert r.status == 200, await r.text()
    sess = await wait_target(state)
    assert sess.phase == "done" and len(sess.results) == 2, (sess.message, sess.fails)
    assert sess.fails.get("tcp_refused") == 1 and sess.counts["tcp_open"] == 2
    row = sess.results[0]
    exp = await client.post("/api/export", json={"urls": [row.url], "fmt": "url"})
    assert (await exp.text()) == row.url, "results of a site check can be exported even if they are not in the pool"
    gw = await client.post("/api/gateway/start", json={"urls": [row.url], "port": 18557})
    assert gw.status == 200, await gw.text()
    await client.post("/api/gateway/stop", json={})


async def test_starting_a_new_site_check_replaces_the_running_one(srv):
    client, state, net, tmp = srv
    seed_pool(state, net)
    r1 = await (await client.post("/api/target/start", json={"url": f"http://127.0.0.1:{net.http_port}/page", "source": "pool"})).json()
    r2 = await (await client.post("/api/target/start", json={"url": f"http://127.0.0.1:{net.http_port}/hop", "source": "pool"})).json()
    assert r1["id"] != r2["id"]
    sess = await wait_target(state)
    assert sess.id == r2["id"] and sess.url.endswith("/hop")
    assert state.settings["target"]["url"].endswith("/hop"), "the last values are remembered"


# ----------------------------------------------------------------------------- concurrency: nothing is lost
async def test_every_candidate_is_counted_exactly_once(srv):
    client, state, net, tmp = srv
    await client.post("/api/start", json={})
    job = await wait_done(state)
    c = job.counts
    assert c["tcp_done"] == c["endpoints"] and c["check_done"] == c["check_total"]
    assert sum(job.fails.values()) + len(job.results) == c["candidates"], (job.fails, len(job.results), c)


async def test_second_chance_pass_recovers_a_proxy_that_failed_once(srv):
    client, state, net, tmp = srv
    (tmp / "sources.txt").write_text(f"http http://127.0.0.1:{net.http_port}/flaky.txt\n", encoding="utf-8")
    state.settings.update(allow_http_only=False, retry_failed=True)
    await client.post("/api/start", json={})
    job = await wait_done(state)
    assert [r.port for r in job.results] == [net.ports["flaky"]], (job.fails, job.message)
    assert job.retry_n == 1 and not job.fails, "its first failure is taken back once it passes"
    assert sum(job.fails.values()) + len(job.results) == job.counts["candidates"]
    # without the second chance the same proxy is (wrongly) lost
    net.flaky_hits = 0
    state.settings.update(retry_failed=False)
    await client.post("/api/start", json={})
    job = await wait_done(state)
    assert job.results == [] and sum(job.fails.values()) == 1


async def test_one_proxy_that_crashes_the_checker_does_not_break_the_scan(srv, monkeypatch):
    client, state, net, tmp = srv
    real = pt.check_detailed

    async def exploding(proto, host, port, o, auth=None):
        if port == net.ports["good"]:
            raise RuntimeError("unexpected bug while checking one proxy")
        return await real(proto, host, port, o, auth)

    monkeypatch.setattr(pt, "check_detailed", exploding)
    await client.post("/api/start", json={})
    job = await wait_done(state)
    assert job.phase == "done", job.message
    assert {r.port for r in job.results} == {net.ports["httponly"]}
    assert job.fails.get("other") == 1, "the crashed check is counted as a failure, and its worker lives on"
    assert sum(job.fails.values()) + len(job.results) == job.counts["candidates"]


def test_running_out_of_local_ports_is_not_blamed_on_the_proxy():
    import aiohttp
    assert pt.classify_error(OSError(10055, "No buffer space available")) == "local_limit"
    assert pt.classify_error(aiohttp.ClientOSError(10048, "address in use")) == "local_limit"
    assert pt.tcp_reason(OSError(10055, "No buffer space")) == "local_limit"
    assert "local_limit" in pt.RETRY_REASONS and "local_limit" in pt.FAIL_LABELS


def test_measured_defaults_and_one_time_migration_of_old_defaults(tmp_path, monkeypatch):
    d = config.DEFAULT_SETTINGS
    assert (d["timeout"], d["concurrency"], d["probe_concurrency"], d["probe_timeout"]) == (10, 400, 300, 3)
    assert d["retry_failed"] is True
    old = tmp_path / "old_settings.json"
    old.write_text(json.dumps({"timeout": 6, "concurrency": 1000, "probe_concurrency": 1500, "probe_timeout": 4,
                               "gateway": {"port": 8081}}), encoding="utf-8")
    monkeypatch.setattr(config, "SETTINGS_FILE", old)
    s = config.load_settings()
    assert (s["timeout"], s["concurrency"], s["probe_concurrency"]) == (10, 400, 300) and s["_v"] == 2
    assert s["gateway"]["port"] == 8081, "everything else the user chose is kept"
    old.write_text(json.dumps({"_v": 2, "concurrency": 123}), encoding="utf-8")
    assert config.load_settings()["concurrency"] == 123, "new-format settings are never overridden"


# ----------------------------------------------------------------------------- import your own proxies
async def test_import_checks_pasted_proxies_and_links_to_lists_in_any_protocol(srv):
    client, state, net, tmp = srv
    state.settings["protocols"] = ["socks5"]        # a scan would drop HTTP proxies; an import must not
    link = f"http://127.0.0.1:{net.http_port}/source.txt"          # a link to a list, not a proxy
    text = f"127.0.0.1:{net.ports['good']}\n{link}\n"
    r = await client.post("/api/start", json={"import": {"text": text, "proto": "http"}})
    assert r.status == 200, await r.text()
    job = await wait_done(state)
    assert job.kind == "import" and job.phase == "done", job.message
    assert {x.port for x in job.results} == {net.ports["good"], net.ports["httponly"]}
    labels = {s["label"] or s["url"]: s["count"] for s in job.sources}
    assert labels["Your pasted list"] == 1 and labels[link] == 3          # list = good, httponly, dead
    assert job.counts["candidates"] == 3, "the proxy that is in both the paste and the list is checked once"
    assert sum(job.fails.values()) + len(job.results) == job.counts["candidates"]


async def test_import_is_checked_even_if_the_dead_cache_remembers_it_failing(srv):
    client, state, net, tmp = srv
    state.settings.update(dead_cache_hours=24, protocols=["http"])
    state.cache.mark_proxy("http", "127.0.0.1", net.ports["good"])
    state.cache.mark_endpoint("127.0.0.1", net.ports["good"])
    await client.post("/api/start", json={"import": {"text": f"127.0.0.1:{net.ports['good']}", "proto": "http"}})
    job = await wait_done(state)
    assert [x.port for x in job.results] == [net.ports["good"]]


async def test_import_with_nothing_usable_is_refused_or_explained(srv):
    client, state, net, tmp = srv
    r = await client.post("/api/start", json={"import": {"text": "   \n  "}})
    assert r.status == 400
    r = await client.post("/api/start", json={"import": {"text": "this is not a list of proxies"}})
    assert r.status == 200
    job = await wait_done(state)
    assert job.counts["candidates"] == 0 and "No proxies were found" in job.message


async def test_import_understands_logins_html_and_json_files_together(srv):
    client, state, net, tmp = srv
    html = "<table><tr><td>127.0.0.1</td><td>%d</td></tr></table>" % net.ports["httponly"]
    js = '{"data":[{"ip":"127.0.0.1","port":"%d","protocols":["http"]}]}' % net.ports["dead"]
    r = await client.post("/api/start", json={"import": {
        "text": "user:pw@127.0.0.1:%d" % net.ports["good"], "proto": "http",
        "docs": [{"name": "table.html", "text": html}, {"name": "list.json", "text": js}]}})
    assert r.status == 200, await r.text()
    job = await wait_done(state)
    assert job.counts["candidates"] == 3 and job.creds[("http", "127.0.0.1", net.ports["good"])] == ("user", "pw")
    assert [s["label"] for s in job.sources] == ["Your pasted list", "file: table.html", "file: list.json"]
