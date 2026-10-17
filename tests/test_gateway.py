"""Gateway behaviour against local fake upstream proxies (no internet needed).   pytest tests/"""
import asyncio
import base64

import pytest

from proxyhive import gateway as gw


async def _reply(w, ident):
    body = f"upstream={ident}".encode()
    w.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    await w.drain()


def fake_upstream(ident, kind="good"):
    """good: CONNECT + plain.  silent: accepts then says nothing (fails the tunnel handshake).
    mute: opens the tunnel, then never answers the request.  httponly: plain only, refuses CONNECT."""
    async def handle(r, w):
        try:
            head = await r.readuntil(b"\r\n\r\n")
            if kind == "silent":
                return
            if head.startswith(b"CONNECT"):
                if kind == "httponly":
                    w.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    await w.drain()
                    return
                w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await w.drain()
                await r.readuntil(b"\r\n\r\n")          # the request sent through the tunnel
                if kind == "mute":
                    return
            await _reply(w, ident)
        except Exception:
            pass
        finally:
            w.close()
    return handle


class Env:
    def __init__(self):
        self.servers, self.next = [], 19100

    async def up(self, ident, kind="good"):
        port, self.next = self.next, self.next + 1
        self.servers.append(await asyncio.start_server(fake_upstream(ident, kind), "127.0.0.1", port))
        return f"http://127.0.0.1:{port}"

    def dead(self):
        port, self.next = self.next, self.next + 1
        return f"http://127.0.0.1:{port}"       # nothing listens: connection refused

    async def close(self):
        for s in self.servers:
            s.close()


@pytest.fixture
async def env():
    e = Env()
    yield e
    await e.close()


async def fetch(port, kind="plain", headers=""):
    """Talk to the gateway like a browser. Returns (status line, body)."""
    r, w = await asyncio.open_connection("127.0.0.1", port)
    try:
        if kind == "plain":
            w.write(f"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n{headers}\r\n".encode())
        else:
            w.write(f"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n{headers}\r\n".encode())
            await w.drain()
            first = (await r.readuntil(b"\r\n\r\n")).split(b"\r\n")[0].decode()
            if " 200 " not in first:
                return first, ""
            w.write(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        await w.drain()
        data = await asyncio.wait_for(r.read(), 15)
        head, _, body = data.partition(b"\r\n\r\n")
        return head.split(b"\r\n")[0].decode() if head else "", body.decode()
    finally:
        w.close()


def ident(body):
    return body.split("=")[-1] if body.startswith("upstream=") else None


async def test_round_robin_visits_every_upstream_in_turn(env):
    g, pool = gw.Gateway(), [await env.up("A"), await env.up("B"), await env.up("C")]
    await g.start(19001, pool, "rotate", 0, order="round_robin")
    seen = [ident((await fetch(19001, "plain"))[1]) for _ in range(6)]
    await g.stop()
    assert sorted(seen[:3]) == ["A", "B", "C"] and seen[:3] == seen[3:], seen


async def test_random_order_uses_all_upstreams(env):
    g, pool = gw.Gateway(), [await env.up("A"), await env.up("B"), await env.up("C")]
    await g.start(19002, pool, "rotate", 0, order="random")
    seen = {ident((await fetch(19002, "connect"))[1]) for _ in range(40)}
    await g.stop()
    assert seen == {"A", "B", "C"}


async def test_rotate_every_n_requests_sticks_to_one_upstream(env):
    g, pool = gw.Gateway(), [await env.up("A"), await env.up("B"), await env.up("C")]
    await g.start(19003, pool, "rotate", 0, rotate_requests=3)
    seen = [ident((await fetch(19003, "plain"))[1]) for _ in range(9)]
    await g.stop()
    blocks = [seen[i:i + 3] for i in range(0, 9, 3)]
    assert all(len(set(b)) == 1 for b in blocks) and len({b[0] for b in blocks}) == 3, seen


async def test_single_mode_never_rotates(env):
    g, pool = gw.Gateway(), [await env.up("A"), await env.up("B")]
    await g.start(19004, pool, "single", 0)
    seen = {ident((await fetch(19004, "plain"))[1]) for _ in range(6)}
    await g.stop()
    assert seen == {"A"}


async def test_failing_upstream_is_dropped_and_refilled_from_the_pool(env):
    dropped, spare = [], await env.up("SPARE")
    dead, good = env.dead(), await env.up("A")
    g = gw.Gateway()
    g.cooldown = 0
    await g.start(19005, [dead, good], "rotate", 0, max_errors=2, on_drop=dropped.append,
                  refill=lambda exclude: spare if spare not in exclude else None)
    bodies = [(await fetch(19005, "plain"))[1] for _ in range(8)]      # every request still succeeds
    st = g.status()
    await g.stop()
    assert all(ident(b) in ("A", "SPARE") for b in bodies), bodies
    assert st["removed"] == 1 and st["refilled"] == 1 and dropped == [dead], st
    assert dead not in g.pool and spare in g.pool


async def test_plain_http_request_is_retried_on_another_proxy(env):
    silent, good = await env.up("MUTE", "mute"), await env.up("GOOD")
    g = gw.Gateway()
    await g.start(19006, [good, silent], "rotate", 0, max_errors=0)    # round robin hits the mute one first
    status, body = await fetch(19006, "plain")
    st = g.status()
    await g.stop()
    assert "200" in status and ident(body) == "GOOD" and st["retried"] >= 1, (status, body, st)


async def test_password_is_required_when_set(env):
    g, pool = gw.Gateway(), [await env.up("A")]
    await g.start(19007, pool, "single", 0, auth=("bob", "s3cret"))
    good = "Proxy-Authorization: Basic " + base64.b64encode(b"bob:s3cret").decode() + "\r\n"
    bad = "Proxy-Authorization: Basic " + base64.b64encode(b"bob:wrong").decode() + "\r\n"
    none, wrong, ok = await fetch(19007, "plain"), await fetch(19007, "plain", bad), await fetch(19007, "plain", good)
    ok_tunnel = await fetch(19007, "connect", good)
    await g.stop()
    assert "407" in none[0] and "407" in wrong[0] and "200" in ok[0] and ident(ok_tunnel[1]) == "A"


async def test_listening_on_the_network_requires_a_password(env):
    g = gw.Gateway()
    with pytest.raises(ValueError):
        await g.start(19008, [await env.up("A")], "single", 0, bind="0.0.0.0")
    await g.start(19008, [await env.up("A2")], "single", 0, bind="0.0.0.0", auth=("u", "p"))
    assert g.status()["protected"] and g.status()["bind"] == "0.0.0.0"
    await g.stop()


async def test_http_only_proxy_serves_plain_requests_but_never_tunnels(env):
    ho = await env.up("HO", "httponly")
    g = gw.Gateway()
    await g.start(19009, [ho], "single", 0, http_only={ho})
    plain, tunnel = await fetch(19009, "plain"), await fetch(19009, "connect")
    await g.stop()
    assert ident(plain[1]) == "HO" and "502" in tunnel[0]
    good = await env.up("G")
    ho2 = await env.up("HO2", "httponly")
    await g.start(19010, [ho2, good], "rotate", 0, http_only={ho2})
    seen = {ident((await fetch(19010, "connect"))[1]) for _ in range(6)}
    await g.stop()
    assert seen == {"G"}


async def test_stop_returns_even_with_an_open_tunnel(env):
    g = gw.Gateway()
    await g.start(19011, [await env.up("A")], "single", 0)
    r, w = await asyncio.open_connection("127.0.0.1", 19011)
    w.write(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
    await w.drain()
    await r.readuntil(b"\r\n\r\n")
    await asyncio.wait_for(g.stop(), 5)
    assert not g.running
    w.close()


def test_public_hides_credentials():
    assert gw.public("socks5://bob:pw@1.2.3.4:1080") == "socks5://1.2.3.4:1080"
    assert gw.public("http://1.2.3.4:80") == "http://1.2.3.4:80"
