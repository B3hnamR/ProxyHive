"""Parser, anonymity classifier, error classifier and pool scoring."""
import asyncio
import json
import ssl

import aiohttp
from aiohttp import web

from proxyhive import engine as pt
from proxyhive import pool as pool_mod


def test_plain_scheme_auth_and_cidr_forms():
    creds = {}
    txt = ("1.2.3.4:8080\nsocks5://5.6.7.8:1080\nhttp://bob:s3cret@9.9.9.9:3128\nuser2:pw2@8.8.4.4:80\n"
           "10.20.30.0/30:8000\nbad 999.1.1.1:80 and 127.0.0.1:9000\n")
    found = pt.parse_proxies(txt, "http", creds)
    assert found == {("http", "1.2.3.4", 8080), ("socks5", "5.6.7.8", 1080), ("http", "9.9.9.9", 3128),
                     ("http", "8.8.4.4", 80), ("http", "10.20.30.1", 8000), ("http", "10.20.30.2", 8000)}
    assert creds[("http", "9.9.9.9", 3128)] == ("bob", "s3cret") and creds[("http", "8.8.4.4", 80)] == ("user2", "pw2")


def test_cidr_ranges_are_capped_at_slash_16():
    assert len(pt.parse_proxies("1.2.0.0/16:80", "http")) == 65534
    assert pt.parse_proxies("1.2.0.0/15:80", "http") == set()


def test_html_table_with_ip_and_port_in_separate_cells():
    html = ("<table><tr><td>11.11.11.11</td><td>3128</td><td>US</td></tr>"
            "<tr><td> 12.12.12.12 </td>\n<td class='x'> 8080 </td></tr></table>")
    assert pt.parse_proxies(html, "http") == {("http", "11.11.11.11", 3128), ("http", "12.12.12.12", 8080)}


def test_json_records_with_protocols_and_logins():
    doc = json.dumps({"data": [{"ip": "21.21.21.21", "port": "1080", "protocols": ["socks4", "socks5"]},
                               {"ip": "22.22.22.22", "port": 8080, "protocols": ["http"], "username": "u", "password": "p"},
                               {"host": "23.23.23.23", "port": 3128}]})
    creds = {}
    found = pt.parse_proxies(doc, "http", creds)
    assert ("socks4", "21.21.21.21", 1080) in found and ("socks5", "21.21.21.21", 1080) in found
    assert ("http", "23.23.23.23", 3128) in found          # no protocol field: falls back to the source's protocol
    assert creds[("http", "22.22.22.22", 8080)] == ("u", "p")


def test_source_protocol_all_fans_out_but_a_scheme_wins():
    assert {p for p, *_ in pt.parse_proxies("3.3.3.3:99", "all")} == {"http", "socks4", "socks5"}
    assert pt.parse_proxies("socks4://3.3.3.3:99", "all") == {("socks4", "3.3.3.3", 99)}


async def test_a_source_over_the_per_source_limit_is_rejected():
    async def big(request):
        return web.Response(text="\n".join(f"10.0.{i // 250}.{i % 250 + 1}:80" for i in range(500)))
    app = web.Application()
    app.router.add_get("/big", big)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    errors = []
    async with aiohttp.ClientSession() as s:
        _, _, ok = await pt.fetch_source(s, "http", f"http://127.0.0.1:{port}/big", attempts=1, max_proxies=1000)
        _, _, rejected = await pt.fetch_source(s, "http", f"http://127.0.0.1:{port}/big", attempts=1, max_proxies=100,
                                               on_error=lambda u, m: errors.append(m))
    await runner.cleanup()
    assert len(ok) == 500 and rejected == set() and "per-source limit" in errors[0]


def _opts(**kw):
    return pt.CheckOptions(own_ips=frozenset({"9.9.9.9"}), baseline_headers=frozenset({"host", "x-forwarded-for"}), **kw)


def test_anonymity_levels():
    body = lambda h, origin="1.1.1.1": json.dumps({"headers": h, "origin": origin})
    o = _opts()
    assert pt.classify_anonymity(body({"Host": "x", "User-Agent": "u"}), o) == "elite"
    assert pt.classify_anonymity(body({"Host": "x", "Via": "1.1 squid"}), o) == "anonymous"
    assert pt.classify_anonymity(body({"X-Forwarded-For": "1.1.1.1"}), o) == "elite"          # echo server's own header
    assert pt.classify_anonymity(body({"X-Forwarded-For": "9.9.9.9, 1.1.1.1"}), o) == "transparent"
    assert pt.classify_anonymity(body({"Host": "x"}, "9.9.9.9, 1.1.1.1"), o) == "transparent"
    assert pt.classify_anonymity(body({"X-Real-Ip": "19.9.9.99"}), o) == "anonymous"         # not a substring match
    assert pt.classify_anonymity("<html>", o) == "unknown"


def test_errors_map_to_readable_reasons():
    """Messages copied from a real scan: these used to all land in 'other'."""
    from aiohttp_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError
    assert pt.classify_error(asyncio.TimeoutError()) == "timeout"
    assert pt.classify_error(ProxyTimeoutError("x")) == "timeout"
    assert pt.classify_error(ConnectionRefusedError()) == "refused"
    assert pt.classify_error(ProxyConnectionError("x")) == "refused"
    assert pt.classify_error(ProxyError("407 Proxy Authentication Required")) == "proxy_auth"
    assert pt.classify_error(ProxyError("No acceptable authentication methods were offered")) == "proxy_auth"
    assert pt.classify_error(ProxyError("Unexpected SOCKS version number: 72")) == "wrong_protocol"
    assert pt.classify_error(ProxyError("Unexpected reply version: 0X48")) == "wrong_protocol"
    assert pt.classify_error(ProxyError("Invalid proxy response")) == "reset"       # hung up / cut-off reply: can be a flake
    assert pt.classify_error(ProxyError("Request rejected or failed")) == "proxy_rejected"
    assert pt.classify_error(ProxyError("502 Bad Gateway")) == "proxy_rejected"
    assert pt.classify_error(ssl.SSLError("bad cert")) == "tls"
    assert pt.classify_error(aiohttp.ClientOSError(5, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")) == "tls"
    assert pt.classify_error(aiohttp.ClientOSError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number")) == "tls"
    assert pt.classify_error(aiohttp.ClientOSError(64, "The specified network name is no longer available")) == "reset"
    assert pt.classify_error(ConnectionResetError()) == "reset"
    assert pt.classify_error(ValueError("?")) == "other"
    assert pt.tcp_reason(asyncio.TimeoutError()) == "tcp_timeout" and pt.tcp_reason(ConnectionRefusedError()) == "tcp_refused"
    assert pt.tcp_reason(OSError()) == "tcp_unreachable"
    assert set(pt.FAIL_LABELS) >= {"timeout", "refused", "tls", "proxy_rejected", "proxy_auth", "wrong_protocol", "tcp_timeout", "target"}


def test_trace_page_from_a_proxy_is_not_trusted_blindly():
    assert pt._clean_trace({"ip": "<script>", "loc": "NL"}) is None
    assert pt._clean_trace({"ip": "1.2.3.4", "loc": "<b>"}) == ("1.2.3.4", "??")
    assert pt._clean_trace({"ip": "1.2.3.4", "loc": "nl"}) == ("1.2.3.4", "NL")


def test_pool_scoring_recovery_and_filters(tmp_path):
    p = pool_mod.Pool(tmp_path / "pool.json")
    mk = lambda host, proto="socks5", ms=500, cc="US", an="elite", https=True: pt.Result(proto, host, 1080, ms, cc, "9.9.9.9", an, None, https)
    a, b, c = mk("1.1.1.1"), mk("2.2.2.2", ms=900, cc="NL"), mk("3.3.3.3", "http", 300, "US", "anonymous", False)
    p.apply_scan([a, b, c], {a.url, b.url, c.url}, 3)
    for _ in range(3):
        p.apply_scan([a, c], {a.url, b.url, c.url}, 3)
    assert p.items[b.url]["fails"] == 3 and b.url in p.items          # at the limit, still kept
    p.apply_scan([a, c], {a.url, b.url, c.url}, 3)
    assert b.url not in p.items                                      # one more failure drops it
    p.add_failure(c.url, 3); p.add_failure(c.url, 3); p.add_success(c)
    assert p.items[c.url]["fails"] == 1                              # a success forgives one failure
    before = p.items[a.url]["checks"]
    p.apply_scan([], set(), 3)
    assert p.items[a.url]["checks"] == before                        # proxies that were not tested are untouched
    assert [e["url"] for e in p.select({"type": "https"})] == [a.url]
    assert [e["url"] for e in p.select({"type": "http"})] == [c.url]
    p.save()
    assert {e["url"] for e in pool_mod.Pool(tmp_path / "pool.json").select()} == {a.url, c.url}


def test_provider_style_lines_host_port_user_pass_with_a_note_in_braces():
    line = "http://203.0.113.10:9999:acct-pool-country-CA-mode-hold-session-abc123:Pa55word{17 October - residential,mobile - CA}"
    creds = {}
    assert pt.parse_proxies(line, "http", creds) == {("http", "203.0.113.10", 9999)}
    assert creds[("http", "203.0.113.10", 9999)] == ("acct-pool-country-CA-mode-hold-session-abc123", "Pa55word")
    creds = {}
    assert pt.parse_proxies("5.6.7.8:3128:bob:s3cret", "http", creds) == {("http", "5.6.7.8", 3128)}
    assert creds[("http", "5.6.7.8", 3128)] == ("bob", "s3cret")


def test_facts_after_the_port_are_not_mistaken_for_a_login():
    creds = {}
    found = pt.parse_proxies("9.9.9.9:8080:US:elite\n8.8.8.8:80:anon:high\n7.7.7.7:1080:socks5:yes", "http", creds)
    assert len(found) == 3 and creds == {}


def test_when_one_gateway_is_listed_with_several_logins_the_first_is_kept():
    creds = {}
    text = "http://198.51.100.7:9999:user-FR:pw1\nhttp://198.51.100.7:9999:user-RU:pw2"
    assert pt.parse_proxies(text, "http", creds) == {("http", "198.51.100.7", 9999)}
    assert creds[("http", "198.51.100.7", 9999)] == ("user-FR", "pw1")
