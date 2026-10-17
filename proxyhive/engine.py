"""proxyhive - scrape public proxy lists, check which ones work, sort by speed.

This file is the engine (scraping + checking) and the terminal front end.
The web dashboard is server.py; run it with `python -m proxyhive --server`.

Check pipeline for every candidate:
  1. TCP connect to ip:port (cheap filter)
  2. HTTPS request through the proxy to a Cloudflare trace page -> latency, exit IP, country
       (an HTTP proxy that refuses HTTPS tunnels but forwards plain HTTP is kept and labelled "HTTP only")
  3. optional extra target URLs that must also load
  4. optional anonymity test (plain-HTTP request to a header-echo page; HTTP proxies only)
  5. optional download speed test

Author: B3hnamR  |  Telegram https://t.me/B3hnamR  |  GitHub https://github.com/B3hnamR
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import random
import re
import ssl
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import aiohttp
from aiohttp_socks import ProxyConnectionError as _AioConnError
from aiohttp_socks import ProxyConnector, ProxyType
from aiohttp_socks import ProxyError as _AioProxyError
from aiohttp_socks import ProxyTimeoutError as _AioTimeoutError
from python_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError

# aiohttp-socks and python-socks each define their own error classes; real requests raise the aiohttp-socks ones
PROXY_TIMEOUT_ERRORS = (ProxyTimeoutError, _AioTimeoutError)
PROXY_CONN_ERRORS = (ProxyConnectionError, _AioConnError)
PROXY_ERRORS = (ProxyError, _AioProxyError)
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from . import exports, paths

console = Console()
HERE = paths.APP_DIR

PROTOCOLS = ("http", "socks4", "socks5")
PROXY_TYPES = {"http": ProxyType.HTTP, "socks4": ProxyType.SOCKS4, "socks5": ProxyType.SOCKS5}
SCHEME_ALIASES = {"http": "http", "https": "http", "socks4": "socks4", "socks4a": "socks4",
                  "socks5": "socks5", "socks5h": "socks5"}
# [scheme://][user:pass@]ip[/cidr]:port[:user:pass]   (the lookarounds stop us matching inside longer numbers).
# The trailing ":user:pass" is the "host:port:user:pass" style many paid providers hand out. Anything after it,
# such as a {note in braces}, is ignored.
PROXY_RE = re.compile(
    r"(?:(?P<scheme>[a-z][a-z0-9]*)://)?"
    r"(?:(?P<user>[^\s:@/<>\"']{1,64}):(?P<pw>[^\s@/<>\"']{0,64})@)?"
    r"(?<![\d.])(?P<host>(?:\d{1,3}\.){3}\d{1,3})(?:/(?P<cidr>\d{1,2}))?:(?P<port>\d{1,5})(?!\d)"
    r"(?::(?P<u2>[^\s:@/{}<>\"']{1,200}):(?P<p2>[^\s:@/{}<>\"']{1,200}))?",
    re.IGNORECASE,
)
# "ip:port:US:elite" style lists add facts after the port, not a login. Without an explicit scheme we only take
# the trailing fields as a login when they do not look like that.
_NOT_A_LOGIN = {"http", "https", "socks4", "socks5", "elite", "anonymous", "transparent", "high", "anon",
                "none", "yes", "no", "true", "false", "unknown"}


def _trailing_login(m: re.Match) -> tuple[str, str] | None:
    user, pw = m["u2"], m["p2"]
    if not user:
        return None
    if m["scheme"]:                       # http://host:port:user:pass is unambiguous
        return user, pw
    if re.fullmatch(r"[A-Za-z]{2}", user) or user.lower() in _NOT_A_LOGIN or pw.lower() in _NOT_A_LOGIN:
        return None
    return user, pw
IP_RE = re.compile(r"[0-9a-fA-F:.]{3,45}")
HTML_CELLS_RE = re.compile(r"\s*</t[dh]\s*>\s*<t[dh][^>]*>\s*", re.IGNORECASE)
HTML_TAG_RE = re.compile(r"<[^>]+>")
MIN_CIDR_PREFIX = 16        # /16 = 65,534 hosts is the largest range we expand
JSON_HOST_KEYS = ("ip", "host", "ip_address", "address", "proxy_address", "hostname")
JSON_PORT_KEYS = ("port", "proxy_port")
JSON_PROTO_KEYS = ("protocols", "protocol", "type", "scheme", "proxy_type", "proxy_protocol")

DEFAULT_TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"
PLAIN_TEST_URL = "http://www.cloudflare.com/cdn-cgi/trace"
DEFAULT_JUDGES = ["http://httpbingo.org/get", "http://httpbin.org/get"]
SPEED_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
HEADERS = {"User-Agent": UA}

# id -> (label, url). A proxy must load every selected target (HTTP status < 400) to count as working.
EXTRA_PRESETS = {
    "google": ("Google", "https://www.google.com/generate_204"),
    "amazon": ("Amazon", "https://www.amazon.com/robots.txt"),
    "youtube": ("YouTube", "https://www.youtube.com/robots.txt"),
    "github": ("GitHub", "https://github.com/robots.txt"),
    "wikipedia": ("Wikipedia", "https://en.wikipedia.org/robots.txt"),
}

# headers a proxy adds that reveal it is a proxy
PROXY_HEADERS = {
    "via", "x-forwarded-for", "x-forwarded", "forwarded", "forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-real-ip", "client-ip", "x-client-ip", "x-proxy-id", "proxy-connection", "x-proxy-connection",
    "x-originating-ip", "x-remote-ip", "x-remote-addr", "x-bluecoat-via", "x-cluster-client-ip", "forwarded-for-ip",
}

# why a check failed: id -> (label, tip shown to the user)
FAIL_LABELS = {
    "tcp_timeout": ("Port timed out", "Nothing answered on the port. Normal for dead proxies; raising the port timeout rarely helps."),
    "tcp_refused": ("Port refused", "The host actively refused the connection (nothing listening)."),
    "tcp_unreachable": ("Host unreachable", "No route to the host or a network error."),
    "timeout": ("Timed out", "The proxy connected but was too slow. If this dominates, try a longer timeout."),
    "refused": ("Refused", "The proxy port closed between the probe and the check."),
    "reset": ("Connection dropped", "The proxy closed the connection mid-request."),
    "proxy_rejected": ("Proxy refused request", "The proxy answered but refused to tunnel the request (blocked or misconfigured)."),
    "proxy_auth": ("Needs a login", "The proxy demands a username and password. Put it in a custom list as user:pass@ip:port to use it."),
    "wrong_protocol": ("Wrong protocol", "The source labelled it SOCKS but it speaks HTTP (or the other way round)."),
    "tls": ("TLS / certificate error", "The proxy tampers with HTTPS (certificate does not verify). Rejected on purpose."),
    "bad_status": ("Bad HTTP status", "The proxy returned an error page instead of the test page."),
    "bad_response": ("Not a valid reply", "The reply was not the expected test page (hijacked or injected content)."),
    "target": ("Extra target failed", "The proxy works, but one of your required target sites did not load through it."),
    "blocked": ("Blocked by the site", "The site answered 401/403/429/503 or a challenge page: it does not accept this proxy's address."),
    "no_match": ("Text not found", "The page loaded, but it did not contain the text you required (often a block or captcha page)."),
    "status": ("Wrong status", "The page answered with a status other than the one you asked for."),
    "too_slow": ("Slower than your limit", "It worked, but slower than the max latency you set, so it was left out."),
    "local_limit": ("Your PC ran out of connections", "Windows ran out of free ports or buffers, so these were not really tested. Lower the parallel counts."),
    "other": ("Other error", "An unclassified network error."),
}
FALLBACK_REASONS = {"proxy_rejected", "bad_status", "reset", "bad_response", "other"}
# failures that are often just a bad moment (flaky free proxy, overloaded link): worth a second chance
RETRY_REASONS = {"timeout", "reset", "proxy_rejected", "bad_status", "other", "local_limit"}
# "this PC ran out of ports/buffers" (WinError 10055/10048, EMFILE, ENOBUFS, EADDRNOTAVAIL): our fault, not the proxy's
LOCAL_LIMIT_ERRNOS = {10055, 10048, 24, 23, 105, 99}


def quiet_connection_resets(loop: asyncio.AbstractEventLoop, context: dict) -> None:
    """Windows' proactor loop prints a traceback whenever a remote host resets a connection.
    With thousands of dead proxies that floods the console, so drop exactly those errors."""
    if isinstance(context.get("exception"), (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return
    loop.default_exception_handler(context)


@dataclass
class Result:
    proto: str
    host: str
    port: int
    latency_ms: int
    country: str
    exit_ip: str
    anonymity: str = "unknown"      # elite | anonymous | transparent | unknown
    speed_mbps: float | None = None
    https: bool = True              # False = forwards plain HTTP only, cannot tunnel HTTPS
    auth: str = ""                  # "user:pass" for proxies that need a login
    city: str = ""
    asn: str = ""
    org: str = ""

    @property
    def url(self) -> str:
        return f"{self.proto}://{self.host}:{self.port}"

    @property
    def full_url(self) -> str:
        """URL including the proxy's own login, if it has one. Never shown in the dashboard."""
        if not self.auth:
            return self.url
        user, _, pw = self.auth.partition(":")
        return f"{self.proto}://{quote(user, safe='')}:{quote(pw, safe='')}@{self.host}:{self.port}"

    @property
    def transparent(self) -> bool:
        return self.anonymity == "transparent"

    def as_dict(self, secret: bool = False) -> dict:
        d = {"proto": self.proto, "host": self.host, "port": self.port, "latency_ms": self.latency_ms,
             "country": self.country, "exit_ip": self.exit_ip, "anonymity": self.anonymity,
             "speed_mbps": self.speed_mbps, "https": self.https, "city": self.city, "asn": self.asn,
             "org": self.org, "has_auth": bool(self.auth)}
        if secret:
            d["auth"] = self.auth
        return d


@dataclass
class CheckOptions:
    url: str = DEFAULT_TEST_URL
    timeout: float = 6
    extra_urls: tuple[str, ...] = ()
    anonymity: bool = False
    speed: bool = False
    speed_bytes: int = 300_000
    speed_timeout: float = 10
    allow_http_only: bool = True
    plain_url: str = PLAIN_TEST_URL
    # filled in by prepare()
    judge_url: str | None = None
    baseline_headers: frozenset = field(default_factory=frozenset)
    own_ips: frozenset = field(default_factory=frozenset)


# --------------------------------------------------------------------------- parsing

def load_sources(path: Path) -> list[tuple[str, str]]:
    sources = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        proto, _, url = line.partition(" ")
        proto = proto.lower()
        if proto not in (*SCHEME_ALIASES, "all") or not url.strip():
            console.print(f"[yellow]skipping bad sources line:[/] {line}")
            continue
        sources.append((proto, url.strip()))
    return sources


def valid_endpoint(host: str, port: int) -> bool:
    """Loopback and 0.x addresses are never real public proxies, so they are rejected (the tests set
    PROXYHIVE_ALLOW_LOOPBACK=1 to use local fake proxies)."""
    if not (0 < port < 65536 and all(int(o) <= 255 for o in host.split("."))):
        return False
    return host.startswith("127.") and os.environ.get("PROXYHIVE_ALLOW_LOOPBACK") == "1" or not host.startswith(("0.", "127."))


def _expand_cidr(host: str, prefix: int) -> list[str]:
    if prefix < MIN_CIDR_PREFIX or prefix > 32:
        return []
    try:
        net = ipaddress.ip_network(f"{host}/{prefix}", strict=False)
    except ValueError:
        return []
    return [str(h) for h in (net.hosts() if prefix < 31 else net)]


def _json_protocols(obj: dict) -> list[str]:
    for key in JSON_PROTO_KEYS:
        val = obj.get(key)
        vals = val if isinstance(val, list) else [val]
        found = [SCHEME_ALIASES[v.lower()] for v in vals if isinstance(v, str) and v.lower() in SCHEME_ALIASES]
        if found:
            return list(dict.fromkeys(found))
    return []


def _walk_json(obj, default_proto: str, found: set, creds: dict, depth: int = 0) -> None:
    """Find records like {"ip": "1.2.3.4", "port": "8080", "protocols": ["socks5"]} anywhere in a JSON document."""
    if depth > 12:
        return
    if isinstance(obj, list):
        for item in obj:
            _walk_json(item, default_proto, found, creds, depth + 1)
    elif isinstance(obj, dict):
        host = next((obj[k] for k in JSON_HOST_KEYS if isinstance(obj.get(k), str)), None)
        port = next((obj[k] for k in JSON_PORT_KEYS if obj.get(k) not in (None, "")), None)
        if host and port is not None and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host.strip()):
            try:
                port_n = int(str(port).strip())
            except ValueError:
                port_n = 0
            host = host.strip()
            if valid_endpoint(host, port_n):
                protos = _json_protocols(obj) or (list(PROTOCOLS) if default_proto == "all" else [SCHEME_ALIASES[default_proto]])
                user = next((obj[k] for k in ("username", "user", "login") if isinstance(obj.get(k), str) and obj[k]), None)
                pw = next((obj[k] for k in ("password", "pass", "pwd") if isinstance(obj.get(k), str)), "")
                for p in protos:
                    found.add((p, host, port_n))
                    if user:
                        creds[(p, host, port_n)] = (user, pw)
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _walk_json(v, default_proto, found, creds, depth + 1)


def _scan_text(text: str, default_proto: str, found: set, creds: dict) -> None:
    for m in PROXY_RE.finditer(text):
        port = int(m["port"])
        hosts = [m["host"]]
        if m["cidr"] is not None:
            hosts = _expand_cidr(m["host"], int(m["cidr"]))
        scheme = SCHEME_ALIASES.get((m["scheme"] or "").lower())
        protos = [scheme] if scheme else (list(PROTOCOLS) if default_proto == "all" else [SCHEME_ALIASES[default_proto]])
        login = (m["user"], m["pw"] or "") if m["user"] else _trailing_login(m)
        for host in hosts:
            if not valid_endpoint(host, port):
                continue
            for p in protos:
                found.add((p, host, port))
                if login:
                    creds.setdefault((p, host, port), login)     # the first login listed for a proxy wins


def parse_proxies(text: str, default_proto: str, creds: dict | None = None) -> set[tuple[str, str, int]]:
    """Return {(proto, host, port)} found in any text, HTML table or JSON document.

    Understands ip:port, scheme://ip:port, user:pass@ip:port, ip/24:port (CIDR ranges up to /16),
    HTML tables with the IP and port in neighbouring cells, and JSON records with ip/port fields.
    proto 'all' with no scheme prefix fans out to every protocol. If `creds` is given it is filled with
    {(proto, host, port): (user, password)} for proxies that carry a login."""
    found: set[tuple[str, str, int]] = set()
    creds = creds if creds is not None else {}
    _scan_text(text, default_proto, found, creds)
    if "</t" in text[:3_000_000].lower():   # HTML table: <td>1.2.3.4</td><td>8080</td>
        _scan_text(HTML_TAG_RE.sub(" ", HTML_CELLS_RE.sub(":", text)), default_proto, found, creds)
    head = text.lstrip()[:1]
    if head in ("[", "{"):
        try:
            _walk_json(json.loads(text), default_proto, found, creds)
        except ValueError:
            pass
    return found


async def fetch_source(session: aiohttp.ClientSession, proto: str, url: str, attempts: int = 2,
                       creds: dict | None = None, max_proxies: int = 0, on_error=None) -> tuple[str, str, set]:
    """Download one source and parse it. `max_proxies` rejects junk lists that are suspiciously huge."""
    def fail(msg: str) -> None:
        console.print(f"[red]  fail[/] {url}  ({msg})", no_wrap=True, overflow="ellipsis", highlight=False)
        if on_error:
            on_error(url, msg)

    for attempt in range(1, attempts + 1):
        try:
            async with session.get(url) as r:
                if r.status != 200:
                    raise aiohttp.ClientError(f"HTTP {r.status}")
                found = await asyncio.to_thread(parse_proxies, await r.text(errors="ignore"), proto, creds)
            if max_proxies and len(found) > max_proxies:
                fail(f"rejected: {len(found):,} proxies is over the per-source limit of {max_proxies:,}")
                return proto, url, set()
            return proto, url, found
        except Exception as e:  # noqa: BLE001 - report and move on
            if attempt == attempts:
                fail(f"{type(e).__name__}: {e}")
    return proto, url, set()


async def scrape(sources: list[tuple[str, str]], max_proxies: int = 0) -> set[tuple[str, str, int]]:
    console.print(f"[bold]Scraping {len(sources)} sources...[/]")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30), headers=HEADERS) as session:
        done = await asyncio.gather(*(fetch_source(session, p, u, max_proxies=max_proxies) for p, u in sources))
    candidates: set[tuple[str, str, int]] = set()
    for proto, url, found in done:
        if found:
            console.print(f"[green]  {len(found):>6}[/] {proto:<6} {url}", no_wrap=True,
                          overflow="ellipsis", highlight=False)
        candidates |= found
    return candidates


# --------------------------------------------------------------------------- checking

class _Fail(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def classify_error(e: BaseException) -> str:
    """Map an exception from a proxied request to one of the FAIL_LABELS ids."""
    msg = str(e).lower()
    if isinstance(e, OSError) and getattr(e, "errno", None) in LOCAL_LIMIT_ERRNOS:
        return "local_limit"
    if isinstance(e, (asyncio.TimeoutError, TimeoutError, aiohttp.ServerTimeoutError, *PROXY_TIMEOUT_ERRORS)):
        return "timeout"
    # TLS problems often arrive wrapped (ClientOSError: [SSL: CERTIFICATE_VERIFY_FAILED] ...)
    if isinstance(e, (ssl.SSLError, aiohttp.ClientSSLError)) or "[ssl:" in msg or "certificate verify" in msg:
        return "tls"
    if isinstance(e, PROXY_CONN_ERRORS) or isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, aiohttp.ClientConnectorError) and isinstance(getattr(e, "os_error", None), ConnectionRefusedError):
        return "refused"
    if isinstance(e, PROXY_ERRORS) or isinstance(e, aiohttp.ClientHttpProxyError):
        if "407" in msg or "authentication" in msg or "auth" in msg:
            return "proxy_auth"
        if "unexpected socks version" in msg or "unexpected reply version" in msg:
            return "wrong_protocol"
        if "invalid proxy response" in msg:      # an empty or cut-off reply: it hung up on us, which can be a flake
            return "reset"
        return "proxy_rejected"
    if isinstance(e, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, asyncio.IncompleteReadError,
                      aiohttp.ServerDisconnectedError, aiohttp.ClientPayloadError)):
        return "reset"
    if isinstance(e, OSError):          # e.g. WinError 64 "network name no longer available"
        return "reset"
    return "other"


def tcp_reason(e: BaseException) -> str:
    if isinstance(e, OSError) and getattr(e, "errno", None) in LOCAL_LIMIT_ERRNOS:
        return "local_limit"
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return "tcp_timeout"
    if isinstance(e, ConnectionRefusedError):
        return "tcp_refused"
    return "tcp_unreachable"


def parse_trace(body: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in body.splitlines() if "=" in line)


def _clean_trace(info: dict[str, str]) -> tuple[str, str] | None:
    # the body comes from an untrusted proxy: accept only an IP-shaped value and a 2-letter country
    exit_ip = info.get("ip", "").strip()
    if not IP_RE.fullmatch(exit_ip):
        return None
    country = info.get("loc", "").strip().upper()
    return exit_ip, country if re.fullmatch(r"[A-Z]{2}", country) else "??"


def _ip_in(ip: str, blob: str) -> bool:
    return re.search(rf"(?<![\d.:]){re.escape(ip)}(?![\d.:])", blob) is not None


def classify_anonymity(body: str, o: CheckOptions) -> str:
    """Read a header-echo page (httpbin style JSON) fetched through an HTTP proxy."""
    try:
        data = json.loads(body)
        raw = data["headers"]
        headers = {k.lower(): (", ".join(v) if isinstance(v, list) else str(v)) for k, v in raw.items()}
    except (ValueError, KeyError, TypeError, AttributeError):
        return "unknown"
    blob = " ".join(headers.values()) + " " + str(data.get("origin", ""))
    if any(_ip_in(ip, blob) for ip in o.own_ips):
        return "transparent"
    # headers the echo server itself would add are in the baseline and do not count
    leaked = [h for h in headers if h in PROXY_HEADERS and h not in o.baseline_headers]
    return "anonymous" if leaked else "elite"


async def judge_anonymity(host: str, port: int, o: CheckOptions, auth: tuple[str, str] | None = None) -> str:
    try:
        async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=o.timeout)) as s:
            # plain http:// through the proxy => the proxy forwards (and may modify) our headers
            async with s.get(o.judge_url, proxy=f"http://{host}:{port}", allow_redirects=False,
                             proxy_auth=aiohttp.BasicAuth(*auth) if auth else None) as r:
                if r.status != 200:
                    return "unknown"
                body = await r.text(errors="ignore")
    except Exception:  # noqa: BLE001
        return "unknown"
    return classify_anonymity(body, o)


async def measure_speed(session: aiohttp.ClientSession, o: CheckOptions) -> float | None:
    """Download a test file through the proxy, return throughput in Mbit/s."""
    got, t1 = 0, time.perf_counter()
    try:
        url = SPEED_URL.format(bytes=o.speed_bytes)
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=o.speed_timeout)) as r:
            if r.status != 200:
                return None
            t1 = time.perf_counter()
            async for chunk in r.content.iter_chunked(16384):
                got += len(chunk)
    except Exception:  # noqa: BLE001 - a slow proxy that times out still tells us its speed so far
        pass
    elapsed = time.perf_counter() - t1
    return round(got * 8 / elapsed / 1e6, 2) if got >= 20_000 and elapsed > 0 else None


async def _plain_check(host: str, port: int, o: CheckOptions, auth: tuple[str, str] | None) -> Result | None:
    """Fallback for HTTP proxies that refuse HTTPS tunnels: forward a plain-HTTP request instead."""
    try:
        async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=o.timeout)) as s:
            t0 = time.perf_counter()
            async with s.get(o.plain_url, proxy=f"http://{host}:{port}", allow_redirects=False,
                             proxy_auth=aiohttp.BasicAuth(*auth) if auth else None) as r:
                if r.status != 200:
                    return None
                info = parse_trace(await r.text(errors="ignore"))
            latency = int((time.perf_counter() - t0) * 1000)
    except Exception:  # noqa: BLE001
        return None
    clean = _clean_trace(info)
    if not clean:
        return None
    exit_ip, country = clean
    if exit_ip in o.own_ips:
        anon = "transparent"
    elif o.anonymity and o.judge_url:
        anon = await judge_anonymity(host, port, o, auth)
    else:
        anon = "unknown"
    return Result("http", host, port, latency, country, exit_ip, anon, None, False,
                  f"{auth[0]}:{auth[1]}" if auth else "")


async def check_detailed(proto: str, host: str, port: int, o: CheckOptions,
                         auth: tuple[str, str] | None = None) -> tuple[Result | None, str]:
    """Check one proxy. Returns (result, reason): reason is 'ok' or a key of FAIL_LABELS."""
    kw = {"username": auth[0], "password": auth[1]} if auth else {}
    connector = ProxyConnector(proxy_type=PROXY_TYPES[proto], host=host, port=port, rdns=True, **kw)
    speed = None
    try:
        async with aiohttp.ClientSession(connector=connector, headers=HEADERS,
                                         timeout=aiohttp.ClientTimeout(total=o.timeout)) as s:
            t0 = time.perf_counter()
            async with s.get(o.url, allow_redirects=False) as r:
                if r.status != 200:
                    raise _Fail("bad_status")
                info = parse_trace(await r.text(errors="ignore"))
            latency = int((time.perf_counter() - t0) * 1000)
            clean = _clean_trace(info)
            if not clean:
                raise _Fail("bad_response")
            for extra in o.extra_urls:
                async with s.get(extra, allow_redirects=False) as r:
                    if r.status >= 400:
                        raise _Fail("target")
                    await r.content.read(1024)
            if o.speed:
                speed = await measure_speed(s, o)
    except _Fail as f:
        reason = f.reason
    except Exception as e:  # noqa: BLE001
        reason = classify_error(e)
    else:
        exit_ip, country = clean
        if exit_ip in o.own_ips:
            anon = "transparent"
        elif proto != "http":
            anon = "elite"  # SOCKS proxies relay bytes and cannot add HTTP headers
        elif o.anonymity and o.judge_url:
            anon = await judge_anonymity(host, port, o, auth)
        else:
            anon = "unknown"
        return Result(proto, host, port, latency, country, exit_ip, anon, speed, True,
                      f"{auth[0]}:{auth[1]}" if auth else ""), "ok"

    if proto == "http" and o.allow_http_only and reason in FALLBACK_REASONS:
        res = await _plain_check(host, port, o, auth)
        if res:
            return res, "ok"
    return None, reason


async def check_one(proto: str, host: str, port: int, o: CheckOptions,
                    auth: tuple[str, str] | None = None) -> Result | None:
    return (await check_detailed(proto, host, port, o, auth))[0]


@dataclass
class TargetOptions:
    """One site to test proxies against (the dashboard's Site check)."""
    url: str
    timeout: float = 10
    expect: str = "ok"          # "ok" = any status below 400, "200" = exactly 200
    contains: str = ""          # text that must appear in the page (case-insensitive)
    max_body: int = 262_144


BLOCK_STATUSES = {401, 403, 407, 429, 451, 503}


async def _read_limited(r: aiohttp.ClientResponse, limit: int) -> bytes:
    body = bytearray()
    async for chunk in r.content.iter_chunked(16384):
        body += chunk
        if len(body) >= limit:
            break
    return bytes(body)


async def _judge_target(r: aiohttp.ClientResponse, o: TargetOptions, t0: float) -> dict:
    status = r.status
    if not (status == 200 if o.expect == "200" else status < 400):
        raise _Fail("blocked" if status in BLOCK_STATUSES else "status" if o.expect == "200" else "bad_status")
    body = await _read_limited(r, o.max_body if o.contains else 2048)
    latency = int((time.perf_counter() - t0) * 1000)
    if o.contains and o.contains.lower() not in body.decode("utf-8", "ignore").lower():
        raise _Fail("no_match")
    return {"status": status, "latency_ms": latency, "size": len(body)}


async def check_target(proto: str, host: str, port: int, o: TargetOptions,
                       auth: tuple[str, str] | None = None) -> tuple[dict | None, str]:
    """Can this proxy load `o.url`? Returns ({status, latency_ms, size}, 'ok') or (None, reason)."""
    kw = {"username": auth[0], "password": auth[1]} if auth else {}
    connector = ProxyConnector(proxy_type=PROXY_TYPES[proto], host=host, port=port, rdns=True, **kw)
    timeout = aiohttp.ClientTimeout(total=o.timeout)
    try:
        async with aiohttp.ClientSession(connector=connector, headers=HEADERS, timeout=timeout) as s:
            t0 = time.perf_counter()
            async with s.get(o.url, allow_redirects=True, max_redirects=3) as r:
                return await _judge_target(r, o, t0), "ok"
    except _Fail as f:
        reason = f.reason
    except aiohttp.TooManyRedirects:
        reason = "bad_status"
    except Exception as e:  # noqa: BLE001
        reason = classify_error(e)
    # HTTP-only proxies cannot tunnel, but can still forward a plain http:// page
    if proto == "http" and o.url.lower().startswith("http://") and reason in FALLBACK_REASONS:
        try:
            async with aiohttp.ClientSession(headers=HEADERS, timeout=timeout) as s:
                t0 = time.perf_counter()
                async with s.get(o.url, proxy=f"http://{host}:{port}", allow_redirects=True, max_redirects=3,
                                 proxy_auth=aiohttp.BasicAuth(*auth) if auth else None) as r:
                    return await _judge_target(r, o, t0), "ok"
        except _Fail as f:
            reason = f.reason
        except Exception:  # noqa: BLE001
            pass
    return None, reason


async def get_own_ip(url: str, timeout: float) -> str | None:
    try:
        async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=timeout)) as s:
            async with s.get(url) as r:
                return parse_trace(await r.text()).get("ip")
    except Exception:  # noqa: BLE001
        return None


async def prepare(o: CheckOptions, judge_urls: list[str]) -> list[str]:
    """Learn our real IP(s) and pick a working anonymity judge. Returns warnings to show the user."""
    warnings, own = [], set()
    ip = await get_own_ip(o.url, max(o.timeout, 8))
    if ip:
        own.add(ip)
    else:
        warnings.append("could not detect your real IP, so transparent proxies may be missed")
    if o.anonymity:
        for ju in judge_urls:
            try:
                async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(ju) as r:
                        data = json.loads(await r.text())
                o.baseline_headers = frozenset(k.lower() for k in data["headers"])
                own.update(IP_RE.findall(str(data.get("origin", ""))))
                o.judge_url = ju
                break
            except Exception:  # noqa: BLE001
                continue
        if not o.judge_url:
            o.anonymity = False
            warnings.append("no anonymity judge reachable, HTTP proxies will be labelled 'unknown'")
    o.own_ips = frozenset(own)
    return warnings


# --------------------------------------------------------------------------- terminal front end

async def run_pool(items, fn, concurrency: int, progress: Progress, task_id) -> None:
    """Run fn(item) over items with a fixed number of workers sharing one iterator."""
    it = iter(items)

    async def worker():
        for item in it:
            await fn(item)
            progress.advance(task_id)

    await asyncio.gather(*(worker() for _ in range(concurrency)))


def make_progress() -> Progress:
    return Progress(TextColumn("[bold]{task.description:<10}"), BarColumn(), MofNCompleteColumn(),
                    TextColumn("{task.fields[extra]}"), TimeElapsedColumn(), TimeRemainingColumn(),
                    console=console)


async def tcp_prefilter(endpoints: list[tuple[str, int]], timeout: float, concurrency: int) -> set[tuple[str, int]]:
    alive: set[tuple[str, int]] = set()

    async def probe(ep):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(*ep), timeout)
            w.close()
            alive.add(ep)
        except Exception:  # noqa: BLE001
            pass

    with make_progress() as progress:
        t = progress.add_task("tcp", total=len(endpoints), extra="")
        task = asyncio.create_task(run_pool(endpoints, probe, concurrency, progress, t))
        while not task.done():
            progress.update(t, extra=f"[green]{len(alive)} open[/]")
            await asyncio.wait({task}, timeout=0.5)
        await task
    return alive


async def check_all(jobs, o: CheckOptions, concurrency: int, results: list[Result],
                    creds: dict | None = None) -> None:
    creds = creds or {}

    async def run(job):
        res = await check_one(*job, o, creds.get(job))
        if res:
            results.append(res)

    with make_progress() as progress:
        t = progress.add_task("check", total=len(jobs), extra="")
        task = asyncio.create_task(run_pool(jobs, run, concurrency, progress, t))
        while not task.done():
            progress.update(t, extra=f"[green]{len(results)} working[/]")
            await asyncio.wait({task}, timeout=0.5)
        await task


def print_summary(results: list[Result], out: Path, top: int) -> None:
    if not results:
        console.print("[red]No working proxies found.[/]")
        return
    table = Table(title=f"Top {min(top, len(results))} of {len(results)} working proxies")
    for col in ("#", "proxy", "ms", "anonymity", "country", "exit ip"):
        table.add_column(col)
    for i, r in enumerate(results[:top], 1):
        table.add_row(str(i), r.url + ("" if r.https else " (HTTP only)"), str(r.latency_ms), r.anonymity,
                      r.country, r.exit_ip)
    console.print(table)
    counts = ", ".join(f"{p}: {sum(r.proto == p for r in results)}" for p in PROTOCOLS)
    console.print(f"[bold]{len(results)} working[/] ({counts})  ->  [cyan]{out.resolve()}[/]")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Scrape public proxy lists, check them, sort by speed.",
                                 epilog=paths.banner())
    ap.add_argument("-s", "--sources", type=Path, default=HERE / "sources.txt", help="sources file")
    ap.add_argument("-i", "--input", type=Path, help="check proxies from this file instead of scraping "
                    "(one ip:port or scheme://ip:port per line; bare ip:port is tried as every protocol)")
    ap.add_argument("-o", "--out", type=Path, default=HERE / "results", help="output directory")
    ap.add_argument("-p", "--protocols", default="http,socks4,socks5", help="comma list to check (default: all)")
    ap.add_argument("-t", "--timeout", type=float, default=6, help="seconds per proxy check (default 6)")
    ap.add_argument("-c", "--concurrency", type=int, default=1000, help="parallel proxy checks (default 1000)")
    ap.add_argument("--connect-timeout", type=float, default=4, help="TCP prefilter timeout (default 4)")
    ap.add_argument("--no-prefilter", action="store_true", help="skip the TCP prefilter")
    ap.add_argument("--url", default=DEFAULT_TEST_URL,
                    help="test URL; must return Cloudflare-trace style key=value text")
    ap.add_argument("--extra-url", action="append", default=[], metavar="URL",
                    help="additional URL that must also load through the proxy (repeatable)")
    ap.add_argument("--anonymity", action="store_true", help="classify HTTP proxies as elite/anonymous/transparent")
    ap.add_argument("--speed", action="store_true", help="measure download speed (slower)")
    ap.add_argument("--no-http-only", action="store_true", help="drop HTTP proxies that cannot tunnel HTTPS")
    ap.add_argument("--max-per-source", type=int, default=150000, help="reject sources with more proxies than this (0 = no limit)")
    ap.add_argument("--sort", choices=exports.SORT_PRESETS, default="latency", help="sort order (default latency)")
    ap.add_argument("--max-latency", type=int, default=0, help="drop proxies slower than this many ms")
    ap.add_argument("--limit", type=int, default=0, help="only check a random sample of N candidates (for testing)")
    ap.add_argument("--top", type=int, default=20, help="rows in the summary table (default 20)")
    ap.add_argument("--ui", action="store_true", help="open the web dashboard instead of running in the terminal")
    ap.add_argument("--port", type=int, default=8765, help="dashboard port (default 8765)")
    ap.add_argument("--no-browser", action="store_true", help="with --ui: do not open a browser tab")
    return ap.parse_args()


async def amain(args: argparse.Namespace, results: list[Result]) -> None:
    asyncio.get_running_loop().set_exception_handler(quiet_connection_resets)
    wanted = {SCHEME_ALIASES.get(p.strip(), p.strip()) for p in args.protocols.split(",")}
    if not wanted <= set(PROTOCOLS):
        sys.exit(f"--protocols must be from: {', '.join(PROTOCOLS)}")

    creds: dict = {}
    if args.input:
        candidates = parse_proxies(args.input.read_text(encoding="utf-8", errors="ignore"), "all", creds)
    else:
        candidates = await scrape(load_sources(args.sources), args.max_per_source)
    jobs = sorted(c for c in candidates if c[0] in wanted)
    console.print(f"[bold]{len(jobs)}[/] unique candidates "
                  f"({len({(h, p) for _, h, p in jobs})} unique ip:port)")
    if args.limit:
        jobs = random.sample(jobs, min(args.limit, len(jobs)))
        console.print(f"sampling {len(jobs)} candidates (--limit)")

    if not args.no_prefilter and jobs:
        endpoints = sorted({(h, p) for _, h, p in jobs})
        alive = await tcp_prefilter(endpoints, args.connect_timeout, 1500)
        jobs = [j for j in jobs if (j[1], j[2]) in alive]
        console.print(f"{len(alive)} endpoints accept TCP -> [bold]{len(jobs)}[/] protocol checks")

    if not jobs:
        return
    opts = CheckOptions(url=args.url, timeout=args.timeout, extra_urls=tuple(args.extra_url),
                        anonymity=args.anonymity, speed=args.speed, allow_http_only=not args.no_http_only)
    for w in await prepare(opts, DEFAULT_JUDGES):
        console.print(f"[yellow]{w}[/]")
    random.shuffle(jobs)
    await check_all(jobs, opts, args.concurrency, results, creds)


def main() -> None:
    paths.ensure_default_files()
    args = parse_args()
    if args.ui:
        from . import server
        server.serve(args.port, args.sources, open_browser=not args.no_browser)
        return
    console.print(f"[dim]{paths.banner()}[/]")
    results: list[Result] = []
    try:
        asyncio.run(amain(args, results))
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted - saving what was found so far[/]")
    if args.max_latency:
        results[:] = [r for r in results if r.latency_ms <= args.max_latency]
    results[:] = exports.sort_results(results, args.sort)
    cfg = {"dir": str(args.out), "formats": ["url", "hostport", "csv", "json"], "filters": {}, "sort": args.sort,
           "split": "protocol", "prefix": "working", "template": "", "user": "", "pass": "", "timestamp": False}
    exports.save_files(results, cfg, HERE)
    print_summary(results, args.out, args.top)
