"""Local forwarding proxy: listens on 127.0.0.1 and sends your traffic out through a chosen upstream proxy.

Point a browser/app at 127.0.0.1:<port> (or let the dashboard set the Windows system proxy) and the
sites you visit see the upstream proxy's IP instead of yours.

Speaks HTTP proxy (CONNECT for https, absolute-URI for plain http) to clients; talks HTTP / SOCKS4 / SOCKS5
to upstreams. Features (ideas from mubeng):
  * several upstreams, round-robin or random, switching every connection / N requests / N seconds
  * drops an upstream after N consecutive errors and refills from the proxy pool
  * plain-HTTP GET/HEAD/OPTIONS requests are retried on another proxy if the first gives no answer
  * optional username/password for the people connecting, and an optional LAN bind address
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
import random
import re
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

from python_socks.async_.asyncio import Proxy

from . import paths

BACKUP = str(paths.APP_DIR / ".system_proxy_backup.json")
# A second copy of the "previous Windows proxy settings" marker lives in the user profile. It is the only thing
# ProxyHive writes outside its own folder, and only while the Windows proxy option is on: it lets a copy of the
# program in another folder undo the setting if the first one crashed, so Windows is never left on a dead proxy.
BACKUP_PROFILE = str(Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
                     / "ProxyHive" / "system_proxy_backup.json")
UPSTREAM_RE = re.compile(r"(http|socks4|socks5)://(?:[^\s/@]+@)?(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}")
HOP_BY_HOP = {"proxy-connection", "proxy-authorization", "connection", "keep-alive", "te", "trailers", "upgrade"}
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def public(url: str | None) -> str | None:
    """Strip the login from a proxy URL so it never reaches the dashboard."""
    return re.sub(r"//[^/@]*@", "//", url) if url else url


class Gateway:
    def __init__(self) -> None:
        self.server: asyncio.AbstractServer | None = None
        self.port = 0
        self.bind = "127.0.0.1"
        self.mode = "single"
        self.order = "round_robin"
        self.rotate_secs = 0
        self.rotate_requests = 0
        self.max_errors = 3
        self.cooldown = 10.0          # seconds a failing upstream is skipped before it is tried again
        self.auth: tuple[str, str] | None = None
        self.refill = None            # callable(exclude: set[str]) -> full proxy URL | None
        self.on_drop = None           # callable(public_url) when an upstream is dropped
        self.pool: list[str] = []
        self.http_only: set[str] = set()   # upstreams that cannot tunnel HTTPS (plain HTTP forwarding only)
        self.idx = 0
        self._cur: str | None = None
        self.switched_at = 0.0
        self.served = 0
        self.bad: dict[str, float] = {}
        self.err: dict[str, int] = {}
        self.dropped: set[str] = set()
        self.system_proxy = False
        self.clients: set[asyncio.StreamWriter] = set()   # every open socket, so stop() can cut them
        self.conns = self.active = self.errors = self.up = self.down = 0
        self.removed = self.refilled = self.retried = 0
        self.last_error = ""

    # ----------------------------------------------------------------- lifecycle
    @property
    def running(self) -> bool:
        return self.server is not None

    @property
    def current(self) -> str | None:
        return public(self._cur)

    async def start(self, port: int, pool: list[str], mode: str = "single", rotate_secs: int = 0, *,
                    order: str = "round_robin", rotate_requests: int = 0, max_errors: int = 3,
                    bind: str = "127.0.0.1", auth: tuple[str, str] | None = None,
                    refill=None, on_drop=None, http_only: set[str] | None = None) -> None:
        await self.stop()
        pool = [u for u in dict.fromkeys(pool) if UPSTREAM_RE.fullmatch(u)]
        if not pool:
            raise ValueError("no valid upstream proxies selected")
        if bind not in LOOPBACK and not auth:
            raise ValueError("set a gateway username and password before listening on your network")
        self.server = await asyncio.start_server(self._handle, bind, port)
        self.port, self.bind, self.pool, self.mode, self.order = port, bind, pool, mode, order
        self.rotate_secs, self.rotate_requests, self.max_errors = rotate_secs, rotate_requests, max_errors
        self.auth, self.refill, self.on_drop = auth, refill, on_drop
        self.http_only = set(http_only or ())
        self.idx, self._cur, self.switched_at, self.served = 0, None, 0.0, 0
        self.bad, self.err, self.dropped = {}, {}, set()
        self.conns = self.active = self.errors = self.up = self.down = 0
        self.removed = self.refilled = self.retried = 0
        self.last_error = ""

    async def stop(self) -> None:
        # 1. give the user their normal internet back before anything that could block
        if self.system_proxy:
            try:
                restore_system_proxy()
            finally:
                self.system_proxy = False
        server, self.server = self.server, None
        self._cur = None
        if server:
            server.close()
            # 2. Python 3.12+ wait_closed() waits for every open connection, and browsers keep tunnels
            #    open for minutes, so cut them ourselves instead of waiting.
            for w in list(self.clients):
                w.close()
            try:
                await asyncio.wait_for(server.wait_closed(), 3)
            except asyncio.TimeoutError:
                pass

    def status(self) -> dict:
        return {"running": self.running, "port": self.port, "bind": self.bind, "mode": self.mode,
                "order": self.order, "rotate_secs": self.rotate_secs, "rotate_requests": self.rotate_requests,
                "pool": len(self.pool), "current": self.current or (public(self.pool[0]) if self.pool else None),
                "conns": self.conns, "active": self.active, "errors": self.errors, "up": self.up, "down": self.down,
                "removed": self.removed, "refilled": self.refilled, "retried": self.retried,
                "protected": self.auth is not None, "system_proxy": self.system_proxy,
                "last_error": self.last_error}

    # ----------------------------------------------------------------- upstream choice
    def _usable(self, tried: set[str], tunnel: bool) -> list[str]:
        now = time.time()
        pool = [u for u in self.pool if u not in tried and not (tunnel and u in self.http_only)]
        return [u for u in pool if self.bad.get(u, 0) < now - self.cooldown] or pool

    def _pick(self, tried: set[str], tunnel: bool = True) -> str | None:
        usable = self._usable(tried, tunnel)
        if not usable:
            return None
        if self.mode == "single" or len(self.pool) == 1:
            return usable[0]
        now, cur = time.time(), self._cur
        if cur in usable:
            due = ((self.rotate_secs and now - self.switched_at >= self.rotate_secs)
                   or (self.rotate_requests and self.served >= self.rotate_requests)
                   or (not self.rotate_secs and not self.rotate_requests))
            if not due:
                self.served += 1
                return cur
        others = [u for u in usable if u != cur] or usable
        if self.order == "random":
            nxt = random.choice(others)
        else:
            nxt = others[0]
            for k in range(1, len(self.pool) + 1):
                cand = self.pool[(self.idx + k) % len(self.pool)]
                if cand in others:
                    nxt, self.idx = cand, (self.idx + k) % len(self.pool)
                    break
        self._cur, self.switched_at, self.served = nxt, now, 1
        return nxt

    def _fail(self, url: str) -> None:
        """An upstream failed to connect or answer. After max_errors in a row it is dropped and replaced."""
        self.bad[url] = time.time()
        self.err[url] = self.err.get(url, 0) + 1
        if not self.max_errors or self.err[url] < self.max_errors or url not in self.pool:
            return
        self.pool.remove(url)
        self.dropped.add(public(url))
        self.removed += 1
        if self._cur == url:
            self._cur = None
        if self.on_drop:
            try:
                self.on_drop(public(url))
            except Exception:  # noqa: BLE001
                pass
        if self.refill:
            try:
                new = self.refill({public(u) for u in self.pool} | self.dropped)
            except Exception:  # noqa: BLE001
                new = None
            if new and UPSTREAM_RE.fullmatch(new) and new not in self.pool:
                self.pool.append(new)
                self.refilled += 1

    async def _open_upstream(self, host: str, port: int, tried: set[str], tunnel: bool = True):
        """Connect to host:port through the next upstream. Returns (reader, writer, url, direct).
        direct=True means we are talking straight to an HTTP-only proxy (no tunnel): send it absolute-URI requests."""
        err: Exception | None = None
        for _ in range(3):
            url = self._pick(tried, tunnel)
            if not url:
                break
            tried.add(url)
            try:
                if not tunnel and url in self.http_only:
                    parts = urlsplit(url)
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(parts.hostname, parts.port), 10)
                    direct = True
                else:
                    sock = await Proxy.from_url(url, rdns=True).connect(dest_host=host, dest_port=port, timeout=10)
                    reader, writer = await asyncio.open_connection(sock=sock)
                    direct = False
                self.err[url] = 0
                self.clients.add(writer)
                return reader, writer, url, direct
            except Exception as e:  # noqa: BLE001
                err = e
                self._fail(url)
        self.errors += 1
        self.last_error = f"{type(err).__name__}: {err}" if err else (
            "no HTTPS-capable upstream (all selected proxies are HTTP-only)" if tunnel and self.http_only
            else "no upstream available")
        raise ConnectionError(self.last_error)

    # ----------------------------------------------------------------- client side
    def _authorized(self, lines: list[str]) -> bool:
        if not self.auth:
            return True
        for ln in lines:
            name, _, value = ln.partition(":")
            if name.strip().lower() == "proxy-authorization":
                kind, _, token = value.strip().partition(" ")
                if kind.lower() == "basic":
                    try:
                        user, _, pw = base64.b64decode(token.strip()).decode("utf-8", "replace").partition(":")
                    except ValueError:
                        return False
                    ok_user = hmac.compare_digest(user.encode(), self.auth[0].encode())
                    ok_pw = hmac.compare_digest(pw.encode(), self.auth[1].encode())
                    return ok_user and ok_pw
        return False

    async def _handle(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        self.conns += 1
        self.active += 1
        uw = None
        self.clients.add(cw)
        try:
            head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 20)
            lines = head.decode("latin-1").split("\r\n")
            if not self._authorized(lines):
                cw.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="ProxyHive"\r\n'
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                await cw.drain()
                return
            method, target, version = lines[0].split(" ", 2)
            tried: set[str] = set()
            first = b""
            if method.upper() == "CONNECT":
                host, _, port = target.rpartition(":")
                ur, uw, _, _ = await self._open_upstream(host.strip("[]"), int(port or 443), tried)
                cw.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await cw.drain()
            else:
                u = urlsplit(target)
                if not u.hostname:
                    cw.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    return
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                hdrs = [ln for ln in lines[1:] if ln]
                names = {ln.split(":", 1)[0].strip().lower() for ln in hdrs}
                cl = next((ln.split(":", 1)[1].strip() for ln in hdrs if ln.lower().startswith("content-length:")), "0")
                bodyless = (method.upper() in ("GET", "HEAD", "OPTIONS") and cl in ("0", "")
                            and "transfer-encoding" not in names)
                kept = [ln for ln in hdrs if ln.split(":", 1)[0].strip().lower() not in HOP_BY_HOP]
                request = "\r\n".join([f"{method} {path} {version}", *kept, "Connection: close", "", ""]).encode("latin-1")
                for attempt in range(3 if bodyless else 1):
                    ur, uw, url, direct = await self._open_upstream(u.hostname, u.port or 80, tried, tunnel=False)
                    if direct:   # HTTP-only proxy: it forwards, so give it the absolute URI (and its login)
                        extra = []
                        ps = urlsplit(url)
                        if ps.username:
                            token = base64.b64encode(
                                f"{unquote(ps.username)}:{unquote(ps.password or '')}".encode()).decode()
                            extra = [f"Proxy-Authorization: Basic {token}"]
                        uw.write("\r\n".join([f"{method} {target} {version}", *kept, *extra, "Connection: close",
                                              "", ""]).encode("latin-1"))
                    else:
                        uw.write(request)
                    await uw.drain()
                    if not bodyless:
                        break
                    try:
                        first = await asyncio.wait_for(ur.read(65536), 20)
                    except (ConnectionError, OSError, asyncio.TimeoutError):
                        first = b""
                    if first:
                        break
                    # connected but no answer: blame this upstream and retry the request on another one
                    self._fail(url)
                    self.retried += 1
                    uw.close()
                    self.clients.discard(uw)
                    uw = None
                else:
                    raise ConnectionError("no upstream answered")
                if first:
                    cw.write(first)
                    await cw.drain()
                    self.down += len(first)
            await asyncio.gather(self._pipe(cr, uw, "up"), self._pipe(ur, cw, "down"))
        except (ConnectionError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError,
                asyncio.LimitOverrunError):
            try:
                cw.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await cw.drain()
            except Exception:  # noqa: BLE001
                pass
        finally:
            self.active -= 1
            for w in (uw, cw):
                if w:
                    w.close()
                    self.clients.discard(w)

    async def _pipe(self, r: asyncio.StreamReader, w: asyncio.StreamWriter, direction: str) -> None:
        try:
            while data := await r.read(65536):
                w.write(data)
                await w.drain()
                if direction == "up":
                    self.up += len(data)
                else:
                    self.down += len(data)
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                w.close()
            except Exception:  # noqa: BLE001
                pass


# --------------------------------------------------------------------------- Windows system proxy

_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_NAMES = ("ProxyEnable", "ProxyServer", "ProxyOverride")
_REG_SZ, _REG_DWORD = 1, 4


def _refresh() -> None:
    import ctypes
    wininet = ctypes.windll.Wininet
    wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH


def _read_values() -> dict:
    """The proxy values Windows has right now: {name: [value, type] or None}."""
    import winreg
    out: dict = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_READ) as key:
        for name in _NAMES:
            try:
                out[name] = list(winreg.QueryValueEx(key, name))
            except FileNotFoundError:
                out[name] = None
    return out


def _write_values(values: dict) -> None:
    """Write {name: [value, type] or None}. None deletes the value."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_SET_VALUE) as key:
        for name, old in values.items():
            if old is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, name, 0, old[1], old[0])


def _load_marker() -> dict | None:
    for path in (BACKUP, BACKUP_PROFILE):
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                return data if isinstance(data, dict) else {}
            except (OSError, ValueError):
                return {}
    return None


def _save_marker(data: dict) -> None:
    os.makedirs(os.path.dirname(BACKUP_PROFILE), exist_ok=True)
    wrote = False
    for path in (BACKUP, BACKUP_PROFILE):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            wrote = True
        except OSError:
            pass                    # e.g. the .exe sits on a read-only drive: the other copy is enough
    if not wrote:
        raise RuntimeError("could not save your current proxy settings, so the Windows proxy was not changed")


def _clear_marker() -> None:
    for path in (BACKUP, BACKUP_PROFILE):
        try:
            os.remove(path)
        except OSError:
            pass


def enable_system_proxy(port: int) -> None:
    """Point Windows (and apps that follow it, e.g. Chrome/Edge/Brave) at the local gateway.
    The previous values are saved first, together with the value WE set, so restore_system_proxy() can put
    things back, even after a crash, without ever overwriting a change somebody else made in between."""
    if os.name != "nt":
        raise RuntimeError("setting the system proxy is only supported on Windows")
    ours = f"127.0.0.1:{port}"
    marker = _load_marker()
    if not marker or not isinstance(marker.get("saved"), dict):      # no marker, or an old-format one: fresh snapshot
        marker = {"saved": _read_values()}
    marker["ours"] = ours
    _save_marker(marker)
    _write_values({"ProxyServer": [ours, _REG_SZ], "ProxyOverride": ["localhost;127.*;<local>", _REG_SZ],
                   "ProxyEnable": [1, _REG_DWORD]})
    _refresh()


def restore_system_proxy() -> bool:
    """Undo enable_system_proxy(). Windows is only touched if the proxy is still the one we set. If another
    program (a VPN or proxy app) changed it since, we leave it alone and just forget our marker."""
    marker = _load_marker()
    if os.name != "nt" or marker is None:
        return False
    restored = False
    try:
        saved, ours = marker.get("saved"), marker.get("ours")
        if isinstance(saved, dict) and ours:                          # an old-format marker has no owner: never guess
            current = _read_values().get("ProxyServer")
            if current and current[0] == ours:
                _write_values(saved)
                _refresh()
                restored = True
    finally:
        _clear_marker()
    return restored


def _server_line_has(text: str, port: int) -> bool:
    return f"127.0.0.1:{port}" in text


def verify_system_proxy(port: int) -> bool | None:
    """Did Windows really get the proxy? True/False, or None if we could not find out.

    A process that runs inside a sandbox (for example an app's built-in preview pane) can have its registry
    writes silently redirected to a private copy: it reads back what it wrote, but Windows, the browser and
    Settings never see it. So we ask a process that is NOT our child (started through WMI) what it sees."""
    if os.name != "nt":
        return None
    import subprocess
    import tempfile
    fd, out = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    inner = f'cmd /c reg query "HKCU\\{_KEY}" /v ProxyServer > "{out}" 2>&1'
    script = ("Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments "
              "@{CommandLine='" + inner.replace("'", "''") + "'} | Out-Null")
    try:
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, timeout=25, creationflags=0x08000000)
        for _ in range(40):
            time.sleep(0.2)
            with open(out, encoding="utf-8", errors="ignore") as f:
                text = f.read()
            if "ProxyServer" in text or "ERROR" in text.upper():
                return _server_line_has(text, port)
        return None
    except Exception:  # noqa: BLE001 - no PowerShell/WMI: we simply cannot tell
        return None
    finally:
        try:
            os.remove(out)
        except OSError:
            pass
