"""Regenerates the pictures in docs/screenshots (used by README.md) from a throw-away demo copy of ProxyHive.

The demo uses made-up proxies from the documentation address ranges (192.0.2.x, 198.51.100.x, 203.0.113.x), so no real
address, login or personal data ever appears in a picture. Nothing in your own data folder is touched.

    pip install playwright pillow        (Microsoft Edge must be installed; no browser download is needed)
    python scripts/make_screenshots.py
"""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "screenshots"
PORT = 8799
NOW = int(time.time())
DOC_NETS = ["192.0.2", "198.51.100", "203.0.113"]
PLACES = [  # country, city, weight
    ("US", "Ashburn", 9), ("DE", "Frankfurt", 7), ("NL", "Amsterdam", 5), ("FR", "Paris", 4), ("GB", "London", 4),
    ("SG", "Singapore", 4), ("JP", "Tokyo", 3), ("BR", "Sao Paulo", 3), ("IN", "Mumbai", 3), ("CA", "Toronto", 3),
    ("PL", "Warsaw", 2), ("TR", "Istanbul", 2), ("ID", "Jakarta", 2), ("AU", "Sydney", 2), ("SE", "Stockholm", 1),
]
ORGS = ["Example Hosting", "Sample Cloud", "Demo Networks", "Placeholder Telecom", "Test-Net Datacenter"]
SOURCES = [("TheSpeedX/PROXY-List", 25), ("monosans/proxy-list", 22), ("proxifly/free-proxy-list", 18),
           ("ProxyScrape API", 14), ("hookzof/socks5_list", 9), ("clarketm/proxy-list", 6)]


def demo_pool(n: int = 140) -> list[dict]:
    rnd = random.Random(7)
    items, seen = [], set()
    weights = [p[2] for p in PLACES]
    while len(items) < n:
        proto = rnd.choices(["http", "socks5", "socks4"], [5, 4, 1])[0]
        host = f"{rnd.choice(DOC_NETS)}.{rnd.randint(2, 250)}"
        port = rnd.choice([80, 443, 1080, 3128, 8080, 8000, 8888, 9999, 4145, 5678, 10808])
        url = f"{proto}://{host}:{port}"
        if url in seen:
            continue
        seen.add(url)
        country, city, _ = rnd.choices(PLACES, weights)[0]
        asn = rnd.choice([64496, 64497, 64500, 64501, 64511])
        anon = "elite" if proto != "http" else rnd.choices(["elite", "anonymous", "transparent"], [6, 3, 1])[0]
        latency = int(rnd.lognormvariate(6.6, 0.55))
        items.append({
            "url": url, "first_seen": NOW - rnd.randint(3600, 86400 * 5), "checks": rnd.randint(3, 9), "fails": rnd.choice([0, 0, 0, 1, 2]),
            "proto": proto, "host": host, "port": port, "latency_ms": max(90, min(latency, 9000)), "country": country, "city": city,
            "asn": f"AS{asn}", "org": rnd.choice(ORGS), "exit_ip": f"{rnd.choice(DOC_NETS)}.{rnd.randint(2, 250)}",
            "anonymity": anon, "speed_mbps": round(rnd.uniform(1.5, 48), 1) if rnd.random() < 0.55 else None,
            "https": not (proto == "http" and rnd.random() < 0.12), "auth": "", "last_ok": NOW - rnd.randint(30, 900), "last_check": NOW - rnd.randint(30, 900),
        })
    return items


def demo_history() -> list[dict]:
    rnd = random.Random(11)
    out = []
    for i in range(5):
        cand = rnd.randint(41_000, 63_000)
        working = rnd.randint(260, 540)
        out.append({
            "id": (NOW - i * 7200) * 1000, "ts": NOW - i * 7200, "duration": rnd.randint(150, 330), "phase": "done", "kind": "scan",
            "counts": {"candidates": cand, "skipped": rnd.randint(0, 3000), "endpoints": cand, "tcp_done": cand, "tcp_open": cand // 7,
                       "check_total": cand // 7, "check_done": cand // 7},
            "working": working, "best_ms": rnd.randint(180, 420),
            "by_proto": {"http": working // 2, "socks4": working // 10, "socks5": working - working // 2 - working // 10},
            "by_anon": {"elite": working * 6 // 10, "anonymous": working * 3 // 10, "transparent": working // 10, "unknown": 0},
            "http_only": rnd.randint(5, 30), "fails": {"connect_timeout": 31_000, "timeout": 5_200, "refused": 3_100},
            "sources": [{"label": s, "proto": "all", "found": f * 400, "working": f * 3} for s, f in SOURCES],
        })
    return out


def make_tour() -> None:
    """An animated tour (docs/screenshots/tour.gif) built from the pictures above."""
    from PIL import Image
    frames = []
    for name in ("results", "results-filtered", "site-check", "sources", "history", "pool-api", "guide"):
        im = Image.open(OUT / f"{name}.png").convert("RGB")
        im = im.resize((1000, round(im.height * 1000 / im.width)), Image.LANCZOS)
        frames.append(im.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
    frames[0].save(OUT / "tour.gif", save_all=True, append_images=frames[1:], duration=2200, loop=0, optimize=True)
    print("saved tour.gif")


def wait_up(url: str, seconds: int = 40) -> None:
    for _ in range(seconds * 4):
        try:
            urllib.request.urlopen(url, timeout=1).read()
            return
        except OSError:
            time.sleep(0.25)
    raise SystemExit("the demo server did not start")


def main() -> None:
    from playwright.sync_api import sync_playwright
    home = Path(tempfile.mkdtemp(prefix="proxyhive_demo_"))
    (home / "pool.json").write_text(json.dumps(demo_pool()), encoding="utf-8")
    (home / "history.json").write_text(json.dumps(demo_history()), encoding="utf-8")
    env = dict(os.environ, PROXYHIVE_HOME=str(home))
    server = subprocess.Popen([sys.executable, str(ROOT / "app.py"), "--server", "--no-browser", "--port", str(PORT)], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT)
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        wait_up(f"http://127.0.0.1:{PORT}/api/init")
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="msedge", headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1280}, device_scale_factor=1.25)
            page.goto(f"http://127.0.0.1:{PORT}/")
            page.wait_for_selector("#vt-win")
            page.click('[data-ds="pool"]')
            page.wait_for_timeout(1200)

            def shot(name: str, tab: str | None = None, wait: int = 700) -> None:
                if tab:
                    page.click(f'[data-tab="{tab}"]')
                page.wait_for_timeout(wait)
                page.screenshot(path=str(OUT / f"{name}.png"))
                print("saved", name)

            shot("results")
            page.fill("#q", "Frankfurt")
            page.wait_for_timeout(500)
            shot("results-filtered")
            page.fill("#q", "")
            shot("site-check", "target")
            shot("sources", "sources")
            shot("history", "history")
            shot("pool-api", "pool")
            shot("guide", "guide")
            browser.close()
        make_tour()
    finally:
        server.terminate()
        try:
            server.wait(10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    main()
