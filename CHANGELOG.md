# Changelog

All notable changes to ProxyHive. Versions follow [Semantic Versioning](https://semver.org/).

## 1.0.0

First release.

- Desktop app window (Edge WebView2) with ProxyHive icon; portable one-file `ProxyHive.exe` that keeps all data next to itself. Browser mode with `--server`.
- Streaming scan pipeline: scrape, port probe and verify at the same time; second-chance pass; measured default speed settings.
- Checks: HTTPS through the proxy, latency, exit IP and country, anonymity level, optional speed test, HTTP-only fallback, extra target sites.
- Parser for `ip:port`, `scheme://`, `user:pass@host`, `host:port:user:pass`, CIDR ranges, HTML tables and JSON.
- Persistent scored pool with a local API for your own scripts.
- Local gateway: use any proxy (or the pool, with rotation) to change your IP, optionally through the Windows system proxy with safe restore.
- Site check, import of your own proxies, saved files with re-check, scan history, offline city/ASN lookup, in-app Guide.
- Export as lists, proxychains, PAC, CSV, JSON or a custom template.
- Terminal scanner with the same engine.
