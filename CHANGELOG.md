# Changelog

## v0.2 (October 2026)

### Live map
- Camera framed on the home location; arc height follows distance and arcs stay inside the canvas.
- Outbound alerts (internal → external) drawn from home outwards; impact rings only for inbound alerts.
- Traffic arcs grouped per place and direction, brightness by connection count; every country drawn.
- Endpoints panel: full country names, top city, in/out counts, worst severity, *Traffic* section per country.
- Land and sea told apart, bump-mapped relief, glossy sea, city lights, key and rim lighting.
- Ctrl + wheel / pinch zoom, `+` / `−` buttons, re-centre button and double-click; reduced-motion respected.
- Multicast, broadcast and CGNAT addresses no longer treated as public; GeoIP refreshes on the newest alert.
- Traffic arcs redrawn once the scene is ready and on new flows; Live Traffic axis labels fixed.

### Firewall integration (`scripts/snort-blocker.py`)
- Snort priority-1 alerts → OPNsense aliases through `alias_util`: home device to `SNORT_QUARANTINE`, external peer to `SNORT_BLOCK`, 24 h.
- Networks configured through the environment (`HOME_NETS`, `NEVER_BLOCK_NETS`, `GATEWAYS`); Cloudflare, public DNS and Telegram always protected; `PROTECTED_NAMES` for hostnames.
- Hourly limits per list, plus a low separate cap for sessionless (UDP/ICMP) external blocks.
- IPv6 ignored; `IGNORE_SIDS` for known false positives; a block is logged only when the router confirms it.
- Router certificate pinned; `DRY_RUN=1` by default.
- Telegram alerts with an *Unblock* button, 24 h pardon, hourly summary; shared-bot mode with a signed HTTP bridge (HMAC-SHA256, fixed bind and origin, strict Content-Length, 5 s timeout).

### Connection page and trusted devices
- `SV_TRUSTED_NETS`: trusted devices receive the API key from the server; `SV_PROXY_IPS` defines which proxies count when reading `X-Forwarded-For` (fail closed).
- Sensor and router settings shown from the server with an *Edit* button; secrets never stored in the browser or returned by the API.
- Router platforms: OPNsense (REST API, pinned certificate), pfSense (SSH), OpenWrt, Linux; read-only by default.
- OPNsense requests sent over the pinned socket; stored secrets dropped when the target changes; interface names validated.
- Database panel shows the real SQLite store (alerts, retention, oldest alert, size, cap).

### Database and backend
- **Alerts kept for 10 days** (`ALERT_RETENTION_DAYS`), **4,000,000-alert safety cap** (`MAX_ALERTS`); batched pruning until both limits are met.
- Duplicate alerts fixed: replaced SSH tails no longer reconnect; GNU `tail` (`gnutail`) used when present.
- Backend saturation fixed: ISO time windows, new indexes on `action` and `(category, ts)`, cached totals.
- SSH tail drops NUL bytes and caps unterminated lines after `copytruncate`.
- Flows feed starts from the newest rows.
- DB explorer at `/db`; frontend nginx proxies `/api` and `/ws`.

## v0.1 (March 2026)
- First public release: Snort 3 JSON alert ingestion over SSH, SQLite, React dashboard, 3D cyberthreat globe, DDoS mitigation page, rules manager, notifications, router integration.
