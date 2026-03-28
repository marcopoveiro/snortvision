# 🛡️ SnortVision v0.1

<p align="center">
  <b>Real-time Snort 3 monitoring dashboard with a 3D Cyberthreat Globe, live alert ingestion, GeoIP attack mapping, DDoS mitigation, router integration, and full backend API control.</b>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.1-orange?style=for-the-badge">
  <img alt="Status" src="https://img.shields.io/badge/status-active%20development-yellow?style=for-the-badge">
  <img alt="Snort 3" src="https://img.shields.io/badge/Snort-3.x-success?style=for-the-badge">
  <img alt="Three.js" src="https://img.shields.io/badge/3D%20Globe-Three.js-black?style=for-the-badge">
  <img alt="Backend" src="https://img.shields.io/badge/backend-Node.js-339933?style=for-the-badge">
  <img alt="Frontend" src="https://img.shields.io/badge/frontend-React%2018-61DAFB?style=for-the-badge">
  <img alt="Database" src="https://img.shields.io/badge/database-SQLite-003B57?style=for-the-badge">
  <img alt="Docker" src="https://img.shields.io/badge/deployment-Docker-2496ED?style=for-the-badge">
</p>

---

## Overview

**SnortVision** is a visual monitoring and management interface for **Snort 3**, built for homelab SOC operators, network security engineers, and blue teamers who want a cleaner, faster, and more operationally useful view of security events.

It ingests Snort 3 JSON alerts via SSH tail, stores them in SQLite, and presents them through a modern React dashboard featuring a **Three.js 3D cyberthreat globe**, live traffic charts, DDoS mitigation controls, IP blocklist management, router integration, and rule management — all deployable as two Docker containers.

> **Live instance:** Running 24/7 from a homelab in Luxembourg 🇱🇺, monitoring real network traffic with Snort 3, Wazuh, Zabbix, and n8n.

---

## What's New — March 28, 2026

### 🌍 3D Cyberthreat Globe

The flat Leaflet map has been replaced by a fully interactive **Three.js 3D globe** — inspired by [Kaspersky's CyberThreat Live Map](https://cybermap.kaspersky.com/).

- Earth rendered with night-side city lights texture
- Animated bezier attack arcs flying from attacker origin → Luxembourg in real-time
- Per-severity colour coding: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low · 🔵 Info
- Persistent origin dot markers at real-world IP coordinates
- Impact shockwave rings burst at home when an arc arrives
- Drag-to-rotate with inertia — **no auto-spin**, globe holds position when released
- Starts facing Europe/Luxembourg on load
- 5,800-point starfield with two depth layers and three-layer atmosphere glow
- Top Attack Origins sidebar overlaid on the globe canvas

### 📡 Real GeoIP Resolution (Backend Proxy)

All IP geolocation is now resolved **server-side** through a new `POST /api/public/geoip` endpoint — eliminating HTTPS mixed-content blocks that silently failed when SnortVision was served over HTTPS.

- Backend calls `ip-api.com/batch` server-side and caches results in memory
- Falls back to `geoip-lite` if installed (fully offline capable)
- Front-end falls back to direct call for plain HTTP deployments
- `geoip-lite`'s `geoLookup()` now also returns `lat`/`lon` for direct plotting

### 🐛 Bug Fixes

| Area | Fix |
|---|---|
| **Black screen on load** | `backendUrl` was used inside `Dashboard` but not passed as a prop — silent React crash on mount |
| **`??` country in sidebar** | Country now pulled from ip-api geo cache with fallback to raw IP — never shows `??` |
| **Router connect returns HTML** | `POST /api/config/router` had no try/catch — SSH timeout crashed Express, nginx returned HTML |
| **SSH tail reconnect loop** | Switched `exec` → `shell()`, added SSH keepalives, fixed double-reconnect race condition |
| **DDoS alerts not appearing** | `j.class` was silently overriding computed `DDOS` category; 15+ patterns now detected |
| **Mitigation Actions empty** | Auto-block only ran in demo mode; now shows live system actions and real IP blocks |
| **DDoS settings reset on tab** | All 5 DDoS state vars now persisted to `localStorage` |
| **Internal IPs as attackers** | RFC1918 / loopback / link-local filtered from globe, sidebar, and DDoS panels |
| **Settings lost after clear** | `GET /api/public/client-config` lets frontend recover `backendUrl` after localStorage wipe |
| **Reverse proxy routing** | `getDefaultBackendUrl()` now uses `window.location.origin` — no more `:4000` external exposure |

### 🗄️ DB Management Panel

New panel in the **Connection** page:

- Total alerts, DB file size, fill %, oldest/newest timestamps
- Purge buttons: **7 / 14 / 30 / 60 / 90 days** or **wipe all** — with confirmation dialogs
- **Auto-retention:** `MAX_ALERTS` env var (default 500,000) prunes oldest rows automatically on startup, every 6 hours, and after each insert

### 🏷️ Label Updates

- `Auto-blocked` → `Auto-detected`
- `Active blocks` → `Tracked IPs`
- `IP Discovered` → `Discovered IPs`

---

## Features

### Dashboard
- Live alert counter with last-minute delta
- Critical events, blocked count, block rate
- Real-time packets/sec chart with DDoS spike overlay
- Alert category breakdown with colour-coded bars
- Severity distribution (Critical / High / Medium / Low)
- **3D Cyberthreat Globe** with real-time attack arcs

### Traffic
- Interface-level packet and byte counters
- Real sensor telemetry via SSH to Snort host
- Router interface fallback when sensor interface not configured
- DDoS spike detection with automatic banner

### Alerts
- Live alert feed via WebSocket
- Severity filter, free-text search
- Source IP, destination IP, protocol, rule, action
- GeoIP country / city enrichment per alert
- New alert highlight animation

### IP Discovered
- Discovered IP tracker with hit counts, severity, last seen
- Manual block / unblock with reason
- Auto-block engine: configurable PPS threshold, window, duration
- Router-level block (nftables / iptables via SSH to OpenWRT or generic Linux)
- Blocklist sync with router

### DDoS Mitigation
- Real-time DDoS detection (PPS threshold + alert rate)
- Rate limiting controls (SYN / ICMP / UDP / connections per IP)
- SYN cookie toggle
- Null routing (blackhole via iptables)
- Geo-blocking by country
- Generated iptables rules preview
- Recent DDoS alerts, top source IPs, mitigation actions log
- AUTO / MANUAL / OFF mitigation modes
- Simulate mode for testing

### Rules Manager
- View, enable/disable, add, edit, and delete Snort rules
- Deploy rules to sensor via SSH
- Oinkcode-based rule subscription (PulledPork 3)

### Notifications
- Telegram bot alerts with severity filter
- Email / SMTP alerts
- Slack webhook alerts
- Jira issue creation
- Per-channel test button

### Connection
- SSH tunnel status
- Snort API connection with API key management
- Database connection and stats
- **DB Management panel** (purge + auto-retention)
- Router management (OpenWRT / generic Linux)
- Snort 3 process status and restart
- Connection Dependency Chain visualisation

---

## Architecture

```
┌──────────────────────────────┐
│         Snort Sensor         │
│      alert_json.txt feed     │
└──────────────┬───────────────┘
               │
               │  SSH shell / local tail
               ▼
┌──────────────────────────────┐       ┌─────────────────────┐
│      Backend (Node.js)       │──────▶│  ip-api.com (GeoIP) │
│  API · SQLite · WebSocket    │       └─────────────────────┘
│  GeoIP proxy · SSH executor  │
└──────────────┬───────────────┘
               │
               │  HTTP REST + WebSocket
               ▼
┌──────────────────────────────┐
│       Frontend (React)       │
│  3D Globe · Charts · Tables  │
│  Three.js · Recharts · Leaflet│
└──────────────────────────────┘

Optional management target:
┌──────────────────────────────┐
│      Main Router / Firewall  │
│   OpenWRT · nftables · SSH   │
└──────────────────────────────┘
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| IDS Engine | Snort 3 |
| Frontend | React 18, Three.js r128, Recharts, Tailwind CSS |
| Backend | Node.js, Express, WebSocket (ws) |
| Database | SQLite (better-sqlite3) |
| GeoIP | ip-api.com (server-side proxy) + geoip-lite (optional offline) |
| SSH | ssh2 |
| Deployment | Docker, Docker Compose, nginx |
| Notifications | Telegram, Email (nodemailer), Slack, Jira |
| Router | OpenWRT (nftables/nft), Generic Linux (iptables) |

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/marcopoveiro/snortvision.git
cd snortvision
```

### 2. Configure environment

```bash
cp .env.example .env
nano .env
```

### 3. Deploy

```bash
chmod +x deploy.sh && ./deploy.sh
# or manually:
docker compose up -d --build
```

### 4. Open the interface

| Service | URL |
|---|---|
| Frontend | `http://your-host:3000` |
| Backend API | `http://your-host:4000` |
| Public health | `http://your-host:4000/api/public/health` |

---

## Environment Variables

```env
# ── Ports ─────────────────────────────────────────────────────────────
FRONTEND_PORT=3000
BACKEND_PORT=4000

# ── Snort Sensor (SSH) ────────────────────────────────────────────────
SNORT_HOST=192.168.1.72
SNORT_SSH_PORT=22
SNORT_SSH_USER=snort
SNORT_AUTH_MODE=SSH Key          # SSH Key | Password
SNORT_LOG_PATH=/var/log/snort/alert_json.txt
SENSOR_INTERFACE=ens18           # Sniffing NIC on the sensor

# ── Router Management (optional) ──────────────────────────────────────
ROUTER_HOST=192.168.1.1
ROUTER_SSH_PORT=22
ROUTER_SSH_USER=root
ROUTER_AUTH_MODE=Password
ROUTER_TYPE=OpenWRT              # OpenWRT | Generic

# ── API & Security ────────────────────────────────────────────────────
API_KEY=                         # Auto-generated if blank
CORS_ORIGIN=https://yourdomain.lu  # Set for reverse proxy deployments

# ── Reverse Proxy ─────────────────────────────────────────────────────
BACKEND_URL=https://yourdomain.lu  # Returned to browser for post-clear recovery

# ── GeoIP ─────────────────────────────────────────────────────────────
GEOIP_ENABLE=false               # Set true after: npm run geoip-update

# ── DDoS Thresholds ───────────────────────────────────────────────────
DDOS_PACKET_PPS_THRESHOLD=8000
DDOS_ALERT_RATE_THRESHOLD=20

# ── DB Retention ──────────────────────────────────────────────────────
MAX_ALERTS=500000                # Auto-prune when over this row count

# ── Notifications ─────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
TELEGRAM_MIN_SEVERITY=high

EMAIL_ENABLED=false
EMAIL_SMTP=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=
EMAIL_PASS=
EMAIL_TO=
EMAIL_MIN_SEVERITY=critical

SLACK_ENABLED=false
SLACK_WEBHOOK=
SLACK_MIN_SEVERITY=high
```

---

## Reverse Proxy (nginx / NPM)

SnortVision is designed to run behind nginx. The frontend container already proxies `/api/` and `/ws` to the backend internally — **you only need one proxy host entry**.

**Nginx Proxy Manager — Details tab:**
- Forward hostname: `your-host-ip`
- Forward port: `3000`
- Websockets Support: ✅ enabled

**No custom location blocks needed.** Set `BACKEND_URL=https://yourdomain` and `CORS_ORIGIN=https://yourdomain` in `.env` then rebuild.

In SnortVision Connection page, set Backend URL to:
```
https://yourdomain.lu
```
(no `:4000` — nginx handles routing)

---

## SSH Key Setup

```bash
# On your management machine
ssh-keygen -t ed25519 -f ./keys/snort_id_rsa -N ""

# Copy public key to Snort sensor
ssh-copy-id -i ./keys/snort_id_rsa.pub snort@192.168.1.72

# The private key is mounted read-only into the backend container
# via the ./keys volume in docker-compose.yml
```

---

## DB Management

### Check from container

```bash
docker exec -it snortvision-backend sh
sqlite3 /app/data/snortvision.db

SELECT COUNT(*) FROM alerts;
SELECT MIN(ts), MAX(ts) FROM alerts;
.quit

# Check file size
docker exec snortvision-backend du -sh /app/data/snortvision.db
```

### Via API

```bash
# Stats
curl -H "X-API-Key: YOUR_KEY" https://yourdomain.lu/api/db/stats

# Delete alerts older than 30 days
curl -X DELETE -H "X-API-Key: YOUR_KEY" "https://yourdomain.lu/api/alerts?days=30"

# Delete all alerts
curl -X DELETE -H "X-API-Key: YOUR_KEY" "https://yourdomain.lu/api/alerts"
```

---

## Snort 3 — Enable JSON Alert Output

Add to `/etc/snort/snort.lua` outputs section:

```lua
alert_json =
{
    file = true,
    limit = 100,
    fields = 'timestamp action msg src_addr src_port dst_addr dst_port proto sid gid class priority'
}
```

---

## Roadmap

- [ ] PCAP capture and replay
- [ ] Rule performance profiling
- [ ] Multi-sensor support
- [ ] CVE enrichment per alert
- [ ] Threat intel feed integration (MISP, OTX)
- [ ] Wazuh integration panel
- [ ] n8n workflow triggers from alert events
- [ ] Mobile-responsive layout improvements
- [ ] Dark / light theme polish
- [ ] Persistent sessions and user accounts

---

## Project Background

SnortVision is built and maintained as part of a homelab SOC in **Luxembourg** running:

- **Snort 3** on a dedicated sensor VM (Proxmox VE)
- **Wazuh** SIEM with n8n + Telegram automation
- **Zabbix** infrastructure monitoring
- **OpenWRT** routers (GL.iNet Flint 3 / SCORPION)
- **Home Assistant** with solar, EV, and camera integration

The project is developed as part of teaching cybersecurity at the **Chambre de Commerce Luxembourg** and through **Level200 (LLLC)** IT consulting.

---

## License

MIT — free to use, fork, and contribute.

---

## Author

**Marco Mata** · Luxembourg  
[LinkedIn](https://linkedin.com/in/marco-mata-lux) · [GitHub](https://github.com/marcopoveiro/snortvision)

---

<p align="center">
  <i>Built with ❤️ from Luxembourg · Running live 24/7 · Monitoring real threats</i>
</p>
