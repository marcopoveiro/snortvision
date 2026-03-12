# 🛡️ SnortVision v0.1

<p align="center">
  <b>Modern real-time Snort 3 monitoring dashboard with live traffic visibility, alert ingestion, GeoIP attack mapping, DDoS indicators, router integration, and backend API control.</b>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.1-orange?style=for-the-badge">
  <img alt="Status" src="https://img.shields.io/badge/status-under%20development-red?style=for-the-badge">
  <img alt="Build" src="https://img.shields.io/badge/build-first%20launch%20testing-blue?style=for-the-badge">
  <img alt="Snort 3" src="https://img.shields.io/badge/Snort-3.x-success?style=for-the-badge">
  <img alt="Backend" src="https://img.shields.io/badge/backend-Node.js-339933?style=for-the-badge">
  <img alt="Frontend" src="https://img.shields.io/badge/frontend-React-61DAFB?style=for-the-badge">
  <img alt="Database" src="https://img.shields.io/badge/database-SQLite-003B57?style=for-the-badge">
  <img alt="Docker" src="https://img.shields.io/badge/deployment-Docker-2496ED?style=for-the-badge">
</p>

---

## Overview

**SnortVision** is a visual monitoring and management interface for **Snort 3**, built to provide a cleaner, faster, and more operationally useful view of security events, suspicious hosts, traffic activity, and mitigation workflows.

This release is **v0.1**, the **first launch / testing build** of the project.

It is already functional for **lab environments**, **proof-of-concept deployments**, **testing**, and **demonstrations**, while remaining under active development for future hardening and production maturity.

---

## Why SnortVision

Traditional IDS workflows can feel fragmented, overly text-based, or operationally slow during live analysis. SnortVision aims to improve that experience by combining:

- **Real-time alert visibility**
- **Live traffic monitoring**
- **GeoIP attack visualization**
- **DDoS-oriented indicators**
- **Optional router integration**
- **Backend API control and validation**
- **Cleaner operator workflows**

The goal is to make Snort 3 more visual, more accessible, and more actionable.

---

## Main Features

- 📡 Real-time Snort 3 alert ingestion
- 📊 Live dashboard with traffic, severity, and attack visibility
- 🌍 GeoIP live attack map
- 🚨 Alert monitoring and event filtering
- 🧠 DDoS detection indicators and thresholds
- 🛑 IP discovery and blocklist management
- 🌐 Router integration support
- 🔐 Backend API with SQLite storage
- 🔔 Notification integration support
- ⚙️ Docker-based deployment
- 🧪 Simulation and testing workflows for development

---

## Current Version

## v0.1 — First Launch / Testing Build

This version introduces the first working public development build of **SnortVision** with the following highlights:

### 🌍 Lighter GeoIP Attack Map
Improved map readability using a lighter tile style for clearer country boundaries, labels, and attack-path visibility.

### 💥 Attack Impact Pulses
Animated pulse effects when attacks reach the protected target, making live hostile activity easier to identify visually.

### 🔗 Connection Dependency Chain
The connection panel now clearly represents the service chain:

```text
SSH → Backend API → Snort3 Process
```

This makes it easier to identify where connectivity or service failures occur.

### 🌐 Router Management Target
Optional router integration currently supports scenarios such as:

- OpenWRT
- Generic Linux / router-based systems

Available router-side checks can include:

- host reachability
- firmware information
- WAN / LAN addressing
- monitored interface details
- bridge or interface names
- firewall zones
- mirror / SPAN hints
- tcpdump availability
- traffic counters
- Snort / Suricata presence detection

### 🔐 Backend API Improvements
The backend connection panel includes:

- username field
- password field
- API key visibility toggle
- verification button
- visual pass / fail feedback

---

## Architecture

```text
┌──────────────────────────────┐
│         Snort Sensor         │
│      alert_json.txt feed     │
└──────────────┬───────────────┘
               │
               │ SSH tail / local tail
               ▼
┌──────────────────────────────┐
│        Backend (Node)        │
│      API + SQLite + WS       │
└──────────────┬───────────────┘
               │
               │ HTTP / WebSocket
               ▼
┌──────────────────────────────┐
│       Frontend (React)       │
│        SnortVision UI        │
└──────────────────────────────┘

Optional management target:
┌──────────────────────────────┐
│      Router / Firewall       │
│ OpenWRT / Linux-based target │
└──────────────────────────────┘
```

---

## Technology Stack

- **Snort 3**
- **React** frontend
- **Node.js** backend
- **SQLite** database
- **WebSocket** live updates
- **Docker / Docker Compose** deployment

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/marcopoveiro/snortvision.git
cd snortvision
```

### 2. Prepare the environment

```bash
cp .env.example .env
```

Edit `.env` with your environment values.

### 3. Deploy with the helper script

```bash
chmod +x deploy.sh
./deploy.sh
```

### 4. Open the interface

- **Frontend:** `http://localhost:3000`
- **Backend:** `http://localhost:4000`

---

## Docker Deployment

To run SnortVision directly with Docker Compose:

```bash
docker compose up -d --build
```

To stop the stack:

```bash
docker compose down
```

To rebuild cleanly:

```bash
docker compose down -v
docker compose up -d --build
```

---

## Important Environment Settings

Example configuration:

```env
FRONTEND_PORT=3000
BACKEND_PORT=4000

SNORT_HOST=
SNORT_SSH_PORT=22
SNORT_SSH_USER=snort3
SNORT_AUTH_MODE=Password
SNORT_LOG_PATH=/var/log/snort/alert_json.txt

ROUTER_HOST=192.168.1.1
ROUTER_SSH_PORT=22
ROUTER_SSH_USER=root
ROUTER_AUTH_MODE=Password
ROUTER_TYPE=OpenWRT

API_KEY=
GEOIP_ENABLE=true

SENSOR_INTERFACE=ens18
DDOS_PACKET_PPS_THRESHOLD=8000
DDOS_ALERT_RATE_THRESHOLD=20
BACKEND_URL=http://192.168.99.99:4000
```

---

## Real Traffic Counters

To use real traffic counters, define the actual capture interface used by Snort:

```env
SENSOR_INTERFACE=ens18
```

Examples:

- `ens18`
- `ens19`
- `eth0`
- `eth1`

This must match the real sniffing or mirrored interface used by the sensor.

---

## GeoIP Support

For the best live attack map experience, enable GeoIP:

```env
GEOIP_ENABLE=true
```

If disabled, SnortVision will still function, but map enrichment and geographic visibility will be limited.

---

## Main Pages

| Page | Purpose |
|------|---------|
| **Dashboard** | Live traffic overview, totals, severity visibility, attack map |
| **Alerts / Traffic** | Real-time event and alert table |
| **IP Discovery / Blocklist** | Discovered IPs, manual block, auto-block workflows |
| **DDoS Mitigation** | Threshold monitoring, mitigation visibility, generated rules |
| **Rules** | Snort rule management |
| **Notifications** | Telegram, Email, Slack, Jira settings |
| **Connection** | Snort sensor, router target, backend verification |

---

## Development Notes

SnortVision v0.1 is primarily a **development-first build** intended for:

- home labs
- testing environments
- proof of concept
- feature validation
- live UI iteration
- ongoing backend integration work

Some modules are already usable and visually mature, while others are still being refined.

---

## Troubleshooting

### Backend container starts but health check fails

Check backend logs:

```bash
sudo docker logs --tail 100 snortvision-backend
```

### SnortVision still tries SSH tail mode

Check `.env`:

```env
SNORT_HOST=
```

If Snort and the backend run on the same host, leave `SNORT_HOST` empty to use local mode.

### No traffic appears on the dashboard

Verify the sniffing interface:

```bash
sudo tcpdump -ni ens18 -c 20
```

Then confirm:

```env
SENSOR_INTERFACE=ens18
```

### GeoIP data is not appearing

Make sure this is enabled:

```env
GEOIP_ENABLE=true
```

Then rebuild:

```bash
docker compose up -d --build
```

### Docker build fails on Debian-based Node images due to `apk`

If your backend Dockerfile uses:

```dockerfile
FROM node:20-bookworm-slim
```

Do **not** use Alpine package commands such as:

```dockerfile
RUN apk add ...
```

Use Debian-compatible packages instead:

```dockerfile
RUN apt-get update && apt-get install -y openssh-client iptables && rm -rf /var/lib/apt/lists/*
```

---

## Roadmap

Planned improvement areas include:

- stronger production hardening
- improved parser coverage
- richer DDoS logic
- more accurate attack classification
- smarter map intelligence
- export and reporting capabilities
- multi-sensor support
- advanced router enforcement
- stronger authentication flows
- more polished release packaging

---

## Support the Project

If you like the project, support its visibility and development:

### GitHub
- ⭐ Star the repository
- 🍴 Follow the project
- 🐛 Report bugs
- 💡 Suggest improvements

### LinkedIn
If you enjoyed the creation of SnortVision, support on LinkedIn is always appreciated:

[🔗 Marco Mata on LinkedIn](https://www.linkedin.com/in/marco-mata-lux)

---

## Author

**Marco Mata**  
Made in Luxembourg 🇱🇺

---

## Disclaimer

**SnortVision v0.1** is a **first launch / testing release**.

It is intended for **validation**, **experimentation**, and **progressive improvement**. While already functional in lab and development scenarios, it should be used carefully in production environments until later hardening phases are completed.
