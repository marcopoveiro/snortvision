# 🛡️ SnortVision v0.1

<p align="center">
  <b>Real-time Snort 3 monitoring dashboard with live traffic visibility, alert ingestion, DDoS monitoring, router integration, and backend API control.</b>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-v0.1-orange?style=for-the-badge">
  <img alt="Status" src="https://img.shields.io/badge/status-under%20development-red?style=for-the-badge">
  <img alt="Build" src="https://img.shields.io/badge/build-first%20launch%20testing-blue?style=for-the-badge">
  <img alt="Snort 3" src="https://img.shields.io/badge/Snort-3.x-success?style=for-the-badge">
  <img alt="Node.js" src="https://img.shields.io/badge/backend-Node.js-339933?style=for-the-badge">
  <img alt="React" src="https://img.shields.io/badge/frontend-React-61DAFB?style=for-the-badge">
  <img alt="SQLite" src="https://img.shields.io/badge/database-SQLite-003B57?style=for-the-badge">
</p>

---

## 🚀 Overview

**SnortVision** is a modern monitoring interface for **Snort 3**, designed to provide a cleaner and more visual way to inspect alerts, traffic, suspicious hosts, and mitigation workflows.

This release is the **first development and testing version (v0.1)**.

It is already functional and useful for lab environments, testing, demonstrations, and ongoing development, but it is still **under active improvement**.

---

## ✨ Main Features

- 📡 Real-time Snort 3 alert ingestion
- 📊 Live dashboard with traffic and severity overview
- 🌍 GeoIP live attack map
- 🚨 Alert monitoring and filtering
- 🧠 DDoS detection indicators
- 🛑 IP discovery / block management
- 🌐 Router management target support
- 🔐 Backend API + SQLite storage
- 🔔 Notification integrations
- ⚙️ Docker-based deployment
- 🧪 Simulation/testing workflow for development

---

## 🧱 Architecture

```text
┌─────────────────┐     SSH tail / local tail     ┌──────────────────┐
│  Snort Sensor   │ ────────────────────────────► │  Backend (Node)  │
│  alert_json.txt │                               │  SQLite + API    │
└─────────────────┘                               │  WebSocket       │
                                                  └────────┬─────────┘
                                                           │ HTTP / WS
                                 optional SSH mgmt         │
┌─────────────────┐ ───────────────────────────────────────┘
│ Router Target   │  firmware / interfaces / firewall / counters
└─────────────────┘
                                                  ┌────────┴─────────┐
                                                  │ Frontend (React) │
                                                  │ SnortVision UI   │
                                                  └──────────────────┘
📦 Current Version
v0.1 — First Launch / Testing Build

This version includes the first working release of SnortVision with:

🌍 Lighter GeoIP Attack Map

Improved visual clarity using a lighter tile style for better country boundaries, labels, and attack-path readability.

💥 Attack Impact Pulses

Animated visual pulses when attacks reach the protected target, making live activity easier to identify.

🔗 Connection Dependency Chain

Visual service path on the Connection page:

SSH → Backend API → Snort3 Process

This helps quickly identify where a failure occurs.

🌐 Router Management Target

Support for optional router integration, including:

OpenWRT

Generic Linux / router systems

It can retrieve:

router reachability

firmware version

WAN/LAN IPs

monitored interface

bridge/interface names

firewall zones

mirror/SPAN hints

tcpdump availability

packet counters

Snort/Suricata presence

🔐 Backend API Improvements

The backend panel now includes:

username field

password field

API key visibility toggle

verification button

visual pass/fail connection feedback
⚙️ Quick Start
1. Clone the repository
git clone https://github.com/marcopoveiro/snortvision.git
cd snortvision
2. Prepare environment
cp .env.example .env

Edit .env with your values.

3. Deploy with helper script
chmod +x deploy.sh
./deploy.sh
4. Open the interface
Frontend: http://localhost:3000
Backend : http://localhost:4000
🐳 Docker Deployment

If you want to run directly with Docker Compose:

docker compose up -d --build

To stop:

docker compose down

To rebuild cleanly:

docker compose down -v
docker compose up -d --build
🔧 Important Environment Settings

Example:

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
BACKEND_URL=http://192.168.1.72:4000
📡 Real Traffic Counters

To use real traffic counters, set the real capture interface:

SENSOR_INTERFACE=ens18

Examples:

ens18

ens19

eth0

eth1

This must be the real sniffing / mirrored interface used by Snort.

🌍 GeoIP

GeoIP should be enabled for the live attack map experience:

GEOIP_ENABLE=true

If disabled, the system still works, but country/city enrichment and map quality will be limited.

🧪 Development Notes

This is a development-first build intended for:

home labs

testing environments

proof of concept

early feature validation

live UI iteration

Some modules are already working well, while others are still being refined.

📄 Main Pages
Page	Purpose
Dashboard	Live traffic, totals, severity view, map
Alerts / Traffic	Real-time alert/event table
IP Discovery / Blocklist	Discovered IPs, manual block, auto-block
DDoS Mitigation	Thresholds, mitigation view, generated rules
Rules	Snort rule management
Notifications	Telegram, Email, Slack, Jira settings
Connection	Snort sensor, router target, backend verification
🛠️ Troubleshooting
Backend container starts but health check fails

Check logs:

sudo docker logs --tail 100 snortvision-backend
SnortVision still tries SSH tail mode

Check .env:

SNORT_HOST=

If backend and Snort are on the same host, leave SNORT_HOST empty for local mode.

No traffic on dashboard

Verify the sniffing interface:

sudo tcpdump -ni ens18 -c 20

Then set:

SENSOR_INTERFACE=ens18
GeoIP not appearing

Make sure this is enabled:

GEOIP_ENABLE=true

Then rebuild:

docker compose up -d --build
Docker build fails on Debian image using apk

If your backend Dockerfile uses:

FROM node:20-bookworm-slim

do not use:

RUN apk add ...

Use:

RUN apt-get update && apt-get install -y openssh-client iptables && rm -rf /var/lib/apt/lists/*
🧭 Roadmap Ideas

better production-ready hardening

improved parser coverage

richer DDoS logic

more accurate attack classification

better map intelligence

export/reporting

multi-sensor support

advanced router enforcement

authentication improvements

polished release build

❤️ Support the Project

If you like the project, support it here:

GitHub

⭐ Star the repository

🍴 Follow the development

🐛 Report bugs

💡 Suggest improvements

LinkedIn

If you enjoyed the creation of SnortVision, a thumbs up and support on LinkedIn means a lot and helps give visibility to the project.



[👍 Support SnortVision on LinkedIn]  www.linkedin.com/in/marco-mata-lux
👨‍💻 Author

Marco Mata
Made in Luxembourg 🇱🇺

⚠️ Disclaimer

SnortVision v0.1 is a first development / testing release.
It is intended for validation, experimentation, and progressive improvement.

Use it carefully in production environments until future hardening phases are completed.
