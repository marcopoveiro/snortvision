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
```

`SENSOR_INTERFACE` must be the real sniffing interface on the Snort sensor, such as `eth1`, `ens18`, or the mirrored-port NIC.
