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
