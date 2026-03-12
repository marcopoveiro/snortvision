# SnortVision v0.1

This is the **first launch and testing build** of SnortVision.

Real-time Snort3 IDS monitoring dashboard with live attack map, alert management, DDoS mitigation, and integrated backend API.

## First Launch / Testing Build (v0.1)

### 1. Lighter Attack Map — CartoDB Voyager
Switched from CartoDB Dark Matter to **CartoDB Voyager (light)** tiles. Country boundaries and geographic labels are now clearer, providing better visual contrast for attack lines and markers.

### 2. Attack Impact Pulses
When attack lines reach the home server (Luxembourg), **animated pulse rings** expand outward from the target. Each pulse inherits the severity color — critical attacks flash red, scans pulse green. Multiple overlapping pulses create a visual intensity indicator during high-volume attacks.

### 3. Connection Dependency Chain
New visual **SSH → Backend API → Snort3 Process** dependency indicator on the Connection page. When SSH goes down, downstream services automatically show BLOCKED/DEGRADED status with cascade warnings. Includes disconnect button and status history.

### 4. Router Management Target (OpenWRT + Generic)
Added a second connection box for a **router management target**. This target is optional and is not used as the source of Snort alerts unless Snort itself runs on the router. It can now query:
- Router reachable state
- Firmware version
- WAN/LAN IPs
- Monitored interface
- Bridge/interface names
- Firewall zones
- Mirror/SPAN target hints
- tcpdump presence
- Packet counters
- Snort/Suricata package presence

### 5. Backend API Panel — Username/Password/IP Verification
The Backend API & SQLite panel now includes:
- **Username** and **Password** fields with show/hide toggles
- **API Key** with visibility toggle
- **Verify Credentials** button that pre-tests authentication before connecting
- Visual pass/fail verification result badges

## Architecture

```
┌─────────────────┐     SSH tail      ┌──────────────────┐
│  Snort Sensor    │ ──────────────── │  Backend (Node)   │
│  alert_json.txt  │                  │  SQLite + API     │
└─────────────────┘                  │  WebSocket        │
                                      └────────┬─────────┘
                                               │ HTTP/WS
                         optional SSH mgmt     │
┌─────────────────┐ ───────────────────────────┘
│ Router Target   │  firmware / interfaces / firewall / counters
└─────────────────┘
                                      ┌────────┴─────────┐
                                      │  Frontend (React) │
                                      │  SnortVision UI   │
                                      └──────────────────┘
```

## Quick Start

```bash
cp .env.example .env
# Edit .env with your Snort host IP, SSH credentials, etc.
docker compose up -d --build
# Open http://localhost:3000
```

## Simulation Mode

SnortVision runs in **simulation mode** by default (no backend required). Click "Simulate" on the DDoS page to trigger attack scenarios. Connect to a real backend to switch to live data.

## Pages

| Page | Description |
|------|-------------|
| Dashboard | Stats, live traffic chart, category/severity bars, GeoIP attack map |
| Alerts | Searchable alert table with severity filters |
| IP Blocklist | Auto-block engine + manual blocks |
| DDoS Mitigation | Rate limiting, SYN cookies, geo-blocking, null routing |
| Rules | Snort rule editor with live preview |
| Notifications | Telegram, Email, Jira, Slack integrations |
| Connection | Sensor SSH, router management target, backend dependency chain, credential verification |
## Real traffic counters

To make the dashboard use real packet counters instead of demo traffic, set these in `.env` before deploy:

```env
SENSOR_INTERFACE=eth0
DDOS_PACKET_PPS_THRESHOLD=8000
DDOS_ALERT_RATE_THRESHOLD=20
```

`SENSOR_INTERFACE` must be the real sniffing interface on the Snort sensor, such as `eth1`, `ens18`, or the mirrored-port NIC.
