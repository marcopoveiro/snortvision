"use strict";

// Load .env FIRST — before anything reads process.env.
// Prefer backend/.env, but fall back to the project root .env for local deployments.
const path = require("path");
const fs = require("fs");
const BACKEND_ENV_PATH = path.resolve(__dirname, ".env");
const ROOT_ENV_PATH = path.resolve(__dirname, "..", ".env");
const DEFAULT_ENV_PATH = fs.existsSync(BACKEND_ENV_PATH) ? BACKEND_ENV_PATH : ROOT_ENV_PATH;
require("dotenv").config({ path: process.env.ENV_FILE || DEFAULT_ENV_PATH });

const express    = require("express");
const { WebSocketServer, WebSocket } = require("ws");
const http       = require("http");
const { Client } = require("ssh2");
const Database   = require("better-sqlite3");
const nodemailer = require("nodemailer");
const fetch      = require("node-fetch");
const cors       = require("cors");
const { exec, spawn } = require("child_process");
const net = require("net");

// ─── Config ────────────────────────────────────────────────────────────────
const PORT     = parseInt(process.env.PORT     || "4000");
const DB_PATH  = process.env.DB_PATH           || path.join(__dirname, "data", "snortvision.db");
const GEOIP_EN = process.env.GEOIP_ENABLE === "true";
const SENSOR_INTERFACE = process.env.SENSOR_INTERFACE || "";
const DDOS_PACKET_PPS_THRESHOLD = parseInt(process.env.DDOS_PACKET_PPS_THRESHOLD || "8000", 10);
const DDOS_ALERT_RATE_THRESHOLD = parseInt(process.env.DDOS_ALERT_RATE_THRESHOLD || "20", 10);

const trafficSamples = new Map();

function parseProcNetDev(content) {
  const out = {};
  for (const raw of content.split("\n").slice(2)) {
    const line = raw.trim();
    if (!line || !line.includes(":")) continue;
    const [iface, rest] = line.split(":");
    const cols = rest.trim().split(/\s+/).map(v => Number(v));
    out[iface.trim()] = {
      rxBytes: cols[0] || 0,
      rxPackets: cols[1] || 0,
      txBytes: cols[8] || 0,
      txPackets: cols[9] || 0,
    };
  }
  return out;
}

function parseInterfaceList(value) {
  return Array.from(new Set(
    String(value || "")
      .split(/[\s,;|]+/)
      .map(v => String(v || "").trim())
      .filter(Boolean)
      .map(v => v.replace(/:$/, ""))
  ));
}

function sumInterfaceCounters(parsed, interfaces = []) {
  return interfaces.reduce((acc, iface) => {
    const item = parsed[iface];
    if (!item) return acc;
    acc.rxBytes += item.rxBytes || 0;
    acc.rxPackets += item.rxPackets || 0;
    acc.txBytes += item.txBytes || 0;
    acc.txPackets += item.txPackets || 0;
    return acc;
  }, { rxBytes: 0, rxPackets: 0, txBytes: 0, txPackets: 0 });
}

function buildTrafficSnapshot(sampleKey, cur) {
  const now = Date.now();
  const prev = trafficSamples.get(sampleKey);
  if (!prev) {
    trafficSamples.set(sampleKey, { ts: now, ...cur });
    return { rx_pps: 0, tx_pps: 0, packet_pps: 0, mbps: 0 };
  }

  const seconds = Math.max((now - prev.ts) / 1000, 1);
  const rxPps = Math.max(0, Math.round((cur.rxPackets - prev.rxPackets) / seconds));
  const txPps = Math.max(0, Math.round((cur.txPackets - prev.txPackets) / seconds));
  const rxBytesPerSec = Math.max(0, (cur.rxBytes - prev.rxBytes) / seconds);
  const txBytesPerSec = Math.max(0, (cur.txBytes - prev.txBytes) / seconds);
  const mbps = Number((((rxBytesPerSec + txBytesPerSec) * 8) / 1_000_000).toFixed(2));

  trafficSamples.set(sampleKey, { ts: now, ...cur });
  return { rx_pps: rxPps, tx_pps: txPps, packet_pps: rxPps + txPps, mbps };
}

async function detectMainRouterInterfaces(cfg) {
  if (cleanValue(cfg.monitorInterface)) return parseInterfaceList(cfg.monitorInterface);

  if (normalizeRouterType(cfg.routerType) === "OpenWRT") {
    const detected = await sshExecValue(`sh -lc '
WAN="$(ubus call network.interface.wan status 2>/dev/null | jsonfilter -e "@.device" 2>/dev/null || uci get network.wan.device 2>/dev/null || uci get network.wan.ifname 2>/dev/null || true)"
LAN="$(ubus call network.interface.lan status 2>/dev/null | jsonfilter -e "@.device" 2>/dev/null || uci get network.lan.device 2>/dev/null || uci get network.lan.ifname 2>/dev/null || true)"
EXTRA="$(ip -o link show type bridge 2>/dev/null | awk -F": " "{print \\$2}" | cut -d"@" -f1 | paste -sd "," -)"
printf "%s,%s,%s" "$WAN" "$LAN" "$EXTRA"
'`, cfg, 10000);
    return parseInterfaceList(detected);
  }

  const detected = await sshExecValue(`sh -lc '
DEF="$(ip route 2>/dev/null | awk "/^default/{print \\$5; exit}")"
BRS="$(ip -o link show type bridge 2>/dev/null | awk -F": " "{print \\$2}" | cut -d"@" -f1 | paste -sd "," -)"
printf "%s,%s" "$DEF" "$BRS"
'`, cfg, 10000);
  return parseInterfaceList(detected);
}

async function readProcNetDev(cfg) {
  if (cfg && cfg.ip) {
    const result = await sshExecCommand("cat /proc/net/dev", cfg, 15000);
    return result.stdout || "";
  }
  return fs.readFileSync("/proc/net/dev", "utf8");
}

async function getSensorTrafficTelemetry() {
  const iface = SENSOR_INTERFACE.trim();
  if (!iface) return null;

  const cfg = getConnConfig();
  const content = await readProcNetDev(cfg);
  const parsed = parseProcNetDev(content);
  const cur = parsed[iface];

  if (!cur) {
    return {
      real: false,
      interface: iface,
      source: cfg.ip ? "sensor-ssh" : "sensor-local",
      error: `Interface '${iface}' not found`,
      rx_pps: 0,
      tx_pps: 0,
      packet_pps: 0,
      mbps: 0,
    };
  }

  return {
    real: true,
    interface: iface,
    source: cfg.ip ? "sensor-ssh" : "sensor-local",
    ...buildTrafficSnapshot(`sensor:${cfg.ip || 'local'}:${iface}`, cur),
  };
}

async function getMainRouterTrafficTelemetry() {
  const cfg = getRouterConfig();
  if (!cleanValue(cfg.ip)) {
    return {
      real: false,
      interface: "",
      source: "no_main_router_configured",
      rx_pps: 0,
      tx_pps: 0,
      packet_pps: 0,
      mbps: 0,
    };
  }

  const interfaces = await detectMainRouterInterfaces(cfg);
  if (!interfaces.length) {
    return {
      real: false,
      interface: "",
      source: "main-router-no-interface-detected",
      rx_pps: 0,
      tx_pps: 0,
      packet_pps: 0,
      mbps: 0,
    };
  }

  const content = await readProcNetDev(cfg);
  const parsed = parseProcNetDev(content);
  const present = interfaces.filter(iface => !!parsed[iface]);

  if (!present.length) {
    return {
      real: false,
      interface: interfaces.join(","),
      source: cleanValue(cfg.monitorInterface) ? "main-router-selected" : "main-router-auto",
      error: `Main router interfaces not found in /proc/net/dev: ${interfaces.join(", ")}`,
      rx_pps: 0,
      tx_pps: 0,
      packet_pps: 0,
      mbps: 0,
    };
  }

  const cur = sumInterfaceCounters(parsed, present);
  return {
    real: true,
    interface: present.join(","),
    source: cleanValue(cfg.monitorInterface) ? "main-router-selected" : "main-router-auto",
    ...buildTrafficSnapshot(`main-router:${cfg.ip}:${present.join(',')}`, cur),
  };
}

async function getTrafficTelemetry() {
  const sensorTraffic = await getSensorTrafficTelemetry();
  if (sensorTraffic?.real || sensorTraffic?.error) return sensorTraffic;

  const routerTraffic = await getMainRouterTrafficTelemetry();
  if (routerTraffic?.real || routerTraffic?.error) return routerTraffic;

  return {
    real: false,
    interface: "",
    source: "no_interface_configured",
    rx_pps: 0,
    tx_pps: 0,
    packet_pps: 0,
    mbps: 0,
  };
}

// Ensure DB directory exists
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) { fs.mkdirSync(dbDir, { recursive: true }); console.log(`[DB] Created directory: ${dbDir}`); }

// ── API Key: generated ONCE on first run, immutable after that ──
const crypto = require("crypto");
let API_KEY = process.env.API_KEY || "";
if (!API_KEY) {
  API_KEY = "sk-" + crypto.randomBytes(24).toString("hex");
  // Write immediately to .env so it persists
  const envPath = path.resolve(process.env.ENV_FILE || DEFAULT_ENV_PATH);
  let envContent = "";
  try { envContent = fs.readFileSync(envPath, "utf8"); } catch(_) {}
  const keyLine = `API_KEY=${API_KEY}`;
  if (/^API_KEY=.*$/m.test(envContent)) {
    envContent = envContent.replace(/^API_KEY=.*$/m, keyLine);
  } else {
    envContent = envContent.trimEnd() + "\n" + keyLine + "\n";
  }
  try { fs.writeFileSync(envPath, envContent); } catch(_) {}
  process.env.API_KEY = API_KEY;
  console.log("┌──────────────────────────────────────────────────────────┐");
  console.log("│  🔑 API KEY GENERATED (first run — save this!)          │");
  console.log(`│  ${API_KEY}  │`);
  console.log("│  This key is written to .env and cannot be changed.     │");
  console.log("└──────────────────────────────────────────────────────────┘");
}

// ─── Optional GeoIP ────────────────────────────────────────────────────────
let geoip = null;
if (GEOIP_EN) {
  try { geoip = require("geoip-lite"); console.log("[GeoIP] enabled"); }
  catch (_) { console.warn("[GeoIP] geoip-lite not installed — run: npm install geoip-lite"); }
}

function geoLookup(ip) {
  if (!geoip) return { country: "", city: "" };
  try {
    const g = geoip.lookup(ip);
    return g ? { country: g.country || "", city: g.city || "" } : { country: "", city: "" };
  } catch { return { country: "", city: "" }; }
}

// ─── SQLite Database ────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL,
    rule      TEXT,
    msg       TEXT,
    category  TEXT,
    severity  TEXT,
    src_ip    TEXT,
    dst_ip    TEXT,
    src_port  INTEGER,
    dst_port  INTEGER,
    proto     TEXT,
    action    TEXT,
    country   TEXT,
    city      TEXT,
    raw       TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_alerts_ts     ON alerts(ts);
  CREATE INDEX IF NOT EXISTS idx_alerts_sev    ON alerts(severity);
  CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);

  CREATE TABLE IF NOT EXISTS blocklist (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ip       TEXT    UNIQUE NOT NULL,
    reason   TEXT,
    added    TEXT    DEFAULT (datetime('now')),
    hits     INTEGER DEFAULT 0,
    active   INTEGER DEFAULT 1,
    source   TEXT    DEFAULT 'Manual'
  );

  CREATE TABLE IF NOT EXISTS rules (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    sid      TEXT,
    gid      INTEGER DEFAULT 1,
    rev      INTEGER DEFAULT 1,
    enabled  INTEGER DEFAULT 1,
    action   TEXT    DEFAULT 'alert',
    proto    TEXT    DEFAULT 'TCP',
    src      TEXT    DEFAULT 'any',
    sport    TEXT    DEFAULT 'any',
    dir      TEXT    DEFAULT '->',
    dst      TEXT    DEFAULT '\$HOME_NET',
    dport    TEXT    DEFAULT 'any',
    msg      TEXT,
    cat      TEXT,
    sev      TEXT,
    hits     INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS iptables_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT DEFAULT (datetime('now')),
    op         TEXT,
    rule       TEXT,
    applied_by TEXT
  );

  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Seed default rules if empty
const ruleCount = db.prepare("SELECT COUNT(*) as c FROM rules").get().c;
if (ruleCount === 0) {
  const ins = db.prepare(`INSERT OR IGNORE INTO rules (sid,gid,rev,enabled,action,proto,src,sport,dir,dst,dport,msg,cat,sev,hits) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  [
    ["2001219",1,20,1,"alert","TCP","any","any","->","$HOME_NET","22",   "ET SCAN Potential SSH Scan",          "SCAN",   "medium",  0],
    ["2021001",1,5, 1,"drop", "TCP","any","any","->","any",       "80",  "ET DOS LOIC HTTP Flood",              "DDOS",   "critical",0],
    ["2013028",1,8, 1,"drop", "TCP","any","any","->","$HOME_NET","any",  "ET TROJAN Win32/Zbot Checkin",        "TROJAN", "critical",0],
    ["2008435",1,3, 1,"drop", "TCP","any","any","->","any",       "80",  "ET EXPLOIT CVE-2014-6271 Shellshock", "EXPLOIT","critical",0],
    ["2019714",1,12,1,"alert","TCP","any","any","->","$HOME_NET","any",  "ET SCAN Nmap Detected",               "SCAN",   "low",     0],
    ["2010935",1,7, 0,"alert","TCP","any","any","->","$HOME_NET","any",  "ET POLICY PE EXE download HTTP",      "MALWARE","high",    0],
    ["2030171",1,2, 1,"drop", "TCP","any","any","->","$HOME_NET","443",  "ET MALWARE Win32/Dridex SSL",         "MALWARE","critical",0],
    ["2011010",1,4, 1,"drop", "UDP","any","any","->","$HOME_NET","631",  "ET WEB CUPS DoS attempt",             "DDOS",   "high",    0],
  ].forEach(r => ins.run(...r));
}

const insertAlert = db.prepare(`
  INSERT INTO alerts (ts,rule,msg,category,severity,src_ip,dst_ip,src_port,dst_port,proto,action,country,city,raw)
  VALUES (@ts,@rule,@msg,@category,@severity,@src_ip,@dst_ip,@src_port,@dst_port,@proto,@action,@country,@city,@raw)
`);

// ─── DB retention ────────────────────────────────────────────────────────────
const MAX_ALERTS = parseInt(process.env.MAX_ALERTS || "500000", 10);
const pruneStmt  = db.prepare("DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY id ASC LIMIT ?)");

function pruneAlerts() {
  try {
    const count = db.prepare("SELECT COUNT(*) as c FROM alerts").get().c;
    if (count > MAX_ALERTS) {
      const toDel = count - MAX_ALERTS;
      pruneStmt.run(toDel);
      console.log(`[DB] Pruned ${toDel} old alerts (retention: ${MAX_ALERTS})`);
    }
  } catch(e) { console.error("[DB] prune error:", e.message); }
}

// Run prune once on startup + every 6 hours
pruneAlerts();
setInterval(pruneAlerts, 6 * 60 * 60 * 1000);

function migrateStoredAlerts() {
  const rows = db.prepare("SELECT id, ts, src_ip, country, city FROM alerts ORDER BY id DESC LIMIT 5000").all();
  const updateTs = db.prepare("UPDATE alerts SET ts=? WHERE id=?");
  const updateGeo = db.prepare("UPDATE alerts SET country=?, city=? WHERE id=?");
  let tsFixed = 0;
  let geoFixed = 0;

  for (const row of rows) {
    const normalizedTs = normaliseSnortTimestamp(row.ts);
    if (normalizedTs !== row.ts) {
      updateTs.run(normalizedTs, row.id);
      tsFixed++;
    }
    if ((!row.country || !String(row.country).trim()) && row.src_ip) {
      const geo = geoLookup(row.src_ip);
      if (geo.country || geo.city) {
        updateGeo.run(geo.country || "", geo.city || "", row.id);
        geoFixed++;
      }
    }
  }

  if (tsFixed || geoFixed) {
    console.log(`[DB] Alert migration complete — timestamps fixed: ${tsFixed}, geo enriched: ${geoFixed}`);
  }
}

migrateStoredAlerts();

function dbGet(key, def = null) {
  const row = db.prepare("SELECT value FROM config WHERE key=?").get(key);
  return row ? JSON.parse(row.value) : def;
}
function dbSet(key, value) {
  db.prepare("INSERT OR REPLACE INTO config (key,value) VALUES (?,?)").run(key, JSON.stringify(value));
}

// ─── .env file writer — persists UI changes to disk ──────────────────────────
const ENV_PATH = path.resolve(process.env.ENV_FILE || DEFAULT_ENV_PATH);

function updateEnvFile(kvPairs) {
  // kvPairs: { KEY: "value", KEY2: "value2", ... }
  let content = "";
  try { content = fs.readFileSync(ENV_PATH, "utf8"); } catch(_) {}

  for (const [key, value] of Object.entries(kvPairs)) {
    const escaped = String(value).replace(/"/g, '\\"');
    const regex = new RegExp(`^${key}=.*$`, "m");
    const line = `${key}=${escaped}`;
    if (regex.test(content)) {
      content = content.replace(regex, line);
    } else {
      content = content.trimEnd() + "\n" + line + "\n";
    }
    // Also update process.env so runtime reflects change immediately
    process.env[key] = String(value);
  }

  try {
    fs.writeFileSync(ENV_PATH, content);
    console.log(`[ENV] Updated ${ENV_PATH}: ${Object.keys(kvPairs).join(", ")}`);
    return true;
  } catch(e) {
    console.error(`[ENV] Failed to write ${ENV_PATH}: ${e.message}`);
    return false;
  }
}

// ─── Runtime config helpers ─────────────────────────────────────────────────
function getConnConfig() {
  return dbGet("connection", {
    ip:           process.env.SNORT_HOST         || "",
    port:         process.env.SNORT_SSH_PORT     || "22",
    user:         process.env.SNORT_SSH_USER     || "snort",
    keyPath:      process.env.SNORT_SSH_KEY_PATH || "/app/keys/snort_id_rsa",
    logPath:      process.env.SNORT_LOG_PATH     || "/var/log/snort/alert_json.txt",
    authMode:     process.env.SNORT_AUTH_MODE    || "SSH Key",
    password:     "",
    sudoPassword: "",
  });
}

function getRouterConfig() {
  return dbGet("router_connection", {
    ip: process.env.ROUTER_HOST || "",
    port: process.env.ROUTER_SSH_PORT || "22",
    user: process.env.ROUTER_SSH_USER || "root",
    keyPath: process.env.ROUTER_SSH_KEY_PATH || "/app/keys/router_id_rsa",
    authMode: process.env.ROUTER_AUTH_MODE || "Password",
    password: "",
    routerType: process.env.ROUTER_TYPE || "OpenWRT",
    monitorInterface: process.env.ROUTER_MONITOR_IFACE || "",
    mirrorTarget: process.env.ROUTER_MIRROR_TARGET || "",
    note: "",
  });
}

function buildSshOptions(cfg = getConnConfig()) {
  const opts = {
    host: cfg.ip,
    port: parseInt(cfg.port || "22"),
    username: cfg.user || "snort",
    readyTimeout: 10000,
    keepaliveInterval: 15000,
    keepaliveCountMax: 4,
  };

  if (cfg.authMode === "SSH Key") {
    const kp = cfg.keyPath || "/app/keys/snort_id_rsa";
    if (!fs.existsSync(kp)) {
      throw new Error(`SSH key not found: ${kp}`);
    }
    opts.privateKey = fs.readFileSync(kp);
  } else {
    opts.password = cfg.password || "";
  }

  return opts;
}

function sshExecCommand(command, cfg = getConnConfig(), timeoutMs = 15000, stdin = null) {
  return new Promise((resolve, reject) => {
    if (!cfg.ip) return reject(new Error("SSH host is not configured"));

    let settled = false;
    const ssh = new Client();
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      try { ssh.end(); } catch (_) {}
      if (err) reject(err);
      else resolve(value);
    };

    let timer = setTimeout(() => {
      finish(new Error(`SSH command timed out after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);

    try {
      ssh.on("ready", () => {
        // Use PTY only when we DON'T need stdin (sudo -S needs raw pipe, not PTY echo)
        const usePty = !stdin;
        ssh.exec(command, { pty: usePty }, (err, stream) => {
          if (err) {
            clearTimeout(timer);
            return finish(err);
          }

          let stdout = "";
          let stderr = "";

          // For sudo -S: wait a moment for the prompt, then send password
          // Do NOT call stream.end() — let the command finish naturally
          if (stdin) {
            setTimeout(() => {
              try { stream.write(stdin); } catch (_) {}
            }, 300);
          }

          stream.on("data", d => { stdout += d.toString(); });
          stream.stderr.on("data", d => { stderr += d.toString(); });
          stream.on("close", code => {
            clearTimeout(timer);
            if (code && code !== 0 && !stdout.trim()) {
              return finish(new Error((stderr || `Remote command failed with exit code ${code}`).trim()));
            }
            finish(null, { stdout, stderr, code: code || 0 });
          });
          stream.on("error", e => {
            clearTimeout(timer);
            finish(e);
          });
        });
      });

      ssh.on("error", err => {
        clearTimeout(timer);
        finish(err);
      });

      ssh.connect(buildSshOptions(cfg));
    } catch (err) {
      clearTimeout(timer);
      finish(err);
    }
  });
}

function testTcpPort(host, port, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.createConnection({ host, port: parseInt(port || "22", 10) });
    let settled = false;

    const finish = (payload) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (_) {}
      resolve(payload);
    };

    socket.setTimeout(timeoutMs);
    socket.on("connect", () => finish({ ok: true, latencyMs: Date.now() - started }));
    socket.on("timeout", () => finish({ ok: false, error: `TCP timeout on ${host}:${port}` }));
    socket.on("error", (err) => finish({ ok: false, error: err.message }));
  });
}

function cleanValue(value, fallback = "") {
  const out = String(value || "").trim();
  return out || fallback;
}

function firstNonEmpty(...values) {
  for (const value of values) {
    const cleaned = cleanValue(value);
    if (cleaned) return cleaned;
  }
  return "";
}

function normalizeRouterType(value = "") {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) return "OpenWRT";
  if (raw.includes("openwrt")) return "OpenWRT";
  if (raw.includes("generic")) return "Generic Router/Linux";
  return value;
}

async function sshExecValue(command, cfg, timeoutMs = 8000) {
  try {
    const result = await sshExecCommand(command, cfg, timeoutMs);
    return cleanValue(result.stdout || result.stderr || "");
  } catch {
    return "";
  }
}

function classifyNetworkTarget(value = "") {
  const raw = String(value || "").trim();
  if (!raw) return { ok: false, error: "IP or CIDR is required" };
  const [addr, prefixRaw] = raw.split("/");
  const family = net.isIP(addr);
  if (!family) return { ok: false, error: `Invalid IP or CIDR: ${raw}` };
  if (prefixRaw !== undefined) {
    if (!/^\d+$/.test(prefixRaw)) return { ok: false, error: `Invalid CIDR prefix: ${raw}` };
    const prefix = Number(prefixRaw);
    const max = family === 4 ? 32 : 128;
    if (prefix < 0 || prefix > max) return { ok: false, error: `CIDR prefix out of range: ${raw}` };
  }
  return { ok: true, target: raw, family };
}

function routerBlockTable(cfg = getRouterConfig()) {
  return normalizeRouterType(cfg.routerType) === "OpenWRT" ? "inet fw4" : "inet snortvision";
}

async function ensureOpenWrtRouterBlockEngine(cfg = getRouterConfig()) {
  const table = routerBlockTable(cfg);
  const script = `
command -v nft >/dev/null 2>&1 || { echo NFT_MISSING; exit 10; }
TABLE="${table.split(" ")[1]}"
FAMILY="${table.split(" ")[0]}"
if [ "$TABLE" = "fw4" ]; then
  nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1 || { echo FW4_TABLE_MISSING; exit 11; }
else
  nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1 || nft add table "$FAMILY" "$TABLE"
fi
nft list set "$FAMILY" "$TABLE" snortvision_block_v4 >/dev/null 2>&1 || nft 'add set ${table} snortvision_block_v4 { type ipv4_addr; flags interval,timeout; }'
nft list set "$FAMILY" "$TABLE" snortvision_block_v6 >/dev/null 2>&1 || nft 'add set ${table} snortvision_block_v6 { type ipv6_addr; flags interval,timeout; }'
if [ "$TABLE" = "fw4" ]; then
  nft list chain ${table} input >/dev/null 2>&1 && nft list chain ${table} input | grep -q 'snortvision input v4' || nft insert rule ${table} input ip saddr @snortvision_block_v4 counter drop comment "snortvision input v4"
  nft list chain ${table} input >/dev/null 2>&1 && nft list chain ${table} input | grep -q 'snortvision input v6' || nft insert rule ${table} input ip6 saddr @snortvision_block_v6 counter drop comment "snortvision input v6"
  nft list chain ${table} forward >/dev/null 2>&1 && nft list chain ${table} forward | grep -q 'snortvision forward v4' || nft insert rule ${table} forward ip saddr @snortvision_block_v4 counter drop comment "snortvision forward v4"
  nft list chain ${table} forward >/dev/null 2>&1 && nft list chain ${table} forward | grep -q 'snortvision forward v6' || nft insert rule ${table} forward ip6 saddr @snortvision_block_v6 counter drop comment "snortvision forward v6"
else
  nft list chain ${table} input >/dev/null 2>&1 || nft 'add chain ${table} input { type filter hook input priority 0; policy accept; }'
  nft list chain ${table} forward >/dev/null 2>&1 || nft 'add chain ${table} forward { type filter hook forward priority 0; policy accept; }'
  nft list chain ${table} input | grep -q 'snortvision input v4' || nft insert rule ${table} input ip saddr @snortvision_block_v4 counter drop comment "snortvision input v4"
  nft list chain ${table} input | grep -q 'snortvision input v6' || nft insert rule ${table} input ip6 saddr @snortvision_block_v6 counter drop comment "snortvision input v6"
  nft list chain ${table} forward | grep -q 'snortvision forward v4' || nft insert rule ${table} forward ip saddr @snortvision_block_v4 counter drop comment "snortvision forward v4"
  nft list chain ${table} forward | grep -q 'snortvision forward v6' || nft insert rule ${table} forward ip6 saddr @snortvision_block_v6 counter drop comment "snortvision forward v6"
fi
printf ENGINE_READY
`.trim();
  const result = await sshExecCommand(`sh -lc ${JSON.stringify(script)}`, cfg, 25000);
  const output = `${result.stdout || ""}${result.stderr || ""}`.trim();
  if (/NFT_MISSING|FW4_TABLE_MISSING/.test(output)) {
    throw new Error(output || "Router nftables engine is unavailable");
  }
  return { ok: true, engine: "router-nft", output };
}

async function applyBlockToMainRouter(target, durationMinutes = 60, cfg = getRouterConfig()) {
  const parsed = classifyNetworkTarget(target);
  if (!parsed.ok) throw new Error(parsed.error);
  if (!cleanValue(cfg.ip)) throw new Error("Main router is not configured");

  if (normalizeRouterType(cfg.routerType) === "OpenWRT") {
    await ensureOpenWrtRouterBlockEngine(cfg);
    const setName = parsed.family === 4 ? "snortvision_block_v4" : "snortvision_block_v6";
    const timeout = `${Math.max(parseInt(durationMinutes || 60, 10), 1)}m`;
    const cmd = `nft add element ${routerBlockTable(cfg)} ${setName} { ${parsed.target} timeout ${timeout} }`;
    const result = await sshExecCommand(cmd, cfg, 15000);
    db.prepare("INSERT INTO iptables_log (op,rule,applied_by) VALUES (?,?,?)").run("ADD", parsed.target, "main-router");
    return { ok: true, target: parsed.target, family: parsed.family, engine: "router-nft", output: `${result.stdout || ""}${result.stderr || ""}`.trim() };
  }

  const chainCmds = [
    `iptables -C INPUT -s ${parsed.target} -m comment --comment SNORTVISION -j DROP 2>/dev/null || iptables -I INPUT -s ${parsed.target} -m comment --comment SNORTVISION -j DROP`,
    `iptables -C FORWARD -s ${parsed.target} -m comment --comment SNORTVISION -j DROP 2>/dev/null || iptables -I FORWARD -s ${parsed.target} -m comment --comment SNORTVISION -j DROP`,
  ];
  const result = await sshExecCommand(`sh -lc ${JSON.stringify(chainCmds.join(" ; "))}`, cfg, 15000);
  db.prepare("INSERT INTO iptables_log (op,rule,applied_by) VALUES (?,?,?)").run("ADD", parsed.target, "main-router-iptables");
  return { ok: true, target: parsed.target, family: parsed.family, engine: "router-iptables", output: `${result.stdout || ""}${result.stderr || ""}`.trim() };
}

async function removeBlockFromMainRouter(target, cfg = getRouterConfig()) {
  const parsed = classifyNetworkTarget(target);
  if (!parsed.ok) throw new Error(parsed.error);
  if (!cleanValue(cfg.ip)) throw new Error("Main router is not configured");

  if (normalizeRouterType(cfg.routerType) === "OpenWRT") {
    await ensureOpenWrtRouterBlockEngine(cfg);
    const setName = parsed.family === 4 ? "snortvision_block_v4" : "snortvision_block_v6";
    const cmd = `nft delete element ${routerBlockTable(cfg)} ${setName} { ${parsed.target} }`;
    const result = await sshExecCommand(`sh -lc ${JSON.stringify(cmd + " >/dev/null 2>&1 || true")}`, cfg, 15000);
    db.prepare("INSERT INTO iptables_log (op,rule,applied_by) VALUES (?,?,?)").run("DEL", parsed.target, "main-router");
    return { ok: true, target: parsed.target, family: parsed.family, engine: "router-nft", output: `${result.stdout || ""}${result.stderr || ""}`.trim() };
  }

  const chainCmds = [
    `while iptables -C INPUT -s ${parsed.target} -m comment --comment SNORTVISION -j DROP 2>/dev/null; do iptables -D INPUT -s ${parsed.target} -m comment --comment SNORTVISION -j DROP; done`,
    `while iptables -C FORWARD -s ${parsed.target} -m comment --comment SNORTVISION -j DROP 2>/dev/null; do iptables -D FORWARD -s ${parsed.target} -m comment --comment SNORTVISION -j DROP; done`,
  ];
  const result = await sshExecCommand(`sh -lc ${JSON.stringify(chainCmds.join(" ; "))}`, cfg, 15000);
  db.prepare("INSERT INTO iptables_log (op,rule,applied_by) VALUES (?,?,?)").run("DEL", parsed.target, "main-router-iptables");
  return { ok: true, target: parsed.target, family: parsed.family, engine: "router-iptables", output: `${result.stdout || ""}${result.stderr || ""}`.trim() };
}

async function applyBlockLocally(target) {
  const parsed = classifyNetworkTarget(target);
  if (!parsed.ok) throw new Error(parsed.error);
  const result = await execLocalCommand(`iptables -C INPUT -s ${parsed.target} -m comment --comment SNORTVISION -j DROP 2>/dev/null || iptables -I INPUT -s ${parsed.target} -m comment --comment SNORTVISION -j DROP`, 15000);
  db.prepare("INSERT INTO iptables_log (op,rule,applied_by) VALUES (?,?,?)").run("ADD", parsed.target, "sensor-local");
  return { ok: true, target: parsed.target, family: parsed.family, engine: "sensor-local-iptables", output: result.output };
}

async function removeLocalBlock(target) {
  const parsed = classifyNetworkTarget(target);
  if (!parsed.ok) throw new Error(parsed.error);
  const result = await execLocalCommand(`sh -lc ${JSON.stringify(`while iptables -C INPUT -s ${parsed.target} -m comment --comment SNORTVISION -j DROP 2>/dev/null; do iptables -D INPUT -s ${parsed.target} -m comment --comment SNORTVISION -j DROP; done`)}`, 15000).catch(err => ({ output: err.output || err.message || "" }));
  db.prepare("INSERT INTO iptables_log (op,rule,applied_by) VALUES (?,?,?)").run("DEL", parsed.target, "sensor-local");
  return { ok: true, target: parsed.target, family: parsed.family, engine: "sensor-local-iptables", output: result.output || "" };
}

async function applyBlockToPreferredTarget(target, durationMinutes = 60) {
  const routerCfg = getRouterConfig();
  if (cleanValue(routerCfg.ip)) {
    try {
      return await applyBlockToMainRouter(target, durationMinutes, routerCfg);
    } catch (err) {
      return { ok: false, target, engine: "main-router", error: err.message };
    }
  }
  try {
    return await applyBlockLocally(target);
  } catch (err) {
    return { ok: false, target, engine: "sensor-local", error: err.message };
  }
}

async function removeBlockFromPreferredTarget(target) {
  const routerCfg = getRouterConfig();
  if (cleanValue(routerCfg.ip)) {
    try {
      return await removeBlockFromMainRouter(target, routerCfg);
    } catch (err) {
      return { ok: false, target, engine: "main-router", error: err.message };
    }
  }
  try {
    return await removeLocalBlock(target);
  } catch (err) {
    return { ok: false, target, engine: "sensor-local", error: err.message };
  }
}

async function fetchMainRouterBlockset(cfg = getRouterConfig()) {
  if (!cleanValue(cfg.ip)) return { ok: false, configured: false, entries: [], output: "Main router not configured" };
  if (normalizeRouterType(cfg.routerType) === "OpenWRT") {
    await ensureOpenWrtRouterBlockEngine(cfg);
    const cmd = `sh -lc ${JSON.stringify(`{ nft list set ${routerBlockTable(cfg)} snortvision_block_v4 2>/dev/null; echo '---'; nft list set ${routerBlockTable(cfg)} snortvision_block_v6 2>/dev/null; }`)}`;
    const result = await sshExecCommand(cmd, cfg, 15000);
    return { ok: true, configured: true, engine: "router-nft", output: `${result.stdout || ""}${result.stderr || ""}`.trim() };
  }
  const result = await sshExecCommand(`sh -lc ${JSON.stringify("iptables-save 2>/dev/null | grep SNORTVISION || true")}`, cfg, 15000);
  return { ok: true, configured: true, engine: "router-iptables", output: `${result.stdout || ""}${result.stderr || ""}`.trim() || "(empty)" };
}

async function reconcilePreferredBlocklist(blockEntries = []) {
  const active = blockEntries.filter(entry => Number(entry.active) === 1 || entry.active === true);
  const results = [];
  for (const entry of active) {
    results.push(await applyBlockToPreferredTarget(entry.ip, 60));
  }
  return {
    ok: results.every(r => r.ok),
    target: cleanValue(getRouterConfig().ip) ? "main-router" : "sensor-local",
    applied: results.filter(r => r.ok).length,
    failed: results.filter(r => !r.ok).length,
    results,
  };
}

async function gatherOpenWrtRouterInfo(cfg) {
  const monitorExpr = cleanValue(cfg.monitorInterface) || '$(ubus call network.interface.wan status 2>/dev/null | jsonfilter -e "@.device" 2>/dev/null)';

  const hostname = await sshExecValue(`ubus call system board 2>/dev/null | jsonfilter -e '@.hostname' 2>/dev/null || hostname 2>/dev/null || uname -n`, cfg);
  const firmware = await sshExecValue(`ubus call system board 2>/dev/null | jsonfilter -e '@.release.description' 2>/dev/null || awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2);print $2}' /etc/os-release 2>/dev/null || uname -a`, cfg);
  const wanIp = await sshExecValue(`ubus call network.interface.wan status 2>/dev/null | jsonfilter -e '@["ipv4-address"][0].address' 2>/dev/null || true`, cfg);
  const lanIp = await sshExecValue(`ubus call network.interface.lan status 2>/dev/null | jsonfilter -e '@["ipv4-address"][0].address' 2>/dev/null || true`, cfg);
  const wanIf = await sshExecValue(`ubus call network.interface.wan status 2>/dev/null | jsonfilter -e '@.device' 2>/dev/null || uci get network.wan.device 2>/dev/null || uci get network.wan.ifname 2>/dev/null || true`, cfg);
  const lanBridge = await sshExecValue(`ubus call network.interface.lan status 2>/dev/null | jsonfilter -e '@.device' 2>/dev/null || uci get network.lan.device 2>/dev/null || uci get network.lan.ifname 2>/dev/null || true`, cfg);
  const firewallZones = await sshExecValue(`uci show firewall 2>/dev/null | awk -F"'" '/zone\[[0-9]+\]\.name=/{print $2}' | paste -sd ',' -`, cfg);
  const mirrorDetected = await sshExecValue(`grep -RihE 'mirror|span|port.?mirror|tee' /etc/config 2>/dev/null | head -n 3 | tr '\n' ';'`, cfg);
  const tcpdumpState = await sshExecValue(`command -v tcpdump >/dev/null 2>&1 && echo installed || echo missing`, cfg);
  const packetCounters = await sshExecValue(`IFACE="${monitorExpr}"; [ -n "$IFACE" ] && ip -s link show "$IFACE" 2>/dev/null | awk '/RX:/{getline; rx=$1} /TX:/{getline; tx=$1} END{if(rx||tx) printf "RX=%s TX=%s", rx, tx}'`, cfg);
  const packages = await sshExecValue(`opkg list-installed 2>/dev/null | awk '/^(snort|snort3|suricata) /{print $1}' | paste -sd ',' -`, cfg);

  const candidateInterfaces = parseInterfaceList([cleanValue(cfg.monitorInterface), wanIf, lanBridge].filter(Boolean).join(",")).join(",");

  return {
    platform: "OpenWRT",
    hostname,
    firmwareVersion: firmware,
    wanIp,
    lanIp,
    monitoredInterface: firstNonEmpty(cleanValue(cfg.monitorInterface), wanIf, lanBridge),
    wanInterface: wanIf,
    lanBridge,
    bridgeNames: lanBridge,
    firewallZones,
    mirrorSpanTarget: firstNonEmpty(cleanValue(cfg.mirrorTarget), mirrorDetected, "not detected"),
    tcpdump: tcpdumpState,
    packetCounters,
    candidateInterfaces,
    packages: packages || "none detected",
  };
}

async function gatherGenericRouterInfo(cfg) {
  const hostname = await sshExecValue(`hostname 2>/dev/null || uname -n`, cfg);
  const firmware = await sshExecValue(`awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2);print $2}' /etc/os-release 2>/dev/null || uname -a`, cfg);
  const wanIp = await sshExecValue(`ip route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'`, cfg);
  const lanIp = await sshExecValue(`hostname -I 2>/dev/null | awk '{print $1}'`, cfg);
  const interfaces = await sshExecValue(`ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | paste -sd ',' -`, cfg);
  const monitorIf = firstNonEmpty(cleanValue(cfg.monitorInterface), await sshExecValue(`ip route 2>/dev/null | awk '/^default/{print $5; exit}'`, cfg));
  const tcpdumpState = await sshExecValue(`command -v tcpdump >/dev/null 2>&1 && echo installed || echo missing`, cfg);
  const packetCounters = monitorIf
    ? await sshExecValue(`ip -s link show "${monitorIf}" 2>/dev/null | awk '/RX:/{getline; rx=$1} /TX:/{getline; tx=$1} END{if(rx||tx) printf "RX=%s TX=%s", rx, tx}'`, cfg)
    : "";
  const packages = await sshExecValue(`(dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || true) | grep -Ei 'snort|suricata' | head -n 5 | tr '\n' ';'`, cfg);

  const candidateInterfaces = parseInterfaceList([cleanValue(cfg.monitorInterface), monitorIf, interfaces].filter(Boolean).join(",")).join(",");

  return {
    platform: "Generic Router/Linux",
    hostname,
    firmwareVersion: firmware,
    wanIp,
    lanIp,
    monitoredInterface: firstNonEmpty(cleanValue(cfg.monitorInterface), monitorIf),
    wanInterface: monitorIf,
    lanBridge: "",
    bridgeNames: interfaces,
    firewallZones: "not detected",
    mirrorSpanTarget: cleanValue(cfg.mirrorTarget, "not specified"),
    tcpdump: tcpdumpState,
    packetCounters,
    candidateInterfaces,
    packages: packages || "none detected",
  };
}

async function getRouterTelemetry(cfg = getRouterConfig()) {
  const info = {
    routerType: normalizeRouterType(cfg.routerType),
    ip: cleanValue(cfg.ip),
    port: cleanValue(cfg.port, "22"),
    reachable: false,
    latencyMs: null,
    sshConnected: false,
    error: "",
  };

  if (!info.ip) {
    info.error = "Router IP is not configured";
    return info;
  }

  const reachability = await testTcpPort(info.ip, info.port, 3500);
  info.reachable = !!reachability.ok;
  info.latencyMs = reachability.latencyMs ?? null;
  if (!reachability.ok) {
    info.error = reachability.error || `TCP probe failed for ${info.ip}:${info.port}`;
    return info;
  }

  try {
    await sshExecCommand('echo SNORTVISION_ROUTER_OK', cfg, 8000);
    info.sshConnected = true;
  } catch (err) {
    info.error = err.message;
    return info;
  }

  const details = info.routerType === "OpenWRT"
    ? await gatherOpenWrtRouterInfo(cfg)
    : await gatherGenericRouterInfo(cfg);

  return {
    ...info,
    ...details,
  };
}

function getNotifConfig() {
  return dbGet("notifications", {
    telegram: {
      enabled: !!(process.env.TELEGRAM_BOT_TOKEN),
      token:   process.env.TELEGRAM_BOT_TOKEN || "",
      chatId:  process.env.TELEGRAM_CHAT_ID   || "",
      minSev:  process.env.TELEGRAM_MIN_SEVERITY || "high",
    },
    email: {
      enabled: process.env.EMAIL_ENABLED === "true",
      smtp:    process.env.EMAIL_SMTP || "smtp.gmail.com",
      port:    process.env.EMAIL_PORT || "587",
      user:    process.env.EMAIL_USER || "",
      pass:    process.env.EMAIL_PASS || "",
      to:      process.env.EMAIL_TO   || "",
      minSev:  process.env.EMAIL_MIN_SEVERITY || "critical",
    },
    jira: {
      enabled: process.env.JIRA_ENABLED === "true",
      url:     process.env.JIRA_URL     || "",
      project: process.env.JIRA_PROJECT || "SEC",
      token:   process.env.JIRA_TOKEN   || "",
      minSev:  "critical",
    },
    slack: { enabled: false, webhook: "", minSev: "high" },
  });
}

// ─── Severity ────────────────────────────────────────────────────────────────
const SEV_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };
function sevAtLeast(a, min) { return (SEV_ORDER[a] || 0) >= (SEV_ORDER[min] || 0); }

// ─── Categorise alert ────────────────────────────────────────────────────────
function categorise(msg = "", snortClass = "") {
  const m = msg.toLowerCase();
  const c = (snortClass || "").toLowerCase();
  // DDoS detection — check message patterns AND snort class field
  const ddosMsg = m.includes("dos") || m.includes("flood") || m.includes("loic") ||
    m.includes("syn flood") || m.includes("icmp flood") || m.includes("udp flood") ||
    m.includes("amplif") || m.includes("reflection") || m.includes("fragmentation") ||
    m.includes("land") || m.includes("smurf") || m.includes("teardrop") ||
    m.includes("slowloris") || m.includes("hulk") || m.includes("overload") ||
    m.includes("brute") || m.includes("rate limit");
  const ddosClass = c.includes("dos") || c.includes("flood") || c.includes("attempted-dos") ||
    c.includes("denial") || c.includes("ddos");
  if (ddosMsg || ddosClass) return { category:"DDOS", severity:"critical" };
  if (m.includes("exploit") || m.includes("shellshock") || m.includes("cve-"))   return { category:"EXPLOIT", severity:"critical" };
  if (m.includes("trojan")  || m.includes("zbot") || m.includes("c2"))           return { category:"TROJAN",  severity:"critical" };
  if (m.includes("malware") || m.includes("dridex"))                              return { category:"MALWARE", severity:"high"     };
  if (m.includes("scan")    || m.includes("nmap") || m.includes("probe"))        return { category:"SCAN",    severity:"medium"   };
  if (m.includes("policy")  || m.includes("irc")  || m.includes("p2p"))         return { category:"POLICY",  severity:"low"      };
  return { category:"HUNTING", severity:"medium" };
}

// ─── Parse Snort3 alert_json line ────────────────────────────────────────────
function normaliseSnortTimestamp(value) {
  if (!value) return new Date().toISOString();
  const raw = String(value).trim();

  // Snort classic: MM/DD-HH:MM:SS(.ffffff)
  const snortClassic = raw.match(/^(\d{2})\/(\d{2})-(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/);
  if (snortClassic) {
    const [, mm, dd, hh, mi, ss, frac = "0"] = snortClassic;
    const now = new Date();
    const ms = Number((frac + "000").slice(0, 3));
    const d = new Date(
      now.getFullYear(),
      Number(mm) - 1,
      Number(dd),
      Number(hh),
      Number(mi),
      Number(ss),
      ms
    );
    return d.toISOString();
  }

  const parsed = Date.parse(raw);
  if (!Number.isNaN(parsed)) return new Date(parsed).toISOString();

  if (/^\d{10}$/.test(raw)) return new Date(Number(raw) * 1000).toISOString();
  if (/^\d{13}$/.test(raw)) return new Date(Number(raw)).toISOString();

  return new Date().toISOString();
}

function enrichAlertGeo(alert) {
  if (!alert || (!alert.src_ip && !alert.src_addr)) return alert;
  if (alert.country && String(alert.country).trim()) return alert;
  const geo = geoLookup(alert.src_ip || alert.src_addr || "");
  return {
    ...alert,
    country: alert.country || geo.country || "",
    city: alert.city || geo.city || "",
  };
}

function parseSnortLine(line) {
  try {
    const j = JSON.parse(line.trim());

    const { category, severity } = categorise(j.msg || j.message || "", j.class || "");
    const sevMap = { 1: "critical", 2: "high", 3: "medium", 4: "low" };

    const src = splitAddrPort(j.src_ap || j.src_addr || j.src_ip || "");
    const dst = splitAddrPort(j.dst_ap || j.dst_addr || j.dst_ip || "");
    const ruleInfo = parseRuleValue(j.rule || "");

    const resolvedSev = sevMap[j.priority] || severity;
    const geo = geoLookup(src.ip || "");

    // Use computed category (which already incorporates j.class via categorise)
    // This prevents snort class strings like "policy-violation" from hiding real DDoS alerts
    const resolvedCategory = category;

    return {
      ts: normaliseSnortTimestamp(j.timestamp),
      rule: j.rule || (j.sid ? `${j.gid || 1}:${j.sid}` : ruleInfo.ruleText),
      msg: j.msg || j.message || "Unknown alert",
      category: resolvedCategory,
      severity: resolvedSev,
      src_ip: src.ip,
      dst_ip: dst.ip,
      src_port: src.port,
      dst_port: dst.port,
      proto: String(j.proto || "TCP").toUpperCase(),
      action: (j.action === "drop" || j.action === "block") ? "BLOCKED" : "ALERT",
      country: geo.country || "",
      city: geo.city || "",
      raw: line.length > 2000 ? line.slice(0, 2000) : line,
    };
  } catch {
    return null;
  }
}

function splitAddrPort(value) {
  const raw = String(value || "").trim();
  if (!raw) return { ip: "0.0.0.0", port: 0 };

  const idx = raw.lastIndexOf(":");
  if (idx === -1) return { ip: raw, port: 0 };

  const ip = raw.slice(0, idx).trim() || "0.0.0.0";
  const portText = raw.slice(idx + 1).trim();
  const port = /^\d+$/.test(portText) ? Number(portText) : 0;

  return { ip, port };
}

function parseRuleValue(rule) {
  const raw = String(rule || "").trim();
  const m = raw.match(/^(\d+):(\d+):(\d+)$/);
  if (!m) {
    return { gid: 1, sid: "0", rev: 1, ruleText: raw || "0:0:0" };
  }

  return {
    gid: Number(m[1]),
    sid: m[2],
    rev: Number(m[3]),
    ruleText: `${m[1]}:${m[2]}:${m[3]}`
  };
}

// ─── Notifications ───────────────────────────────────────────────────────────
async function sendTelegram(cfg, alert) {
  if (!cfg.enabled || !cfg.token || !cfg.chatId) return;
  if (!sevAtLeast(alert.severity, cfg.minSev)) return;
  const e = { critical:"🔴", high:"🟠", medium:"🟡", low:"🟢" }[alert.severity] || "⚪";
  const text =
    `${e} *SnortVision Alert*\n` +
    `*Sev:* \`${alert.severity.toUpperCase()}\`  *Cat:* ${alert.category}\n` +
    `*Rule:* \`${alert.rule}\`\n` +
    `*Msg:* ${alert.msg}\n` +
    `*Src:* \`${alert.src_ip}:${alert.src_port}\`\n` +
    `*Dst:* \`${alert.dst_ip}:${alert.dst_port}\`\n` +
    `*Proto:* ${alert.proto}  *Action:* ${alert.action}\n` +
    `_${new Date(alert.ts).toLocaleString()}_`;
  await fetch(`https://api.telegram.org/bot${cfg.token}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: cfg.chatId, text, parse_mode: "Markdown" }),
  }).catch(e => console.error("[Telegram]", e.message));
}

async function sendEmail(cfg, alert) {
  if (!cfg.enabled || !cfg.user || !cfg.pass || !cfg.to) return;
  if (!sevAtLeast(alert.severity, cfg.minSev)) return;
  const t = nodemailer.createTransport({ host:cfg.smtp, port:parseInt(cfg.port), secure:false, auth:{user:cfg.user,pass:cfg.pass} });
  await t.sendMail({
    from: `SnortVision <${cfg.user}>`, to: cfg.to,
    subject: `[SnortVision] ${alert.severity.toUpperCase()} — ${alert.category} — ${alert.msg}`,
    text: `Rule: ${alert.rule}\nMsg: ${alert.msg}\nSrc: ${alert.src_ip}:${alert.src_port}\nDst: ${alert.dst_ip}:${alert.dst_port}\nProto: ${alert.proto}\nAction: ${alert.action}\nTime: ${alert.ts}`,
  }).catch(e => console.error("[Email]", e.message));
}

async function sendSlack(cfg, alert) {
  if (!cfg.enabled || !cfg.webhook) return;
  if (!sevAtLeast(alert.severity, cfg.minSev)) return;
  const color = { critical:"#ff2d55", high:"#ff9f0a", medium:"#ffd60a", low:"#30d158" }[alert.severity] || "#8e8e93";
  await fetch(cfg.webhook, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ attachments: [{ color, title: `🛡️ SnortVision — ${alert.severity.toUpperCase()}`,
      fields: [
        { title:"Message",  value:alert.msg,      short:false },
        { title:"Category", value:alert.category, short:true  },
        { title:"Source",   value:`${alert.src_ip}:${alert.src_port}`, short:true },
        { title:"Action",   value:alert.action,   short:true  },
      ]}]
    }),
  }).catch(e => console.error("[Slack]", e.message));
}

async function dispatchNotifications(alert) {
  const cfg = getNotifConfig();
  await Promise.allSettled([
    sendTelegram(cfg.telegram, alert),
    sendEmail(cfg.email, alert),
    sendSlack(cfg.slack, alert),
  ]);
}

// ─── Log tail (local or SSH) ─────────────────────────────────────────────────
let sshClient  = null;
let localChild = null;

function startTail(onLine) {
  const cfg = getConnConfig();

  // ── Local mode: no SSH, tail the file directly on this machine ──
  if (!cfg.ip) {
    const logPath = cfg.logPath || process.env.SNORT_LOG_PATH || "/var/log/snort/alert_json.txt";
    if (!fs.existsSync(logPath)) {
      console.log(`[Local] Log file not found: ${logPath} — waiting for it to appear…`);
      // Retry every 10s until file appears
      setTimeout(() => startTail(onLine), 10000);
      return;
    }
    console.log(`[Local] Tailing ${logPath} (no SSH — local mode)`);
    if (localChild) { try { localChild.kill(); } catch(_){} localChild = null; }

    const child = spawn("tail", ["-n", "0", "-F", logPath]);
    localChild = child;
    let buf = "";
    child.stdout.on("data", d => {
      buf += d.toString();
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const l of lines) { if (l.trim()) onLine(l); }
    });
    child.stderr.on("data", d => {
      const msg = d.toString().trim();
      if (msg && !msg.includes("file truncated")) console.warn("[Local stderr]", msg);
    });
    child.on("close", code => {
      console.log(`[Local] tail exited (code ${code}) — restarting in 5s…`);
      localChild = null;
      setTimeout(() => startTail(onLine), 5000);
    });
    child.on("error", err => {
      console.error("[Local] spawn error:", err.message);
      setTimeout(() => startTail(onLine), 10000);
    });
    return;
  }

  // ── SSH mode: tail via SSH tunnel ──
  if (sshClient) { try { sshClient.end(); } catch(_){} sshClient = null; }

  const ssh = new Client();
  sshClient = ssh;

  let opts;
  try {
    opts = buildSshOptions(cfg);
  } catch (err) {
    console.warn(`[SSH] ${err.message}`);
    return;
  }

  // Guard: prevent double-reconnect if both stream.close and ssh.close fire
  let reconnectScheduled = false;
  function scheduleReconnect(delayMs, reason) {
    if (reconnectScheduled) return;
    reconnectScheduled = true;
    if (sshClient === ssh) sshClient = null;
    try { ssh.end(); } catch (_) {}
    console.log(`[SSH] ${reason} — reconnecting in ${delayMs / 1000}s…`);
    setTimeout(() => startTail(onLine), delayMs);
  }

  ssh.on("ready", () => {
    console.log(`[SSH] Connected → ${cfg.ip}  tailing ${cfg.logPath}`);
    // Use shell() instead of exec() — shell sessions are persistent and survive
    // server-side exec timeouts that kill long-running exec channels.
    ssh.shell({ term: "dumb", rows: 24, cols: 200 }, (err, stream) => {
      if (err) {
        console.error("[SSH] shell:", err.message);
        scheduleReconnect(5000, "shell open failed");
        return;
      }
      let buf = "";
      stream.on("data", d => {
        buf += d.toString();
        const lines = buf.split("\n");
        buf = lines.pop();
        for (const l of lines) {
          const t = l.trim();
          // Skip shell prompts and the echo of our own command
          if (!t || t.startsWith("tail -F") || t.match(/^[\w@.~$#%>\]]+\s*[\$#>]\s*$/)) continue;
          onLine(t);
        }
      });
      stream.stderr.on("data", d => {
        const msg = d.toString().trim();
        if (msg && !msg.includes("file truncated")) console.warn("[SSH stderr]", msg);
      });
      stream.on("close", () => scheduleReconnect(5000, "stream closed"));
      // Send the tail command into the shell
      stream.write(`tail -n 0 -F "${cfg.logPath}"\n`);
    });
  });

  ssh.on("error", err => {
    console.error("[SSH] Error:", err.message);
    scheduleReconnect(10000, `error: ${err.message}`);
  });

  // Connection-level close (TCP dropped, keepalive timeout, etc.)
  ssh.on("close", () => scheduleReconnect(5000, "connection closed"));
  ssh.on("end",   () => scheduleReconnect(5000, "connection ended"));

  ssh.connect(opts);
}

// ─── Express + WebSocket ─────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server, path: "/ws" });

// Allow requests from any origin that the frontend might be served from.
// Set CORS_ORIGIN env var to restrict (e.g. https://snort.rodrigues.lu).
// Default '*' keeps local dev working out of the box.
const corsOrigin = process.env.CORS_ORIGIN || '*';
app.use(cors({
  origin: corsOrigin === '*' ? '*' : corsOrigin.split(',').map(s => s.trim()),
  credentials: corsOrigin !== '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','x-api-key'],
}));
app.options('*', cors());
app.use(express.json());

const FRONTEND_DIST = path.resolve(__dirname, "..", "frontend", "dist");
const FRONTEND_INDEX = path.join(FRONTEND_DIST, "index.html");
const HAS_FRONTEND_DIST = fs.existsSync(FRONTEND_INDEX);

if (HAS_FRONTEND_DIST) {
  app.use(express.static(FRONTEND_DIST));
}

app.get("/", (req, res) => {
  if (HAS_FRONTEND_DIST) return res.sendFile(FRONTEND_INDEX);
  res.json({
    ok: true,
    app: "SnortVision backend",
    version: "0.1",
    message: "Backend is running. This port serves the API, not the frontend UI.",
    endpoints: {
      public_health: "/api/public/health",
      protected_health: "/api/health?key=YOUR_API_KEY",
      websocket: "/ws",
    },
  });
});

app.get("/api/public/health", (req, res) => {
  res.json({
    ok: true,
    app: "SnortVision backend",
    version: "0.1",
    auth_required: !!API_KEY,
    timestamp: new Date().toISOString(),
  });
});

// Optional API key auth middleware
function auth(req, res, next) {
  if (!API_KEY) return next();
  const k = req.headers["x-api-key"] || req.query.key;
  if (k !== API_KEY) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// Broadcast to all WS clients
function broadcast(type, data) {
  const msg = JSON.stringify({ type, data });
  for (const c of wss.clients) {
    if (c.readyState === WebSocket.OPEN) c.send(msg);
  }
}

// New WS client → send history
wss.on("connection", ws => {
  const history = db.prepare("SELECT * FROM alerts ORDER BY ts DESC LIMIT 200").all();
  ws.send(JSON.stringify({ type: "history", data: history.reverse() }));
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get("/api/health", auth, async (req, res) => {
  const alerts_total = db.prepare("SELECT COUNT(*) as c FROM alerts").get().c;
  const blocklist_count = db.prepare("SELECT COUNT(*) as c FROM blocklist").get().c;
  const rules_count = db.prepare("SELECT COUNT(*) as c FROM rules").get().c;

  let db_size = "—";
  try {
    const s = fs.statSync(DB_PATH);
    db_size = (s.size / 1024 / 1024).toFixed(1) + " MB";
  } catch (_) {}

  const recentAlerts = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE ts > datetime('now','-5 seconds')").get().c;
  const alert_pps = Math.round(recentAlerts / 5);
  const ddos_alerts_10s = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE category='DDOS' AND ts > datetime('now','-10 seconds')").get().c;

  const traffic = await getTrafficTelemetry().catch(err => ({
    real: false,
    interface: SENSOR_INTERFACE || "",
    source: "error",
    error: err.message,
    rx_pps: 0,
    tx_pps: 0,
    packet_pps: 0,
    mbps: 0,
  }));

  const tailMode = localChild ? "local" : sshClient ? "ssh" : "none";
  const maskedKey = API_KEY ? API_KEY.slice(0, 6) + "••••••••" + API_KEY.slice(-4) : "(none)";

  const cfg = getConnConfig();
  const alertPath = cfg.logPath || process.env.SNORT_LOG_PATH || "/var/log/snort/alert_json.txt";
  let alert_file = { path: alertPath, exists: false, size: 0, readable: false };

  try {
    const stat = fs.statSync(alertPath);
    alert_file.exists = true;
    alert_file.size = stat.size;
    alert_file.modified = stat.mtime.toISOString();
    fs.accessSync(alertPath, fs.constants.R_OK);
    alert_file.readable = true;
  } catch (e) {
    alert_file.error = e.message;
  }

  const ddos_detected =
    traffic.packet_pps >= DDOS_PACKET_PPS_THRESHOLD ||
    ddos_alerts_10s >= DDOS_ALERT_RATE_THRESHOLD;

  res.json({
    ok: true,
    alerts_total,
    blocklist_count,
    rules_count,
    db_size,
    tail_mode: tailMode,
    api_key_masked: maskedKey,
    alert_file,
    alert_pps,
    packet_pps: traffic.packet_pps,
    rx_pps: traffic.rx_pps,
    tx_pps: traffic.tx_pps,
    mbps: traffic.mbps,
    traffic_real: traffic.real,
    traffic_source: traffic.source,
    sensor_interface: traffic.interface,
    ddos_alerts_10s,
    ddos_detected,
  });
});

// ── Alerts ────────────────────────────────────────────────────────────────────
app.get("/api/alerts", auth, (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit  || "100"), 1000);
  const offset = parseInt(req.query.offset || "0");
  const sev    = req.query.severity;
  const q      = req.query.q;
  let sql = "SELECT * FROM alerts", params = [], where = [];
  if (sev && sev !== "all") { where.push("severity = ?"); params.push(sev); }
  if (q)                    { where.push("(msg LIKE ? OR src_ip LIKE ?)"); params.push(`%${q}%`, `%${q}%`); }
  if (where.length) sql += " WHERE " + where.join(" AND ");
  sql += " ORDER BY ts DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);
  const data  = db.prepare(sql).all(...params).map(enrichAlertGeo);
  const total = db.prepare("SELECT COUNT(*) as c FROM alerts").get().c;
  res.json({ data, total });
});

// New alerts since id — used by frontend polling
app.get("/api/alerts/new", auth, async (req, res) => {
  const since = parseInt(req.query.since) || 0;
  const alerts = db.prepare("SELECT * FROM alerts WHERE id > ? ORDER BY id ASC LIMIT 100").all(since).map(enrichAlertGeo);

  const recentAlerts = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE ts > datetime('now','-5 seconds')").get().c;
  const alert_pps = Math.round(recentAlerts / 5);
  const ddos_alerts_10s = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE category='DDOS' AND ts > datetime('now','-10 seconds')").get().c;

  const traffic = await getTrafficTelemetry().catch(() => ({
    real: false,
    interface: SENSOR_INTERFACE || "",
    source: "error",
    rx_pps: 0,
    tx_pps: 0,
    packet_pps: 0,
    mbps: 0,
  }));

  const ddos_detected =
    traffic.packet_pps >= DDOS_PACKET_PPS_THRESHOLD ||
    ddos_alerts_10s >= DDOS_ALERT_RATE_THRESHOLD;

  res.json({
    alerts,
    alert_pps,
    packet_pps: traffic.packet_pps,
    rx_pps: traffic.rx_pps,
    tx_pps: traffic.tx_pps,
    mbps: traffic.mbps,
    traffic_real: traffic.real,
    traffic_source: traffic.source,
    sensor_interface: traffic.interface,
    ddos_alerts_10s,
    ddos_detected,
  });
});

// ── Stats ─────────────────────────────────────────────────────────────────────
app.get("/api/stats", auth, async (req, res) => {
  const total = db.prepare("SELECT COUNT(*) as c FROM alerts").get().c;
  const critical = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE severity='critical'").get().c;
  const blocked = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE action='BLOCKED'").get().c;
  const lastMin = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE ts > datetime('now','-1 minute')").get().c;

  const recentAlerts = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE ts > datetime('now','-5 seconds')").get().c;
  const alert_pps = Math.round(recentAlerts / 5);
  const ddos_alerts_10s = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE category='DDOS' AND ts > datetime('now','-10 seconds')").get().c;

  const traffic = await getTrafficTelemetry().catch(() => ({
    real: false,
    interface: SENSOR_INTERFACE || "",
    source: "error",
    rx_pps: 0,
    tx_pps: 0,
    packet_pps: 0,
    mbps: 0,
  }));

  const ddos_detected =
    traffic.packet_pps >= DDOS_PACKET_PPS_THRESHOLD ||
    ddos_alerts_10s >= DDOS_ALERT_RATE_THRESHOLD;

  res.json({
    total,
    critical,
    blocked,
    lastMin,
    alert_pps,
    packet_pps: traffic.packet_pps,
    rx_pps: traffic.rx_pps,
    tx_pps: traffic.tx_pps,
    mbps: traffic.mbps,
    traffic_real: traffic.real,
    traffic_source: traffic.source,
    sensor_interface: traffic.interface,
    ddos_alerts_10s,
    ddos_detected,
  });
});

// ── Blocklist ─────────────────────────────────────────────────────────────────
app.get("/api/blocklist", auth, (req, res) => {
  res.json(db.prepare("SELECT * FROM blocklist ORDER BY id DESC").all());
});

app.post("/api/blocklist", auth, async (req, res) => {
  const { ip, reason, source, active = true, durationMinutes = 60 } = req.body || {};
  const parsed = classifyNetworkTarget(ip);
  if (!parsed.ok) return res.status(400).json({ ok: false, message: parsed.error });
  try {
    db.prepare("INSERT OR REPLACE INTO blocklist (ip,reason,source,active) VALUES (?,?,?,?)").run(parsed.target, reason || "Manual", source || "Manual", active ? 1 : 0);
    const row = db.prepare("SELECT * FROM blocklist WHERE ip=?").get(parsed.target);
    const enforcement = active ? await applyBlockToPreferredTarget(parsed.target, durationMinutes) : { ok: true, target: parsed.target, engine: "database-only" };
    res.json({ ok: true, row, enforcement, target: cleanValue(getRouterConfig().ip) ? "main-router" : "sensor-local" });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

app.put("/api/blocklist/:id", auth, async (req, res) => {
  const existing = db.prepare("SELECT * FROM blocklist WHERE id=?").get(req.params.id);
  if (!existing) return res.status(404).json({ ok: false, message: "Block entry not found" });

  const nextReason = req.body?.reason ?? existing.reason;
  const nextSource = req.body?.source ?? existing.source;
  const nextActive = req.body?.active === undefined ? existing.active : (req.body.active ? 1 : 0);

  db.prepare("UPDATE blocklist SET reason=?, source=?, active=? WHERE id=?").run(nextReason, nextSource, nextActive, req.params.id);
  const row = db.prepare("SELECT * FROM blocklist WHERE id=?").get(req.params.id);
  const enforcement = nextActive ? await applyBlockToPreferredTarget(row.ip, req.body?.durationMinutes || 60) : await removeBlockFromPreferredTarget(row.ip);
  res.json({ ok: true, row, enforcement });
});

app.delete("/api/blocklist/:id", auth, async (req, res) => {
  const existing = db.prepare("SELECT * FROM blocklist WHERE id=?").get(req.params.id);
  if (!existing) return res.status(404).json({ ok: false, message: "Block entry not found" });
  const enforcement = await removeBlockFromPreferredTarget(existing.ip);
  db.prepare("DELETE FROM blocklist WHERE id=?").run(req.params.id);
  res.json({ ok: true, enforcement });
});

// Sync blocklist → preferred enforcement target (main router first)
app.post("/api/blocklist/sync", auth, async (req, res) => {
  const active = db.prepare("SELECT * FROM blocklist WHERE active=1 ORDER BY id DESC").all();
  try {
    const result = await reconcilePreferredBlocklist(active);
    res.json({ ok: result.ok, synced: active.length, applied: result.applied, failed: result.failed, target: result.target, results: result.results });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.post("/api/router/block", auth, async (req, res) => {
  try {
    const result = await applyBlockToMainRouter(req.body?.ip, req.body?.durationMinutes || 60, getRouterConfig());
    res.json({ ok: true, result });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.post("/api/router/unblock", auth, async (req, res) => {
  try {
    const result = await removeBlockFromMainRouter(req.body?.ip, getRouterConfig());
    res.json({ ok: true, result });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.post("/api/router/reconcile", auth, async (req, res) => {
  const active = db.prepare("SELECT * FROM blocklist WHERE active=1 ORDER BY id DESC").all();
  try {
    const result = await reconcilePreferredBlocklist(active);
    res.json({ ok: result.ok, synced: active.length, applied: result.applied, failed: result.failed, target: result.target, results: result.results });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.get("/api/router/block-status", auth, async (req, res) => {
  const cfg = getRouterConfig();
  if (!cleanValue(cfg.ip)) return res.json({ ok: false, configured: false, message: "Main router not configured" });
  try {
    const info = await getRouterTelemetry(cfg);
    res.json({ ok: true, configured: true, target: cfg.ip, hostname: info.hostname || "", routerType: normalizeRouterType(cfg.routerType), monitorInterface: info.monitoredInterface || cfg.monitorInterface || "", reachable: info.reachable, sshConnected: info.sshConnected, engine: normalizeRouterType(cfg.routerType) === "OpenWRT" ? "router-nft" : "router-iptables" });
  } catch (err) {
    res.status(500).json({ ok: false, configured: true, message: err.message });
  }
});

app.get("/api/router/blockset", auth, async (req, res) => {
  try {
    const result = await fetchMainRouterBlockset(getRouterConfig());
    res.json(result);
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// ── Rules ─────────────────────────────────────────────────────────────────────
app.get("/api/rules", auth, (req, res) => {
  res.json(db.prepare("SELECT * FROM rules ORDER BY id ASC").all());
});

app.post("/api/rules", auth, (req, res) => {
  const r = req.body;
  const result = db.prepare(`INSERT INTO rules (sid,gid,rev,enabled,action,proto,src,sport,dir,dst,dport,msg,cat,sev)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(r.sid,r.gid||1,r.rev||1,r.enabled?1:0,r.action||"alert",
    r.proto||"TCP",r.src||"any",r.sport||"any",r.dir||"->",r.dst||"$HOME_NET",r.dport||"any",r.msg,r.cat,r.sev);
  res.json({ ok: true, id: result.lastInsertRowid });
});

app.put("/api/rules/:id", auth, (req, res) => {
  const r = req.body;
  db.prepare(`UPDATE rules SET sid=?,gid=?,rev=?,enabled=?,action=?,proto=?,src=?,sport=?,dir=?,dst=?,dport=?,msg=?,cat=?,sev=?
    WHERE id=?`).run(r.sid,r.gid||1,r.rev||1,r.enabled?1:0,r.action,r.proto,r.src,r.sport,r.dir,r.dst,r.dport,r.msg,r.cat,r.sev,req.params.id);
  res.json({ ok: true });
});

app.delete("/api/rules/:id", auth, (req, res) => {
  db.prepare("DELETE FROM rules WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.post("/api/rules/deploy", auth, (req, res) => {
  const rules = db.prepare("SELECT * FROM rules WHERE enabled=1").all();
  const RULES_PATH = process.env.RULES_PATH || "/etc/snort/rules/snortvision.rules";
  const lines = rules.map(r =>
    `${r.action} ${r.proto.toLowerCase()} ${r.src} ${r.sport} ${r.dir} ${r.dst} ${r.dport} (msg:"${r.msg}"; sid:${r.sid}; gid:${r.gid}; rev:${r.rev};)`
  );
  try {
    fs.mkdirSync(path.dirname(RULES_PATH), { recursive: true });
    fs.writeFileSync(RULES_PATH, lines.join("\n") + "\n");
    const reload = process.env.SNORT_RELOAD_CMD || "";
    if (reload) exec(reload, err => { if (err) console.error("[Rules] reload:", err.message); });
    res.json({ ok: true, rules_written: lines.length, path: RULES_PATH });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Oinkcode — update Snort rules via PulledPork3 (official layout + managed config) ──
app.post("/api/rules/oinkcode", auth, async (req, res) => {
  const { oinkcode, autoInstall = true } = req.body || {};
  const trimmedOinkcode = cleanValue(oinkcode);
  if (trimmedOinkcode.length < 10) {
    return res.status(400).json({ ok: false, message: "Invalid Oinkcode" });
  }

  updateEnvFile({ OINKCODE: trimmedOinkcode });

  const cfg = getConnConfig();
  const isRemote = cleanValue(cfg.ip).length > 0;
  const rulesDir = process.env.RULES_PATH ? path.dirname(process.env.RULES_PATH) : "/etc/snort/rules";
  const localRulesPath = process.env.RULES_PATH || path.join(rulesDir, "snortvision.rules");
  const pulledPorkConf = process.env.PULLEDPORK_CONF || "/usr/local/etc/pulledpork/pulledpork.conf";
  const pulledPorkRepoDir = process.env.PULLEDPORK_REPO_DIR || "/opt/pulledpork3";
  const pulledPorkInstallDir = process.env.PULLEDPORK_INSTALL_DIR || "/usr/local/bin/pulledpork";
  const pulledPorkScriptPath = path.join(pulledPorkInstallDir, "pulledpork.py");
  const pulledPorkVenvDir = process.env.PULLEDPORK_VENV_DIR || `${pulledPorkRepoDir}/.venv`;
  const pulledPorkRulePath = process.env.PULLEDPORK_RULE_PATH || path.join(rulesDir, "snort.rules");
  const pulledPorkBlocklistPath = process.env.PULLEDPORK_BLOCKLIST_PATH || path.join(rulesDir, "iplists", "default.blocklist");
  const reloadCmd = cleanValue(process.env.SNORT_RELOAD_CMD);
  const sudoSecret = cleanValue(cfg.sudoPassword || cfg.password || "");
  const runnerKind = isRemote ? `ssh:${cfg.user || "snort"}@${cfg.ip}` : "local";
  const manualHint = `/usr/local/bin/pulledpork3 -c ${pulledPorkConf} -i`;

  const shellQuote = (value = "") => `'${String(value).replace(/'/g, `'"'"'`)}'`;
  const scriptToCommand = (script = "") => `sh -s <<'__SNORTVISION__'\n${String(script).trim()}\n__SNORTVISION__`;
  const wrapWithRc = (raw = "") => `${String(raw).trim()}\nRC=$?\necho __SNORTVISION_RC__=$RC`;

  const runCmd = async (command, timeoutMs = 180000, stdin = null) => {
    if (isRemote) return sshExecCommand(command, cfg, timeoutMs, stdin);
    return execLocalCommand(command, timeoutMs);
  };

  const parseMethod = (raw = "") => {
    const m = String(raw).match(/PULLEDPORK_METHOD=([^\n\r]+)/);
    const token = cleanValue(m?.[1] || "missing");
    const map = {
      pulledpork3: {
        token: "pulledpork3",
        label: "/usr/local/bin/pulledpork3",
        baseCmd: `/usr/local/bin/pulledpork3 -c ${shellQuote(pulledPorkConf)} -i`,
      },
      pulledpork_py: {
        token: "pulledpork_py",
        label: "/usr/local/bin/pulledpork.py",
        baseCmd: `/usr/local/bin/pulledpork.py -c ${shellQuote(pulledPorkConf)} -i`,
      },
      pulledpork_py_full: {
        token: "pulledpork_py_full",
        label: `python3 ${pulledPorkScriptPath}`,
        baseCmd: `python3 ${shellQuote(pulledPorkScriptPath)} -c ${shellQuote(pulledPorkConf)} -i`,
      },
    };
    return map[token] || { token: "missing", label: "missing", baseCmd: "" };
  };

  const detectScript = `
set -e
mkdir -p ${shellQuote(rulesDir)}
if [ -x /usr/local/bin/pulledpork3 ] && /usr/local/bin/pulledpork3 -V >/dev/null 2>&1; then
  echo PULLEDPORK_METHOD=pulledpork3
elif command -v pulledpork3 >/dev/null 2>&1 && pulledpork3 -V >/dev/null 2>&1; then
  echo PULLEDPORK_METHOD=pulledpork3
elif [ -x /usr/local/bin/pulledpork.py ] && /usr/local/bin/pulledpork.py -V >/dev/null 2>&1; then
  echo PULLEDPORK_METHOD=pulledpork_py
elif command -v pulledpork.py >/dev/null 2>&1 && pulledpork.py -V >/dev/null 2>&1; then
  echo PULLEDPORK_METHOD=pulledpork_py
elif [ -f ${shellQuote(pulledPorkScriptPath)} ] && python3 ${shellQuote(pulledPorkScriptPath)} -V >/dev/null 2>&1; then
  echo PULLEDPORK_METHOD=pulledpork_py_full
else
  echo PULLEDPORK_METHOD=missing
fi
`;

  const privilegeBootstrap = (purpose = "install") => `
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo ${String(purpose || "install").toUpperCase()}_ERROR=sudo_not_available
    exit 97
  fi
  SUDO="sudo -S -p ''"
  $SUDO -v >/dev/null 2>&1
fi
`;

  const buildInstallScript = () => `
set -e
${privilegeBootstrap("install")}
PKG_OK=0
if command -v apt-get >/dev/null 2>&1; then
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y git ca-certificates python3 python3-pip python3-venv python3-requests
  PKG_OK=1
elif command -v dnf >/dev/null 2>&1; then
  $SUDO dnf install -y git ca-certificates python3 python3-pip python3-requests
  PKG_OK=1
elif command -v yum >/dev/null 2>&1; then
  $SUDO yum install -y git ca-certificates python3 python3-pip python3-requests
  PKG_OK=1
fi
if [ "$PKG_OK" != "1" ]; then
  echo INSTALL_ERROR=unsupported_package_manager
  exit 98
fi
REPO_DIR=${shellQuote(pulledPorkRepoDir)}
INSTALL_DIR=${shellQuote(pulledPorkInstallDir)}
CONF_DIR="$(dirname ${shellQuote(pulledPorkConf)})"
VENV_DIR=${shellQuote(pulledPorkVenvDir)}
if [ -d "$REPO_DIR/.git" ]; then
  $SUDO git -C "$REPO_DIR" pull --ff-only
else
  $SUDO rm -rf "$REPO_DIR"
  $SUDO git clone https://github.com/shirkdog/pulledpork3.git "$REPO_DIR"
fi
$SUDO mkdir -p "$CONF_DIR" "$INSTALL_DIR"
$SUDO cp "$REPO_DIR/etc/pulledpork.conf" "$CONF_DIR/"
$SUDO cp "$REPO_DIR/pulledpork.py" "$INSTALL_DIR/"
$SUDO rm -rf "$INSTALL_DIR/lib"
$SUDO cp -r "$REPO_DIR/lib" "$INSTALL_DIR/"
$SUDO chmod +x "$INSTALL_DIR/pulledpork.py"
$SUDO ln -sf "$INSTALL_DIR/pulledpork.py" /usr/local/bin/pulledpork.py
if command -v python3 >/dev/null 2>&1 && python3 -m venv --help >/dev/null 2>&1; then
  $SUDO rm -rf "$VENV_DIR"
  $SUDO python3 -m venv "$VENV_DIR"
  $SUDO "$VENV_DIR/bin/pip" install --upgrade pip wheel >/dev/null 2>&1 || true
  if [ -f "$REPO_DIR/requirements.txt" ]; then
    $SUDO "$VENV_DIR/bin/pip" install -r "$REPO_DIR/requirements.txt"
  fi
fi
WRAP_FILE="$(mktemp)"
cat > "$WRAP_FILE" <<EOF
#!/usr/bin/env sh
PY=${shellQuote(path.join(pulledPorkVenvDir, 'bin', 'python3'))}
if [ ! -x "$PY" ]; then
  PY="$(command -v python3)"
fi
exec "$PY" ${shellQuote(pulledPorkScriptPath)} "$@"
EOF
$SUDO cp "$WRAP_FILE" /usr/local/bin/pulledpork3
$SUDO chmod +x /usr/local/bin/pulledpork3
rm -f "$WRAP_FILE"
/usr/local/bin/pulledpork3 -V 2>&1 || true
`;

  const buildConfigScript = () => `
set -e
${privilegeBootstrap("config")}
RULES_DIR=${shellQuote(rulesDir)}
LOCAL_RULES=${shellQuote(localRulesPath)}
PP_CONF=${shellQuote(pulledPorkConf)}
PP_RULE_PATH=${shellQuote(pulledPorkRulePath)}
PP_BLOCKLIST=${shellQuote(pulledPorkBlocklistPath)}
PP_INSTALL_DIR=${shellQuote(pulledPorkInstallDir)}
$SUDO mkdir -p "$RULES_DIR" "$(dirname "$PP_RULE_PATH")" "$(dirname "$PP_BLOCKLIST")" "$(dirname "$PP_CONF")" "$PP_INSTALL_DIR"
TMP_CONF="$(mktemp)"
cat > "$TMP_CONF" <<EOF
# SnortVision managed PulledPork3 configuration
community_ruleset = false
registered_ruleset = false
lightspd_ruleset = true
oinkcode = ${trimmedOinkcode}
rule_mode = simple
ips_policy = connectivity
rule_path = $PP_RULE_PATH
blocklist_path = $PP_BLOCKLIST
ignored_files = includes.rules, snort3-deleted.rules
temp_path = /tmp
EOF
if [ -f "$LOCAL_RULES" ]; then
  printf 'local_rules = %s\n' "$LOCAL_RULES" >> "$TMP_CONF"
fi
SNORT_BIN="$(command -v snort 2>/dev/null || command -v snort3 2>/dev/null || true)"
if [ -n "$SNORT_BIN" ]; then
  printf 'snort_path = %s\n' "$SNORT_BIN" >> "$TMP_CONF"
fi
$SUDO cp "$TMP_CONF" "$PP_CONF"
rm -f "$TMP_CONF"
`;

  const buildUpdateScript = (methodInfo) => `
set +e
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo -S -p ''"
    $SUDO -v >/dev/null 2>&1 || exit 97
  else
    SUDO=""
  fi
fi
$SUDO ${methodInfo.baseCmd}
RC=$?
echo __SNORTVISION_RC__=$RC
`;

  let stage = "detect";
  let method = { token: "missing", label: "missing", baseCmd: "" };
  let autoInstalled = false;
  let installOutput = "";

  try {
    let detect = await runCmd(scriptToCommand(detectScript), 30000);
    let detectOut = `${detect.stdout || detect.output || ""}${detect.stderr || ""}`.trim();
    method = parseMethod(detectOut);

    if (method.token === "missing" && autoInstall) {
      const needsSudoSecret = (isRemote && cleanValue(cfg.user).toLowerCase() !== "root") || (!isRemote && process.getuid && process.getuid() !== 0);
      if (needsSudoSecret && !sudoSecret) {
        return res.json({
          ok: false,
          applied: false,
          runner: runnerKind,
          method: "missing",
          stage: "install",
          message: "PulledPork is missing and automatic install requires a sudo password on the Snort host",
          install_hint: `Set the Snort Sensor sudo password in the Connection page for ${cfg.user || "snort"}@${cfg.ip || "localhost"}`,
          hint: manualHint,
        });
      }

      stage = "install";
      const install = await runCmd(scriptToCommand(buildInstallScript()), 420000, sudoSecret ? `${sudoSecret}\n` : null);
      installOutput = `${install.stdout || install.output || ""}${install.stderr || ""}`.trim();
      autoInstalled = true;

      detect = await runCmd(scriptToCommand(detectScript), 30000);
      detectOut = `${detect.stdout || detect.output || ""}${detect.stderr || ""}`.trim();
      method = parseMethod(detectOut);
    }

    if (method.token === "missing") {
      return res.json({
        ok: false,
        applied: false,
        runner: runnerKind,
        method: "missing",
        stage,
        auto_installed: autoInstalled,
        install_output: installOutput.slice(-4000),
        message: autoInstalled ? "PulledPork automatic install did not produce a usable runner" : "No usable PulledPork runner was found on the Snort host",
        install_hint: isRemote ? `SSH to ${cfg.user || "snort"}@${cfg.ip} and validate /usr/local/bin/pulledpork3 -V` : "Validate /usr/local/bin/pulledpork3 -V on the backend host",
        hint: manualHint,
      });
    }

    stage = "configure";
    const confResult = await runCmd(scriptToCommand(buildConfigScript()), 60000, sudoSecret ? `${sudoSecret}\n` : null);
    const confOutput = `${confResult.stdout || confResult.output || ""}${confResult.stderr || ""}`.trim();

    stage = "update";
    const result = await runCmd(scriptToCommand(buildUpdateScript(method)), 300000, sudoSecret ? `${sudoSecret}\n` : null);
    const output = `${result.stdout || result.output || ""}${result.stderr || ""}`.trim();
    const rcMatch = output.match(/__SNORTVISION_RC__=(\d+)/);
    const updateRc = rcMatch ? parseInt(rcMatch[1], 10) : 1;
    const cleanedOutput = output.replace(/__SNORTVISION_RC__=\d+\s*$/m, "").trim();

    const countResult = await runCmd(scriptToCommand(`[ -f ${shellQuote(pulledPorkRulePath)} ] && echo 1 || echo 0`), 15000);
    const rulesUpdated = parseInt(String(countResult.stdout || countResult.output || "0").trim(), 10) || 0;

    let reload = { attempted: false, ok: false, rc: null, message: "No reload command configured" };
    if (reloadCmd) {
      try {
        stage = "reload";
        const reloadResult = await runCmd(scriptToCommand(`${wrapWithRc(reloadCmd)}`), 60000, sudoSecret ? `${sudoSecret}\n` : null);
        const reloadOutput = `${reloadResult.stdout || reloadResult.output || ""}${reloadResult.stderr || ""}`.trim();
        const reloadRcMatch = reloadOutput.match(/__SNORTVISION_RC__=(\d+)/);
        const reloadRc = reloadRcMatch ? parseInt(reloadRcMatch[1], 10) : 1;
        reload = {
          attempted: true,
          ok: reloadRc === 0,
          rc: reloadRc,
          message: cleanValue(reloadOutput.replace(/__SNORTVISION_RC__=\d+\s*$/m, "").trim(), reloadRc === 0 ? "Reload command executed" : "Reload command failed"),
        };
      } catch (err) {
        reload = { attempted: true, ok: false, rc: null, message: err.output || err.message };
      }
    }

    if (updateRc !== 0) {
      return res.json({
        ok: false,
        applied: false,
        runner: runnerKind,
        method: method.label,
        stage,
        auto_installed: autoInstalled,
        install_output: installOutput.slice(-4000),
        config_output: confOutput.slice(-4000),
        rules_updated: rulesUpdated,
        rules_path: rulesDir,
        reload,
        message: `Rule update failed via ${method.label} on ${runnerKind}`,
        error: cleanedOutput.slice(-4000) || `Command exited with rc=${updateRc}`,
        rc: updateRc,
        hint: manualHint,
      });
    }

    return res.json({
      ok: true,
      applied: true,
      runner: runnerKind,
      method: method.label,
      stage,
      auto_installed: autoInstalled,
      install_output: installOutput.slice(-4000),
      config_output: confOutput.slice(-4000),
      rc: updateRc,
      rules_updated: rulesUpdated,
      rules_path: rulesDir,
      reload,
      message: autoInstalled ? `PulledPork installed automatically and rules updated via ${method.label} on ${runnerKind}` : `Rules updated via ${method.label} on ${runnerKind}`,
      output: cleanedOutput.slice(-4000),
    });
  } catch (err) {
    return res.json({
      ok: false,
      applied: false,
      runner: runnerKind,
      method: method.label || "unknown",
      stage,
      message: `Rule update failed on ${runnerKind}`,
      error: err.output || err.message,
      hint: manualHint,
    });
  }
});

// ── Firewall / enforcement snapshot ───────────────────────────────────────────
app.get("/api/iptables", auth, async (req, res) => {
  const routerCfg = getRouterConfig();
  if (cleanValue(routerCfg.ip)) {
    try {
      const blockset = await fetchMainRouterBlockset(routerCfg);
      return res.json({ output: blockset.output || "(empty)", engine: blockset.engine || "main-router", target: routerCfg.ip, mode: "main-router" });
    } catch (err) {
      return res.json({ output: err.message || "(empty)", engine: "main-router", target: routerCfg.ip, mode: "main-router" });
    }
  }
  exec("iptables-save 2>&1 || iptables -L -n -v 2>&1", (err, stdout, stderr) => {
    res.json({ output: stdout || stderr || "(empty)", engine: "sensor-local", mode: "sensor-local" });
  });
});

// ── Connection config ─────────────────────────────────────────────────────────
app.get("/api/config/connection", auth, (req, res) => res.json(getConnConfig()));

app.post("/api/config/connection", auth, (req, res) => {
  dbSet("connection", req.body);
  const cfg = req.body;

  // Write to .env for persistence across restarts
  updateEnvFile({
    SNORT_HOST:       cfg.ip || "",
    SNORT_SSH_PORT:   cfg.port || "22",
    SNORT_SSH_USER:   cfg.user || "snort",
    SNORT_LOG_PATH:   cfg.logPath || "/var/log/snort/alert_json.txt",
    SNORT_AUTH_MODE:  cfg.authMode || "SSH Key",
  });

  // If no IP, switch to local tail mode
  if (!cfg.ip) {
    if (sshClient) { try { sshClient.end(); } catch(_){} sshClient = null; }
    setTimeout(() => startTail(handleNewAlertLine), 500);
    return res.json({ ok: true, message: "Local mode — tailing log file directly" });
  }

  const testSsh = new Client();
  const opts = { host: cfg.ip, port: parseInt(cfg.port || "22"), username: cfg.user, readyTimeout: 8000 };
  if (cfg.authMode === "SSH Key") {
    const kp = cfg.keyPath || "/app/keys/snort_id_rsa";
    if (!fs.existsSync(kp)) return res.json({ ok: false, message: `Key file not found: ${kp}` });
    opts.privateKey = fs.readFileSync(kp);
  } else {
    opts.password = cfg.password || "";
  }

  testSsh
    .on("ready", () => {
      testSsh.end();
      // Restart tail with new config
      setTimeout(() => startTail(handleNewAlertLine), 500);
      res.json({ ok: true, message: `Connected to ${cfg.ip}` });
    })
    .on("error", e => res.json({ ok: false, message: e.message }))
    .connect(opts);
});

app.get("/api/config/router", auth, (req, res) => res.json(getRouterConfig()));

app.post("/api/config/router", auth, async (req, res) => {
  const base = getRouterConfig();
  const cfg = {
    ...base,
    ...req.body,
    routerType: normalizeRouterType(req.body.routerType || base.routerType),
  };

  dbSet("router_connection", cfg);
  updateEnvFile({
    ROUTER_HOST: cfg.ip || "",
    ROUTER_SSH_PORT: cfg.port || "22",
    ROUTER_SSH_USER: cfg.user || "root",
    ROUTER_AUTH_MODE: cfg.authMode || "Password",
    ROUTER_TYPE: cfg.routerType || "OpenWRT",
    ROUTER_MONITOR_IFACE: cfg.monitorInterface || "",
    ROUTER_MIRROR_TARGET: cfg.mirrorTarget || "",
  });

  if (!cfg.ip) {
    return res.json({ ok: true, message: "Router target saved without IP — management panel is disabled until an IP is set." });
  }

  try {
    const info = await getRouterTelemetry(cfg);
    if (!info.reachable)   return res.json({ ok: false, message: info.error || `Router ${cfg.ip} is unreachable`, info });
    if (!info.sshConnected) return res.json({ ok: false, message: info.error || `SSH login failed for ${cfg.ip}`, info });
    return res.json({ ok: true, message: `Router ${cfg.ip} connected`, info });
  } catch(e) {
    return res.json({ ok: false, message: `Router connection error: ${e.message}` });
  }
});

app.get("/api/router/info", auth, async (req, res) => {
  try {
    const info = await getRouterTelemetry(getRouterConfig());
    res.json({ ok: info.reachable && info.sshConnected, info });
  } catch(e) {
    res.json({ ok: false, message: e.message, info: { error: e.message } });
  }
});

// ── Notification config ───────────────────────────────────────────────────────
app.get("/api/config/notifications", auth, (req, res) => res.json(getNotifConfig()));
app.post("/api/config/notifications", auth, (req, res) => {
  dbSet("notifications", req.body);
  // Persist key notification settings to .env
  const n = req.body;
  const envPairs = {};
  if (n.telegram) {
    envPairs.TELEGRAM_BOT_TOKEN = n.telegram.token || "";
    envPairs.TELEGRAM_CHAT_ID   = n.telegram.chatId || "";
    envPairs.TELEGRAM_MIN_SEVERITY = n.telegram.minSev || "high";
  }
  if (n.email) {
    envPairs.EMAIL_ENABLED = n.email.enabled ? "true" : "false";
    envPairs.EMAIL_SMTP = n.email.smtp || "";
    envPairs.EMAIL_USER = n.email.user || "";
    envPairs.EMAIL_TO   = n.email.to || "";
  }
  if (n.slack) {
    envPairs.SLACK_ENABLED = n.slack.enabled ? "true" : "false";
    envPairs.SLACK_WEBHOOK = n.slack.webhook || "";
  }
  if (Object.keys(envPairs).length) updateEnvFile(envPairs);
  res.json({ ok: true });
});

app.post("/api/config/notifications/test/:ch", auth, async (req, res) => {
  const cfg   = getNotifConfig();
  const ch    = req.params.ch;
  const dummy = { ts: new Date().toISOString(), rule:"TEST:001", msg:"SnortVision test notification",
    category:"TEST", severity:"high", src_ip:"1.2.3.4", dst_ip:"192.168.1.1", src_port:9999, dst_port:443, proto:"TCP", action:"ALERT" };
  try {
    if (ch === "telegram") await sendTelegram({ ...cfg.telegram, minSev:"low" }, dummy);
    if (ch === "email")    await sendEmail(   { ...cfg.email,    minSev:"low" }, dummy);
    if (ch === "slack")    await sendSlack(   { ...cfg.slack,    minSev:"low" }, dummy);
    res.json({ ok: true, message: `Test sent via ${ch}` });
  } catch(e) { res.json({ ok: false, message: e.message }); }
});

// ── .env settings — read/write individual keys ───────────────────────────────
app.get("/api/config/env", auth, (req, res) => {
  let content = {};
  try {
    const raw = fs.readFileSync(ENV_PATH, "utf8");
    for (const line of raw.split("\n")) {
      const m = line.match(/^([A-Z_]+)=(.*)$/);
      if (m) content[m[1]] = m[2];
    }
  } catch(_) {}
  // Mask sensitive values
  if (content.API_KEY) content.API_KEY = content.API_KEY.slice(0,6) + "•••";
  if (content.OINKCODE) content.OINKCODE = content.OINKCODE.slice(0,8) + "•••";
  if (content.EMAIL_PASS) content.EMAIL_PASS = "•••";
  res.json(content);
});

app.post("/api/config/env", auth, (req, res) => {
  const { key, value } = req.body;
  if (!key || typeof key !== "string") return res.status(400).json({ ok: false, message: "key required" });
  // Security: only allow known keys
  const ALLOWED = [
    "SNORT_HOST","SNORT_SSH_PORT","SNORT_SSH_USER","SNORT_LOG_PATH","SNORT_AUTH_MODE",
    "ROUTER_HOST","ROUTER_SSH_PORT","ROUTER_SSH_USER","ROUTER_AUTH_MODE","ROUTER_TYPE","ROUTER_MONITOR_IFACE","ROUTER_MIRROR_TARGET",
    "OINKCODE","GEOIP_ENABLE","BACKEND_URL",
    "TELEGRAM_BOT_TOKEN","TELEGRAM_CHAT_ID","TELEGRAM_MIN_SEVERITY",
    "EMAIL_ENABLED","EMAIL_SMTP","EMAIL_PORT","EMAIL_USER","EMAIL_PASS","EMAIL_TO","EMAIL_MIN_SEVERITY",
    "SLACK_ENABLED","SLACK_WEBHOOK","SLACK_MIN_SEVERITY",
    "SNORT_RELOAD_CMD","RULES_PATH","DB_PATH","PORT"
  ];
  if (!ALLOWED.includes(key)) return res.status(403).json({ ok: false, message: `Key "${key}" is not allowed (API_KEY is immutable)` });
  const ok = updateEnvFile({ [key]: value || "" });
  res.json({ ok, message: ok ? `${key} updated in .env` : "Failed to write .env" });
});

// Bulk update
app.post("/api/config/env/bulk", auth, (req, res) => {
  const pairs = req.body; // { KEY: "value", ... }
  if (!pairs || typeof pairs !== "object") return res.status(400).json({ ok: false });
  const ok = updateEnvFile(pairs);
  res.json({ ok, message: ok ? `${Object.keys(pairs).length} keys updated` : "Failed" });
});

// ── Service control — restart Snort3 / SnortVision backend ────────────────────
const hasSystemctl = () => {
  try {
    return fs.existsSync("/bin/systemctl") || fs.existsSync("/usr/bin/systemctl");
  } catch {
    return false;
  }
};

const LOCAL_SNORT_STATUS_CMD = "systemctl is-active snort3 2>/dev/null || systemctl is-active snortd 2>/dev/null || pgrep -af \"snort3|snortd|snort \" >/dev/null && echo active || echo inactive";
function isRootUser(cfg = getConnConfig()) {
  return String(cfg.user || "").trim().toLowerCase() === "root";
}

function buildRemoteStatusCommand(cfg = getConnConfig()) {
  if (isRootUser(cfg)) {
    return `sh -lc '
S3="$(systemctl is-active snort3 2>/dev/null || true)"
SD="$(systemctl is-active snortd 2>/dev/null || true)"
COMBINED="$S3 $SD"
case "$COMBINED" in
  *active*) echo active ;;
  *inactive*|*failed*|*dead*) echo inactive ;;
  *)
    if pgrep -af "snort3|snortd|snort " >/dev/null 2>&1; then
      echo active
    else
      echo unknown
    fi
  ;;
esac
'`;
  }

  return `sh -lc '
SS3="$(sudo -n systemctl is-active snort3 2>/dev/null || true)"
SSD="$(sudo -n systemctl is-active snortd 2>/dev/null || true)"
COMBINED="$SS3 $SSD"
case "$COMBINED" in
  *active*) echo active ;;
  *inactive*|*failed*|*dead*) echo inactive ;;
  *)
    if pgrep -af "snort3|snortd|snort " >/dev/null 2>&1; then
      echo active
    else
      echo AUTH_REQUIRED
      exit 3
    fi
  ;;
esac
'`;
}

function buildRemoteRestartCommand(cfg = getConnConfig(), mode = "non-interactive") {
  if (isRootUser(cfg)) {
    return `sh -lc '
if systemctl restart snort3 >/dev/null 2>&1 || systemctl restart snortd >/dev/null 2>&1 || service snort restart >/dev/null 2>&1 || service snort3 restart >/dev/null 2>&1; then
  echo RESTART_OK
  exit 0
fi
echo RESTART_FAILED
exit 4
'`;
  }

  if (mode === "password") {
    return `sh -lc '
if sudo -S -k -p "" systemctl restart snort3 >/dev/null 2>&1 || sudo -S -k -p "" systemctl restart snortd >/dev/null 2>&1 || sudo -S -k -p "" service snort restart >/dev/null 2>&1 || sudo -S -k -p "" service snort3 restart >/dev/null 2>&1; then
  echo RESTART_OK
  exit 0
fi
echo AUTH_REQUIRED
exit 3
'`;
  }

  return `sh -lc '
if sudo -n systemctl restart snort3 >/dev/null 2>&1 || sudo -n systemctl restart snortd >/dev/null 2>&1 || sudo -n service snort restart >/dev/null 2>&1 || sudo -n service snort3 restart >/dev/null 2>&1; then
  echo RESTART_OK
  exit 0
fi
echo AUTH_REQUIRED
exit 3
'`;
}

function getServiceControlMode() {
  const cfg = getConnConfig();
  if ((process.env.SNORT_RELOAD_CMD || "").trim()) {
    return { mode: "custom-local", cfg, label: "custom command" };
  }
  if ((cfg.ip || "").trim()) {
    return { mode: "ssh-remote", cfg, label: `SSH ${cfg.user || "snort"}@${cfg.ip}` };
  }
  if (hasSystemctl()) {
    return { mode: "systemctl-local", cfg, label: "local systemctl" };
  }
  return { mode: "manual", cfg, label: "manual" };
}

function mapSnortState(stdout = "") {
  const out = String(stdout).trim().toLowerCase();
  if (out === "active" || out === "running") return "running";
  if (out === "inactive" || out === "failed" || out === "dead" || out === "stopped") return "stopped";
  return out ? "unknown" : "stopped";
}

function outputSuggestsAuthRequired(output = "") {
  const out = String(output || "").toLowerCase();
  return out.includes("auth_required")
    || out.includes("interactive authentication required")
    || out.includes("a terminal is required")
    || out.includes("password is required")
    || out.includes("sudo:")
    || out.includes("polkit");
}

function execLocalCommand(command, timeout = 15000) {
  return new Promise((resolve, reject) => {
    exec(command, { timeout }, (err, stdout, stderr) => {
      const output = `${stdout || ""}${stderr || ""}`.trim();
      if (err) {
        err.output = output;
        return reject(err);
      }
      resolve({ stdout: stdout || "", stderr: stderr || "", output });
    });
  });
}

// Track last restart result (persists in memory across API calls)
let lastRestartResult = null;

async function getSnortServiceState() {
  const cfg = getConnConfig();
  const control = getServiceControlMode();

  if ((cfg.ip || "").trim()) {
    const statusCmd = buildRemoteStatusCommand(cfg);
    const result = await sshExecCommand(statusCmd, cfg, 12000);
    const combined = `${result.stdout || ""}${result.stderr || ""}`.trim();
    const requiresAuth = outputSuggestsAuthRequired(combined);
    return {
      state: requiresAuth ? "unknown" : mapSnortState(result.stdout),
      source: "ssh-remote",
      label: `SSH ${cfg.user || "snort"}@${cfg.ip}`,
      detail: combined,
      sshConnected: true,
      requiresAuth,
    };
  }

  const statusCmd = hasSystemctl() ? LOCAL_SNORT_STATUS_CMD : "pgrep -x snort >/dev/null && echo active || echo inactive";
  const result = await execLocalCommand(statusCmd, 5000);
  return {
    state: mapSnortState(result.stdout),
    source: control.mode,
    label: control.label,
    detail: (result.stdout || result.stderr || "").trim(),
    sshConnected: false,
    requiresAuth: false,
  };
}

app.get("/api/services/status", auth, async (req, res) => {
  const checks = {};
  const control = getServiceControlMode();

  try {
    const snort = await getSnortServiceState();
    checks.snort3 = snort.state;
    checks.snort_status_source = snort.source;
    checks.snort_status_detail = snort.detail;
    checks.snort_status_requires_auth = !!snort.requiresAuth;
    checks.ssh_connection_state = snort.sshConnected ? "connected" : "not_configured";
    checks.ssh_connection_label = snort.label;
  } catch (err) {
    checks.snort3 = "unknown";
    checks.snort_status_source = control.mode;
    checks.snort_status_error = err.message;
    checks.snort_status_requires_auth = outputSuggestsAuthRequired(err.message);
    checks.ssh_connection_state = control.mode === "ssh-remote" ? "error" : "not_configured";
    checks.ssh_connection_label = control.label;
  }

  checks.backend = "running";
  checks.tail_mode = localChild ? "local" : sshClient ? "ssh" : "none";
  checks.uptime = Math.round(process.uptime());
  checks.pid = process.pid;
  checks.env_file = ENV_PATH;
  checks.env_writable = (() => { try { fs.accessSync(ENV_PATH, fs.constants.W_OK); return true; } catch { return false; } })();
  checks.restart_method = control.mode;
  checks.restart_label = control.label;
  if (lastRestartResult) checks.last_restart = lastRestartResult;
  res.json(checks);
});

app.post("/api/services/restart/snort", auth, async (req, res) => {
  const control = getServiceControlMode();

  if (control.mode === "manual") {
    return res.json({
      ok: false,
      state: "error",
      message: "No automatic restart method is configured. Add SNORT_RELOAD_CMD or configure SSH access to the Snort host.",
      output: "Restart method: manual",
    });
  }

  try {
    let result;

    if (control.mode === "ssh-remote") {
      console.log(`[Services] Restarting Snort3 over SSH on ${control.cfg.ip}`);
      const sudoPassword = String(control.cfg.sudoPassword || control.cfg.password || "").trim();
      const nonInteractiveCmd = buildRemoteRestartCommand(control.cfg, "non-interactive");

      result = await sshExecCommand(nonInteractiveCmd, control.cfg, 60000);
      const combined = `${result.stdout || ""}${result.stderr || ""}`.trim();

      if (outputSuggestsAuthRequired(combined)) {
        if (sudoPassword) {
          try {
            const stdin = (sudoPassword + "\n").repeat(6);
            const passwordCmd = buildRemoteRestartCommand(control.cfg, "password");
            const r2 = await sshExecCommand(passwordCmd, control.cfg, 60000, stdin);
            const combined2 = `${r2.stdout || ""}${r2.stderr || ""}`.trim();
            if (!outputSuggestsAuthRequired(combined2)) {
              lastRestartResult = { ok: true, ts: new Date().toISOString(), message: `Restarted via sudo password on ${control.cfg.ip}` };
              return res.json({
                ok: true,
                state: "restarted",
                message: `Snort3 restarted over SSH on ${control.cfg.ip} using sudo password — waiting for running confirmation`,
                output: combined2 || "RESTART_OK",
              });
            }
          } catch (e) {
            // fall through to auth-required error
          }
        }

        lastRestartResult = { ok: false, ts: new Date().toISOString(), message: "Requires sudo password" };
        return res.json({
          ok: false,
          state: "error",
          message: `SSH connected to ${control.cfg.ip}, but restarting Snort3 requires passwordless sudo or a sudo password in the connection box`,
          output: combined,
        });
      }

      lastRestartResult = { ok: true, ts: new Date().toISOString(), message: `Restarted via SSH on ${control.cfg.ip}` };
      return res.json({
        ok: true,
        state: "restarted",
        message: `Snort3 restart command executed over SSH on ${control.cfg.ip} — waiting for running confirmation`,
        output: combined || `Remote restart command sent via ${control.label}`,
      });
    }

    const cmd = control.mode === "custom-local" ? process.env.SNORT_RELOAD_CMD : "systemctl restart snort3 2>&1 || systemctl restart snortd 2>&1";
    console.log(`[Services] Restarting Snort3 (${control.mode}): ${cmd}`);
    result = await execLocalCommand(cmd, 30000);

    lastRestartResult = { ok: true, ts: new Date().toISOString(), message: "Restart succeeded" };
    return res.json({
      ok: true,
      state: "restarted",
      message: "Snort3 restart command sent — waiting for running confirmation",
      output: result.output || `Restart command sent via ${control.label}`,
    });
  } catch (err) {
    const combined = `${err.output || ""} ${err.message || ""}`.trim();
    const authHint = control.mode === "ssh-remote" && outputSuggestsAuthRequired(combined)
      ? `SSH connected to ${control.cfg.ip}, but restarting Snort3 requires passwordless sudo or a sudo password in the connection box`
      : `Restart failed: ${err.message}`;

    lastRestartResult = { ok: false, ts: new Date().toISOString(), message: authHint };
    return res.json({
      ok: false,
      state: "error",
      message: authHint,
      output: (err.output || "").trim(),
    });
  }
});

app.post("/api/services/restart/backend", auth, (req, res) => {
  res.json({ ok: true, message: "Backend restarting in 2 seconds…" });
  console.log("[Services] Backend restart requested — exiting in 2s (Docker/systemd will restart)");
  setTimeout(() => {
    try { sshClient?.end(); localChild?.kill(); } catch(_){}
    process.exit(0); // Docker restart policy or systemd will bring it back
  }, 2000);
});

app.post("/api/services/restart/tail", auth, (req, res) => {
  console.log("[Services] Restarting log tail…");
  if (localChild) { try { localChild.kill(); } catch(_){} localChild = null; }
  if (sshClient) { try { sshClient.end(); } catch(_){} sshClient = null; }
  setTimeout(() => startTail(handleNewAlertLine), 500);
  res.json({ ok: true, message: "Log tail restarted" });
});

// ─── Handle new alert from SSH tail ──────────────────────────────────────────
function handleNewAlertLine(line) {
  const alert = parseSnortLine(line);
  if (!alert) return;

  try {
    const result = insertAlert.run(alert);
    alert.id = result.lastInsertRowid;
  } catch(e) { console.error("[DB]", e.message); return; }

  broadcast("alert", alert);
  dispatchNotifications(alert).catch(e => console.error("[Notify]", e.message));

  // Non-blocking prune — runs asap after insert but doesn't block the alert pipeline
  setImmediate(()=>{
    const count = db.prepare("SELECT COUNT(*) as c FROM alerts").get().c;
    if (count > MAX_ALERTS) pruneAlerts();
  });
}

// ─── DB management endpoints ─────────────────────────────────────────────────
app.get("/api/db/stats", auth, (req, res) => {
  const count   = db.prepare("SELECT COUNT(*) as c FROM alerts").get().c;
  const oldest  = db.prepare("SELECT ts FROM alerts ORDER BY id ASC  LIMIT 1").get();
  const newest  = db.prepare("SELECT ts FROM alerts ORDER BY id DESC LIMIT 1").get();
  const dbSizeBytes = (() => { try { return fs.statSync(DB_PATH).size; } catch { return 0; } })();
  const configRows  = db.prepare("SELECT COUNT(*) as c FROM config").get().c;
  const blocklistRows = db.prepare("SELECT COUNT(*) as c FROM blocklist").get().c;
  res.json({ count, oldest: oldest?.ts || null, newest: newest?.ts || null, dbSizeBytes, maxAlerts: MAX_ALERTS, configRows, blocklistRows });
});

// DELETE /api/alerts?days=30  — delete older than N days
// DELETE /api/alerts           — delete ALL alerts
app.delete("/api/alerts", auth, (req, res) => {
  const days = parseInt(req.query.days);
  let deleted;
  if (days && days > 0) {
    const result = db.prepare(`DELETE FROM alerts WHERE ts < datetime('now','-${days} days')`).run();
    deleted = result.changes;
  } else {
    const result = db.prepare("DELETE FROM alerts").run();
    deleted = result.changes;
  }
  db.prepare("VACUUM").run();
  const remaining = db.prepare("SELECT COUNT(*) as c FROM alerts").get().c;
  console.log(`[DB] Manual purge: deleted ${deleted} alerts, ${remaining} remaining`);
  res.json({ ok: true, deleted, remaining });
});

// Public — no auth — lets the frontend recover backendUrl after localStorage clear
app.get("/api/public/client-config", (req, res) => {
  res.json({
    backendUrl:   process.env.BACKEND_URL || "",
    requiresAuth: !!(API_KEY),
    version:      "0.1",
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
if (HAS_FRONTEND_DIST) {
  app.get(/^\/(?!api(?:\/|$)|ws(?:\/|$)).*/, (req, res) => {
    res.sendFile(FRONTEND_INDEX);
  });
}

server.listen(PORT, "0.0.0.0", () => {
  console.log("┌───────────────────────────────────────────────────┐");
  console.log("│  SnortVision Backend v0.1                         │");
  console.log(`│  API  : http://0.0.0.0:${PORT}                       │`);
  console.log(`│  WS   : ws://0.0.0.0:${PORT}/ws                    │`);
  console.log(`│  DB   : ${DB_PATH}`);
  console.log(`│  KEY  : ${API_KEY.slice(0,6)}••••${API_KEY.slice(-4)}  (see .env for full key)  │`);
  console.log("└───────────────────────────────────────────────────┘");
  startTail(handleNewAlertLine);
});

process.on("SIGTERM", () => { try { sshClient?.end(); localChild?.kill(); } catch(_){} server.close(); });
process.on("SIGINT",  () => { try { sshClient?.end(); localChild?.kill(); } catch(_){} server.close(); process.exit(0); });
