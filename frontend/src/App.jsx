import { useState, useEffect, useRef, useCallback } from "react";
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import {
  Shield, AlertTriangle, Activity, Bell, Terminal, Wifi, Database,
  Zap, Filter, RefreshCw, TrendingUp, X, Check, AlertCircle,
  Ban, ShieldOff, ShieldCheck, Siren, Cpu, FileText,
  ToggleLeft, ToggleRight, Plus, Trash2, Edit3, Search,
  ChevronUp, ChevronDown, Globe, Lock, Unlock, Eye, EyeOff,
  Clock, Hash, Layers, Play, Pause, Save, RotateCcw, Copy,
  ArrowUp, ArrowDown, Minus, Link2, Unlink, Server,
  User, Key, CheckCircle2, XCircle, Loader2, Download, HardDrive, Radio, Sun, Moon
} from "lucide-react";

// ─── Sim data ────────────────────────────────────────────────────────────────
const GEO = [
  { country: "CN", city: "Beijing" }, { country: "RU", city: "Moscow" },
  { country: "US", city: "Chicago" }, { country: "KP", city: "Pyongyang" },
  { country: "IR", city: "Tehran" },  { country: "BR", city: "São Paulo" },
  { country: "IN", city: "Mumbai" },  { country: "NG", city: "Lagos" },
];
const TPLS = [
  { rule: "1:2001219", msg: "ET SCAN Potential SSH Scan",                  cat: "SCAN",    sev: "medium"   },
  { rule: "1:2010935", msg: "ET POLICY PE EXE download HTTP",              cat: "MALWARE", sev: "high"     },
  { rule: "1:2013028", msg: "ET TROJAN Win32/Zbot Checkin",                cat: "TROJAN",  sev: "critical" },
  { rule: "1:2021001", msg: "ET DOS LOIC HTTP Flood",                      cat: "DDOS",    sev: "critical" },
  { rule: "1:2008435", msg: "ET EXPLOIT CVE-2014-6271 shellshock attempt", cat: "EXPLOIT", sev: "critical" },
  { rule: "1:2019714", msg: "ET SCAN Nmap Scripting Engine Detected",      cat: "SCAN",    sev: "low"      },
  { rule: "1:2011010", msg: "ET WEB_SERVER CUPS scheduler DoS",            cat: "DDOS",    sev: "high"     },
  { rule: "1:2100498", msg: "GPL ATTACK_RESPONSE id check returned root",  cat: "EXPLOIT", sev: "high"     },
  { rule: "1:2030171", msg: "ET MALWARE Win32/Dridex SSL Cert Pattern M2", cat: "MALWARE", sev: "critical" },
];
const PROTOS = ["TCP","UDP","ICMP","HTTP","DNS","SSH","FTP","SMTP"];
const PORTS  = [22,80,443,3389,8080,53,25,445,3306,1433,8443,6379];

let ctr = 1;
function rng(n) { return Math.floor(Math.random() * n); }
function randIp() { return `${rng(210)+10}.${rng(255)}.${rng(255)}.${rng(254)+1}`; }

function genAlert(forceDdos = false) {
  const tpl = forceDdos ? TPLS[3] : TPLS[rng(TPLS.length)];
  const geo  = GEO[rng(GEO.length)];
  return {
    id: ctr++, ts: new Date(),
    rule: tpl.rule, msg: tpl.msg, category: tpl.cat, severity: tpl.sev,
    src_ip: randIp(), dst_ip: `192.168.${rng(4)+1}.${rng(50)+10}`,
    src_port: rng(60000)+1024, dst_port: PORTS[rng(PORTS.length)],
    proto: PROTOS[rng(PROTOS.length)], country: geo.country, city: geo.city,
    action: Math.random() > 0.3 ? "BLOCKED" : "ALERT",
  };
}

function genTraffic(t, ddos) {
  const base = 1200 + Math.sin(t/5)*300;
  const spike = ddos ? rng(12000)+4000 : Math.random() > 0.93 ? rng(3000) : 0;
  return {
    time: new Date().toLocaleTimeString("en",{hour:"2-digit",minute:"2-digit",second:"2-digit"}),
    pps: Math.round(base + rng(200) + spike), ddos: Math.round(spike),
    mbps: parseFloat(((base+spike)*0.0012).toFixed(2)),
  };
}

function blankTrafficPoint() {
  return {
    time: new Date().toLocaleTimeString("en", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }),
    pps: 0,
    ddos: 0,
    mbps: 0,
  };
}

function toAlertTimeMs(value) {
  if (!value) return 0;
  if (value instanceof Date) return value.getTime();
  const parsed = Date.parse(value);
  if (!Number.isNaN(parsed)) return parsed;
  return 0;
}

function dedupeAlerts(rows = []) {
  const seen = new Set();
  return rows.filter((row) => {
    const key = row?.id ?? `${row?.ts || row?.timestamp || ""}|${row?.rule || ""}|${row?.src_ip || row?.src_addr || ""}|${row?.msg || row?.message || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── Constants ───────────────────────────────────────────────────────────────
const SEV = {
  critical: { color:"#ff2d55", bg:"rgba(255,45,85,0.12)",  label:"CRITICAL" },
  high:     { color:"#ff9f0a", bg:"rgba(255,159,10,0.12)", label:"HIGH"     },
  medium:   { color:"#ffd60a", bg:"rgba(255,214,10,0.12)", label:"MEDIUM"   },
  low:      { color:"#30d158", bg:"rgba(48,209,88,0.12)",  label:"LOW"      },
  info:     { color:"#0a84ff", bg:"rgba(10,132,255,0.12)", label:"INFO"     },
};
const CATC = { DDOS:"#ff2d55",EXPLOIT:"#ff6b35",TROJAN:"#bf5af2",MALWARE:"#ff9f0a",SCAN:"#30d158",POLICY:"#0a84ff",HUNTING:"#64d2ff" };

// ─── Shared atoms ─────────────────────────────────────────────────────────────
const Pill = ({ c, bg, border, children }) => (
  <span style={{ color:c, background:bg, border:`1px solid ${border}` }}
    className="text-xs font-bold px-2 py-0.5 rounded font-mono tracking-widest">{children}</span>
);
const SevBadge  = ({ sev }) => { const s=SEV[sev]||SEV.info; return <Pill c={s.color} bg={s.bg} border={`${s.color}40`}>{s.label}</Pill>; };
const CatBadge  = ({ cat }) => <Pill c={CATC[cat]||"#8e8e93"} bg={`${CATC[cat]||"#8e8e93"}15`} border={`${CATC[cat]||"#8e8e93"}30`}>{cat}</Pill>;
const BlockBadge = ({ b }) => (
  <Pill c={b?"#ff2d55":"#30d158"} bg={b?"rgba(255,45,85,0.12)":"rgba(48,209,88,0.12)"} border={b?"#ff2d5540":"#30d15840"}>
    {b ? "BLOCKED" : "ACTIVE"}
  </Pill>
);

function StatCard({ icon:Icon, label, value, sub, accent, live }) {
  const isLight = typeof document !== "undefined" && document.documentElement.dataset.theme === "light";
  const cardBase = isLight ? "#fffaf3" : "#0d1117";
  return (
    <div style={{ borderColor:`${accent}30`, background:`linear-gradient(135deg,${cardBase},${accent}08)` }}
      className="rounded-xl border p-4 flex flex-col gap-2 relative overflow-hidden">
      <div style={{ background:`${accent}18`, color:accent }} className="w-9 h-9 rounded-lg flex items-center justify-center"><Icon size={18}/></div>
      <div className="flex items-end gap-2">
        <span className="text-2xl font-black text-white font-mono">{value}</span>
        {live && <span style={{color:accent}} className="text-xs mb-1 animate-pulse">● LIVE</span>}
      </div>
      <div className="text-xs text-gray-400">{label}</div>
      {sub && <div className="text-xs" style={{color:accent}}>{sub}</div>}
    </div>
  );
}

function Toast({ alert:a, onClose }) {
  const s = SEV[a.severity]||SEV.info;
  const isLight = typeof document !== "undefined" && document.documentElement.dataset.theme === "light";
  useEffect(() => { const t=setTimeout(onClose,6000); return ()=>clearTimeout(t); },[onClose]);
  return (
    <div style={{ borderLeft:`3px solid ${s.color}`, background:isLight?"#fffaf3":"#161b22", animation:"slideIn 0.3s ease" }}
      className="w-80 rounded-r-xl p-3 shadow-2xl flex gap-3 items-start">
      <AlertCircle size={16} style={{color:s.color,flexShrink:0}} className="mt-0.5"/>
      <div className="flex-1 min-w-0">
        <div className="text-xs font-bold text-white truncate">{a.msg}</div>
        <div className="text-xs text-gray-400 mt-0.5">{a.src_ip} → {a.dst_ip}</div>
      </div>
      <button onClick={onClose} className="text-gray-600 hover:text-gray-300"><X size={14}/></button>
    </div>
  );
}

const ACTION_STATE_META = {
  connected: { short:"OK",   label:"CONNECTED", color:"#30d158", bg:"rgba(48,209,88,0.12)", border:"rgba(48,209,88,0.35)", icon:CheckCircle2 },
  updated:   { short:"OK",   label:"UPDATED",   color:"#0a84ff", bg:"rgba(10,132,255,0.12)", border:"rgba(10,132,255,0.35)", icon:CheckCircle2 },
  synced:    { short:"OK",   label:"SYNCED",    color:"#64d2ff", bg:"rgba(100,210,255,0.12)", border:"rgba(100,210,255,0.35)", icon:CheckCircle2 },
  restarted: { short:"OK",   label:"RESTARTED", color:"#30d158", bg:"rgba(48,209,88,0.12)", border:"rgba(48,209,88,0.35)", icon:CheckCircle2 },
  error:     { short:"ERR",  label:"ERROR",     color:"#ff2d55", bg:"rgba(255,45,85,0.12)", border:"rgba(255,45,85,0.35)", icon:XCircle },
  info:      { short:"INFO", label:"STATUS",    color:"#8e8e93", bg:"rgba(142,142,147,0.12)", border:"rgba(142,142,147,0.30)", icon:AlertCircle },
};

function detectActionState(type, msg = "") {
  const t = String(type || "").toUpperCase();
  const m = String(msg || "").toLowerCase();

  if (m.includes("waiting") || m.includes("monitoring") || m.includes("checking") || m.includes("pending")) return "info";
  if (t === "ERR" || m.includes("error") || m.includes("failed") || m.includes("unauthorized") || m.includes("not found") || m.includes("read-only") || m.includes("requires passwordless sudo") || m.includes("auth required")) return "error";
  if (m.includes("sync")) return "synced";
  if (m.includes("update") || m.includes("updated") || m.includes("saved") || m.includes("writable")) return "updated";
  if (m.includes("connect") || m.includes("connected") || m.includes("online") || m.includes("receiving") || m.includes("watching")) return "connected";
  if (m.includes("restart") || m.includes("restarting")) return t === "OK" ? "restarted" : "info";
  if (t === "OK") return "connected";
  return "info";
}

function ActionStatePill({ type, msg, className = "" }) {
  const meta = ACTION_STATE_META[detectActionState(type, msg)] || ACTION_STATE_META.info;
  return (
    <span
      style={{ color:meta.color, background:meta.bg, borderColor:meta.border }}
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-bold font-mono tracking-wide whitespace-nowrap ${className}`}
    >
      <meta.icon size={11}/>
      {meta.short} {meta.label}
    </span>
  );
}

// ─── GeoIP Map (Leaflet) — v0.1: Voyager tiles + attack impact pulses ──────
// Expanded country coords used by 3D map
const COUNTRY_COORDS = {
  CN:[35.86,104.19],RU:[61.52,105.31],US:[37.09,-95.71],KP:[40.34,127.51],
  IR:[32.42,53.68], BR:[-14.23,-51.92],IN:[20.59,78.96], NG:[9.08,8.67],
  DE:[51.16,10.45], FR:[46.22,2.21],  GB:[55.37,-3.43], JP:[36.20,138.25],
  AU:[-25.27,133.77],MX:[23.63,-102.55],ZA:[-30.55,22.93],UA:[48.37,31.16],
  CA:[56.13,-106.34],IT:[41.87,12.56],ES:[40.46,-3.74],NL:[52.13,5.29],
  BE:[50.50,4.47], PL:[51.92,19.14], TR:[38.96,35.24],SA:[23.88,45.08],
  AR:[-38.42,-63.62],CL:[-35.68,-71.54],CO:[4.57,-74.30],EG:[26.82,30.80],
  PK:[30.37,69.34], BD:[23.68,90.36], VN:[14.06,108.28],MY:[4.21,108.96],
  ID:[-0.79,113.92], TH:[15.87,100.99],PH:[12.88,121.77],KR:[35.91,127.77],
  TW:[23.69,120.96], SG:[1.35,103.82], HK:[22.32,114.17],IL:[31.05,34.85],
  SE:[60.12,18.64],  NO:[60.47,8.47],  DK:[56.26,9.50], FI:[61.92,25.75],
  CH:[46.82,8.23],   AT:[47.51,14.55], CZ:[49.82,15.47],HU:[47.16,19.50],
  RO:[45.94,24.96],  BG:[42.73,25.48], GR:[39.07,21.82],PT:[39.40,-8.22],
  RS:[44.02,21.01],  HR:[45.10,15.20], SK:[48.67,19.70],UA:[48.37,31.16],
  LU:[49.61,6.13],   LV:[56.88,24.60], LT:[55.17,23.88],EE:[58.59,25.01],
};
const HOME_COORD = [49.61, 6.13]; // Luxembourg
const FLAG = {CN:"🇨🇳",RU:"🇷🇺",US:"🇺🇸",KP:"🇰🇵",IR:"🇮🇷",BR:"🇧🇷",IN:"🇮🇳",NG:"🇳🇬",DE:"🇩🇪",FR:"🇫🇷",GB:"🇬🇧",JP:"🇯🇵",AU:"🇦🇺",MX:"🇲🇽",ZA:"🇿🇦",UA:"🇺🇦",CA:"🇨🇦",IT:"🇮🇹",ES:"🇪🇸",NL:"🇳🇱",BE:"🇧🇪",PL:"🇵🇱",TR:"🇹🇷",SA:"🇸🇦",AR:"🇦🇷",KR:"🇰🇷",TW:"🇹🇼",SG:"🇸🇬",SE:"🇸🇪",NO:"🇳🇴",CH:"🇨🇭",LU:"🇱🇺"};

// ─── Three.js CDN loader ──────────────────────────────────────────────────────
let _threeLoading = false;
const _threeQ = [];
function ensureThree(cb) {
  if (window.THREE) { cb(); return; }
  _threeQ.push(cb);
  if (_threeLoading) return;
  _threeLoading = true;
  const s = document.createElement("script");
  s.src = "https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js";
  s.onload = () => { _threeQ.forEach(f => f()); _threeQ.length = 0; };
  document.head.appendChild(s);
}

// ─── Module-level GeoIP cache for 3D map (persists across re-renders) ────────
const _geo3d = {};
const _geo3dPending = new Set();
// Use backend as GeoIP proxy — avoids HTTPS mixed-content block
// Falls back to direct ip-api.com only if backend is unavailable
async function _resolveGeo3d(ips, backendUrl) {
  const todo = ips.filter(ip => ip && !_isPrivate3d(ip) && !_geo3d[ip] && !_geo3dPending.has(ip));
  if (!todo.length) return false;
  todo.forEach(ip => _geo3dPending.add(ip));
  const base = backendUrl || window.location.origin;
  try {
    // Primary: backend proxy (HTTPS-safe, same origin)
    const res = await fetch(`${base}/api/public/geoip`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ips: todo }),
    });
    if (!res.ok) throw new Error("proxy " + res.status);
    const { results } = await res.json();
    results.forEach(r => {
      if (r.lat !== null) _geo3d[r.ip] = { lat: r.lat, lon: r.lon, country: r.country, cc: r.cc, city: r.city };
    });
    todo.forEach(ip => _geo3dPending.delete(ip));
    return true;
  } catch(e) {
    console.warn("[GeoIP] backend proxy failed, trying direct:", e.message);
    try {
      // Fallback: direct call (works on HTTP deployments)
      const r2 = await fetch("http://ip-api.com/batch?fields=status,query,lat,lon,country,countryCode,city", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(todo.map(q => ({ query: q }))),
      });
      const data = await r2.json();
      data.forEach(r => {
        if (r.status === "success") _geo3d[r.query] = { lat: r.lat, lon: r.lon, country: r.country, cc: r.countryCode, city: r.city };
      });
      todo.forEach(ip => _geo3dPending.delete(ip));
      return true;
    } catch {
      todo.forEach(ip => _geo3dPending.delete(ip));
      return false;
    }
  }
}
function _isPrivate3d(ip) {
  if (!ip) return true;
  const p = ip.split(".").map(Number);
  return p.length < 4 || p[0] === 10 || p[0] === 127 || p[0] === 0 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254);
}

// ─── 3D Cyberthreat Globe (Kaspersky-style) ───────────────────────────────────
function GeoMap({ alerts, backendUrl }) {
  const mountRef = useRef(null);
  const S = useRef({   // all mutable Three.js state in one object to avoid stale closures
    scene:null, camera:null, renderer:null, globe:null,
    arcs:[], markers:{}, rings:[], frame:null,
    t:0, dragging:false, lastMouse:{x:0,y:0},
    vel:{x:0,y:0}, autoRot:false, autoTimer:null, ready:false,  // autoRot permanently off
  });
  const [geoV, setGeoV] = useState(0);

  const GR = 2; // globe radius
  const HOME = [49.61, 6.13]; // Luxembourg

  function ll(lat, lon, r) {
    const phi = (90 - lat) * Math.PI / 180;
    const th  = (lon + 180) * Math.PI / 180;
    return new window.THREE.Vector3(
      -r * Math.sin(phi) * Math.cos(th),
       r * Math.cos(phi),
       r * Math.sin(phi) * Math.sin(th)
    );
  }

  // ── Init Three.js scene ──────────────────────────────────────────────────────
  useEffect(() => {
    ensureThree(() => {
      const s = S.current;
      if (s.ready || !mountRef.current) return;
      s.ready = true;
      const THREE = window.THREE;
      const W = mountRef.current.clientWidth, H = 520;

      // Core
      s.scene  = new THREE.Scene();
      s.camera = new THREE.PerspectiveCamera(45, W / H, 0.1, 200);
      s.camera.position.z = 5.2;  // slightly closer for more globe presence
      s.renderer = new THREE.WebGLRenderer({ antialias: true });
      s.renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
      s.renderer.setSize(W, H);
      s.renderer.setClearColor(0x020409);
      mountRef.current.appendChild(s.renderer.domElement);

      // ── Stars (two layers for depth) ──
      for (const [n, col, sz, r0] of [[5000, 0xaabbee, 0.07, 55], [800, 0x7799ff, 0.05, 52]]) {
        const verts = new Float32Array(n * 3);
        for (let i = 0; i < n; i++) {
          const th = Math.random() * Math.PI * 2;
          const ph = Math.acos(2 * Math.random() - 1);
          const r  = r0 + Math.random() * 30;
          verts[i*3]   = r * Math.sin(ph) * Math.cos(th);
          verts[i*3+1] = r * Math.cos(ph);
          verts[i*3+2] = r * Math.sin(ph) * Math.sin(th);
        }
        const g = new THREE.BufferGeometry();
        g.setAttribute("position", new THREE.BufferAttribute(verts, 3));
        s.scene.add(new THREE.Points(g, new THREE.PointsMaterial({ color: col, size: sz, transparent: true, opacity: 0.75, sizeAttenuation: true })));
      }

      // ── Lighting ──
      s.scene.add(new THREE.AmbientLight(0x0d1933, 3));
      const sun = new THREE.DirectionalLight(0x4477ff, 2);
      sun.position.set(8, 4, 6);
      s.scene.add(sun);

      // ── Globe group ──
      s.globe = new THREE.Group();
      // Rotate so Europe (lon ≈ 6°E) faces the camera on load
      // In our ll() formula lon maps to th=(lon+180)*PI/180, globe x=-r*sin(phi)*cos(th)
      // To face lon=6° → rotation.y ≈ -(6°)*PI/180 adjusted for texture orientation
      // Rotation to face Luxembourg (lon=6.13°E) toward camera (+z axis)
      // Formula: rot.y = -(th_LU - PI/2), where th_LU = (6.13+180)*PI/180 = 3.249
      s.globe.rotation.y = -1.68;   // places Europe/LU facing camera
      s.globe.rotation.x =  0.18;   // tilt to show northern hemisphere nicely
      s.scene.add(s.globe);

      // Base sphere
      const gMat = new THREE.MeshPhongMaterial({
        color: 0x060e1f, emissive: 0x020810, specular: 0x0055ff, shininess: 18,
      });
      s.globe.add(new THREE.Mesh(new THREE.SphereGeometry(GR, 64, 64), gMat));

      // Load Earth night texture with fallbacks
      const tl = new THREE.TextureLoader();
      const tryTex = (urls, i = 0) => {
        if (i >= urls.length) return;
        tl.load(urls[i], tex => {
          gMat.map = tex; gMat.color.set(0xffffff); gMat.needsUpdate = true;
        }, undefined, () => tryTex(urls, i + 1));
      };
      tryTex([
        "https://unpkg.com/three-globe/example/img/earth-night.jpg",
        "https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-night.jpg",
      ]);

      // Lat/lon grid
      const gL = new THREE.LineBasicMaterial({ color: 0x0a2550, transparent: true, opacity: 0.2 });
      for (let lat = -80; lat <= 80; lat += 20) {
        const pts = []; for (let lon = -180; lon <= 181; lon += 3) pts.push(ll(lat, lon, GR + 0.003));
        s.globe.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), gL.clone()));
      }
      for (let lon = -180; lon < 180; lon += 20) {
        const pts = []; for (let lat = -89; lat <= 89; lat += 3) pts.push(ll(lat, lon, GR + 0.003));
        s.globe.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), gL.clone()));
      }

      // ── Atmosphere layers ──
      [[GR*1.02, 0x0044ff, 0.06], [GR*1.055, 0x002299, 0.035], [GR*1.10, 0x001177, 0.018]].forEach(([r, c, o]) => {
        s.scene.add(new THREE.Mesh(
          new THREE.SphereGeometry(r, 32, 32),
          new THREE.MeshPhongMaterial({ color: c, transparent: true, opacity: o, blending: THREE.AdditiveBlending, depthWrite: false })
        ));
      });
      // Rim glow (back side)
      s.scene.add(new THREE.Mesh(
        new THREE.SphereGeometry(GR * 1.09, 32, 32),
        new THREE.MeshPhongMaterial({ color: 0x002299, transparent: true, opacity: 0.12, side: THREE.BackSide, blending: THREE.AdditiveBlending, depthWrite: false })
      ));

      // ── Home marker — Luxembourg ──
      const homePos = ll(HOME[0], HOME[1], GR + 0.04);
      const homeDot = new THREE.Mesh(
        new THREE.SphereGeometry(0.055, 16, 16),
        new THREE.MeshBasicMaterial({ color: 0x30d158, blending: THREE.AdditiveBlending })
      );
      homeDot.position.copy(homePos);
      s.globe.add(homeDot);

      for (let i = 0; i < 3; i++) {
        const ring = new THREE.Mesh(
          new THREE.RingGeometry(0.07*(i+1), 0.07*(i+1)+0.018, 32),
          new THREE.MeshBasicMaterial({ color: 0x30d158, transparent: true, opacity: 0.4/(i+1), side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false })
        );
        ring.position.copy(homePos);
        ring.lookAt(new THREE.Vector3(0, 0, 0));
        ring.userData.ri = i;
        s.globe.add(ring);
        s.rings.push(ring);
      }

      // ── Animation loop ──
      const animate = () => {
        s.frame = requestAnimationFrame(animate);
        s.t += 0.016;

        // Rotation
        // Auto-rotation disabled — globe only moves on drag
        if (!s.dragging) {
          s.globe.rotation.y += s.vel.y;
          s.globe.rotation.x = Math.max(-0.65, Math.min(0.65, s.globe.rotation.x + s.vel.x));
          s.vel.x *= 0.92; s.vel.y *= 0.92;
        }

        // Pulse home rings
        s.rings.forEach(r => {
          const sc = 1 + 0.45 * Math.sin(s.t * 1.7 + r.userData.ri * 1.3);
          r.scale.setScalar(sc);
          r.material.opacity = (0.32 / (r.userData.ri + 1)) * (0.55 + 0.45 * Math.sin(s.t * 1.7 + r.userData.ri * 1.3));
        });

        // Animate arcs
        s.arcs.forEach(arc => {
          arc.t += arc.speed;
          if (arc.t > 1.8) arc.t = 0;
          const progress = Math.min(arc.t, 1);
          // Rebuild line up to progress
          const count = Math.max(2, Math.floor(70 * progress));
          const pts = [];
          for (let i = 0; i <= count; i++) pts.push(arc.curve.getPoint(i / 70));
          arc.geom.setFromPoints(pts);
          // Move particle dot
          arc.dot.position.copy(arc.curve.getPoint(progress));
          arc.dot.material.opacity = arc.t < 1 ? 0.95 : Math.max(0, (1.8 - arc.t) * 2.2);
          const ps = 0.7 + 0.5 * Math.sin(s.t * 10 + arc.phase);
          arc.dot.scale.setScalar(ps);
          // Impact pulse at home when arc first arrives
          if (arc.t >= 1 && !arc.pulsed) {
            arc.pulsed = true;
            // Spawn a brief impact ring
            for (let ri = 0; ri < 2; ri++) {
              const ring = new THREE.Mesh(
                new THREE.RingGeometry(0.01, 0.025, 24),
                new THREE.MeshBasicMaterial({ color: arc.col, transparent: true, opacity: 0.9, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false })
              );
              const hp = ll(HOME[0], HOME[1], GR + 0.02);
              ring.position.copy(hp);
              ring.lookAt(new THREE.Vector3(0,0,0));
              ring.userData.birth = s.t; ring.userData.ri = ri; ring.userData.col = arc.col;
              s.globe.add(ring);
              if (!s.impactRings) s.impactRings = [];
              s.impactRings.push(ring);
            }
          }
          // Fade line after particle passes destination
          if (arc.t > 1) arc.line.material.opacity = Math.max(0, (1.8 - arc.t) * 0.45);
        });

        // Animate & prune impact rings
        if (s.impactRings) {
          s.impactRings = s.impactRings.filter(ring => {
            const age = s.t - ring.userData.birth;
            const maxAge = 1.8 + ring.userData.ri * 0.6;
            if (age > maxAge) { s.globe.remove(ring); ring.material.dispose(); ring.geometry.dispose(); return false; }
            const sc = 1 + age * 4.5;
            ring.scale.setScalar(sc);
            ring.material.opacity = Math.max(0, 0.7 * (1 - age / maxAge));
            return true;
          });
        }

        s.renderer.render(s.scene, s.camera);
      };
      animate();

      // ── Drag to rotate ──
      const el = s.renderer.domElement;
      const dn = e => {
        s.dragging = true;
        s.lastMouse = { x: e.clientX, y: e.clientY };
        el.style.cursor = "grabbing";
      };
      const mv = e => {
        if (!s.dragging) return;
        const dx = e.clientX - s.lastMouse.x, dy = e.clientY - s.lastMouse.y;
        s.globe.rotation.y += dx * 0.004;
        s.globe.rotation.x = Math.max(-0.65, Math.min(0.65, s.globe.rotation.x + dy * 0.004));
        s.vel = { x: dy * 0.002, y: dx * 0.002 };
        s.lastMouse = { x: e.clientX, y: e.clientY };
      };
      const up = () => {
        s.dragging = false; el.style.cursor = "grab";
        // No auto-rotate resume — globe stays where user leaves it
      };
      el.addEventListener("mousedown", dn);
      window.addEventListener("mousemove", mv);
      window.addEventListener("mouseup", up);

      // Resize
      const onResize = () => {
        if (!mountRef.current) return;
        const w = mountRef.current.clientWidth;
        s.camera.aspect = w / 520;
        s.camera.updateProjectionMatrix();
        s.renderer.setSize(w, 520);
      };
      window.addEventListener("resize", onResize);

      s._cleanup = () => {
        cancelAnimationFrame(s.frame);
        el.removeEventListener("mousedown", dn);
        window.removeEventListener("mousemove", mv);
        window.removeEventListener("mouseup", up);
        window.removeEventListener("resize", onResize);
        if (mountRef.current?.contains(el)) mountRef.current.removeChild(el);
        s.renderer.dispose();
        s.ready = false;
      };
    });
    return () => S.current._cleanup?.();
  }, []);

  // ── Resolve GeoIPs ────────────────────────────────────────────────────────────
  useEffect(() => {
    const ips = [...new Set(alerts.filter(a => !_isPrivate3d(a.src_ip)).map(a => a.src_ip).filter(Boolean))];
    const unknown = ips.filter(ip => !_geo3d[ip]);
    if (unknown.length) _resolveGeo3d(unknown, backendUrl).then(ok => { if (ok) setGeoV(v => v + 1); });
  }, [alerts.length]);

  // ── Add arcs for new alerts ───────────────────────────────────────────────────
  useEffect(() => {
    const s = S.current;
    if (!s.ready || !s.globe || !window.THREE) return;
    const THREE = window.THREE;
    const SEV_HEX = { critical: 0xff2d55, high: 0xff9f0a, medium: 0xffd60a, low: 0x30d158, info: 0x0a84ff };

    alerts.filter(a => !_isPrivate3d(a.src_ip) && a.src_ip !== "0.0.0.0").slice(0, 80).forEach((alert, idx) => {
      const arcId = alert.id != null ? alert.id : idx;
      if (s.arcs.find(a => a.id === arcId)) return;

      // Priority: 1) ip-api exact coords  2) country centroid  3) skip
      const geo = _geo3d[alert.src_ip];
      const ccCoord = COUNTRY_COORDS[alert.country] || COUNTRY_COORDS[_geo3d[alert.src_ip]?.cc];
      const src = geo ? [geo.lat, geo.lon] : ccCoord;
      if (!src) return;  // no coords yet — will appear after geo resolves

      const from = ll(src[0], src[1], GR + 0.01);
      const to   = ll(HOME[0], HOME[1], GR + 0.01);
      const mid  = new THREE.Vector3().addVectors(from, to).normalize()
        .multiplyScalar(GR * (1.3 + Math.random() * 0.6));
      const curve = new THREE.QuadraticBezierCurve3(from, mid, to);
      const col = SEV_HEX[alert.severity] || SEV_HEX.info;

      // Arc line
      const geom = new THREE.BufferGeometry();
      const line = new THREE.Line(geom, new THREE.LineBasicMaterial({
        color: col, transparent: true, opacity: 0.55,
        blending: THREE.AdditiveBlending, depthWrite: false,
      }));
      s.globe.add(line);

      // Moving particle
      const dot = new THREE.Mesh(
        new THREE.SphereGeometry(0.03, 8, 8),
        new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending, depthWrite: false })
      );
      dot.position.copy(from);
      s.globe.add(dot);

      // Origin dot marker
      if (!s.markers[alert.src_ip]) {
        const mk = new THREE.Mesh(
          new THREE.SphereGeometry(0.024, 8, 8),
          new THREE.MeshBasicMaterial({ color: col, blending: THREE.AdditiveBlending })
        );
        mk.position.copy(ll(src[0], src[1], GR + 0.016));
        s.globe.add(mk);
        s.markers[alert.src_ip] = mk;
      }

      // Impact ring burst at home when arc arrives (spawned lazily in animate loop)
      s.arcs.push({ id: arcId, curve, geom, line, dot, t: Math.random() * 0.25, speed: 0.003 + Math.random() * 0.005, phase: Math.random() * Math.PI * 2, col, pulsed: false });

      // Prune oldest arcs
      if (s.arcs.length > 70) {
        const old = s.arcs.shift();
        s.globe.remove(old.line); s.globe.remove(old.dot);
        old.geom.dispose(); old.line.material.dispose(); old.dot.material.dispose();
      }
    });
  }, [alerts.length, geoV]);

  // ── Derived stats for sidebar ─────────────────────────────────────────────────
  const topAtk = Object.entries(
    alerts.slice(0, 500).reduce((acc, x) => {
      if (_isPrivate3d(x.src_ip)) return acc;
      // Prefer backend country → ip-api geo cache → raw IP as fallback (never "??")
      const geoEntry = _geo3d[x.src_ip];
      const cc  = x.country || geoEntry?.cc  || "";
      const label = x.country || geoEntry?.country || x.src_ip || "Unknown";
      const k   = cc || `ip:${x.src_ip}`;
      if (!acc[k]) acc[k] = { country: cc, label, src_ip: x.src_ip || "", hits: 0, sev: x.severity, city: geoEntry?.city || "" };
      acc[k].hits++; acc[k].sev = x.severity;
      if (!acc[k].country && cc) { acc[k].country = cc; acc[k].label = label; }
      return acc;
    }, {})
  ).map(([, v]) => v).sort((a, b) => b.hits - a.hits).slice(0, 8);

  const SC = { critical: "#ff2d55", high: "#ff9f0a", medium: "#ffd60a", low: "#30d158", info: "#0a84ff" };
  const totalHits = topAtk.reduce((s, a) => s + a.hits, 0);

  return (
    <div style={{ position:"relative", borderRadius:14, overflow:"hidden", border:"1px solid #1a2535", background:"#020409" }}>
      {/* ── Title bar ── */}
      <div style={{ position:"absolute", top:0, left:0, right:0, zIndex:20, display:"flex", alignItems:"center", gap:8, padding:"10px 16px", background:"linear-gradient(180deg,rgba(2,4,9,0.97)0%,transparent 100%)", pointerEvents:"none" }}>
        <Globe size={13} style={{ color:"#4a9eff" }}/>
        <span style={{ fontSize:12, fontWeight:800, letterSpacing:"0.15em", color:"white", fontFamily:"monospace" }}>CYBERTHREAT</span>
        <span style={{ fontSize:12, fontWeight:300, letterSpacing:"0.1em", color:"#4a9eff", fontFamily:"monospace" }}>LIVE MAP</span>
        <span style={{ fontSize:10, color:"#ff2d55", marginLeft:4 }} className="animate-pulse">⬤ LIVE</span>
        <span style={{ marginLeft:"auto", fontSize:10, color:"#4a5568", fontFamily:"monospace" }}>{totalHits.toLocaleString()} attacks tracked</span>
      </div>

      {/* ── 3D Canvas ── */}
      <div ref={mountRef} style={{ width:"100%", height:520, cursor:"grab" }}/>

      {/* ── Legend ── */}
      <div style={{ position:"absolute", bottom:14, left:14, zIndex:20, display:"flex", gap:10, background:"rgba(2,4,9,0.82)", padding:"6px 12px", borderRadius:8, border:"1px solid #1a2535", pointerEvents:"none" }}>
        {[["#30d158","Home (LU)"],["#ff2d55","Critical"],["#ff9f0a","High"],["#ffd60a","Medium"],["#0a84ff","Low"]].map(([c,l])=>(
          <span key={l} style={{ display:"flex", alignItems:"center", gap:4, fontSize:10, color:"#8e8e93", fontFamily:"monospace" }}>
            <span style={{ width:7, height:7, borderRadius:"50%", background:c, display:"inline-block", boxShadow:`0 0 6px ${c}` }}/>
            {l}
          </span>
        ))}
      </div>

      {/* ── Top Attack Origins sidebar ── */}
      <div style={{ position:"absolute", top:44, right:12, zIndex:20, width:188, background:"rgba(2,4,9,0.88)", borderRadius:10, border:"1px solid #1a2535", padding:"10px 12px" }}>
        <div style={{ fontSize:9, fontWeight:700, color:"#4a5568", letterSpacing:"0.13em", marginBottom:10, fontFamily:"monospace", display:"flex", alignItems:"center", gap:4 }}>
          <TrendingUp size={9}/> TOP ATTACK ORIGINS
        </div>
        {topAtk.map((a, i) => {
          const col = SC[a.sev] || SC.info;
          return (
            <div key={a.src_ip || a.country} style={{ marginBottom:8 }}>
              <div style={{ display:"flex", alignItems:"center", gap:5, marginBottom:2 }}>
                <span style={{ fontSize:9, color:"#4a5568", fontFamily:"monospace", width:12, textAlign:"right", flexShrink:0 }}>{i + 1}</span>
                <span style={{ fontSize:10, color:"white", fontFamily:"monospace", flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                  {FLAG[a.country] || "🌐"} {a.label || a.src_ip || "Unknown"}{a.city ? `, ${a.city}` : ""}
                </span>
                <span style={{ fontSize:10, fontWeight:700, color:col, fontFamily:"monospace" }}>{a.hits}</span>
              </div>
              <div style={{ height:2, background:"#0d1117", borderRadius:1, marginLeft:17, overflow:"hidden" }}>
                <div style={{ height:"100%", background:`linear-gradient(90deg,${col}cc,${col}33)`, width:`${(a.hits / (topAtk[0]?.hits || 1)) * 100}%`, transition:"width 1s ease", borderRadius:1 }}/>
              </div>
            </div>
          );
        })}
        {topAtk.length === 0 && (
          <div style={{ fontSize:9, color:"#2d3748", fontFamily:"monospace", textAlign:"center", padding:"10px 0" }}>No external attacks yet…</div>
        )}
      </div>

      {/* ── Drag hint ── */}
      <div style={{ position:"absolute", bottom:14, right:14, zIndex:20, fontSize:9, color:"#2d3748", fontFamily:"monospace", pointerEvents:"none" }}>
        drag to rotate
      </div>
    </div>
  );
}


// ─── v0.1: Connection Dependency Indicator ──────────────────────────────────
function DependencyChain({ sshStatus, backendStatus, dbStatus, snortStatus, routerStatus, router }) {
  const hostname = router?.routerInfo?.hostname || router?.hostname || "";
  const routerLabel = hostname ? `Main Router
${hostname}` : "Main Router";
  const nodes = [
    { id:"ssh",     label:"SSH Tunnel",    icon:Terminal,  status:sshStatus,   dependsOn:null },
    { id:"backend", label:"Snort API",     icon:Shield,    status:backendStatus, dependsOn:"ssh" },
    { id:"db",      label:"Database",      icon:HardDrive, status:dbStatus,    dependsOn:"backend" },
    { id:"snort",   label:"Snort3",        icon:Radio,     status:snortStatus, dependsOn:"backend" },
    { id:"router",  label:routerLabel,      icon:Globe,     status:routerStatus, dependsOn:"backend", optional:true },
  ];
  const nodeMap = Object.fromEntries(nodes.map((n)=>[n.id, n]));
  const isBad = (s) => s==="error" || s==="down" || s==="idle";
  const statusColor = (s) => {
    if(s==="connected"||s==="running") return "#30d158";
    if(s==="degraded") return "#ff9f0a";
    if(s==="error"||s==="down") return "#ff2d55";
    if(s==="connecting"||s==="checking") return "#ffd60a";
    return "#6e7681";
  };
  const statusLabel = (s, optional = false) => {
    if(s==="connected"||s==="running") return "OK";
    if(s==="degraded") return "DEGRADED";
    if(s==="error"||s==="down") return "DOWN";
    if(s==="connecting"||s==="checking") return "WAIT";
    return optional ? "OPTIONAL" : "IDLE";
  };
  const StatusIcon = ({s}) => {
    if(s==="connected"||s==="running") return <CheckCircle2 size={14}/>;
    if(s==="connecting"||s==="checking") return <Loader2 size={14} className="animate-spin"/>;
    if(s==="error"||s==="down") return <XCircle size={14}/>;
    if(s==="degraded") return <AlertTriangle size={14}/>;
    return <Minus size={14}/>;
  };
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
      <div className="flex items-center gap-2 mb-4">
        <Link2 size={14} className="text-cyan-400"/>
        <span className="text-sm font-bold text-white">Connection Dependency Chain</span>
        <span className="text-xs text-gray-600">sensor path + main router context</span>
      </div>
      <div className="flex items-center justify-center gap-0 flex-wrap xl:flex-nowrap">
        {nodes.map((n,i)=>{
          const parentStatus = n.dependsOn ? nodeMap[n.dependsOn]?.status : null;
          const blocked = !!n.dependsOn && isBad(parentStatus);
          const currentColor = statusColor(n.status);
          const effectiveColor = blocked ? "#6e7681" : currentColor;
          const effectiveLabel = blocked ? "BLOCKED" : statusLabel(n.status, n.optional);
          const connectorFrom = n.dependsOn ? statusColor(nodeMap[n.dependsOn]?.status) : currentColor;
          return (
            <div key={n.id} className="flex items-center my-1">
              {i > 0 && (
                <div className="flex items-center mx-2">
                  <div style={{width:32,height:2,background:blocked?"#30363d":`linear-gradient(90deg,${connectorFrom},${effectiveColor})`}}/>
                  <div style={{width:0,height:0,borderTop:"4px solid transparent",borderBottom:"4px solid transparent",borderLeft:`6px solid ${blocked?"#30363d":effectiveColor}`}}/>
                </div>
              )}
              <div style={{borderColor:`${effectiveColor}40`,background:`${effectiveColor}08`}}
                className="rounded-xl border p-3 flex flex-col items-center gap-2 min-w-[120px] transition-all">
                <div style={{background:`${effectiveColor}20`,color:effectiveColor}} className="w-8 h-8 rounded-lg flex items-center justify-center"><n.icon size={16}/></div>
                <span className="text-xs font-bold text-white text-center leading-tight whitespace-pre-line">{n.label}</span>
                <div className="flex items-center gap-1" style={{color:effectiveColor}}>
                  <StatusIcon s={blocked?"idle":n.status}/>
                  <span className="text-xs font-bold font-mono">{effectiveLabel}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      {(sshStatus==="error"||sshStatus==="down") && (
        <div className="mt-3 flex items-center gap-2 text-xs text-amber-400 bg-amber-900/10 rounded-lg px-3 py-2 border border-amber-900/30">
          <AlertTriangle size={12}/>SSH tunnel is down — all downstream services are unreachable.
        </div>
      )}
      {sshStatus!=="error"&&sshStatus!=="down"&&(backendStatus==="error"||backendStatus==="down") && (
        <div className="mt-3 flex items-center gap-2 text-xs text-amber-400 bg-amber-900/10 rounded-lg px-3 py-2 border border-amber-900/30">
          <AlertTriangle size={12}/>Snort API is down — Database, Snort3, and main router checks are unavailable. SSH tunnel is active.
        </div>
      )}
      {sshStatus!=="error"&&sshStatus!=="down"&&backendStatus!=="error"&&backendStatus!=="down"&&(dbStatus==="error"||dbStatus==="down") && (
        <div className="mt-3 flex items-center gap-2 text-xs text-amber-400 bg-amber-900/10 rounded-lg px-3 py-2 border border-amber-900/30">
          <AlertTriangle size={12}/>Database connection failed — alerts are not being persisted. Snort API and SSH are active.
        </div>
      )}
      {backendStatus==="connected" && routerStatus!=="connected" && router?.ip && (
        <div className="mt-3 flex items-center gap-2 text-xs text-cyan-200 bg-cyan-900/10 rounded-lg px-3 py-2 border border-cyan-900/30">
          <Globe size={12}/>Main router visibility is optional. Snort alerts still come from the Snort sensor unless Snort runs on the router itself.
        </div>
      )}
    </div>
  );
}

// ─── Backend API / DB Panel ────────────────────────────────────────────────────
// ─── v0.1: Snort API Connection Panel (checks app ↔ snort backend) ─────────
function SnortAPIPanel({ backendUrl, setBackendUrl, apiKey, setApiKey, status, setStatus, dbStats, setDbStats }) {
  const [showApiKey,setShowApiKey] = useState(false);
  const [verifying,setVerifying]   = useState(false);
  const [verifyResult,setVerifyResult] = useState(null);
  const [oinkcode,setOinkcode]     = useState(()=>loadSaved("oinkcode",""));
  const [showOink,setShowOink]     = useState(false);
  const [oinkStatus,setOinkStatus] = useState("idle");
  const [oinkLog,setOinkLog]       = useState([]);
  const [maskedKey,setMaskedKey]   = useState("");
  const [apiKeyLocked,setApiKeyLocked] = useState(false);
  const [copied,setCopied]         = useState(false);

  // Persist oinkcode
  useEffect(()=>{ saveSetting("oinkcode",oinkcode); },[oinkcode]);

  const testAPI = async () => {
    setVerifying(true); setVerifyResult(null);
    try {
      const res = await fetch(`${backendUrl}/api/health`,{ headers: apiKey ? {"X-API-Key":apiKey} : {} });
      if(res.status===401) { setVerifyResult({ok:false,msg:"401 Unauthorized — wrong API key"}); setStatus("error"); }
      else if(res.ok) {
        const data = await res.json();
        let fileInfo = "";
        if(data.alert_file) {
          const af = data.alert_file;
          if(af.exists && af.readable) fileInfo = ` — log: ✓ ${af.path} (${af.size} bytes)`;
          else if(af.alternative_found) fileInfo = ` — ⚠ log NOT at ${af.path}, found: ${af.alternative_found}`;
          else if(!af.exists) fileInfo = ` — ⚠ log missing: ${af.path}`;
          else fileInfo = ` — ⚠ log not readable: ${af.path}`;
        }
        setVerifyResult({ok:true,msg:`Backend reachable — ${data.alerts_total||0} alerts, ${data.rules_count||0} rules — tail: ${data.tail_mode||"unknown"}${fileInfo}`});
        setStatus("connected"); setDbStats(data);
        // Show masked key from backend (key is immutable, generated on first run)
        if(data.api_key_masked) { setMaskedKey(data.api_key_masked); setApiKeyLocked(true); }
        // Auto-save backendUrl to .env
        try { await fetch(`${backendUrl}/api/config/env/bulk`,{method:"POST",headers:{"X-API-Key":apiKey,"Content-Type":"application/json"},body:JSON.stringify({BACKEND_URL:backendUrl})}); } catch {}
      } else { setVerifyResult({ok:false,msg:`HTTP ${res.status}`}); setStatus("error"); }
    } catch(e) { setVerifyResult({ok:false,msg:`Network error: ${e.message}`}); setStatus("error"); }
    setVerifying(false);
  };

  const disconnect = () => { setStatus("disconnected"); setVerifyResult(null); setDbStats(null); };

  const copyKey = () => {
    if(apiKey) { navigator.clipboard?.writeText(apiKey); setCopied(true); setTimeout(()=>setCopied(false),2000); }
  };

  const updateOinkcode = async () => {
    if(!oinkcode.trim()) return;
    setOinkStatus("updating");
    setOinkLog(p=>[{ts:new Date(),type:"INFO",msg:`Starting Snort rule update with Oinkcode…`},...p]);
    try {
      const res = await fetch(`${backendUrl}/api/rules/oinkcode`,{
        method:"POST", headers:{"X-API-Key":apiKey,"Content-Type":"application/json"},
        body:JSON.stringify({oinkcode:oinkcode.trim()})
      });
      const data = await res.json();
      const next = [];
      if(data.ok) {
        setOinkStatus("done");
        next.push({ts:new Date(),type:"OK",msg:data.message||"Rules updated successfully"});
        next.push({ts:new Date(),type:"INFO",msg:`Applied: ${data.applied ? "yes" : "no"} • Runner: ${data.runner||"unknown"} • Method: ${data.method||"unknown"}`});
        if(data.auto_installed) next.push({ts:new Date(),type:"OK",msg:"PulledPork was missing and was installed automatically on the Snort host"});
        next.push({ts:new Date(),type:"INFO",msg:`Rules found: ${data.rules_updated ?? 0} • Path: ${data.rules_path || "/etc/snort/rules"}`});
        if(data.install_output) next.push({ts:new Date(),type:"INFO",msg:String(data.install_output).split("\n").slice(-3).join(" | ")});
        if(data.reload?.attempted) next.push({ts:new Date(),type:data.reload.ok?"OK":"WARN",msg:`Reload ${data.reload.ok?"OK":"failed"}${data.reload.rc!=null?` (rc=${data.reload.rc})`:""} — ${data.reload.message||""}`});
        if(data.output) next.push({ts:new Date(),type:"INFO",msg:data.output.split("\n").slice(-3).join(" | ")});
      } else {
        setOinkStatus("error");
        next.push({ts:new Date(),type:"ERR",msg:data.message||"Update failed"});
        if(data.runner || data.method || data.stage) next.push({ts:new Date(),type:"INFO",msg:`Runner: ${data.runner||"unknown"} • Method: ${data.method||"unknown"}${data.stage?` • Stage: ${data.stage}`:""}${data.rc!=null?` • rc=${data.rc}`:""}`});
        if(data.auto_installed) next.push({ts:new Date(),type:"INFO",msg:"Automatic PulledPork installation was attempted before the rule update"});
        if(data.install_output) next.push({ts:new Date(),type:"INFO",msg:String(data.install_output).split("\n").slice(-3).join(" | ")});
        if(data.error) next.push({ts:new Date(),type:"INFO",msg:String(data.error).split("\n").slice(-3).join(" | ")});
        if(data.install_hint) next.push({ts:new Date(),type:"INFO",msg:data.install_hint});
        if(data.hint) next.push({ts:new Date(),type:"INFO",msg:`Run manually: ${data.hint}`});
      }
      setOinkLog(p=>[...next,...p].slice(0,20));
      setTimeout(()=>setOinkStatus("idle"),5000);
    } catch(e) {
      setOinkStatus("error");
      setOinkLog(p=>[
        {ts:new Date(),type:"ERR",msg:`Network error: ${e.message}`},
        {ts:new Date(),type:"INFO",msg:`Run manually on Snort host:`},
        {ts:new Date(),type:"INFO",msg:`/usr/local/bin/pulledpork3 -c /usr/local/etc/pulledpork/pulledpork.conf -i`},
        ...p
      ].slice(0,20));
      setTimeout(()=>setOinkStatus("idle"),5000);
    }
  };

  const logColor = {OK:"#30d158",ERR:"#ff2d55",INFO:"#0a84ff",WARN:"#ffd60a"};

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-950 p-4 space-y-4">
      <div className="flex items-center gap-2">
        <Shield size={14} className="text-blue-400"/>
        <span className="text-sm font-bold text-white">Snort API Connection</span>
        <span className="text-xs text-gray-600 ml-1">app ↔ backend</span>
        <div style={{
          background:status==="connected"?"rgba(48,209,88,0.1)":status==="error"?"rgba(255,45,85,0.1)":"rgba(110,118,129,0.1)",
          color:status==="connected"?"#30d158":status==="error"?"#ff2d55":"#6e7681",
          borderColor:status==="connected"?"rgba(48,209,88,0.3)":status==="error"?"rgba(255,45,85,0.3)":"rgba(110,118,129,0.3)"
        }} className="ml-auto text-xs px-2.5 py-1 rounded-full border font-mono flex items-center gap-1.5">
          <span style={{width:6,height:6,borderRadius:"50%",background:"currentColor",display:"inline-block"}}/>
          {status.toUpperCase()}
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Backend URL</label>
          <input value={backendUrl} onChange={e=>setBackendUrl(e.target.value)} placeholder="http://192.168.1.72:4000"
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
        </div>
        <div>
          <label className="text-xs text-gray-500 mb-1 block flex items-center gap-1.5">
            API Key
            {apiKeyLocked && <span className="text-yellow-500 flex items-center gap-0.5"><Lock size={9}/>immutable</span>}
          </label>
          <div className="relative">
            <input value={apiKey} onChange={apiKeyLocked?undefined:e=>setApiKey(e.target.value)}
              readOnly={apiKeyLocked} type={showApiKey?"text":"password"} placeholder="Enter key from backend console"
              className={`w-full bg-gray-900 border rounded-lg px-3 py-2 pr-16 text-sm text-white font-mono focus:outline-none ${
                apiKeyLocked?"border-yellow-900/50 cursor-default opacity-80":"border-gray-700 focus:border-blue-500"}`}/>
            <div className="absolute right-1.5 top-1.5 flex items-center gap-1">
              <button onClick={copyKey} title="Copy key" className="text-gray-600 hover:text-gray-300 p-1">
                {copied?<Check size={13} className="text-green-400"/>:<Copy size={13}/>}
              </button>
              <button onClick={()=>setShowApiKey(p=>!p)} className="text-gray-600 hover:text-gray-300 p-1">
                {showApiKey?<EyeOff size={13}/>:<Eye size={13}/>}
              </button>
            </div>
          </div>
          {apiKeyLocked && maskedKey && <div className="text-xs text-gray-600 mt-1 font-mono">Server key: {maskedKey}</div>}
          <div className="text-xs text-gray-600 mt-1">Direct browser checks on <span className="font-mono text-blue-400">/api/health</span> need the API key in the header or query string. Use <span className="font-mono text-cyan-300">/api/public/health</span> for a public check.</div>
          {backendUrl && (
            <div className="mt-2 grid grid-cols-1 gap-1.5 text-[11px] font-mono">
              <div className="rounded-lg border border-gray-800 bg-black/30 px-2.5 py-1.5 text-gray-400 break-all">Public check: <span className="text-cyan-300">{`${backendUrl}/api/public/health`}</span></div>
              {apiKey && <div className="rounded-lg border border-gray-800 bg-black/30 px-2.5 py-1.5 text-gray-400 break-all">Authorized browser check: <span className="text-green-300">{`${backendUrl}/api/health?key=${encodeURIComponent(apiKey)}`}</span></div>}
            </div>
          )}
          {!apiKey && <div className="text-xs text-yellow-500/70 mt-1">First run? Check backend console for the auto-generated key: <span className="font-mono">node server.js</span></div>}
        </div>
      </div>
      <div className="flex gap-2 items-center flex-wrap">
        <button onClick={testAPI} disabled={verifying}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition-all disabled:opacity-50">
          {verifying?<><Loader2 size={12} className="animate-spin"/>Testing…</>:<><Wifi size={12}/>Test Connection</>}
        </button>
        {status==="connected" && (
          <button onClick={disconnect} className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-gray-700 text-gray-400 hover:border-red-700 hover:text-red-400 text-xs font-bold transition-all">
            <Unlink size={12}/>Disconnect
          </button>
        )}
        {verifyResult && (
          <div className={`flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-lg border ${
            verifyResult.ok?"text-green-400 bg-green-900/10 border-green-900/40":"text-red-400 bg-red-900/10 border-red-900/40"
          }`}>
            <ActionStatePill type={verifyResult.ok?"OK":"ERR"} msg={verifyResult.msg}/>
            <span>{verifyResult.msg}</span>
          </div>
        )}
      </div>
      {/* Oinkcode */}
      <div className="rounded-lg border border-gray-800 bg-black/30 p-3 space-y-2">
        <div className="flex items-center gap-2">
          <Download size={12} className="text-yellow-400"/>
          <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Snort Oinkcode — Rule Subscription</span>
        </div>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <input value={oinkcode} onChange={e=>setOinkcode(e.target.value)} type={showOink?"text":"password"}
              placeholder="Enter your Oinkcode from snort.org"
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 pr-9 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
            <button onClick={()=>setShowOink(p=>!p)} className="absolute right-2.5 top-2.5 text-gray-600 hover:text-gray-300">
              {showOink?<EyeOff size={14}/>:<Eye size={14}/>}
            </button>
          </div>
          <button onClick={updateOinkcode} disabled={!oinkcode.trim()||oinkStatus==="updating"||status!=="connected"}
            className={`px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all whitespace-nowrap disabled:opacity-40 ${
              oinkStatus==="done"?"bg-green-700 text-white":"bg-yellow-600 hover:bg-yellow-500 text-white"
            }`}>
            {oinkStatus==="updating"?<><Loader2 size={12} className="animate-spin"/>Updating…</>:
             oinkStatus==="done"?<><Check size={12}/>Updated</>:
             <><Download size={12}/>Update Rules</>}
          </button>
        </div>
        {oinkLog.length>0 && (
          <div className="bg-black rounded-lg p-2 max-h-24 overflow-auto space-y-0.5">
            {oinkLog.slice(0,8).map((e,i)=>(
              <div key={i} className="flex gap-2 text-xs font-mono items-center">
                <span className="text-gray-700 flex-shrink-0">{new Date(e.ts).toLocaleTimeString()}</span>
                <ActionStatePill type={e.type} msg={e.msg}/>
                <span className="text-gray-400">{e.msg}</span>
              </div>
            ))}
          </div>
        )}
        <div className="text-xs text-gray-600">Get your Oinkcode at <span className="text-blue-400">snort.org/oinkcodes</span> — the backend installs PulledPork3 in the official project layout when missing, writes a managed configuration file, and then updates Snort rules on the Snort host</div>
      </div>
    </div>
  );
}

// ─── v0.1: Database Connection Panel (separate from API) ──────────────────────
function DatabasePanel({ backendUrl, apiKey, backendStatus, dbStatus, setDbStatus }) {
  const [dbForm,setDbForm] = useState(()=>loadSaved("dbForm",{ host:"127.0.0.1", port:"3306", user:"snortvision", pass:"", dbName:"snortvision", type:"sqlite" }));
  const [showPass,setShowPass]   = useState(false);
  const [dbResult,setDbResult]   = useState(null);
  const [dbStats,setDbStats]     = useState(null);

  // Persist DB form
  useEffect(()=>{ saveSetting("dbForm",{...dbForm,pass:""}); },[dbForm]);

  const testDB = async () => {
    setDbStatus("connecting"); setDbResult(null);
    try {
      if(backendStatus==="connected") {
        const res = await fetch(`${backendUrl}/api/health`,{ headers: apiKey ? {"X-API-Key":apiKey} : {} });
        if(!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        setDbStatus("connected"); setDbStats(data);
        setDbResult({ok:true,msg:`Database reachable — ${data.alerts_total||0} alerts, ${data.db_size||"unknown"} size`});
      } else { throw new Error("Connect Snort API first to verify database"); }
    } catch(e) { setDbStatus("error"); setDbResult({ok:false,msg:e.message}); }
  };
  const disconnect = () => { setDbStatus("idle"); setDbResult(null); setDbStats(null); };

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-950 p-4 space-y-4">
      <div className="flex items-center gap-2">
        <HardDrive size={14} className="text-purple-400"/>
        <span className="text-sm font-bold text-white">Database Connection</span>
        <span className="text-xs text-gray-600 ml-1">alert persistence</span>
        <div style={{
          background:dbStatus==="connected"?"rgba(48,209,88,0.1)":dbStatus==="error"?"rgba(255,45,85,0.1)":"rgba(110,118,129,0.1)",
          color:dbStatus==="connected"?"#30d158":dbStatus==="error"?"#ff2d55":"#6e7681",
          borderColor:dbStatus==="connected"?"rgba(48,209,88,0.3)":dbStatus==="error"?"rgba(255,45,85,0.3)":"rgba(110,118,129,0.3)"
        }} className="ml-auto text-xs px-2.5 py-1 rounded-full border font-mono flex items-center gap-1.5">
          <span style={{width:6,height:6,borderRadius:"50%",background:"currentColor",display:"inline-block"}}/>
          {dbStatus.toUpperCase()}
        </div>
      </div>
      <div className="flex gap-2">
        {["sqlite","mysql"].map(t=>(
          <button key={t} onClick={()=>setDbForm(p=>({...p,type:t}))}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-all font-mono ${
              dbForm.type===t?"bg-purple-600 border-purple-600 text-white":"border-gray-700 text-gray-400 hover:border-gray-500"}`}>{t.toUpperCase()}</button>
        ))}
      </div>
      {dbForm.type==="mysql" && (
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {[{k:"host",label:"DB Host",ph:"127.0.0.1"},{k:"port",label:"Port",ph:"3306"},{k:"dbName",label:"Database",ph:"snortvision"}].map(f=>(
            <div key={f.k}>
              <label className="text-xs text-gray-500 mb-1 block">{f.label}</label>
              <input value={dbForm[f.k]} onChange={e=>setDbForm(p=>({...p,[f.k]:e.target.value}))} placeholder={f.ph}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
            </div>
          ))}
          <div>
            <label className="text-xs text-gray-500 mb-1 block">DB User</label>
            <div className="relative">
              <User size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={dbForm.user} onChange={e=>setDbForm(p=>({...p,user:e.target.value}))} placeholder="snortvision"
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">DB Password</label>
            <div className="relative">
              <Lock size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={dbForm.pass} onChange={e=>setDbForm(p=>({...p,pass:e.target.value}))} type={showPass?"text":"password"} placeholder="••••••••"
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-9 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
              <button onClick={()=>setShowPass(p=>!p)} className="absolute right-2.5 top-2.5 text-gray-600 hover:text-gray-300">{showPass?<EyeOff size={14}/>:<Eye size={14}/>}</button>
            </div>
          </div>
        </div>
      )}
      {dbForm.type==="sqlite" && (
        <div className="text-xs text-gray-500 bg-gray-900/50 rounded-lg px-3 py-2 font-mono">
          SQLite database at <span className="text-blue-400">/app/data/snortvision.db</span> — managed by backend
        </div>
      )}
      {dbStats && dbStatus==="connected" && (
        <div className="grid grid-cols-4 gap-2">
          {[{label:"Alerts",val:dbStats.alerts_total||0,color:"#ff2d55"},{label:"Blocklist",val:dbStats.blocklist_count||0,color:"#ff9f0a"},
            {label:"Rules",val:dbStats.rules_count||0,color:"#0a84ff"},{label:"DB size",val:dbStats.db_size||"—",color:"#30d158"}
          ].map(s=>(
            <div key={s.label} style={{borderColor:`${s.color}20`,background:`${s.color}06`}} className="rounded-lg border p-2.5 text-center">
              <div style={{color:s.color}} className="text-lg font-black font-mono">{typeof s.val==="number"?s.val.toLocaleString():s.val}</div>
              <div className="text-xs text-gray-500 mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}
      <div className="flex gap-2 items-center flex-wrap">
        <button onClick={testDB} disabled={dbStatus==="connecting"}
          className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition-all disabled:opacity-50 ${
            dbStatus==="connected"?"bg-green-700 hover:bg-green-600 text-white":"bg-purple-600 hover:bg-purple-500 text-white"}`}>
          {dbStatus==="connecting"?<><Loader2 size={12} className="animate-spin"/>Testing…</>:
           dbStatus==="connected"?<><CheckCircle2 size={12}/>Connected</>:<><Database size={12}/>Test DB Connection</>}
        </button>
        {dbStatus==="connected" && (
          <button onClick={disconnect} className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-gray-700 text-gray-400 hover:border-red-700 hover:text-red-400 text-xs font-bold transition-all">
            <Unlink size={12}/>Disconnect
          </button>
        )}
        {dbResult && (
          <div className={`flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border ${
            dbResult.ok?"text-green-400 bg-green-900/10 border-green-900/40":"text-red-400 bg-red-900/10 border-red-900/40"}`}>
            {dbResult.ok?<CheckCircle2 size={12}/>:<XCircle size={12}/>}{dbResult.msg}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── DB Management Panel ──────────────────────────────────────────────────────
function DbManagePanel({ backendUrl, apiKey }) {
  const [stats, setStats]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [confirmDays, setConfirmDays] = useState("");
  const [showConfirmAll, setShowConfirmAll] = useState(false);

  const headers = apiKey ? { "X-API-Key": apiKey } : {};

  const fetchStats = async () => {
    if(!backendUrl || !apiKey) return;
    setLoading(true);
    try {
      const r = await fetch(`${backendUrl}/api/db/stats`, { headers });
      const d = await r.json();
      setStats(d);
    } catch(e) { setResult({ ok:false, msg: e.message }); }
    setLoading(false);
  };

  useEffect(()=>{ fetchStats(); }, [backendUrl, apiKey]);

  const purge = async (days) => {
    setLoading(true); setResult(null);
    try {
      const url = days ? `${backendUrl}/api/alerts?days=${days}` : `${backendUrl}/api/alerts`;
      const r = await fetch(url, { method:"DELETE", headers });
      const d = await r.json();
      setResult({ ok:d.ok, msg: `Deleted ${d.deleted?.toLocaleString()} alerts — ${d.remaining?.toLocaleString()} remaining` });
      await fetchStats();
    } catch(e) { setResult({ ok:false, msg:e.message }); }
    setLoading(false); setShowConfirmAll(false);
  };

  const fmt = (bytes) => {
    if(!bytes) return "0 B";
    const units = ["B","KB","MB","GB"];
    let i = 0, v = bytes;
    while(v >= 1024 && i < units.length-1) { v /= 1024; i++; }
    return `${v.toFixed(i===0?0:1)} ${units[i]}`;
  };

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-950 p-4 space-y-4">
      <div className="flex items-center gap-2">
        <Database size={14} className="text-orange-400"/>
        <span className="text-sm font-bold text-white">DB Storage & Cleanup</span>
        <button onClick={fetchStats} disabled={loading} className="ml-auto text-xs text-gray-500 hover:text-gray-300 font-mono flex items-center gap-1">
          <RefreshCw size={11} className={loading?"animate-spin":""}/>Refresh
        </button>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {[
            { label:"Total Alerts",   val: stats.count?.toLocaleString(),          color:"#ff2d55" },
            { label:"DB Size",        val: fmt(stats.dbSizeBytes),                  color:"#ff9f0a" },
            { label:"Max Retention",  val: stats.maxAlerts?.toLocaleString(),        color:"#0a84ff" },
            { label:"Fill %",         val: `${Math.round((stats.count/Math.max(stats.maxAlerts,1))*100)}%`, color:"#30d158" },
          ].map(s=>(
            <div key={s.label} style={{borderColor:`${s.color}20`,background:`${s.color}06`}} className="rounded-lg border p-2.5 text-center">
              <div style={{color:s.color}} className="text-lg font-black font-mono">{s.val}</div>
              <div className="text-xs text-gray-500 mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {stats && (
        <div className="text-xs text-gray-500 font-mono bg-black/30 rounded-lg px-3 py-2 space-y-0.5">
          <div>Oldest alert: <span className="text-gray-300">{stats.oldest ? new Date(stats.oldest).toLocaleString() : "—"}</span></div>
          <div>Newest alert: <span className="text-gray-300">{stats.newest ? new Date(stats.newest).toLocaleString() : "—"}</span></div>
        </div>
      )}

      <div className="space-y-2">
        <div className="text-xs font-bold text-gray-400 uppercase tracking-wider">Purge Alerts</div>
        <div className="flex gap-2 flex-wrap">
          {[7, 14, 30, 60, 90].map(d=>(
            <button key={d} onClick={()=>{ setConfirmDays(String(d)); setShowConfirmAll(false); }}
              disabled={loading}
              className="px-3 py-1.5 rounded-lg text-xs font-bold font-mono border border-gray-700 text-gray-400 hover:border-orange-700 hover:text-orange-400 transition-all disabled:opacity-40">
              &gt; {d} days old
            </button>
          ))}
          <button onClick={()=>{ setShowConfirmAll(true); setConfirmDays(""); }}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg text-xs font-bold font-mono border border-red-900/50 text-red-500 hover:border-red-500 transition-all disabled:opacity-40">
            🗑 ALL alerts
          </button>
        </div>

        {confirmDays && (
          <div className="rounded-lg border border-orange-900/40 bg-orange-900/10 p-3 flex items-center gap-3">
            <AlertTriangle size={14} className="text-orange-400 flex-shrink-0"/>
            <span className="text-xs text-orange-300 flex-1">Delete alerts older than <b>{confirmDays} days</b>?</span>
            <button onClick={()=>purge(confirmDays)} disabled={loading}
              className="px-3 py-1.5 rounded-lg bg-orange-700 hover:bg-orange-600 text-white text-xs font-bold">Confirm</button>
            <button onClick={()=>setConfirmDays("")} className="text-gray-500 hover:text-gray-300 text-xs">Cancel</button>
          </div>
        )}
        {showConfirmAll && (
          <div className="rounded-lg border border-red-900/40 bg-red-900/10 p-3 flex items-center gap-3">
            <AlertTriangle size={14} className="text-red-400 flex-shrink-0"/>
            <span className="text-xs text-red-300 flex-1"><b>Delete ALL alerts?</b> This cannot be undone.</span>
            <button onClick={()=>purge(null)} disabled={loading}
              className="px-3 py-1.5 rounded-lg bg-red-700 hover:bg-red-600 text-white text-xs font-bold">Delete All</button>
            <button onClick={()=>setShowConfirmAll(false)} className="text-gray-500 hover:text-gray-300 text-xs">Cancel</button>
          </div>
        )}
      </div>

      {result && (
        <div className={`flex items-center gap-2 text-xs font-mono px-3 py-2 rounded-lg border ${
          result.ok?"text-green-400 bg-green-900/10 border-green-900/40":"text-red-400 bg-red-900/10 border-red-900/40"}`}>
          {result.ok ? "✓" : "✗"} {result.msg}
        </div>
      )}
    </div>
  );
}

// ─── v0.1: Sync & Operations Panel ────────────────────────────────────────────
function SyncPanel({ backendUrl, apiKey, status, router }) {
  const [syncLog,setSyncLog]       = useState([]);
  const [autoSync,setAutoSync]     = useState(false);
  const [lastSync,setLastSync]     = useState(null);
  const [firewallOut,setFirewallOut] = useState("");
  const [firewallRunning,setFirewallRunning] = useState(false);
  const [tab,setTab]               = useState(()=>loadSaved("syncPanelTab","sync"));
  const routerLabel = router?.ip ? `Main Router ${router.ip}` : "Preferred enforcement target";

  const syncBlocklist = async () => {
    setSyncLog(p=>[{ts:new Date(),type:"INFO",msg:`Syncing blocklist to ${routerLabel}…`},...p]);
    try {
      const res = await fetch(`${backendUrl}/api/blocklist/sync`,{method:"POST",headers:{"X-API-Key":apiKey,"Content-Type":"application/json"},body:JSON.stringify({source:"snortvision"})});
      if(!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setLastSync(new Date());
      setSyncLog(p=>[{ts:new Date(),type:data.ok?"OK":"ERR",msg:`Sync target ${data.target||"runtime"} — applied ${data.applied||0}/${data.synced||0}${data.failed?` • failed ${data.failed}`:""}`},...p]);
    } catch(e) { setSyncLog(p=>[{ts:new Date(),type:"ERR",msg:`Sync failed: ${e.message}`},...p]); }
  };

  const syncRules = async () => {
    setSyncLog(p=>[{ts:new Date(),type:"INFO",msg:"Pushing rules to Snort host…"},...p]);
    try {
      const res = await fetch(`${backendUrl}/api/rules/deploy`,{method:"POST",headers:{"X-API-Key":apiKey,"Content-Type":"application/json"},body:JSON.stringify({restart:false})});
      if(!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setSyncLog(p=>[{ts:new Date(),type:"OK",msg:`Rules deployed — ${data.rules_written||0} rules written`},...p]);
    } catch(e) { setSyncLog(p=>[{ts:new Date(),type:"ERR",msg:`Deploy failed: ${e.message}`},...p]); }
  };

  const runFirewallSnapshot = async () => {
    setFirewallRunning(true);
    try {
      const res = await fetch(`${backendUrl}/api/iptables`,{headers:{"X-API-Key":apiKey}});
      if(!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setFirewallOut(data.output||"(empty)");
      setSyncLog(p=>[{ts:new Date(),type:"INFO",msg:`Fetched ${data.mode||"runtime"} firewall snapshot`},...p]);
    } catch(e) { setFirewallOut(`Error: ${e.message}`); }
    setFirewallRunning(false);
  };

  useEffect(()=>{ saveSetting("syncPanelTab",tab); },[tab]);

  useEffect(()=>{
    if(!autoSync||status!=="connected") return;
    const iv = setInterval(syncBlocklist, 30000);
    return ()=>clearInterval(iv);
  },[autoSync,status,backendUrl,apiKey,routerLabel]);

  const TABS = [{id:"sync",label:"Sync & Deploy"},{id:"iptables",label:"Firewall Snapshot"},{id:"install",label:"Install Guide"}];
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-950 p-4 space-y-4">
      <div className="flex items-center gap-2"><RefreshCw size={14} className="text-orange-400"/><span className="text-sm font-bold text-white">Sync & Operations</span></div>
      <div className="flex gap-1 border-b border-gray-800 pb-0">
        {TABS.map(t=>(<button key={t.id} onClick={()=>setTab(t.id)} className={`px-3 py-1.5 text-xs font-bold rounded-t-lg transition-all -mb-px border-b-2 ${tab===t.id?"text-white border-blue-500":"text-gray-500 border-transparent hover:text-gray-300"}`}>{t.label}</button>))}
      </div>
      {tab==="sync" && (<div className="space-y-3">
        <div className="flex flex-wrap gap-2">
          <button onClick={syncBlocklist} disabled={status!=="connected"} className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-orange-600/80 hover:bg-orange-500 text-white text-xs font-bold disabled:opacity-40 transition-all"><Ban size={12}/>Sync Blocklist → {router?.ip?"Main Router":"Runtime"}</button>
          <button onClick={syncRules} disabled={status!=="connected"} className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-blue-600/80 hover:bg-blue-500 text-white text-xs font-bold disabled:opacity-40 transition-all"><FileText size={12}/>Deploy Rules → Snort</button>
          <div className="flex items-center gap-2 ml-auto"><span className="text-xs text-gray-500">Auto-sync 30s</span>
            <button onClick={()=>setAutoSync(p=>!p)} disabled={status!=="connected"} style={{background:autoSync?"#30d158":"#21262d"}} className="w-10 h-5 rounded-full relative transition-all disabled:opacity-40"><div style={{left:autoSync?"calc(100% - 18px)":"2px"}} className="absolute top-0.5 w-4 h-4 bg-white rounded-full transition-all"/></button>
          </div>
        </div>
        <div className="text-xs text-gray-500">Enforcement target: <span className="text-cyan-300 font-mono">{routerLabel}</span></div>
        {lastSync && <div className="text-xs text-gray-600 font-mono">Last sync: {lastSync.toLocaleTimeString()}</div>}
      </div>)}
      {tab==="iptables" && (<div className="space-y-3">
        <button onClick={runFirewallSnapshot} disabled={status!=="connected"||firewallRunning} className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-purple-600/80 hover:bg-purple-500 text-white text-xs font-bold disabled:opacity-40 transition-all">
          {firewallRunning?<><RefreshCw size={12} className="animate-spin"/>Fetching…</>:<><Terminal size={12}/>Fetch enforcement snapshot</>}</button>
        <div className="bg-black rounded-lg p-3 font-mono text-xs text-green-400 max-h-52 overflow-auto whitespace-pre-wrap break-all">
          {firewallOut || <span className="text-gray-600">Click to pull the current main-router block set or local firewall state.</span>}</div>
      </div>)}
      {tab==="install" && (<div className="space-y-3">
        <div className="bg-black rounded-lg p-3 font-mono text-xs space-y-0.5">
          <div className="text-gray-500"># Backend</div>
          <div className="text-green-400">git clone https://github.com/marco-mata/snortvision</div>
          <div className="text-green-400">cp .env.example .env</div>
          <div className="text-green-400">./deploy.sh</div>
          <div className="text-gray-500 mt-1"># OpenWRT main-router blocking</div>
          <div className="text-blue-400">Configure the Main Router box with SSH access</div>
          <div className="text-blue-400">SnortVision creates nftables sets on inet/fw4 automatically</div>
        </div>
      </div>)}
      <div><div className="text-xs text-gray-600 mb-1.5 flex items-center gap-1.5"><Clock size={10}/>Operations log</div>
        <div className="bg-black rounded-lg p-2 max-h-24 overflow-auto space-y-0.5">
          {syncLog.length===0 && <div className="text-xs text-gray-700 py-2 text-center font-mono">No events yet</div>}
          {syncLog.map((e,i)=>(<div key={i} className="flex gap-2 text-xs font-mono items-center"><span className="text-gray-700 flex-shrink-0">{new Date(e.ts).toLocaleTimeString()}</span><ActionStatePill type={e.type} msg={e.msg}/><span className="text-gray-400">{e.msg}</span></div>))}
        </div>
      </div>
    </div>
  );
}

// ─── v0.1: Service Control Panel // ─── v0.1: Service Control Panel ──────────────────────────────────────────────
function ServiceControlPanel({ backendUrl, apiKey, status }) {
  const [services,setServices] = useState(null);
  const [restarting,setRestarting] = useState(null);
  const [actionLog,setActionLog] = useState([]);
  const [pollFast,setPollFast] = useState(false);
  const [restartError,setRestartError] = useState(null); // fast-poll after restart

  const fetchStatus = async () => {
    if(status!=="connected") return;
    try {
      const res = await fetch(`${backendUrl}/api/services/status`,{headers:apiKey?{"X-API-Key":apiKey}:{}});
      if(res.ok) {
        const data = await res.json();
        setServices(data);
        // If we were waiting for Snort to come back online
        if(pollFast && data.snort3==="running") {
          setActionLog(p=>[{ts:new Date(),type:"OK",msg:"Snort3 is running and connected — watching for alerts"},...p]);
          setPollFast(false);
        }
        if(pollFast && data.snort_status_requires_auth) {
          setActionLog(p=>{
            const next = "SSH connected, but Snort3 status needs passwordless sudo on the remote host";
            const top = p[0]?.msg || "";
            return top===next ? p : [{ts:new Date(),type:"ERR",msg:next},...p].slice(0,20);
          });
          setPollFast(false);
        }
        if(data.snort_status_error) {
          setActionLog(p=>{
            const top = p[0]?.msg || "";
            const next = `Service status check error: ${data.snort_status_error}`;
            return top===next ? p : [{ts:new Date(),type:"ERR",msg:next},...p].slice(0,20);
          });
        }
      }
    } catch {}
  };

  // Normal poll every 10s, fast poll every 2s after restart
  useEffect(()=>{
    fetchStatus();
    const iv=setInterval(fetchStatus, pollFast ? 2000 : 10000);
    return ()=>clearInterval(iv);
  },[status,pollFast]);

  const restart = async (svc) => {
    setRestarting(svc);
    setActionLog(p=>[{ts:new Date(),type:"INFO",msg:`Restarting ${svc}…`},...p]);
    try {
      const res = await fetch(`${backendUrl}/api/services/restart/${svc}`,{
        method:"POST",headers:{"X-API-Key":apiKey,"Content-Type":"application/json"}
      });
      const data = await res.json();
      setActionLog(p=>[{ts:new Date(),type:data.ok?"OK":"ERR",msg:data.message||"Unknown result"},...p]);
      if (data.output) {
        const out = String(data.output).trim();
        // Hide internal markers; keep only meaningful output
        if (out && out !== "AUTH_REQUIRED" && out !== "RESTART_OK") {
          setActionLog(p=>[{ts:new Date(),type:"INFO",msg:out.slice(0,200)},...p]);
        }
      }
      if(svc==="snort" && data.ok) {
        setActionLog(p=>[{ts:new Date(),type:"INFO",msg:"Waiting for Snort3 to come online and confirm connected state…"},...p]);
        setPollFast(true);
        setTimeout(()=>setPollFast(false), 30000);
      }
      // Show clear failure if restart failed
      if(svc==="snort" && !data.ok) {
        setRestartError(data.message || "Restart failed");
        setTimeout(()=>setRestartError(null), 15000);
      }
      if(svc!=="backend") setTimeout(fetchStatus,2000);
    } catch(e) {
      setActionLog(p=>[{ts:new Date(),type:"ERR",msg:e.message},...p]);
    }
    setTimeout(()=>setRestarting(null),3000);
  };

  const logColor = {OK:"#30d158",ERR:"#ff2d55",INFO:"#0a84ff"};

  // Color helper for service cards
  const svcColor = (state) => {
    if(state==="running"||state==="active") return { text:"#30d158", bg:"rgba(48,209,88,0.08)", border:"rgba(48,209,88,0.4)", glow:"0 0 12px rgba(48,209,88,0.2)" };
    if(state==="stopped"||state==="inactive"||state==="dead") return { text:"#ff2d55", bg:"rgba(255,45,85,0.08)", border:"rgba(255,45,85,0.4)", glow:"0 0 12px rgba(255,45,85,0.2)" };
    if(state==="unknown") return { text:"#ffd60a", bg:"rgba(255,214,10,0.08)", border:"rgba(255,214,10,0.35)", glow:"0 0 12px rgba(255,214,10,0.15)" };
    return { text:"#6e7681", bg:"rgba(110,118,129,0.05)", border:"rgba(110,118,129,0.3)", glow:"none" };
  };

  const ServiceBtn = ({svc,label,icon:Icon,danger}) => (
    <button onClick={()=>restart(svc)} disabled={status!=="connected"||restarting===svc}
      className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-bold transition-all disabled:opacity-40 ${
        danger?"bg-red-600/80 hover:bg-red-500 text-white":"bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700"
      }`}>
      {restarting===svc?<Loader2 size={13} className="animate-spin"/>:<Icon size={13}/>}
      {restarting===svc?"Restarting…":label}
    </button>
  );

  const snortState = services?.snort3 || "unknown";
  const tailState  = services?.tail_mode || "none";
  const sshConnectionState = services?.ssh_connection_state || "not_configured";
  const snortNeedsAuth = !!services?.snort_status_requires_auth;
  const snortDetail = services?.snort_status_detail || services?.snort_status_error || "";
  const snortC = svcColor(snortState);
  const tailC  = svcColor(tailState==="local"||tailState==="ssh"?"running":"stopped");
  const restartLabel = services?.restart_label || "manual";

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-950 p-4 space-y-4">
      <div className="flex items-center gap-2">
        <Cpu size={14} className="text-red-400"/>
        <span className="text-sm font-bold text-white">Service Control</span>
        <span className="text-xs text-gray-600 ml-1">restart & status</span>
        {pollFast && <span className="text-xs text-yellow-400 animate-pulse ml-auto">● Monitoring restart…</span>}
      </div>

      {/* Service status cards — color-coded */}
      {services ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <div style={{borderColor:snortC.border,background:snortC.bg,boxShadow:snortC.glow}} className="rounded-lg border p-3 text-center transition-all">
            <div style={{color:snortC.text}} className="text-sm font-black font-mono">{snortState.toUpperCase()}</div>
            <div className="text-xs text-gray-500 mt-0.5">Snort3</div>
            {snortState==="running" && <div className="text-xs mt-1" style={{color:"#30d158"}}>● Running</div>}
            {snortState==="unknown" && snortNeedsAuth && <div className="text-xs mt-1" style={{color:"#ffd60a"}}>● SSH connected / sudo required</div>}
            {snortState==="unknown" && !snortNeedsAuth && sshConnectionState==="connected" && <div className="text-xs mt-1" style={{color:"#64d2ff"}}>● SSH connected / checking status</div>}
            {snortState==="unknown" && sshConnectionState!=="connected" && <div className="text-xs mt-1" style={{color:"#ffd60a"}}>● Status check issue</div>}
            {snortState!=="running" && snortState!=="unknown" && <div className="text-xs mt-1" style={{color:"#ff2d55"}}>● Service stopped</div>}
            {sshConnectionState==="connected" && <div className="text-[11px] mt-1 text-blue-400">↻ SSH connected</div>}
            {snortDetail && <div className="text-[10px] mt-1 text-gray-600 truncate" title={snortDetail}>{snortDetail}</div>}
            {services.last_restart && (
              <div className="text-[10px] mt-1 font-mono" style={{color:services.last_restart.ok?"#30d158":"#ff2d55"}}>
                {services.last_restart.ok?"✓":"✗"} {services.last_restart.message}
              </div>
            )}
          </div>
          <div style={{borderColor:"rgba(48,209,88,0.4)",background:"rgba(48,209,88,0.08)",boxShadow:"0 0 12px rgba(48,209,88,0.2)"}} className="rounded-lg border p-3 text-center">
            <div className="text-sm font-black font-mono text-green-400">RUNNING</div>
            <div className="text-xs text-gray-500 mt-0.5">Backend</div>
            <div className="text-xs text-gray-600 mt-1 font-mono">PID {services.pid}</div>
          </div>
          <div style={{borderColor:tailC.border,background:tailC.bg,boxShadow:tailC.glow}} className="rounded-lg border p-3 text-center transition-all">
            <div style={{color:tailC.text}} className="text-sm font-black font-mono">{tailState.toUpperCase()}</div>
            <div className="text-xs text-gray-500 mt-0.5">Log Tail</div>
            {(tailState==="local"||tailState==="ssh") && <div className="text-xs mt-1" style={{color:"#30d158"}}>● Receiving</div>}
            {tailState==="none" && <div className="text-xs mt-1" style={{color:"#ff2d55"}}>● No tail</div>}
          </div>
          <div className="rounded-lg border border-gray-700 p-3 text-center">
            <div className="text-sm font-black font-mono text-gray-300">{Math.round((services.uptime||0)/60)}m</div>
            <div className="text-xs text-gray-500 mt-0.5">Uptime</div>
            <div className="text-[11px] mt-1 text-blue-400">↻ {restartLabel}</div>
            {services.env_writable ? (
              <div className="text-xs mt-1 text-green-500">● .env writable</div>
            ) : (
              <div className="text-xs mt-1 text-red-400">● .env read-only</div>
            )}
          </div>
        </div>
      ) : (
        <div className="text-xs text-gray-600 text-center py-4">
          {status==="connected"?"Loading service status…":"Connect Snort API to see service status"}
        </div>
      )}

      {/* Restart error banner */}
      {restartError && (
        <div className="flex items-center gap-2 text-xs text-red-400 bg-red-900/15 rounded-lg px-3 py-2.5 border border-red-900/40 animate-pulse">
          <XCircle size={14} className="flex-shrink-0"/>
          <div>
            <div className="font-bold">Snort3 restart failed</div>
            <div className="text-red-400/80 mt-0.5">{restartError}</div>
          </div>
          <button onClick={()=>setRestartError(null)} className="ml-auto text-red-600 hover:text-red-400"><X size={14}/></button>
        </div>
      )}

      {/* Restart buttons */}
      <div className="flex flex-wrap gap-2">
        <ServiceBtn svc="snort" label="Restart Snort3" icon={Shield} danger/>
        <ServiceBtn svc="tail" label="Restart Log Tail" icon={RefreshCw}/>
        <ServiceBtn svc="backend" label="Restart Backend" icon={Server} danger/>
      </div>

      <div className="text-xs text-gray-600 flex items-center gap-1.5">
        <AlertTriangle size={10}/>
        Restarting backend will briefly disconnect the UI. Docker/systemd will auto-restart the process.
      </div>

      {services?.snort_status_error && (
        <div className="text-xs text-yellow-400 bg-yellow-900/10 border border-yellow-900/30 rounded-lg px-3 py-2 flex items-center gap-1.5">
          <AlertTriangle size={12}/>
          Snort status check issue: {services.snort_status_error}
        </div>
      )}

      {services?.snort_status_requires_auth && (
        <div className="text-xs text-orange-300 bg-orange-900/10 border border-orange-900/30 rounded-lg px-3 py-2 flex items-center gap-1.5">
          <AlertTriangle size={12}/>
          SSH is connected, but Snort3 control on the remote host requires passwordless sudo or a sudo password in the connection box.
        </div>
      )}

      {/* Latest confirmation */}
      {actionLog.length>0 && (
        <div className="rounded-lg border border-gray-800 bg-black/40 px-3 py-2 flex items-center gap-2">
          <ActionStatePill type={actionLog[0].type} msg={actionLog[0].msg}/>
          <span className="text-xs text-gray-300 font-mono">{actionLog[0].msg}</span>
        </div>
      )}

      {/* Action log */}
      {actionLog.length>0 && (
        <div className="bg-black rounded-lg p-2 max-h-28 overflow-auto space-y-0.5">
          {actionLog.slice(0,8).map((e,i)=>(
            <div key={i} className="flex gap-2 text-xs font-mono items-center">
              <span className="text-gray-700 flex-shrink-0">{new Date(e.ts).toLocaleTimeString()}</span>
              <ActionStatePill type={e.type} msg={e.msg}/>
              <span className="text-gray-400">{e.msg}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Dashboard({ alerts, traffic, stats, backendUrl }) {
  const catData = Object.entries(alerts.slice(0,300).reduce((a,x)=>{a[x.category]=(a[x.category]||0)+1;return a;},{}))
    .map(([name,value])=>({name,value,fill:CATC[name]||"#0a84ff"})).sort((a,b)=>b.value-a.value).slice(0,7);
  const sevData = ["critical","high","medium","low"].map(s=>({ name:s.toUpperCase(), value:alerts.filter(a=>a.severity===s).length, color:SEV[s].color }));
  const mx = Math.max(...sevData.map(s=>s.value),1);
  const catMx = Math.max(...catData.map(c=>c.value),1);
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard icon={AlertTriangle} label="Total Alerts"   value={stats.total.toLocaleString()}   sub={`+${stats.lastMin} last min`} accent="#ff2d55" live/>
        <StatCard icon={Zap}           label="Critical Events" value={stats.critical.toLocaleString()} sub="Require attention"          accent="#ff6b35"/>
        <StatCard icon={Shield}        label="Blocked"          value={stats.blocked.toLocaleString()}
          sub={`${Math.round(stats.blocked/Math.max(stats.total,1)*100)}% block rate`} accent="#30d158"/>
        <StatCard
          icon={Activity}
          label={stats.trafficReal ? "Packets/sec" : "Alert rate/sec"}
          value={stats.pps.toLocaleString()}
          sub={
            stats.trafficReal
              ? `${String(stats.trafficSource || "").startsWith("main-router") ? "Main Router" : "Sensor"} ${stats.sensorInterface || "interface"} • ${stats.mbps} Mbps`
              : "No real sensor or main-router interface configured"
          }
          accent="#0a84ff"
          live
        />
      </div>
      <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div className="flex items-center gap-2 mb-3">
          <Activity size={14} className="text-blue-400"/>
          <span className="text-sm font-bold text-white">Live Traffic</span>
          <span className="text-xs text-red-400 animate-pulse ml-1">● LIVE</span>
        </div>
        <ResponsiveContainer width="100%" height={160}>
          <AreaChart data={traffic}>
            <defs>
              <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#0a84ff" stopOpacity={0.3}/><stop offset="95%" stopColor="#0a84ff" stopOpacity={0}/></linearGradient>
              <linearGradient id="g2" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ff2d55" stopOpacity={0.5}/><stop offset="95%" stopColor="#ff2d55" stopOpacity={0}/></linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#21262d"/>
            <XAxis dataKey="time" stroke="#4a5568" tick={{fontSize:10}} interval="preserveStartEnd"/>
            <YAxis stroke="#4a5568" tick={{fontSize:10}}/>
            <Tooltip contentStyle={{background:"#161b22",border:"1px solid #30363d",borderRadius:8,fontSize:12}}/>
            <Area type="monotone" dataKey="pps"  stroke="#0a84ff" fill="url(#g1)" strokeWidth={2} name="PPS"        dot={false}/>
            <Area type="monotone" dataKey="ddos" stroke="#ff2d55" fill="url(#g2)" strokeWidth={2} name="DDoS Spike" dot={false}/>
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Alert Categories — colored bars */}
        <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
          <div className="flex items-center gap-2 mb-4"><Filter size={13} className="text-purple-400"/><span className="text-sm font-bold text-white">Alert Categories</span></div>
          <div className="space-y-2.5">
            {catData.map(c=>(
              <div key={c.name}>
                <div className="flex justify-between text-xs mb-1">
                  <span style={{color:c.fill}} className="font-bold font-mono flex items-center gap-1.5">
                    <span style={{width:8,height:8,borderRadius:2,background:c.fill,display:"inline-block"}}/>
                    {c.name}
                  </span>
                  <span className="text-gray-300 font-mono font-bold">{c.value}</span>
                </div>
                <div className="h-2 rounded-full bg-gray-800 overflow-hidden">
                  <div style={{
                    width:`${(c.value/catMx)*100}%`,
                    background:`linear-gradient(90deg,${c.fill},${c.fill}99)`,
                    transition:"width 1s ease",
                    boxShadow:`0 0 6px ${c.fill}66`
                  }} className="h-full rounded-full"/>
                </div>
              </div>
            ))}
          </div>
        </div>
        {/* Severity Distribution */}
        <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
          <div className="flex items-center gap-2 mb-4"><TrendingUp size={13} className="text-orange-400"/><span className="text-sm font-bold text-white">Severity Distribution</span></div>
          <div className="space-y-3">
            {sevData.map(s=>(
              <div key={s.name}>
                <div className="flex justify-between text-xs mb-1">
                  <span style={{color:s.color}} className="font-bold font-mono">{s.name}</span>
                  <span className="text-gray-300 font-mono font-bold">{s.value}</span>
                </div>
                <div className="h-2 rounded-full bg-gray-800 overflow-hidden">
                  <div style={{
                    width:`${(s.value/mx)*100}%`,
                    background:s.color,
                    transition:"width 1s ease",
                    boxShadow:`0 0 6px ${s.color}66`
                  }} className="h-full rounded-full"/>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
      {/* GeoIP Map */}
      <GeoMap alerts={alerts} backendUrl={backendUrl}/>
    </div>
  );
}

// ─── ALERTS ───────────────────────────────────────────────────────────────────
function Alerts({ alerts, newIds, onBlockIp }) {
  const [sev,setSev] = useState("all");
  const [q,setQ]     = useState("");
  const filtered = alerts.filter(a=>{
    if(sev!=="all"&&a.severity!==sev) return false;
    if(q&&!a.msg.toLowerCase().includes(q.toLowerCase())&&!a.src_ip.includes(q)) return false;
    return true;
  }).slice(0,120);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-2 text-gray-600"/>
          <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search alerts, IPs…"
            className="bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 w-52"/>
        </div>
        <div className="flex gap-1">
          {["all","critical","high","medium","low"].map(f=>(
            <button key={f} onClick={()=>setSev(f)}
              style={sev===f&&f!=="all"?{background:SEV[f]?.color,borderColor:SEV[f]?.color}:{}}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono border transition-all ${
                sev===f?"text-white border-transparent":"text-gray-400 border-gray-700 hover:border-gray-500"
              }`}>{f.toUpperCase()}</button>
          ))}
        </div>
        <span className="text-xs text-gray-500 ml-auto">{filtered.length} events</span>
      </div>
      <div className="rounded-xl border border-gray-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-gray-900 border-b border-gray-800">
                {["Time","Sev","Message","Cat","Source","Dst","Proto","Action",""].map(h=>(
                  <th key={h} className="px-3 py-2 text-left text-xs font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(a=>{
                const s=SEV[a.severity]||SEV.info;
                const isN=newIds.has(a.id);
                return (
                  <tr key={a.id} style={{background:isN?`${s.color}10`:"transparent",transition:"background 2s",borderBottom:"1px solid #21262d"}}
                    className="hover:bg-white/[0.02]">
                    <td className="px-3 py-2 text-xs text-gray-500 font-mono whitespace-nowrap">{new Date(a.ts).toLocaleTimeString()}</td>
                    <td className="px-3 py-2"><SevBadge sev={a.severity}/></td>
                    <td className="px-3 py-2 max-w-xs">
                      <div className="text-xs font-medium text-gray-200 truncate" title={a.msg}>{a.msg}</div>
                      <div className="text-xs text-gray-600 font-mono">{a.rule}</div>
                    </td>
                    <td className="px-3 py-2"><CatBadge cat={a.category}/></td>
                    <td className="px-3 py-2">
                      <div className="text-xs text-gray-300 font-mono">{a.src_ip}</div>
                      <div className="text-xs text-gray-600">{a.city}, {a.country}</div>
                    </td>
                    <td className="px-3 py-2 text-xs text-gray-400 font-mono">{a.dst_ip}</td>
                    <td className="px-3 py-2 text-xs text-gray-500 font-mono">{a.proto}</td>
                    <td className="px-3 py-2">
                      <span className={`text-xs font-bold px-2 py-0.5 rounded font-mono ${
                        a.action==="BLOCKED"?"text-green-400 bg-green-900/30 border border-green-800":"text-amber-400 bg-amber-900/30 border border-amber-800"
                      }`}>{a.action}</span>
                    </td>
                    <td className="px-3 py-2">
                      <button onClick={()=>onBlockIp(a.src_ip,"Manual block from alert")}
                        title="Block this IP"
                        className="text-gray-600 hover:text-red-400 transition-colors">
                        <Ban size={13}/>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ─── IP BLOCKLIST ─────────────────────────────────────────────────────────────
function IpBlocklist({ blocklist, setBlocklist, autoBlock, setAutoBlock, backendUrl, apiKey, backendStatus, onBlockIp, router }) {
  const [newIp,setNewIp]       = useState("");
  const [newReason,setNewReason] = useState("");
  const [q,setQ]               = useState("");
  const [confirm,setConfirm]   = useState(null);

  const addIp = async () => {
    const ip = newIp.trim();
    if(!ip) return;
    await onBlockIp(ip, newReason||"Manual block", "Manual");
    setNewIp(""); setNewReason("");
  };

  const toggleIp = async (entry) => {
    if (backendStatus === "connected" && backendUrl && apiKey && entry?.id) {
      try {
        const res = await fetch(`${backendUrl}/api/blocklist/${entry.id}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
          body: JSON.stringify({ active: !entry.active, durationMinutes: autoBlock.blockDuration || 60 }),
        });
        const data = await res.json();
        if (data?.row) {
          setBlocklist(p => p.map(x => x.id === data.row.id ? data.row : x));
          return;
        }
      } catch (_) {}
    }
    setBlocklist(p=>p.map(x=>x.id===entry.id?{...x,active:!x.active}:x));
  };

  const removeIp = async (entry) => {
    if (backendStatus === "connected" && backendUrl && apiKey && entry?.id) {
      try {
        await fetch(`${backendUrl}/api/blocklist/${entry.id}`, { method: "DELETE", headers: { "X-API-Key": apiKey } });
      } catch (_) {}
    }
    setBlocklist(p=>p.filter(x=>x.id!==entry.id));
    setConfirm(null);
  };

  const filtered = blocklist.filter(x=>!q||x.ip.includes(q)||String(x.reason||"").toLowerCase().includes(q.toLowerCase()));
  const autoBlocked = blocklist.filter(x=>x.source==="Auto").length;

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div className="flex items-center gap-3 mb-4">
          <Cpu size={14} className="text-orange-400"/>
          <span className="text-sm font-bold text-white">Auto-Block Engine</span>
          <div className="ml-auto flex items-center gap-2">
            <span className="text-xs text-gray-500">{autoBlock.enabled?"ACTIVE":"DISABLED"}</span>
            <button onClick={()=>setAutoBlock(p=>({...p,enabled:!p.enabled}))}
              style={{background:autoBlock.enabled?"#ff9f0a":"#21262d"}}
              className="w-10 h-5 rounded-full relative transition-all">
              <div style={{left:autoBlock.enabled?"calc(100% - 18px)":"2px"}} className="absolute top-0.5 w-4 h-4 bg-white rounded-full transition-all"/>
            </button>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { k:"threshold",   label:"Hits to trigger",    unit:"alerts",  min:1,  max:100 },
            { k:"window",      label:"Time window",         unit:"seconds", min:10, max:600 },
            { k:"blockDuration",label:"Block duration",    unit:"minutes", min:1,  max:1440},
            { k:"minSeverity", label:"Min severity",        unit:"",        opts:["low","medium","high","critical"] },
          ].map(f=>(
            <div key={f.k}>
              <label className="text-xs text-gray-500 mb-1 block">{f.label}</label>
              {f.opts ? (
                <select value={autoBlock[f.k]} onChange={e=>setAutoBlock(p=>({...p,[f.k]:e.target.value}))}
                  disabled={!autoBlock.enabled}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none disabled:opacity-40">
                  {f.opts.map(o=><option key={o} value={o}>{o.toUpperCase()}</option>)}
                </select>
              ) : (
                <div className="flex items-center gap-1">
                  <input type="number" value={autoBlock[f.k]} min={f.min} max={f.max}
                    disabled={!autoBlock.enabled}
                    onChange={e=>setAutoBlock(p=>({...p,[f.k]:+e.target.value}))}
                    className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white font-mono focus:outline-none disabled:opacity-40 w-0"/>
                  <span className="text-xs text-gray-600 whitespace-nowrap">{f.unit}</span>
                </div>
              )}
            </div>
          ))}
        </div>
        <div className="mt-3 pt-3 border-t border-gray-800 flex gap-4 text-xs text-gray-500 flex-wrap">
          <span>Auto-detected: <span className="text-orange-400 font-bold font-mono">{autoBlocked}</span></span>
          <span>Tracked IPs: <span className="text-red-400 font-bold font-mono">{blocklist.filter(x=>x.active).length}</span></span>
          <span>Target: <span className="text-cyan-300 font-mono">{router?.ip ? `Main Router ${router.ip}` : "Sensor runtime"}</span></span>
          <span className="ml-auto text-gray-600">Rule: &gt;{autoBlock.threshold} alerts in {autoBlock.window}s → block for {autoBlock.blockDuration}min</span>
        </div>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div className="flex items-center gap-2 mb-3"><Plus size={13} className="text-blue-400"/><span className="text-sm font-bold text-white">Add Manual Block</span></div>
        <div className="flex gap-2">
          <input value={newIp} onChange={e=>setNewIp(e.target.value)} placeholder="IP address (e.g. 1.2.3.4 or 10.0.0.0/24)"
            onKeyDown={e=>e.key==="Enter"&&addIp()}
            className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
          <input value={newReason} onChange={e=>setNewReason(e.target.value)} placeholder="Reason (optional)"
            onKeyDown={e=>e.key==="Enter"&&addIp()}
            className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"/>
          <button onClick={addIp}
            className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-bold flex items-center gap-1.5 transition-all">
            <Ban size={14}/> Block
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-950 overflow-hidden">
        <div className="p-3 border-b border-gray-800 flex items-center gap-2">
          <Ban size={13} className="text-red-400"/>
          <span className="text-sm font-bold text-white">Discovered IPs</span>
          <span className="text-xs text-gray-600 ml-1">({filtered.length})</span>
          <div className="ml-auto relative">
            <Search size={12} className="absolute left-2 top-1.5 text-gray-600"/>
            <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Filter…"
              className="bg-gray-900 border border-gray-700 rounded-lg pl-7 pr-3 py-1 text-xs text-white focus:outline-none focus:border-blue-500 w-40"/>
          </div>
        </div>
        <table className="w-full">
          <thead>
            <tr className="bg-gray-900 border-b border-gray-800">
              {["IP / CIDR","Source","Reason","Added","Hits","Status","Actions"].map(h=>(<th key={h} className="px-3 py-2 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">{h}</th>))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(x=>(
              <tr key={x.id} style={{borderBottom:"1px solid #21262d"}} className="hover:bg-white/[0.02]">
                <td className="px-3 py-2.5 text-sm text-white font-mono font-bold">{x.ip}</td>
                <td className="px-3 py-2.5"><span className={`text-xs font-bold font-mono px-2 py-0.5 rounded ${x.source==="Auto"?"text-orange-400 bg-orange-900/20 border border-orange-900":x.source==="DDoS"?"text-red-400 bg-red-900/20 border border-red-900":"text-blue-400 bg-blue-900/20 border border-blue-900"}`}>{x.source}</span></td>
                <td className="px-3 py-2.5 text-xs text-gray-400 max-w-xs truncate">{x.reason}</td>
                <td className="px-3 py-2.5 text-xs text-gray-500 font-mono whitespace-nowrap">{new Date(x.added).toLocaleString()}</td>
                <td className="px-3 py-2.5 text-xs font-bold font-mono" style={{color:x.hits>10?"#ff2d55":x.hits>5?"#ff9f0a":"#8e8e93"}}>{x.hits}</td>
                <td className="px-3 py-2.5"><BlockBadge b={!x.active}/></td>
                <td className="px-3 py-2.5 flex items-center gap-2">
                  <button onClick={()=>toggleIp(x)} title={x.active?"Disable":"Enable"} className={`text-xs px-2 py-1 rounded border font-mono transition-all ${x.active?"text-yellow-400 border-yellow-900 hover:bg-yellow-900/20":"text-green-400 border-green-900 hover:bg-green-900/20"}`}>{x.active?"Pause":"Enable"}</button>
                  <button onClick={()=>setConfirm(x.id)} title="Remove" className="text-gray-600 hover:text-red-400 transition-colors"><Trash2 size={13}/></button>
                  {confirm===x.id && <span className="flex items-center gap-1"><button onClick={()=>removeIp(x)} className="text-xs text-red-400 hover:text-red-300 font-bold">Confirm?</button><button onClick={()=>setConfirm(null)} className="text-xs text-gray-600 hover:text-gray-400">Cancel</button></span>}
                </td>
              </tr>
            ))}
            {filtered.length===0 && (<tr><td colSpan={7} className="px-3 py-8 text-center text-xs text-gray-600">No blocked IPs yet</td></tr>)}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── DDOS MITIGATION// ─── DDOS MITIGATION ─────────────────────────────────────────────────────────
function DdosMitigation({ alerts, traffic, ddosMode, setDdosMode, blocklist, setBlocklist, backendStats, backendStatus }) {
  const [mitMode,setMitMode]     = useState(()=>loadSaved("ddos_mitMode","auto"));
  const [rateLimits,setRateLimits] = useState(()=>loadSaved("ddos_rateLimits",{
    enabled: true, ppsThreshold: 5000, synFloodRate: 500, icmpRate: 200, udpRate: 1000,
    connPerIp: 50, connWindow: 10
  }));
  const [geoBlock,setGeoBlock]   = useState(()=>loadSaved("ddos_geoBlock",{ enabled:false, countries:["KP"] }));
  const [synCookie,setSynCookie] = useState(()=>loadSaved("ddos_synCookie",true));
  const [nullRoute,setNullRoute] = useState(()=>loadSaved("ddos_nullRoute",false));

  // Persist DDoS settings so they survive tab switches
  useEffect(()=>{ saveSetting("ddos_mitMode",    mitMode);    }, [mitMode]);
  useEffect(()=>{ saveSetting("ddos_rateLimits", rateLimits); }, [rateLimits]);
  useEffect(()=>{ saveSetting("ddos_geoBlock",   geoBlock);   }, [geoBlock]);
  useEffect(()=>{ saveSetting("ddos_synCookie",  synCookie);  }, [synCookie]);
  useEffect(()=>{ saveSetting("ddos_nullRoute",  nullRoute);  }, [nullRoute]);

  const ddosAlerts = alerts.filter(a=>a.category==="DDOS").sort((a,b)=>toAlertTimeMs(b.ts)-toAlertTimeMs(a.ts));
  const recentDdos = ddosAlerts.slice(0, 25);
  const ddosSources = Object.values(ddosAlerts.reduce((acc, alert) => {
    if(!alert.src_ip || alert.src_ip === "unknown") return acc;
    // External IPs only — internal traffic is not a DDoS source
    const parts = alert.src_ip.split(".").map(Number);
    const isPrivate = parts[0]===10 || parts[0]===127 ||
      (parts[0]===172&&parts[1]>=16&&parts[1]<=31) ||
      (parts[0]===192&&parts[1]===168) || parts[0]===0;
    if(isPrivate) return acc;
    const key = alert.src_ip;
    if (!acc[key]) acc[key] = { ip:key, hits:0, lastTs:alert.ts, lastMsg:alert.msg, severity:alert.severity, blocked:0 };
    acc[key].hits += 1;
    acc[key].lastTs = alert.ts;
    acc[key].lastMsg = alert.msg;
    acc[key].severity = alert.severity;
    if (alert.action === "BLOCKED") acc[key].blocked += 1;
    return acc;
  }, {})).sort((a,b)=>b.hits-a.hits).slice(0, 8);

  const pps = Number(backendStats?.packet_pps ?? traffic[traffic.length-1]?.pps ?? 0);
  const realDdosDetected = !!backendStats?.ddos_detected;
  const isDdos = realDdosDetected || pps > 3500 || ddosMode;
  const latestDdosTs = recentDdos[0]?.ts ? new Date(recentDdos[0].ts).toLocaleString() : "None";

  const ALL_COUNTRIES = ["CN","RU","KP","IR","NG","BY","VN","PK","BD","UA"];
  const mitTypeColor = { RATE_LIMIT:"#0a84ff", AUTO_BLOCK:"#ff2d55", GEO_BLOCK:"#ffd60a", SYN_COOKIE:"#30d158", NULL_ROUTE:"#bf5af2", PAUSED:"#8e8e93" };
  const mitTypeIcon  = { RATE_LIMIT:"⚡", AUTO_BLOCK:"🚫", GEO_BLOCK:"🌍", SYN_COOKIE:"🍪", NULL_ROUTE:"⬛", PAUSED:"⏸" };

  // Track when current DDoS event started so we don't duplicate system-action entries
  const ddosStartRef = useRef(null);
  useEffect(()=>{
    if(isDdos && !ddosStartRef.current) ddosStartRef.current = new Date().toISOString();
    if(!isDdos) ddosStartRef.current = null;
  },[isDdos]);

  // ── Real auto-block: when genuinely connected and DDoS detected in AUTO mode,
  //    add top attacker IPs to the blocklist (deduped, max every 15 s per IP).
  const autoBlockedRef = useRef(new Set());
  useEffect(()=>{
    if(!realDdosDetected || mitMode !== "auto" || backendStatus !== "connected") return;
    ddosSources.forEach(src => {
      if(!src.ip || src.ip === "unknown" || autoBlockedRef.current.has(src.ip)) return;
      autoBlockedRef.current.add(src.ip);
      setBlocklist(p => {
        if(p.some(e => e.ip === src.ip)) return p;
        return [{ id:Date.now()+Math.random(), ip:src.ip, reason:`DDoS auto-block — ${src.hits} hits`, added:new Date().toISOString(), hits:src.hits, active:true, source:"DDoS" }, ...p];
      });
    });
  },[realDdosDetected, mitMode, backendStatus, ddosSources.length]);

  // Clear auto-block cache when DDoS ends so next event gets fresh blocks
  useEffect(()=>{ if(!isDdos) autoBlockedRef.current.clear(); },[isDdos]);

  // ── Demo auto-block (offline only)
  useEffect(()=>{
    if(!ddosMode || backendStatus === "connected") return;
    const t = setInterval(()=>{
      const ip = randIp();
      setBlocklist(p=>[{ id:Date.now(), ip, reason:"DDoS auto-block — demo mode", added:new Date().toISOString(), hits:0, active:true, source:"DDoS" },...p]);
    }, 4000);
    return ()=>clearInterval(t);
  },[ddosMode, backendStatus, setBlocklist]);

  // ── Build mitigation log: blocklist-derived auto-blocks + active system actions
  const blocklistActions = blocklist
    .filter((entry) => String(entry.source || "").toLowerCase() === "ddos" || String(entry.reason || "").toLowerCase().includes("ddos"))
    .map((entry) => ({
      ts: entry.added,
      type: entry.active ? "AUTO_BLOCK" : "PAUSED",
      msg: `${entry.ip} — ${entry.reason || "DDoS protection"}`,
      status: entry.active ? "active" : "paused",
      hits: entry.hits || 0,
    }));

  // System-level mitigations that are currently active during a DDoS event
  const systemActions = [];
  const eventTs = ddosStartRef.current || recentDdos[0]?.ts || new Date().toISOString();
  if(isDdos && mitMode !== "off") {
    if(rateLimits.enabled) systemActions.push({ ts:eventTs, type:"RATE_LIMIT",  msg:`PPS cap active — SYN ${rateLimits.synFloodRate}pps / ICMP ${rateLimits.icmpRate}pps / UDP ${rateLimits.udpRate}pps`, status:"active", hits:0 });
    if(synCookie)          systemActions.push({ ts:eventTs, type:"SYN_COOKIE",  msg:"TCP SYN cookie validation active — blocking SYN flood", status:"active", hits:0 });
    if(nullRoute)          systemActions.push({ ts:eventTs, type:"NULL_ROUTE",  msg:"Null route (blackhole) applied via iptables", status:"active", hits:0 });
    if(geoBlock.enabled)   systemActions.push({ ts:eventTs, type:"GEO_BLOCK",   msg:`Geo-block active — dropping traffic from: ${geoBlock.countries.join(", ")}`, status:"active", hits:0 });
  }

  const mitigationLog = [...systemActions, ...blocklistActions]
    .sort((a,b)=>toAlertTimeMs(b.ts)-toAlertTimeMs(a.ts));

  return (
    <div className="space-y-4">
      {/* Status banner */}
      <div style={{
        background: isDdos?"rgba(255,45,85,0.1)":"rgba(48,209,88,0.07)",
        borderColor: isDdos?"rgba(255,45,85,0.4)":"rgba(48,209,88,0.3)",
        animation: isDdos?"pulseRed 1.5s infinite":"none"
      }} className="rounded-xl border p-4 flex items-center gap-4">
        <div style={{ background:isDdos?"#ff2d5520":"#30d15820", color:isDdos?"#ff2d55":"#30d158" }}
          className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0">
          {isDdos ? <Siren size={20}/> : <ShieldCheck size={20}/>}
        </div>
        <div className="flex-1">
          <div style={{color:isDdos?"#ff2d55":"#30d158"}} className="font-bold text-sm">
            {isDdos ? "⚠ DDoS ATTACK IN PROGRESS" : "✓ NO ACTIVE DDoS DETECTED"}
          </div>
          <div className="text-xs text-gray-400 mt-0.5">
            {isDdos
              ? `Traffic spike: ${pps.toLocaleString()} pps — ${backendStats?.traffic_real ? "real interface telemetry" : "alert-driven detection"}`
              : `Traffic normal: ${pps.toLocaleString()} pps — Last DDoS event: ${latestDdosTs}`}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {["auto","manual","off"].map(m=>(
            <button key={m} onClick={()=>setMitMode(m)}
              style={mitMode===m?{background:m==="off"?"#ff2d55":m==="auto"?"#30d158":"#0a84ff",borderColor:"transparent"}:{}}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold border border-gray-700 font-mono transition-all ${
                mitMode===m?"text-white":"text-gray-400 hover:border-gray-500"
              }`}>{m.toUpperCase()}</button>
          ))}
        </div>
        <button onClick={()=>setDdosMode(p=>!p)}
          style={{borderColor:"#ff2d5540",color:ddosMode?"#ff2d55":"#666"}}
          className="text-xs px-3 py-1.5 rounded-lg border font-mono hover:opacity-80">
          {ddosMode?"Stop Sim":"Simulate"}
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Rate limiting */}
        <div className="rounded-xl border border-gray-800 bg-gray-950 p-4 space-y-3">
          <div className="flex items-center gap-2 justify-between">
            <div className="flex items-center gap-2"><Activity size={14} className="text-blue-400"/><span className="text-sm font-bold text-white">Rate Limiting</span></div>
            <button onClick={()=>setRateLimits(p=>({...p,enabled:!p.enabled}))}
              style={{background:rateLimits.enabled?"#0a84ff":"#21262d"}} className="w-10 h-5 rounded-full relative transition-all">
              <div style={{left:rateLimits.enabled?"calc(100% - 18px)":"2px"}} className="absolute top-0.5 w-4 h-4 bg-white rounded-full transition-all"/>
            </button>
          </div>
          <div className="space-y-2.5">
            {[
              { k:"ppsThreshold", label:"PPS threshold (trigger)",    unit:"pps" },
              { k:"synFloodRate", label:"SYN flood max rate",          unit:"pps" },
              { k:"icmpRate",     label:"ICMP max rate",               unit:"pps" },
              { k:"udpRate",      label:"UDP max rate",                unit:"pps" },
              { k:"connPerIp",    label:"Max concurrent conns per IP", unit:"conns" },
              { k:"connWindow",   label:"Connection tracking window",  unit:"sec" },
            ].map(f=>(
              <div key={f.k} className="flex items-center gap-2">
                <label className="text-xs text-gray-500 flex-1">{f.label}</label>
                <input type="number" value={rateLimits[f.k]} disabled={!rateLimits.enabled}
                  onChange={e=>setRateLimits(p=>({...p,[f.k]:+e.target.value}))}
                  className="w-24 bg-gray-900 border border-gray-700 rounded-lg px-2 py-1 text-xs text-white font-mono focus:outline-none disabled:opacity-40 text-right"/>
                <span className="text-xs text-gray-600 w-10">{f.unit}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Protection modules */}
        <div className="space-y-3">
          <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
            <div className="flex items-center gap-3">
              <div style={{background:"rgba(48,209,88,0.15)",color:"#30d158"}} className="w-8 h-8 rounded-lg flex items-center justify-center text-sm">🍪</div>
              <div className="flex-1">
                <div className="text-sm font-bold text-white">SYN Cookies</div>
                <div className="text-xs text-gray-500">Protect against SYN flood by validating TCP handshake</div>
              </div>
              <button onClick={()=>setSynCookie(p=>!p)} style={{background:synCookie?"#30d158":"#21262d"}} className="w-10 h-5 rounded-full relative transition-all">
                <div style={{left:synCookie?"calc(100% - 18px)":"2px"}} className="absolute top-0.5 w-4 h-4 bg-white rounded-full transition-all"/>
              </button>
            </div>
          </div>
          <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
            <div className="flex items-center gap-3">
              <div style={{background:"rgba(191,90,242,0.15)",color:"#bf5af2"}} className="w-8 h-8 rounded-lg flex items-center justify-center text-sm">⬛</div>
              <div className="flex-1">
                <div className="text-sm font-bold text-white">Null Routing</div>
                <div className="text-xs text-gray-500">Blackhole route attack traffic at network level (iptables)</div>
              </div>
              <button onClick={()=>setNullRoute(p=>!p)} style={{background:nullRoute?"#bf5af2":"#21262d"}} className="w-10 h-5 rounded-full relative transition-all">
                <div style={{left:nullRoute?"calc(100% - 18px)":"2px"}} className="absolute top-0.5 w-4 h-4 bg-white rounded-full transition-all"/>
              </button>
            </div>
          </div>
          <div className="rounded-xl border border-gray-800 bg-gray-950 p-4 space-y-3">
            <div className="flex items-center gap-3">
              <div style={{background:"rgba(255,214,10,0.15)",color:"#ffd60a"}} className="w-8 h-8 rounded-lg flex items-center justify-center"><Globe size={16}/></div>
              <div className="flex-1">
                <div className="text-sm font-bold text-white">Geo-Blocking</div>
                <div className="text-xs text-gray-500">Drop all traffic from selected countries</div>
              </div>
              <button onClick={()=>setGeoBlock(p=>({...p,enabled:!p.enabled}))} style={{background:geoBlock.enabled?"#ffd60a":"#21262d"}} className="w-10 h-5 rounded-full relative transition-all">
                <div style={{left:geoBlock.enabled?"calc(100% - 18px)":"2px"}} className="absolute top-0.5 w-4 h-4 bg-white rounded-full transition-all"/>
              </button>
            </div>
            {geoBlock.enabled && (
              <div className="flex flex-wrap gap-1.5">
                {ALL_COUNTRIES.map(c=>{
                  const sel = geoBlock.countries.includes(c);
                  return (
                    <button key={c} onClick={()=>setGeoBlock(p=>({
                      ...p, countries: sel?p.countries.filter(x=>x!==c):[...p.countries,c]
                    }))} style={sel?{background:"rgba(255,45,85,0.15)",borderColor:"#ff2d55",color:"#ff2d55"}:{}}
                      className="px-2.5 py-1 rounded text-xs font-bold border border-gray-700 text-gray-400 hover:border-gray-500 font-mono transition-all">
                      {c}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
          <div className="rounded-xl border border-gray-800 bg-gray-950 p-3">
            <div className="text-xs font-bold text-gray-500 mb-2 flex items-center gap-1.5"><Hash size={11}/>Generated iptables rules</div>
            <div className="bg-black rounded-lg p-2.5 font-mono text-xs text-green-400 space-y-0.5 max-h-28 overflow-auto">
              {rateLimits.enabled && <>
                <div className="text-gray-500"># Rate limiting</div>
                <div>iptables -A INPUT -p tcp --syn -m limit --limit {rateLimits.synFloodRate}/s -j ACCEPT</div>
                <div>iptables -A INPUT -p icmp -m limit --limit {rateLimits.icmpRate}/s -j ACCEPT</div>
                <div>iptables -A INPUT -p udp -m limit --limit {rateLimits.udpRate}/s -j ACCEPT</div>
              </>}
              {synCookie && <><div className="text-gray-500 mt-1"># SYN cookies</div><div>sysctl -w net.ipv4.tcp_syncookies=1</div></>}
              {geoBlock.enabled && geoBlock.countries.length>0 && <>
                <div className="text-gray-500 mt-1"># Geo-block</div>
                {geoBlock.countries.map(c=><div key={c}>iptables -I INPUT -m geoip --src-cc {c} -j DROP</div>)}
              </>}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-xl border border-gray-800 bg-gray-950 overflow-hidden">
          <div className="p-3 border-b border-gray-800 flex items-center gap-2">
            <Clock size={13} className="text-purple-400"/>
            <span className="text-sm font-bold text-white">Recent DDoS Alerts</span>
            <span className="text-xs text-gray-600 ml-1">({recentDdos.length})</span>
          </div>
          <div className="max-h-72 overflow-auto">
            {recentDdos.map((alert)=>{
              const sev = SEV[alert.severity] || SEV.info;
              return (
                <div key={alert.id} style={{borderBottom:"1px solid #21262d"}} className="px-3 py-2 flex items-start gap-3 hover:bg-white/[0.02]">
                  <span style={{color:sev.color}} className="text-xs font-bold font-mono w-16 flex-shrink-0">{alert.severity.toUpperCase()}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs text-gray-200 truncate" title={alert.msg}>{alert.msg}</div>
                    <div className="text-xs text-gray-500 font-mono">{alert.src_ip} → {alert.dst_ip} • {alert.proto}</div>
                  </div>
                  <span className="text-xs text-gray-600 font-mono flex-shrink-0">{new Date(alert.ts).toLocaleTimeString()}</span>
                </div>
              );
            })}
            {recentDdos.length===0 && <div className="px-3 py-6 text-center text-xs text-gray-600">No real DDoS alerts ingested yet</div>}
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-950 overflow-hidden">
          <div className="p-3 border-b border-gray-800 flex items-center gap-2">
            <TrendingUp size={13} className="text-orange-400"/>
            <span className="text-sm font-bold text-white">Top DDoS Source IPs</span>
            <span className="text-xs text-gray-600 ml-1">({ddosSources.length})</span>
          </div>
          <div className="max-h-72 overflow-auto">
            {ddosSources.map((src)=>{
              const sev = SEV[src.severity] || SEV.info;
              return (
                <div key={src.ip} style={{borderBottom:"1px solid #21262d"}} className="px-3 py-2 hover:bg-white/[0.02]">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-bold text-white font-mono flex-1">{src.ip}</span>
                    <span style={{color:sev.color}} className="text-xs font-bold font-mono">{src.hits} hits</span>
                  </div>
                  <div className="text-xs text-gray-500 truncate" title={src.lastMsg}>{src.lastMsg}</div>
                  <div className="text-xs text-gray-600 font-mono mt-1">Blocked alerts: {src.blocked} • Last seen: {new Date(src.lastTs).toLocaleTimeString()}</div>
                </div>
              );
            })}
            {ddosSources.length===0 && <div className="px-3 py-6 text-center text-xs text-gray-600">No DDoS source IPs yet</div>}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-950 overflow-hidden">
        <div className="p-3 border-b border-gray-800 flex items-center gap-2">
          <Shield size={13} className="text-red-400"/>
          <span className="text-sm font-bold text-white">Mitigation Actions</span>
          <span className="text-xs text-gray-600 ml-1">({mitigationLog.length})</span>
          {isDdos && mitMode !== "off" && (
            <span className="ml-auto text-xs font-bold font-mono px-2 py-0.5 rounded" style={{background:"rgba(48,209,88,0.12)",color:"#30d158",border:"1px solid rgba(48,209,88,0.3)"}}>
              AUTO RESPONDING
            </span>
          )}
        </div>
        <div className="max-h-56 overflow-auto">
          {mitigationLog.map((e,i)=>(
            <div key={`${e.ts}-${e.type}-${i}`} style={{borderBottom:"1px solid #21262d"}} className="px-3 py-2 flex items-center gap-3 hover:bg-white/[0.02]">
              <span className="text-base w-5 text-center flex-shrink-0">{mitTypeIcon[e.type]||"⚙"}</span>
              <span style={{color:mitTypeColor[e.type]||"#8e8e93"}} className="text-xs font-bold font-mono w-24 flex-shrink-0">{e.type}</span>
              <span className="text-xs text-gray-300 flex-1">{e.msg}</span>
              <span style={{color:e.status==="active"?"#30d158":"#8e8e93"}} className="text-xs font-mono flex-shrink-0">{e.status}</span>
              <span className="text-xs text-gray-600 font-mono flex-shrink-0">{new Date(e.ts).toLocaleTimeString()}</span>
            </div>
          ))}
          {mitigationLog.length===0 && <div className="px-3 py-6 text-center text-xs text-gray-600">No DDoS mitigation actions recorded yet</div>}
        </div>
      </div>
    </div>
  );
}

// ─── RULES MANAGER ────────────────────────────────────────────────────────────
const DEFAULT_RULES = [
  { id:1, sid:"2001219", gid:1, rev:20, enabled:true,  action:"alert", proto:"TCP",  src:"any", sport:"any", dir:"->", dst:"$HOME_NET", dport:"22", msg:"ET SCAN Potential SSH Scan", cat:"SCAN",    sev:"medium",   hits:142 },
  { id:2, sid:"2021001", gid:1, rev:5,  enabled:true,  action:"drop",  proto:"TCP",  src:"any", sport:"any", dir:"->", dst:"any",        dport:"80",  msg:"ET DOS LOIC HTTP Flood",    cat:"DDOS",    sev:"critical", hits:38  },
  { id:3, sid:"2013028", gid:1, rev:8,  enabled:true,  action:"drop",  proto:"TCP",  src:"any", sport:"any", dir:"->", dst:"$HOME_NET", dport:"any", msg:"ET TROJAN Win32/Zbot",       cat:"TROJAN",  sev:"critical", hits:7   },
  { id:4, sid:"2008435", gid:1, rev:3,  enabled:true,  action:"drop",  proto:"TCP",  src:"any", sport:"any", dir:"->", dst:"any",        dport:"80",  msg:"ET EXPLOIT CVE-2014-6271",  cat:"EXPLOIT", sev:"critical", hits:2   },
  { id:5, sid:"2019714", gid:1, rev:12, enabled:true,  action:"alert", proto:"TCP",  src:"any", sport:"any", dir:"->", dst:"$HOME_NET", dport:"any", msg:"ET SCAN Nmap Detected",      cat:"SCAN",    sev:"low",      hits:891 },
  { id:6, sid:"2010935", gid:1, rev:7,  enabled:false, action:"alert", proto:"TCP",  src:"any", sport:"any", dir:"->", dst:"$HOME_NET", dport:"any", msg:"ET POLICY PE EXE download",  cat:"MALWARE", sev:"high",     hits:0   },
  { id:7, sid:"2030171", gid:1, rev:2,  enabled:true,  action:"drop",  proto:"TCP",  src:"any", sport:"any", dir:"->", dst:"$HOME_NET", dport:"443", msg:"ET MALWARE Win32/Dridex",    cat:"MALWARE", sev:"critical", hits:1   },
  { id:8, sid:"2011010", gid:1, rev:4,  enabled:true,  action:"drop",  proto:"UDP",  src:"any", sport:"any", dir:"->", dst:"$HOME_NET", dport:"631", msg:"ET WEB CUPS DoS attempt",    cat:"DDOS",    sev:"high",     hits:3   },
  { id:9, sid:"2000419", gid:1, rev:15, enabled:false, action:"alert", proto:"TCP",  src:"any", sport:"any", dir:"->", dst:"any",        dport:"6667",msg:"ET POLICY IRC message",      cat:"POLICY",  sev:"low",      hits:0   },
  { id:10,sid:"2027758", gid:1, rev:1,  enabled:true,  action:"alert", proto:"TCP",  src:"any", sport:"any", dir:"->", dst:"any",        dport:"any", msg:"ET HUNTING POST to Quad IP", cat:"HUNTING", sev:"medium",   hits:19  },
];

function RulesManager() {
  const [rules,setRules]     = useState(DEFAULT_RULES);
  const [q,setQ]             = useState("");
  const [catF,setCatF]       = useState("ALL");
  const [editing,setEditing] = useState(null);   // rule id or "new"
  const [editForm,setEditForm] = useState({});
  const [saved,setSaved]     = useState(false);
  const [sortBy,setSortBy]   = useState("hits");
  const [sortDir,setSortDir] = useState("desc");

  const CATS = ["ALL","SCAN","DDOS","EXPLOIT","TROJAN","MALWARE","POLICY","HUNTING"];
  const ACTIONS = ["alert","drop","pass","reject","log"];

  const sorted = [...rules]
    .filter(r=>(catF==="ALL"||r.cat===catF)&&(!q||(r.msg.toLowerCase().includes(q.toLowerCase())||r.sid.includes(q))))
    .sort((a,b)=>{
      const av = a[sortBy], bv = b[sortBy];
      if(typeof av==="number") return sortDir==="desc"?bv-av:av-bv;
      return sortDir==="desc"?String(bv).localeCompare(String(av)):String(av).localeCompare(String(bv));
    });

  const toggleRule = (id) => setRules(p=>p.map(r=>r.id===id?{...r,enabled:!r.enabled}:r));
  const deleteRule = (id) => setRules(p=>p.filter(r=>r.id!==id));

  const openEdit = (rule) => {
    setEditForm(rule ? {...rule} : {
      sid:"", gid:1, rev:1, enabled:true, action:"alert", proto:"TCP",
      src:"any", sport:"any", dir:"->", dst:"$HOME_NET", dport:"any",
      msg:"", cat:"SCAN", sev:"medium", hits:0
    });
    setEditing(rule ? rule.id : "new");
  };

  const saveEdit = () => {
    if(editing==="new") {
      setRules(p=>[...p,{...editForm, id:Date.now(), hits:0}]);
    } else {
      setRules(p=>p.map(r=>r.id===editing?{...editForm,id:editing}:r));
    }
    setEditing(null);
    setSaved(true); setTimeout(()=>setSaved(false),2000);
  };

  const ruleToSnort = (r) =>
    `${r.action} ${r.proto.toLowerCase()} ${r.src} ${r.sport} ${r.dir} ${r.dst} ${r.dport} (msg:"${r.msg}"; sid:${r.sid}; gid:${r.gid}; rev:${r.rev};)`;

  const toggleSort = (col) => {
    if(sortBy===col) setSortDir(p=>p==="desc"?"asc":"desc");
    else { setSortBy(col); setSortDir("desc"); }
  };

  const SortIcon = ({col}) => sortBy!==col?<Minus size={10} className="text-gray-700"/>:
    sortDir==="desc"?<ChevronDown size={10} className="text-blue-400"/>:<ChevronUp size={10} className="text-blue-400"/>;

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative">
          <Search size={12} className="absolute left-2.5 top-2 text-gray-600"/>
          <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search rules, SIDs…"
            className="bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 w-52"/>
        </div>
        <div className="flex gap-1 flex-wrap">
          {CATS.map(c=>(
            <button key={c} onClick={()=>setCatF(c)}
              style={catF===c&&c!=="ALL"?{background:CATC[c]||"#8e8e93",borderColor:"transparent"}:{}}
              className={`px-2.5 py-1 rounded text-xs font-bold font-mono border transition-all ${
                catF===c?"text-white border-transparent":"text-gray-500 border-gray-700 hover:border-gray-500"
              }`}>{c}</button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          {saved && <span className="text-xs text-green-400 flex items-center gap-1"><Check size={11}/>Saved</span>}
          <button onClick={()=>openEdit(null)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition-all">
            <Plus size={12}/>New Rule
          </button>
        </div>
      </div>

      {/* Edit modal */}
      {editing !== null && (
        <div className="rounded-xl border border-blue-900 bg-gray-950 p-4 space-y-3">
          <div className="flex items-center gap-2 mb-1">
            <Edit3 size={13} className="text-blue-400"/>
            <span className="text-sm font-bold text-white">{editing==="new"?"New Rule":"Edit Rule — SID "+editForm.sid}</span>
            <button onClick={()=>setEditing(null)} className="ml-auto text-gray-600 hover:text-gray-300"><X size={14}/></button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { k:"msg",     label:"Message",      span:4 },
              { k:"sid",     label:"SID" },
              { k:"gid",     label:"GID" },
              { k:"rev",     label:"Revision" },
              { k:"action",  label:"Action",       opts:ACTIONS },
              { k:"proto",   label:"Protocol",     opts:["TCP","UDP","ICMP","any"] },
              { k:"src",     label:"Source IP" },
              { k:"sport",   label:"Src Port" },
              { k:"dir",     label:"Direction",    opts:["->","<>","<-"] },
              { k:"dst",     label:"Dest IP" },
              { k:"dport",   label:"Dst Port" },
              { k:"cat",     label:"Category",     opts:["SCAN","DDOS","EXPLOIT","TROJAN","MALWARE","POLICY","HUNTING"] },
              { k:"sev",     label:"Severity",     opts:["low","medium","high","critical"] },
            ].map(f=>(
              <div key={f.k} style={{gridColumn:`span ${f.span||1}`}}>
                <label className="text-xs text-gray-500 mb-1 block">{f.label}</label>
                {f.opts ? (
                  <select value={editForm[f.k]||""} onChange={e=>setEditForm(p=>({...p,[f.k]:e.target.value}))}
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white font-mono focus:outline-none">
                    {f.opts.map(o=><option key={o} value={o}>{o}</option>)}
                  </select>
                ) : (
                  <input value={editForm[f.k]||""} onChange={e=>setEditForm(p=>({...p,[f.k]:e.target.value}))}
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-blue-500"/>
                )}
              </div>
            ))}
          </div>
          {/* Snort rule preview */}
          <div>
            <div className="text-xs text-gray-600 mb-1 flex items-center gap-1"><Eye size={10}/>Rule preview</div>
            <div className="bg-black rounded-lg p-2.5 font-mono text-xs text-green-400 break-all">
              {ruleToSnort(editForm)}
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={saveEdit} className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition-all">
              <Save size={12}/>Save Rule
            </button>
            <button onClick={()=>setEditing(null)} className="px-4 py-2 rounded-lg border border-gray-700 text-gray-400 text-xs hover:border-gray-500 transition-all">Cancel</button>
          </div>
        </div>
      )}

      {/* Rules table */}
      <div className="rounded-xl border border-gray-800 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="bg-gray-900 border-b border-gray-800">
              {[
                { label:"En",      col:null },
                { label:"SID",     col:"sid" },
                { label:"Action",  col:"action" },
                { label:"Message", col:"msg" },
                { label:"Cat",     col:"cat" },
                { label:"Sev",     col:"sev" },
                { label:"Proto",   col:"proto" },
                { label:"Dst Port",col:"dport" },
                { label:"Hits",    col:"hits" },
                { label:"",        col:null },
              ].map(h=>(
                <th key={h.label} onClick={h.col?()=>toggleSort(h.col):undefined}
                  className={`px-3 py-2 text-left text-xs font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap ${h.col?"cursor-pointer hover:text-gray-300":""}`}>
                  <span className="flex items-center gap-1">{h.label}{h.col&&<SortIcon col={h.col}/>}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map(r=>(
              <tr key={r.id} style={{borderBottom:"1px solid #21262d",opacity:r.enabled?1:0.45}} className="hover:bg-white/[0.02]">
                <td className="px-3 py-2.5">
                  <button onClick={()=>toggleRule(r.id)}
                    style={{color:r.enabled?"#30d158":"#8e8e93"}} className="hover:opacity-80 transition-opacity">
                    {r.enabled ? <ToggleRight size={18}/> : <ToggleLeft size={18}/>}
                  </button>
                </td>
                <td className="px-3 py-2.5 text-xs text-gray-400 font-mono">{r.gid}:{r.sid}</td>
                <td className="px-3 py-2.5">
                  <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded ${
                    r.action==="drop"||r.action==="reject"
                      ?"text-red-400 bg-red-900/20 border border-red-900"
                      :r.action==="pass"
                        ?"text-green-400 bg-green-900/20 border border-green-900"
                        :"text-blue-400 bg-blue-900/20 border border-blue-900"
                  }`}>{r.action}</span>
                </td>
                <td className="px-3 py-2.5 text-xs text-gray-200 max-w-xs truncate font-medium" title={r.msg}>{r.msg}</td>
                <td className="px-3 py-2.5"><CatBadge cat={r.cat}/></td>
                <td className="px-3 py-2.5"><SevBadge sev={r.sev}/></td>
                <td className="px-3 py-2.5 text-xs text-gray-500 font-mono">{r.proto}</td>
                <td className="px-3 py-2.5 text-xs text-gray-500 font-mono">{r.dport}</td>
                <td className="px-3 py-2.5">
                  <span className={`text-xs font-bold font-mono ${r.hits>50?"text-red-400":r.hits>10?"text-orange-400":"text-gray-500"}`}>{r.hits}</span>
                </td>
                <td className="px-3 py-2.5 flex items-center gap-2">
                  <button onClick={()=>openEdit(r)} className="text-gray-600 hover:text-blue-400 transition-colors"><Edit3 size={13}/></button>
                  <button onClick={()=>{ navigator.clipboard?.writeText(ruleToSnort(r)); }}
                    title="Copy rule" className="text-gray-600 hover:text-yellow-400 transition-colors"><Copy size={13}/></button>
                  <button onClick={()=>deleteRule(r.id)} className="text-gray-600 hover:text-red-400 transition-colors"><Trash2 size={13}/></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="px-3 py-2 border-t border-gray-800 flex items-center gap-4 text-xs text-gray-600">
          <span>Total: <span className="text-white font-bold">{rules.length}</span></span>
          <span>Enabled: <span className="text-green-400 font-bold">{rules.filter(r=>r.enabled).length}</span></span>
          <span>Disabled: <span className="text-gray-500 font-bold">{rules.filter(r=>!r.enabled).length}</span></span>
          <span>Drop rules: <span className="text-red-400 font-bold">{rules.filter(r=>r.action==="drop"||r.action==="reject").length}</span></span>
          <button onClick={()=>{
            const txt = rules.filter(r=>r.enabled).map(ruleToSnort).join("\n");
            navigator.clipboard?.writeText(txt);
          }} className="ml-auto flex items-center gap-1 text-gray-500 hover:text-white transition-colors">
            <Copy size={11}/>Export active rules
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── NOTIFICATIONS (compact) ──────────────────────────────────────────────────
function Notifications() {
  const [cfg,setCfg] = useState({
    telegram:{ enabled:true,  token:"", chatId:"", minSev:"high"     },
    email:   { enabled:false, smtp:"smtp.gmail.com", port:"587", user:"", pass:"", to:"", minSev:"critical" },
    jira:    { enabled:false, url:"", project:"SEC", token:"", minSev:"critical" },
    slack:   { enabled:false, webhook:"", minSev:"high" },
  });
  const [saved,setSaved] = useState(false);
  const [testing,setTesting] = useState(null);
  const test = async (ch) => { setTesting(ch); await new Promise(r=>setTimeout(r,1500)); setTesting(null); };

  const channels = [
    { key:"telegram", label:"Telegram",  icon:"✈️", color:"#0a84ff", fields:[{k:"token",label:"Bot Token",ph:"7812345678:AAH..."},{k:"chatId",label:"Chat ID",ph:"-100123456789"}] },
    { key:"email",    label:"Email",     icon:"📧", color:"#30d158", fields:[{k:"smtp",label:"SMTP",ph:"smtp.gmail.com"},{k:"port",label:"Port",ph:"587"},{k:"user",label:"User",ph:"you@domain.com"},{k:"to",label:"Recipient",ph:"soc@domain.com"}] },
    { key:"jira",     label:"Jira",      icon:"🔵", color:"#bf5af2", fields:[{k:"url",label:"Jira URL",ph:"https://org.atlassian.net"},{k:"project",label:"Project",ph:"SEC"},{k:"token",label:"API Token",ph:"••••••••"}] },
    { key:"slack",    label:"Slack",     icon:"💬", color:"#ff9f0a", fields:[{k:"webhook",label:"Webhook URL",ph:"https://hooks.slack.com/..."}] },
  ];

  return (
    <div className="space-y-3 max-w-2xl">
      {channels.map(ch=>(
        <div key={ch.key} style={{borderColor:cfg[ch.key].enabled?`${ch.color}40`:"#21262d"}} className="rounded-xl border bg-gray-950 p-4 transition-all">
          <div className="flex items-center gap-3 mb-3">
            <span className="text-xl">{ch.icon}</span>
            <span className="font-bold text-white">{ch.label}</span>
            <div className="ml-auto flex items-center gap-3">
              <button onClick={()=>test(ch.key)} disabled={!cfg[ch.key].enabled||testing===ch.key}
                style={{color:ch.color,borderColor:`${ch.color}40`}} className="text-xs px-3 py-1 rounded-lg border disabled:opacity-30 hover:opacity-80 font-mono">
                {testing===ch.key?"Testing…":"Test"}
              </button>
              <button onClick={()=>setCfg(p=>({...p,[ch.key]:{...p[ch.key],enabled:!p[ch.key].enabled}}))}
                style={{background:cfg[ch.key].enabled?ch.color:"#21262d"}} className="w-10 h-5 rounded-full relative transition-all">
                <div style={{left:cfg[ch.key].enabled?"calc(100% - 18px)":"2px"}} className="absolute top-0.5 w-4 h-4 bg-white rounded-full transition-all"/>
              </button>
            </div>
          </div>
          {cfg[ch.key].enabled && (
            <div className="space-y-2">
              <div className="grid grid-cols-2 gap-2">
                {ch.fields.map(f=>(
                  <div key={f.k}>
                    <label className="text-xs text-gray-500 mb-1 block">{f.label}</label>
                    <input value={cfg[ch.key][f.k]||""} placeholder={f.ph}
                      type={f.k==="pass"||f.k==="token"?"password":"text"}
                      onChange={e=>setCfg(p=>({...p,[ch.key]:{...p[ch.key],[f.k]:e.target.value}}))}
                      className="w-full bg-gray-900 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-blue-500"/>
                  </div>
                ))}
              </div>
              <div className="flex items-center gap-2">
                <label className="text-xs text-gray-500">Min severity</label>
                <select value={cfg[ch.key].minSev} onChange={e=>setCfg(p=>({...p,[ch.key]:{...p[ch.key],minSev:e.target.value}}))}
                  className="bg-gray-900 border border-gray-700 rounded-lg px-2 py-1 text-xs text-white focus:outline-none">
                  {["low","medium","high","critical"].map(v=><option key={v} value={v}>{v.toUpperCase()}+</option>)}
                </select>
              </div>
            </div>
          )}
        </div>
      ))}
      <button onClick={()=>{setSaved(true);setTimeout(()=>setSaved(false),2500);}}
        className="flex items-center gap-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold transition-all">
        {saved?<><Check size={14}/>Saved!</>:<><Save size={14}/>Save Configuration</>}
      </button>
    </div>
  );
}

// ─── CONNECTION ───────────────────────────────────────────────────────────────
function Connection({ host, setHost, router, setRouter, backendUrl, setBackendUrl, apiKey, setApiKey, backendStatus, setBackendStatus, backendStats, setBackendStats, sshStatus, setSshStatus, snortStatus, setSnortStatus, dbStatus, setDbStatus, routerStatus, setRouterStatus }) {
  const [form,setForm] = useState({...host});
  const [routerForm,setRouterForm] = useState({...router});
  const [showSshPass,setShowSshPass] = useState(false);
  const [showRouterPass,setShowRouterPass] = useState(false);
  const [routerBusy,setRouterBusy] = useState(false);

  useEffect(()=>{ setForm({...host}); },[host]);
  useEffect(()=>{ setRouterForm({...router}); },[router]);

  const connectSSH = async () => {
    if(!form.ip) { setSshStatus("error"); return; }
    setSshStatus("connecting");
    setSnortStatus("checking");
    try {
      const payload = {
        ip: form.ip, port: form.port || "22", user: form.user || "snort",
        password: form.sshPass || "", sudoPassword: form.sudoPass || "", authMode: form.authMode || "SSH Key",
        logPath: form.logPath || "/var/log/snort/alert_json.txt",
        keyPath: "/app/keys/snort_id_rsa",
      };
      const res = await fetch(`${backendUrl}/api/config/connection`,{
        method:"POST",
        headers:{"Content-Type":"application/json",...(apiKey?{"X-API-Key":apiKey}:{})},
        body:JSON.stringify(payload)
      });
      const data = await res.json();
      if(data.ok) {
        setSshStatus("connected");
        setSnortStatus("running");
        setHost({...form,...payload,connected:true,lastError:""});
      } else {
        setSshStatus("error");
        setSnortStatus("down");
        setHost({...form,...payload,connected:false,lastError:data.message||"Connection failed"});
      }
    } catch(e) {
      setSshStatus("error");
      setSnortStatus("down");
      setHost({...form,connected:false,lastError:e.message});
    }
  };

  const disconnectSSH = () => {
    setSshStatus("idle");
    setSnortStatus("idle");
    setHost({...form,connected:false});
  };

  const saveRouterState = (nextForm, data = {}) => {
    const next = {
      ...nextForm,
      connected: !!data.ok,
      routerInfo: data.info || nextForm.routerInfo || null,
      lastError: data.ok ? "" : (data.message || nextForm.lastError || ""),
      lastMessage: data.message || "",
    };
    setRouter(next);
    setRouterForm(next);
  };

  const connectRouter = async () => {
    if(!routerForm.ip) {
      setRouterStatus("error");
      saveRouterState(routerForm, { ok:false, message:"Main router IP is required" });
      return;
    }
    setRouterBusy(true);
    setRouterStatus("connecting");
    try {
      const payload = {
        ip: routerForm.ip,
        port: routerForm.port || "22",
        user: routerForm.user || "root",
        password: routerForm.sshPass || "",
        authMode: routerForm.authMode || "Password",
        keyPath: "/app/keys/router_id_rsa",
        routerType: routerForm.routerType || "OpenWRT",
        monitorInterface: routerForm.monitorInterface || "",
        mirrorTarget: routerForm.mirrorTarget || "",
        note: routerForm.note || "",
      };
      const res = await fetch(`${backendUrl}/api/config/router`,{
        method:"POST",
        headers:{"Content-Type":"application/json",...(apiKey?{"X-API-Key":apiKey}:{})},
        body:JSON.stringify(payload)
      });
      const data = await res.json();
      setRouterStatus(data.ok ? "connected" : "error");
      saveRouterState({...routerForm,...payload}, data);
    } catch(e) {
      setRouterStatus("error");
      saveRouterState(routerForm, { ok:false, message:e.message });
    } finally {
      setRouterBusy(false);
    }
  };

  const refreshRouter = async () => {
    if(!routerForm.ip) return;
    setRouterBusy(true);
    try {
      const res = await fetch(`${backendUrl}/api/router/info`,{ headers: apiKey ? {"X-API-Key":apiKey} : {} });
      const data = await res.json();
      setRouterStatus(data.ok ? "connected" : "error");
      saveRouterState(routerForm, data);
    } catch(e) {
      setRouterStatus("error");
      saveRouterState(routerForm, { ok:false, message:e.message });
    } finally {
      setRouterBusy(false);
    }
  };

  const disconnectRouter = () => {
    setRouterStatus("idle");
    setRouter({...routerForm,connected:false,routerInfo:null,lastError:"",lastMessage:""});
  };

  const effectiveBackend = sshStatus==="error"||sshStatus==="down" ? "degraded" : backendStatus;
  const effectiveDb      = sshStatus==="error"||sshStatus==="down" ? "down" : dbStatus;
  const effectiveSnort   = sshStatus==="error"||sshStatus==="down" ? "down" : snortStatus;
  const routerInfo = router.routerInfo || null;
  const routerIdentifier = routerInfo?.hostname || routerForm.ip || "main-router";

  const infoCards = [
    { label:"Main router reachable", value: routerInfo ? (routerInfo.reachable ? "yes" : "no") : "—" },
    { label:"Hostname", value: routerInfo?.hostname || "not detected", mono:true },
    { label:"Firmware version", value: routerInfo?.firmwareVersion || "not detected" },
    { label:"WAN IP", value: routerInfo?.wanIp || "not detected", mono:true },
    { label:"LAN IP", value: routerInfo?.lanIp || "not detected", mono:true },
    { label:"Monitored interface", value: routerInfo?.monitoredInterface || routerForm.monitorInterface || "not set", mono:true },
    { label:"Bridge / interfaces", value: routerInfo?.bridgeNames || routerInfo?.lanBridge || "not detected", mono:true },
    { label:"Firewall zones", value: routerInfo?.firewallZones || "not detected", mono:true },
    { label:"Mirror / SPAN target", value: routerInfo?.mirrorSpanTarget || routerForm.mirrorTarget || "not detected", mono:true },
    { label:"tcpdump test", value: routerInfo?.tcpdump || "not tested", mono:true },
    { label:"Packet counters", value: routerInfo?.packetCounters || "not available", mono:true },
    { label:"Candidate interfaces", value: routerInfo?.candidateInterfaces || "not detected", mono:true },
    { label:"Snort / Suricata packages", value: routerInfo?.packages || "not detected", mono:true },
    { label:"Latency", value: routerInfo?.latencyMs != null ? `${routerInfo.latencyMs} ms` : "not measured", mono:true },
  ];

  return (
    <div className="max-w-5xl space-y-4">
      <DependencyChain sshStatus={sshStatus} backendStatus={effectiveBackend} dbStatus={effectiveDb} snortStatus={effectiveSnort} routerStatus={routerStatus} router={router}/>

      <div className="rounded-xl border border-cyan-900/30 bg-cyan-950/10 p-4 text-sm text-cyan-100 space-y-2">
        <div className="font-bold flex items-center gap-2"><Radio size={14} className="text-cyan-400"/>Traffic source model</div>
        <div className="text-cyan-100/80 text-xs leading-5">
          SnortVision still reads alerts from the <span className="text-white font-semibold">Snort sensor</span>. The main router box below is an optional <span className="text-white font-semibold">management target</span> for OpenWRT, another router platform, or any SSH-accessible edge device. When no dedicated sensor interface is configured, the backend can now fall back to the main router interface counters so the dashboard shows real edge traffic instead of staying blind.
        </div>
      </div>

      <SnortAPIPanel
        backendUrl={backendUrl} setBackendUrl={setBackendUrl}
        apiKey={apiKey} setApiKey={setApiKey}
        status={backendStatus} setStatus={setBackendStatus}
        dbStats={backendStats} setDbStats={setBackendStats}/>

      <div className="rounded-xl border border-gray-800 bg-gray-950 p-5 space-y-3">
        <div className="flex items-center gap-2">
          <Terminal size={14} className="text-green-400"/>
          <span className="font-bold text-white">Snort Sensor — Alert Source & SSH</span>
          {sshStatus==="connected" && <span className="ml-auto flex items-center gap-1.5 text-xs text-green-400 font-mono"><CheckCircle2 size={12}/>CONNECTED</span>}
        </div>
        <div className="text-xs text-gray-500">This is the host that runs Snort3 and produces the alert log consumed by the GUI.</div>
        {backendStatus!=="connected" && (
          <div className="text-xs text-yellow-500/80 bg-yellow-900/10 rounded-lg px-3 py-2 border border-yellow-900/20 flex items-center gap-1.5">
            <AlertTriangle size={11}/>Connect the Snort API above first — SSH goes through the backend.
          </div>
        )}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Sensor IP</label>
            <div className="relative"><Globe size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={form.ip||""} placeholder="192.168.1.72" onChange={e=>setForm(p=>({...p,ip:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">SSH Port</label>
            <div className="relative"><Hash size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={form.port||""} placeholder="22" onChange={e=>setForm(p=>({...p,port:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">SSH User</label>
            <div className="relative"><User size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={form.user||""} placeholder="snort3" onChange={e=>setForm(p=>({...p,user:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">SSH Password</label>
            <div className="relative"><Lock size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={form.sshPass||""} type={showSshPass?"text":"password"} placeholder="••••••••" onChange={e=>setForm(p=>({...p,sshPass:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-9 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
              <button onClick={()=>setShowSshPass(p=>!p)} className="absolute right-2.5 top-2.5 text-gray-600 hover:text-gray-300">{showSshPass?<EyeOff size={14}/>:<Eye size={14}/>}</button>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Sudo Password</label>
            <div className="relative"><Shield size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={form.sudoPass||""} type={showSshPass?"text":"password"} placeholder="optional — used for service control" onChange={e=>setForm(p=>({...p,sudoPass:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
            </div>
          </div>
        </div>
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Alert Log Path</label>
          <div className="relative"><FileText size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
            <input value={form.logPath||""} placeholder="/var/log/snort/alert_json.txt" onChange={e=>setForm(p=>({...p,logPath:e.target.value}))}
              className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"/>
          </div>
        </div>
        <div className="flex gap-2 flex-wrap">
          {["SSH Key","Password"].map(m=>(
            <button key={m} onClick={()=>setForm(p=>({...p,authMode:m}))}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-all ${form.authMode===m?"bg-blue-600 border-blue-600 text-white":"border-gray-700 text-gray-400 hover:border-gray-500"}`}>
              {m==="SSH Key"?<span className="flex items-center gap-1.5"><Key size={11}/>{m}</span>:<span className="flex items-center gap-1.5"><Lock size={11}/>{m}</span>}
            </button>
          ))}
        </div>
        <div className="text-xs text-gray-500 bg-gray-900/50 rounded-lg px-3 py-2">
          Use <span className="text-white font-semibold">SSH Password</span> for SSH login when auth mode is Password. Use <span className="text-white font-semibold">Sudo Password</span> when the SSH user can connect but still needs <span className="font-mono text-cyan-300">sudo</span> for Snort3 status/restart.
        </div>
        {form.authMode==="SSH Key" && (
          <div className="text-xs text-gray-500 bg-gray-900/50 rounded-lg px-3 py-2 font-mono">
            Sensor SSH key path: <span className="text-blue-400">/app/keys/snort_id_rsa</span>
          </div>
        )}
        <div className="flex gap-2">
          <button onClick={connectSSH} disabled={sshStatus==="connecting"}
            className={`flex-1 py-2.5 rounded-xl font-bold text-sm flex items-center justify-center gap-2 transition-all ${
              sshStatus==="connected"?"bg-green-600 text-white":sshStatus==="connecting"?"bg-gray-700 text-gray-400 cursor-wait":"bg-blue-600 hover:bg-blue-500 text-white"}`}>
            {sshStatus==="connected"?<><Check size={14}/>Connected to {form.ip}</>:sshStatus==="connecting"?<><RefreshCw size={14} className="animate-spin"/>Connecting…</>:<><Wifi size={14}/>Connect Sensor</>}
          </button>
          {sshStatus==="connected" && (
            <button onClick={disconnectSSH} className="px-4 py-2.5 rounded-xl border border-gray-700 text-gray-400 hover:border-red-700 hover:text-red-400 text-sm font-bold transition-all flex items-center gap-1.5">
              <Unlink size={14}/>Disconnect
            </button>
          )}
        </div>
        {sshStatus==="error" && host.lastError && (
          <div className="flex items-center gap-2 text-xs text-red-400 bg-red-900/10 rounded-lg px-3 py-2 border border-red-900/30">
            <XCircle size={12} className="flex-shrink-0"/>
            <span className="font-mono">{host.lastError}</span>
          </div>
        )}
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-950 p-5 space-y-4">
        <div className="flex items-center gap-2">
          <Server size={14} className="text-cyan-400"/>
          <span className="font-bold text-white">Main Router Connection</span>
          {routerStatus==="connected" && <span className="ml-auto flex items-center gap-1.5 text-xs text-cyan-300 font-mono"><CheckCircle2 size={12}/>MANAGED {routerIdentifier}</span>}
        </div>
        <div className="text-xs text-gray-500">Use this target for main-router metadata and packet-path context. It is not the source of Snort alerts unless Snort itself runs on that router.</div>
        {backendStatus!=="connected" && (
          <div className="text-xs text-yellow-500/80 bg-yellow-900/10 rounded-lg px-3 py-2 border border-yellow-900/20 flex items-center gap-1.5">
            <AlertTriangle size={11}/>Connect the Snort API above first — router checks are performed by the backend.
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Main Router Type</label>
            <select value={routerForm.routerType||"OpenWRT"} onChange={e=>setRouterForm(p=>({...p,routerType:e.target.value}))}
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
              {["OpenWRT","Generic Router/Linux"].map(v=><option key={v} value={v}>{v}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Main Router IP</label>
            <div className="relative"><Globe size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={routerForm.ip||""} placeholder="192.168.1.1" onChange={e=>setRouterForm(p=>({...p,ip:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyan-500"/>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">SSH Port</label>
            <div className="relative"><Hash size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={routerForm.port||""} placeholder="22" onChange={e=>setRouterForm(p=>({...p,port:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyan-500"/>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">SSH User</label>
            <div className="relative"><User size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={routerForm.user||""} placeholder={routerForm.routerType==="OpenWRT"?"root":"admin"} onChange={e=>setRouterForm(p=>({...p,user:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyan-500"/>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Monitored Interface</label>
            <div className="relative"><Activity size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={routerForm.monitorInterface||""} placeholder="eth1 / br-lan / pppoe-wan" onChange={e=>setRouterForm(p=>({...p,monitorInterface:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyan-500"/>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 mb-1 block">Mirror / SPAN Target</label>
            <div className="relative"><Link2 size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={routerForm.mirrorTarget||""} placeholder="snort-sensor:eth1 or switch span note" onChange={e=>setRouterForm(p=>({...p,mirrorTarget:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyan-500"/>
            </div>
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-gray-500 mb-1 block">SSH Password</label>
            <div className="relative"><Lock size={13} className="absolute left-2.5 top-2.5 text-gray-600"/>
              <input value={routerForm.sshPass||""} type={showRouterPass?"text":"password"} placeholder="••••••••" onChange={e=>setRouterForm(p=>({...p,sshPass:e.target.value}))}
                className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-8 pr-9 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyan-500"/>
              <button onClick={()=>setShowRouterPass(p=>!p)} className="absolute right-2.5 top-2.5 text-gray-600 hover:text-gray-300">{showRouterPass?<EyeOff size={14}/>:<Eye size={14}/>}</button>
            </div>
          </div>
        </div>

        <div className="flex gap-2 flex-wrap">
          {["Password","SSH Key"].map(m=>(
            <button key={m} onClick={()=>setRouterForm(p=>({...p,authMode:m}))}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-all ${routerForm.authMode===m?"bg-cyan-600 border-cyan-600 text-white":"border-gray-700 text-gray-400 hover:border-gray-500"}`}>
              {m==="SSH Key"?<span className="flex items-center gap-1.5"><Key size={11}/>{m}</span>:<span className="flex items-center gap-1.5"><Lock size={11}/>{m}</span>}
            </button>
          ))}
        </div>
        {routerForm.authMode==="SSH Key" && (
          <div className="text-xs text-gray-500 bg-gray-900/50 rounded-lg px-3 py-2 font-mono">
            Main router SSH key path: <span className="text-cyan-300">/app/keys/router_id_rsa</span>
          </div>
        )}

        <div className="flex gap-2 flex-wrap">
          <button onClick={connectRouter} disabled={routerBusy}
            className={`flex-1 min-w-[220px] py-2.5 rounded-xl font-bold text-sm flex items-center justify-center gap-2 transition-all ${
              routerBusy?"bg-gray-700 text-gray-400 cursor-wait":routerStatus==="connected"?"bg-cyan-600 text-white":"bg-blue-600 hover:bg-blue-500 text-white"}`}>
            {routerBusy?<><RefreshCw size={14} className="animate-spin"/>Checking main router…</>:routerStatus==="connected"?<><Check size={14}/>Main router connected</>:<><Wifi size={14}/>Connect Main Router</>}
          </button>
          <button onClick={refreshRouter} disabled={routerBusy || !routerForm.ip} className="px-4 py-2.5 rounded-xl border border-gray-700 text-gray-300 hover:border-cyan-500 hover:text-cyan-300 text-sm font-bold transition-all flex items-center gap-1.5 disabled:opacity-40">
            <RefreshCw size={14}/>Refresh Router Info
          </button>
          {(routerStatus==="connected" || router.connected) && (
            <button onClick={disconnectRouter} className="px-4 py-2.5 rounded-xl border border-gray-700 text-gray-400 hover:border-red-700 hover:text-red-400 text-sm font-bold transition-all flex items-center gap-1.5">
              <Unlink size={14}/>Disconnect
            </button>
          )}
        </div>

        {(router.lastMessage || router.lastError) && (
          <div className={`flex items-center gap-2 text-xs rounded-lg px-3 py-2 border ${router.lastError?"text-red-400 bg-red-900/10 border-red-900/30":"text-cyan-200 bg-cyan-900/10 border-cyan-900/30"}`}>
            {router.lastError?<XCircle size={12} className="flex-shrink-0"/>:<CheckCircle2 size={12} className="flex-shrink-0"/>}
            <span className="font-mono">{router.lastError || router.lastMessage}</span>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {infoCards.map(card=>(
            <div key={card.label} className="rounded-xl border border-gray-800 bg-black/30 p-3">
              <div className="text-[11px] uppercase tracking-wider text-gray-500 mb-1">{card.label}</div>
              <div className={`${card.mono?"font-mono":""} text-sm text-white break-words`}>{card.value}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div className="text-xs font-bold text-gray-500 mb-2">Snort3 JSON output config</div>
        <div className="bg-black rounded-lg p-3 font-mono text-xs text-green-400 space-y-0.5">
          <div className="text-gray-500"># /etc/snort/snort.lua</div>
          <div>alert_json = {"{"}</div>
          <div className="pl-4">file = true, limit = 100,</div>
          <div className="pl-4">fields = 'timestamp action msg src_addr src_port dst_addr dst_port proto sid gid'</div>
          <div>{"}"}</div>
        </div>
      </div>

      <DatabasePanel backendUrl={backendUrl} apiKey={apiKey} backendStatus={backendStatus} dbStatus={dbStatus} setDbStatus={setDbStatus}/>
      <DbManagePanel backendUrl={backendUrl} apiKey={apiKey}/>
      <SyncPanel backendUrl={backendUrl} apiKey={apiKey} status={backendStatus} router={router}/>
      <ServiceControlPanel backendUrl={backendUrl} apiKey={apiKey} status={backendStatus}/>
    </div>
  );
}

// ─── Persistence (localStorage) ─────────────────────────────────────────────
function loadSaved(key, fallback) {
  try { const v = localStorage.getItem(`sv_${key}`); return v ? JSON.parse(v) : fallback; }
  catch { return fallback; }
}
function saveSetting(key, value) {
  try { localStorage.setItem(`sv_${key}`, JSON.stringify(value)); } catch {}
}

function getDefaultBackendUrl() {
  // 1. Explicit build-time override (VITE_BACKEND_URL in .env)
  const envUrl = typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_BACKEND_URL
    ? String(import.meta.env.VITE_BACKEND_URL).trim()
    : "";
  if (envUrl) return envUrl;

  if (typeof window !== "undefined") {
    // 2. When served via a reverse proxy (nginx/NPM) the frontend nginx.conf
    //    already proxies /api/ and /ws to the backend container.
    //    Use same-origin (no port) so it works both on LAN (:3000) and via domain (HTTPS).
    const port = window.location.port;
    // Only append :4000 if accessing the raw Vite dev server (port 5173)
    // or an explicit VITE_BACKEND_PORT override.
    const vitePort = (typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_BACKEND_PORT)
      ? String(import.meta.env.VITE_BACKEND_PORT).trim()
      : "";
    if (vitePort) {
      const proto = window.location.protocol === "https:" ? "https:" : "http:";
      return `${proto}//${window.location.hostname}:${vitePort}`;
    }
    // Same-origin: nginx in the frontend container handles the /api/ proxy
    return window.location.origin;
  }

  return "http://localhost:4000";
}

if (typeof document !== "undefined") {
  document.documentElement.dataset.theme = loadSaved("theme", "dark");
}

// ─── APP ──────────────────────────────────────────────────────────────────────
export default function SnortVision() {
  const [page,setPage]       = useState(()=>loadSaved("page","dashboard"));
  const [alerts,setAlerts]   = useState([]);
  const [traffic,setTraffic] = useState(() => Array.from({ length: 40 }, () => blankTrafficPoint()));
  const [newIds,setNewIds]   = useState(new Set());
  const [toasts,setToasts]   = useState([]);
  const [ddosMode,setDdosMode] = useState(false);
  const [theme,setTheme]     = useState(()=>loadSaved("theme","dark"));
  const [host,setHost]       = useState(()=>loadSaved("host",{ip:"192.168.10.50",port:"22",user:"snort",sshPass:"",sudoPass:"",authMode:"SSH Key",logPath:"/var/log/snort/alert_json.txt",connected:false}));
  const [router,setRouter]   = useState(()=>loadSaved("router",{ip:"",port:"22",user:"root",sshPass:"",authMode:"Password",routerType:"OpenWRT",monitorInterface:"",mirrorTarget:"",connected:false,routerInfo:null}));
  const tickRef   = useRef(0);
  const lastIdRef = useRef(0);

  // ── Backend connection state (lifted here so Connection panels share it)
  const [backendUrl,setBackendUrl]   = useState(()=>{
    const saved = loadSaved("backendUrl", "");
    if (saved) {
      try {
        const u = new URL(saved);
        // Strip any saved URL that hardcodes :4000 on a non-localhost host
        // (would fail behind a reverse proxy). Use same-origin instead.
        if (u.port === "4000" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") {
          return getDefaultBackendUrl();
        }
        // Discard stale default placeholder IPs
        if (u.hostname === "192.168.10.50") return getDefaultBackendUrl();
        return saved;
      } catch { /* invalid URL saved — fall through */ }
    }
    return getDefaultBackendUrl();
  });
  const [apiKey,setApiKey]           = useState(()=>loadSaved("apiKey",""));
  const [backendStatus,setBackendStatus] = useState("disconnected");
  const [backendStats,setBackendStats]   = useState(null);
  const backendRef = useRef({url:"http://192.168.10.50:4000",key:"",status:"disconnected"});

  // ── Connection statuses (lifted to root so they survive tab switches)
  const [sshStatus,setSshStatus]     = useState("idle");
  const [snortStatus,setSnortStatus] = useState("idle");
  const [dbStatus,setDbStatus]       = useState("idle");
  const [routerStatus,setRouterStatus] = useState("idle");
  const [blocklist,setBlocklist] = useState([]);
  const [autoBlock,setAutoBlock] = useState({ enabled:true, threshold:10, window:30, blockDuration:60, minSeverity:"medium" });

  // Persist settings on change (connected:false to avoid stale state on reload)
  useEffect(()=>{ saveSetting("host",{...host,connected:false}); },[host]);
  useEffect(()=>{ saveSetting("router",{...router,connected:false}); },[router]);
  useEffect(()=>{ saveSetting("backendUrl",backendUrl); },[backendUrl]);
  useEffect(()=>{ saveSetting("apiKey",apiKey); },[apiKey]);
  useEffect(()=>{ saveSetting("theme",theme); document.documentElement.dataset.theme = theme; },[theme]);
  useEffect(()=>{ saveSetting("page",page); },[page]);

  // ── Recover backendUrl from server if localStorage was cleared ──────────────
  useEffect(()=>{
    if(backendUrl) return; // already have it
    fetch("/api/public/client-config")
      .then(r=>{ if(!r.ok) throw new Error("no config"); return r.json(); })
      .then(cfg=>{ if(cfg.backendUrl) setBackendUrl(cfg.backendUrl); })
      .catch(()=>{}); // silently ignore — user can fill in manually
  },[]);

  // keep ref in sync so polling closures always see latest values
  useEffect(()=>{ backendRef.current = {url:backendUrl, key:apiKey, status:backendStatus}; },[backendUrl,apiKey,backendStatus]);

  // ── Auto-reconnect on page load — tests API, SSH, DB, Snort in sequence
  useEffect(()=>{
    if(!backendUrl || !apiKey) return;
    (async ()=>{
      // 1. Test Snort API
      try {
        const res = await fetch(`${backendUrl}/api/health`,{ headers: {"X-API-Key":apiKey} });
        if(res.ok) {
          const data = await res.json();
          setBackendStatus("connected");
          setBackendStats(data);
          setDbStatus("connected"); // DB is managed by backend

          // 2. Test Snort3 service status
          try {
            const svcRes = await fetch(`${backendUrl}/api/services/status`,{ headers: {"X-API-Key":apiKey} });
            if(svcRes.ok) {
              const svc = await svcRes.json();
              if(svc.snort3==="running") setSnortStatus("running");
              else setSnortStatus(svc.snort3||"idle");
              // SSH status from service check
              if(svc.ssh_connection_state==="connected") setSshStatus("connected");
              else if(svc.tail_mode==="ssh") setSshStatus("connected");
              else if(svc.tail_mode==="local") setSshStatus("connected"); // local mode = no SSH needed but we show OK
            }
          } catch {}

          // 3. Test SSH if host configured
          const savedHost = loadSaved("host",{});
          if(savedHost.ip) {
            try {
              const sshRes = await fetch(`${backendUrl}/api/config/connection`,{
                method:"POST",
                headers:{"Content-Type":"application/json","X-API-Key":apiKey},
                body:JSON.stringify({
                  ip: savedHost.ip, port: savedHost.port || "22", user: savedHost.user || "snort",
                  password: savedHost.sshPass || "", sudoPassword: savedHost.sudoPass || "", authMode: savedHost.authMode || "SSH Key",
                  logPath: savedHost.logPath || "/var/log/snort/alert_json.txt",
                  keyPath: "/app/keys/snort_id_rsa",
                })
              });
              const sshData = await sshRes.json();
              if(sshData.ok) { setSshStatus("connected"); setHost(p=>({...p,connected:true})); }
            } catch {}
          }

          const savedRouter = loadSaved("router",{});
          if(savedRouter.ip) {
            try {
              const routerRes = await fetch(`${backendUrl}/api/config/router`,{
                method:"POST",
                headers:{"Content-Type":"application/json","X-API-Key":apiKey},
                body:JSON.stringify({
                  ip: savedRouter.ip,
                  port: savedRouter.port || "22",
                  user: savedRouter.user || "root",
                  password: savedRouter.sshPass || "",
                  authMode: savedRouter.authMode || "Password",
                  keyPath: "/app/keys/router_id_rsa",
                  routerType: savedRouter.routerType || "OpenWRT",
                  monitorInterface: savedRouter.monitorInterface || "",
                  mirrorTarget: savedRouter.mirrorTarget || "",
                })
              });
              const routerData = await routerRes.json();
              if(routerData.ok) {
                setRouterStatus("connected");
                setRouter(p=>({...p,connected:true,routerInfo:routerData.info || p.routerInfo,lastError:"",lastMessage:routerData.message || ""}));
              }
            } catch {}
          }
        }
      } catch {}
    })();
  },[]);  // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
  if (backendStatus !== "connected" || !backendUrl || !apiKey) return;

  const pollStats = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/stats`, {
        headers: { "X-API-Key": apiKey },
      });
      if (!res.ok) return;
      const data = await res.json();
      setBackendStats(data);
    } catch (_) {}
  };

  pollStats();
  const iv = setInterval(pollStats, 2000);
  return () => clearInterval(iv);
}, [backendStatus, backendUrl, apiKey]);

useEffect(() => {
  if (backendStatus !== "connected" || !backendUrl || !apiKey) return;

  const loadBlocklist = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/blocklist`, { headers: { "X-API-Key": apiKey } });
      if (!res.ok) return;
      const data = await res.json();
      if (Array.isArray(data)) setBlocklist(data);
    } catch (_) {}
  };

  loadBlocklist();
  const iv = setInterval(loadBlocklist, 5000);
  return () => clearInterval(iv);
}, [backendStatus, backendUrl, apiKey]);

useEffect(() => {
  if (backendStatus !== "connected" || !backendUrl || !apiKey) return;

  const hydrateAlerts = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/alerts?limit=500`, {
        headers: { "X-API-Key": apiKey },
      });
      if (!res.ok) return;
      const data = await res.json();
      const raw = Array.isArray(data) ? data : (data.data || []);
      const normalised = dedupeAlerts(raw.map((r, i) => normaliseAlert(r, i))).sort((a, b) => toAlertTimeMs(b.ts) - toAlertTimeMs(a.ts));
      setAlerts(normalised.slice(0, 1000));
      if (normalised.length > 0) {
        lastIdRef.current = Math.max(...normalised.map((a) => Number(a.id) || 0), lastIdRef.current);
      }
    } catch (_) {}
  };

  hydrateAlerts();
}, [backendStatus, backendUrl, apiKey]);

// ── Normalise a raw Snort JSON alert line into our internal format
  function normaliseAlert(raw, idx) {
    // Accept both raw Snort alert_json lines and already-normalised DB/API rows.
    const sevMap = { 1:"critical", 2:"high", 3:"medium", 4:"low" };
    const catGuess = (msg="")=>{
      msg = msg.toLowerCase();
      if(msg.includes("dos")||msg.includes("flood")||msg.includes("loic")) return "DDOS";
      if(msg.includes("exploit")||msg.includes("shellshock")||msg.includes("cve")) return "EXPLOIT";
      if(msg.includes("trojan")||msg.includes("zbot")||msg.includes("c2")) return "TROJAN";
      if(msg.includes("malware")||msg.includes("dridex")||msg.includes("pe exe")) return "MALWARE";
      if(msg.includes("scan")||msg.includes("nmap")||msg.includes("probe")) return "SCAN";
      if(msg.includes("policy")||msg.includes("download")) return "POLICY";
      return "HUNTING";
    };

    const rawMsg = raw.msg || raw.message || "Unknown alert";
    const sev = raw.severity || sevMap[raw.priority] || (raw.action==="drop"?"high":"medium");
    const category = raw.category || catGuess(rawMsg);
    const tsValue = raw.ts || raw.timestamp || new Date().toISOString();
    const parsedTs = new Date(tsValue);

    return {
      id:         raw.id ?? (Date.now()*1000 + (idx||0)),
      ts:         Number.isNaN(parsedTs.getTime()) ? new Date() : parsedTs,
      rule:       raw.rule || `${raw.gid||1}:${raw.sid||0}`,
      msg:        rawMsg,
      category,
      severity:   sev,
      src_ip:     raw.src_addr || raw.src_ip  || "0.0.0.0",
      dst_ip:     raw.dst_addr || raw.dst_ip  || "0.0.0.0",
      src_port:   raw.src_port || 0,
      dst_port:   raw.dst_port || 0,
      proto:      (raw.proto||"TCP").toUpperCase(),
      country:    raw.country || "",
      city:       raw.city    || "",
      action:     raw.action === "BLOCKED" ? "BLOCKED" : ((raw.action==="drop"||raw.action==="block")?"BLOCKED":"ALERT"),
    };
  }

// ── Poll backend for new alerts every 2 s when connected
useEffect(()=>{
  const poll = async ()=>{
    const {url,key,status} = backendRef.current;
    if(status !== "connected") return;
    try {
      const res = await fetch(
        `${url}/api/alerts/new?since=${lastIdRef.current}`,
        { headers: key ? {"X-API-Key":key} : {} }
      );
      if(!res.ok) return;
      const data = await res.json();
      const raw  = Array.isArray(data) ? data : (data.alerts || []);
      if(raw.length > 0) {
        const newA = raw.map((r,i)=>normaliseAlert(r,i));
        lastIdRef.current = Math.max(...newA.map(a=>a.id), lastIdRef.current);
        setAlerts(p=>dedupeAlerts([...newA,...p]).slice(0,1000));
        setNewIds(new Set(newA.map(a=>a.id)));
        setTimeout(()=>setNewIds(new Set()),3000);
        const crit = newA.filter(a=>a.severity==="critical"||a.severity==="high");
        if(crit.length>0) setToasts(p=>[...p,...crit].slice(-3));
      }

      const packetPps = Number(data.packet_pps ?? 0);
      const ddosPps = data.ddos_detected ? packetPps : 0;
      const mbps = Number(data.mbps ?? 0);

      setTraffic(p => [
        ...p.slice(-59),
        {
          time: new Date().toLocaleTimeString("en", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
          pps: packetPps,
          ddos: ddosPps,
          mbps,
        },
      ]);
    } catch(_){ }
  };
  const iv = setInterval(poll, 2000);
  return ()=>clearInterval(iv);
}, []);


// Offline demo mode only. Never overwrite real backend traffic.
useEffect(() => {
  if (!ddosMode || backendStatus === "connected") return;

  const iv = setInterval(() => {
    tickRef.current++;

    const count = rng(4) + 3;
    const newA = Array.from({ length: count }, () => genAlert(true));
    setAlerts(p => [...newA, ...p].slice(0, 1000));
    setNewIds(new Set(newA.map(a => a.id)));
    setTimeout(() => setNewIds(new Set()), 3000);

    const crit = newA.filter(a => a.severity === "critical");
    if (crit.length > 0) setToasts(p => [...p, crit[0]].slice(-3));

    setTraffic(p => [...p.slice(-59), genTraffic(tickRef.current, true)]);
  }, 1200);

  return () => clearInterval(iv);
}, [ddosMode, backendStatus]);

  // Auto-block engine
  useEffect(()=>{
    if(!autoBlock.enabled) return;
    const windowMs = autoBlock.window * 1000;
    const now = Date.now();
    const recent = alerts.filter(a=>(now - new Date(a.ts).getTime()) < windowMs);
    const counts = recent.reduce((acc,a)=>{acc[a.src_ip]=(acc[a.src_ip]||0)+1;return acc;},{});
    Object.entries(counts).forEach(([ip,count])=>{
      if(count >= autoBlock.threshold && !blocklist.some(b=>b.ip===ip&&b.active)) {
        onBlockIp(ip, `Auto-block: ${count} alerts in ${autoBlock.window}s`, "Auto");
      }
    });
  },[alerts,autoBlock,onBlockIp]);

  async function onBlockIp(ip, reason, source = "Manual") {
    if (!ip || blocklist.some(b => b.ip === ip)) return;
    if (backendStatus === "connected" && backendUrl && apiKey) {
      try {
        const res = await fetch(`${backendUrl}/api/blocklist`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
          body: JSON.stringify({ ip, reason, source, active: true, durationMinutes: autoBlock.blockDuration || 60 }),
        });
        const data = await res.json();
        if (data?.row) {
          setBlocklist(p => [data.row, ...p.filter(x => x.id !== data.row.id && x.ip !== data.row.ip)]);
          return;
        }
      } catch (_) {}
    }
    setBlocklist(p=>[{id:Date.now(),ip,reason,added:new Date().toISOString(),hits:0,active:true,source},...p]);
  }

const stats = {
  total: backendStats?.total ?? alerts.length,
  critical: backendStats?.critical ?? alerts.filter(a => a.severity === "critical").length,
  blocked: backendStats?.blocked ?? alerts.filter(a => a.action === "BLOCKED").length,
  lastMin: backendStats?.lastMin ?? alerts.filter(a => (Date.now() - new Date(a.ts).getTime()) < 60000).length,
  pps: backendStats?.packet_pps ?? traffic[traffic.length - 1]?.pps ?? 0,
  alertPps: backendStats?.alert_pps ?? 0,
  trafficReal: backendStats?.traffic_real ?? false,
  trafficSource: backendStats?.traffic_source || "",
  sensorInterface: backendStats?.sensor_interface || "",
  mbps: backendStats?.mbps ?? 0,
};

const isDdos = !!backendStats?.ddos_detected || (ddosMode && backendStatus !== "connected");

  const NAV = [
    { id:"dashboard",  icon:Activity,      label:"Dashboard"    },
    { id:"alerts",     icon:AlertTriangle, label:"Traffic"       },
    { id:"blocklist",  icon:Ban,           label:"IP Discovered", badge:blocklist.filter(b=>b.active).length },
    { id:"ddos",       icon:Siren,         label:"DDoS Mitigation", alert:isDdos },
    { id:"rules",      icon:FileText,      label:"Rules"        },
    { id:"notif",      icon:Bell,          label:"Notifications" },
    { id:"connection", icon:Terminal,      label:"Connection"   },
  ];

  return (
    <div className={theme === "light" ? "theme-light" : "theme-dark"} style={{fontFamily:"'JetBrains Mono','Fira Code',monospace",background:"var(--app-bg)",minHeight:"100vh",color:"var(--app-text)",transition:"background 0.2s ease,color 0.2s ease"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap');
        :root{--app-bg:#0d1117;--app-text:#e6edf3;--app-panel:#0d1117;--app-border:#21262d;}
        .theme-light{--app-bg:#f3efe7;--app-text:#2b241f;--app-panel:#faf6ef;--app-border:#d6cec2;--app-panel-strong:#fffaf3;--app-panel-soft:#f3ede3;--app-input:#fffdf8;}
        *{box-sizing:border-box;margin:0;padding:0}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-track{background:var(--app-panel)}
        ::-webkit-scrollbar-thumb{background:#94a3b8;border-radius:4px}
        @keyframes slideIn{from{transform:translateX(100px);opacity:0}to{transform:translateX(0);opacity:1}}
        @keyframes pulseRed{0%,100%{opacity:1}50%{opacity:0.4}}
        .theme-light .bg-gray-950,.theme-light .bg-gray-900,.theme-light .bg-gray-800,.theme-light .bg-black,.theme-light .bg-black\/30,.theme-light .bg-black\/40,.theme-light .bg-gray-900\/50{background:var(--app-panel-strong) !important;background-image:none !important;color:var(--app-text) !important}
        .theme-light .border-gray-800,.theme-light .border-gray-700,.theme-light .border-gray-900\/40,.theme-light .border-green-900\/40,.theme-light .border-red-900\/40,.theme-light .border-amber-900\/30{border-color:var(--app-border) !important}
        .theme-light .text-white{color:var(--app-text) !important}
        .theme-light .text-gray-700{color:#6b5e54 !important}
        .theme-light .text-gray-600{color:#76685d !important}
        .theme-light .text-gray-500{color:#5f5249 !important}
        .theme-light .text-gray-400{color:#4b4038 !important}
        .theme-light .text-gray-300{color:#3b322c !important}
        .theme-light input,.theme-light textarea,.theme-light select{background-color:var(--app-input) !important;color:var(--app-text) !important;border-color:var(--app-border) !important}
        .theme-light input::placeholder,.theme-light textarea::placeholder{color:#8a7e73 !important}
        .theme-light header,.theme-light .shadow-2xl,.theme-light .shadow-xl{box-shadow:none !important}
        .theme-light .bg-green-900\/10,.theme-light .bg-red-900\/10,.theme-light .bg-amber-900\/10,.theme-light .bg-cyan-900\/10{background-color:var(--app-panel-soft) !important}
        .theme-light .hover\:bg-white\/\[0\.02\]:hover{background-color:rgba(43,36,31,0.06) !important}
      `}</style>

      {/* Toasts */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {toasts.map((t,i)=>(
          <Toast key={t.id} alert={t} onClose={()=>setToasts(p=>p.filter((_,j)=>j!==i))}/>
        ))}
      </div>

      {/* Header */}
      <header style={{borderBottom:"1px solid var(--app-border)",background:"var(--app-panel)"}} className="sticky top-0 z-40 px-4 py-2.5 flex items-center gap-3">
        <div className="flex items-center gap-2 flex-shrink-0">
          <div style={{background:"linear-gradient(135deg,#ff2d55,#ff6b35)"}} className="w-7 h-7 rounded-lg flex items-center justify-center">
            <Shield size={14} className="text-white"/>
          </div>
          <div className="leading-none">
            <div className="text-sm font-black text-white">SnortVision</div>
            <div className="text-xs text-gray-600">v0.1</div>
          </div>
        </div>

        <nav className="flex gap-0.5 ml-2 flex-wrap">
          {NAV.map(n=>(
            <button key={n.id} onClick={()=>setPage(n.id)}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all relative ${
                page===n.id?"bg-gray-800 text-white":"text-gray-500 hover:text-gray-300"
              }`}>
              <n.icon size={12}/>
              <span>{n.label}</span>
              {n.badge>0 && (
                <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 text-white text-xs flex items-center justify-center font-bold" style={{fontSize:"9px"}}>
                  {n.badge>9?"9+":n.badge}
                </span>
              )}
              {n.alert && <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-red-500 animate-pulse"/>}
            </button>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-3 flex-shrink-0">
          <button onClick={()=>setTheme(t=>t==="dark"?"light":"dark")} className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-500 transition-all" title="Toggle theme">
            {theme==="dark" ? <Sun size={12}/> : <Moon size={12}/>} {theme==="dark" ? "Light" : "Dark"}
          </button>
          <div style={{
            background:isDdos?"rgba(255,45,85,0.1)":"transparent",
            borderColor:isDdos?"rgba(255,45,85,0.4)":"#30363d",
            color:isDdos?"#ff2d55":"#6e7681"
          }} className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border font-mono transition-all">
            {isDdos?<><Siren size={11} style={{animation:"pulseRed 0.8s infinite"}}/>DDoS</>:<><Shield size={11}/>Clean</>}
          </div>
          <div className="flex items-center gap-1.5 text-xs">
            <div className={`w-2 h-2 rounded-full ${backendStatus==="connected"?"bg-green-500 animate-pulse":"bg-red-500"}`}/>
            <span className={`font-mono ${backendStatus==="connected"?"text-green-400":"text-red-400"}`}>{backendStatus==="connected"?"LIVE":ddosMode?"SIM":"OFFLINE"}</span>
            <span className="text-gray-700 font-mono">{host.ip}</span>
          </div>
        </div>
      </header>

      {/* DDoS banner */}
      {isDdos && (
        <div style={{background:"rgba(255,45,85,0.08)",borderBottom:"1px solid rgba(255,45,85,0.2)",animation:"pulseRed 2s infinite"}}
          className="px-4 py-1.5 flex items-center gap-3">
          <AlertCircle size={12} className="text-red-400"/>
          <span className="text-xs font-bold text-red-400">⚠ DDoS ATTACK — {stats.pps.toLocaleString()} pps — Mitigation active</span>
          <button onClick={()=>setPage("ddos")} className="text-xs text-red-300 hover:text-red-200 ml-2 underline">View mitigation →</button>
          <button onClick={()=>setDdosMode(false)} className="ml-auto text-red-600 hover:text-red-400 text-xs">Dismiss sim</button>
        </div>
      )}

      <main className="p-4 max-w-7xl mx-auto">
        <div className="flex items-center gap-2 mb-4">
          <span className="text-gray-600">/</span>
          <span className="text-sm font-bold text-gray-300">{NAV.find(n=>n.id===page)?.label}</span>
        </div>

        {page==="dashboard"  && <Dashboard     alerts={alerts} traffic={traffic} stats={stats} backendUrl={backendUrl}/>}
        {page==="alerts"     && <Alerts         alerts={alerts} newIds={newIds} onBlockIp={onBlockIp}/>}
        {page==="blocklist"  && <IpBlocklist    blocklist={blocklist} setBlocklist={setBlocklist} autoBlock={autoBlock} setAutoBlock={setAutoBlock} backendUrl={backendUrl} apiKey={apiKey} backendStatus={backendStatus} onBlockIp={onBlockIp} router={router}/>}
        {page==="ddos"       && <DdosMitigation alerts={alerts} traffic={traffic} ddosMode={ddosMode} setDdosMode={setDdosMode} blocklist={blocklist} setBlocklist={setBlocklist} backendStats={backendStats} backendStatus={backendStatus}/>}
        {page==="rules"      && <RulesManager/>}
        {page==="notif"      && <Notifications/>}
        {page==="connection" && <Connection host={host} setHost={setHost}
          router={router} setRouter={setRouter}
          backendUrl={backendUrl} setBackendUrl={setBackendUrl}
          apiKey={apiKey} setApiKey={setApiKey}
          backendStatus={backendStatus} setBackendStatus={setBackendStatus}
          backendStats={backendStats} setBackendStats={setBackendStats}
          sshStatus={sshStatus} setSshStatus={setSshStatus}
          snortStatus={snortStatus} setSnortStatus={setSnortStatus}
          dbStatus={dbStatus} setDbStatus={setDbStatus}
          routerStatus={routerStatus} setRouterStatus={setRouterStatus}/>}
      </main>
    </div>
  );
}
