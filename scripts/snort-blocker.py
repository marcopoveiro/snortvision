#!/usr/bin/env python3
"""Snort 3 -> OPNsense: quarantines or blocks IPs through the router's aliases.

Follows Snort's alert_json (a copy of the router traffic from the switch mirror port) and,
for priority-1 alerts:
  - home device (HOME_NETS) as the SOURCE          -> quarantine alias (SNORT_QUARANTINE)
  - external IP as the source or the destination   -> block alias (SNORT_BLOCK)
Every entry expires on its own after BLOCK_HOURS. Never touches servers, management,
the router, Cloudflare or public DNS. Hourly limits on the number of actions.

Dry run (DRY_RUN=1, the default): only logs what it would do; the API is only used at
start-up to check that the key can read the aliases.

Configured through environment variables (see snort-blocker.service):
  DRY_RUN=1|0, HOME_NETS, NEVER_BLOCK_NETS, GATEWAYS, ALERT_LOG,
  API_KEY_FILE (key=/secret= file downloaded from OPNsense), ROUTER (https://192.168.1.1),
  BLOCK_HOURS (24), MAX_PER_HOUR (10), STATE_FILE, LOG_FILE
"""
import base64
import ipaddress
import hashlib
import hmac
import html
import http.server
import json
import socket
import threading
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

DRY_RUN = os.environ.get("DRY_RUN", "1") != "0"
ALERT_LOG = os.environ.get("ALERT_LOG", "/var/log/snort/alert_json.txt")
API_KEY_FILE = os.environ.get("API_KEY_FILE", "/etc/snort-blocker/opnsense.key")
ROUTER = os.environ.get("ROUTER", "https://192.168.1.1").rstrip("/")
# Router certificate stored separately: only this certificate is trusted (it is self-signed).
ROUTER_CERT = os.environ.get("ROUTER_CERT", "/etc/snort-blocker/router.pem")
BLOCK_HOURS = float(os.environ.get("BLOCK_HOURS", "24"))
MAX_PER_HOUR = int(os.environ.get("MAX_PER_HOUR", "10"))
# Firewall aliases (type External) filled by this script.
QUARANTINE = os.environ.get("QUARANTINE_ALIAS", "SNORT_QUARANTINE")
BLOCK = os.environ.get("BLOCK_ALIAS", "SNORT_BLOCK")
# Counter for external blocks raised by sessionless alerts (not an alias).
SESSIONLESS = BLOCK + "_SESSIONLESS"
# Limits per list: few home devices per hour (more than that is a big problem and the
# administrator decides); many external IPs (pf tables handle thousands at no cost).
MAX_PER_HOUR_LIST = {
    QUARANTINE: int(os.environ.get("MAX_PER_HOUR_QUARANTINE", MAX_PER_HOUR)),
    BLOCK: int(os.environ.get("MAX_PER_HOUR_BLOCK", "200")),
    # Sessionless alerts (UDP/ICMP): the source can be forged to make us block third parties,
    # so their external blocks are counted separately, with the low limit.
    SESSIONLESS: int(os.environ.get("MAX_PER_HOUR_SESSIONLESS", MAX_PER_HOUR)),
}
# Hostnames whose IPs are never blocked (resolved at start-up and every hour).
PROTECTED_NAMES = [x.strip() for x in os.environ.get(
    "PROTECTED_NAMES", "api.telegram.org").split(",") if x.strip()]
# Telegram (optional): file with TELEGRAM_TOKEN= and CHAT_ID=. Without it there are no alerts or buttons.
TELEGRAM_FILE = os.environ.get("TELEGRAM_FILE", "/etc/snort-blocker/telegram.env")
# After an unblock from Telegram, the IP is not blocked again for this long.
PARDON_HOURS = float(os.environ.get("PARDON_HOURS", "24"))
# Notifications of external blocks per hour; above that everything goes into a summary.
NOTIFY_PER_HOUR = int(os.environ.get("NOTIFY_PER_HOUR", "20"))
STATE_FILE = os.environ.get("STATE_FILE", "/var/lib/snort-blocker/state.json")
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/snort-blocker/actions.log")
# Rules that never block (known false positives), "gid:sid" separated by commas.
IGNORE_SIDS = {x.strip() for x in os.environ.get("IGNORE_SIDS", "").split(",") if x.strip()}

SESSIONLESS_TAG = "[no session]"


def _nets(name):
    """Networks/IPs separated by commas in an environment variable."""
    return [ipaddress.ip_network(x.strip(), strict=False) for x in os.environ.get(name, "").split(",") if x.strip()]


# Networks of the devices that may be quarantined (the same as in the router rules).
# E.g. HOME_NETS=192.168.10.0/24,192.168.11.0/24. Empty = never quarantine.
HOME = _nets("HOME_NETS")
# Networks and IPs that are never blocked (management, servers, admin workstation...).
# E.g. NEVER_BLOCK_NETS=192.168.1.0/24,192.168.10.5/32
NEVER = _nets("NEVER_BLOCK_NETS") + [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10",
    "224.0.0.0/3",                         # multicast, reserved, broadcast
    # Cloudflare (sites behind Cloudflare: an alert "from Cloudflare" is a visitor)
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Public DNS
    "9.9.9.9/32", "149.112.112.112/32", "1.1.1.1/32", "1.0.0.1/32",
    "8.8.8.8/32", "8.8.4.4/32",
    # Telegram (notifications and the Unblock button)
    "149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22",
    "91.108.16.0/22", "91.108.56.0/22", "95.161.64.0/20",
)]
# Gateways are never blocked: the .1 of each home network, plus the IPs in GATEWAYS.
GATEWAYS = {n.network_address + 1 for n in HOME} | {ipaddress.ip_address(x.strip()) for x in os.environ.get("GATEWAYS", "").split(",") if x.strip()}


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {'[DRY RUN] ' if DRY_RUN else ''}{msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def ip_of(value):
    """'1.2.3.4:443' or '1.2.3.4' -> ip_address; None if it is not IPv4."""
    if not value:
        return None
    v = str(value)
    try:
        ip = ipaddress.ip_address(v.rsplit(":", 1)[0] if v.count(":") == 1 else v)
    except ValueError:
        return None
    # The NEVER list and the router rules are IPv4 only: an IPv6 address (e.g. Cloudflare)
    # must not pass as "not protected", so it is ignored.
    return ip if ip.version == 4 else None


PROTECTED_DNS = set()


def resolve_protected():
    found = set()
    for name in PROTECTED_NAMES:
        try:
            for info in socket.getaddrinfo(name, None, socket.AF_INET):
                found.add(ipaddress.ip_address(info[4][0]))
        except OSError:
            pass
    PROTECTED_DNS.update(found)    # only adds, never removes: a failed lookup never unprotects anything


def protected(ip):
    return ip in GATEWAYS or ip in PROTECTED_DNS or any(ip in n for n in NEVER)


def is_home(ip):
    return any(ip in n for n in HOME)


# ── OPNsense API (alias_util only; the key has no other privileges) ───────────
class Router:
    def __init__(self, path):
        d = dict(l.strip().split("=", 1) for l in open(path) if "=" in l)
        self.auth = "Basic " + base64.b64encode(f"{d['key']}:{d['secret']}".encode()).decode()
        # The router certificate is self-signed and issued for the router's name, not its IP:
        # only that certificate is trusted (pinned in ROUTER_CERT) and the name is not checked.
        self.ctx = ssl.create_default_context(cafile=ROUTER_CERT)
        self.ctx.check_hostname = False
        self.ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": self.auth}
        if data is not None:                  # OPNsense rejects (400) a GET with a JSON Content-Type and no body
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(ROUTER + path, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, context=self.ctx, timeout=10) as r:
            return json.load(r)

    def list(self, alias):
        return [row.get("ip") for row in self._request("GET", f"/api/firewall/alias_util/list/{alias}").get("rows", [])]

    def add(self, alias, ip):
        return self._request("POST", f"/api/firewall/alias_util/add/{alias}", {"address": str(ip)})

    def remove(self, alias, ip):
        return self._request("POST", f"/api/firewall/alias_util/delete/{alias}", {"address": str(ip)})


# ── state: what is applied and when it expires ────────────────────────────────
def load_state():
    try:
        return json.load(open(STATE_FILE))
    except (OSError, ValueError):
        return {"active": {}, "actions": {}}


def save_state(s):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f, indent=1)
    os.replace(tmp, STATE_FILE)


def decide(alert):
    """List of (alias, ip, reason) for an alert; empty when there is nothing to do."""
    if int(alert.get("priority", 9)) != 1:
        return []
    if f"{alert.get('gid', 1)}:{alert.get('sid', '')}" in IGNORE_SIDS:
        return []
    # src_addr/dst_addr first (address only); *_ap only when they are missing
    src = ip_of(alert.get("src_addr")) if alert.get("src_addr") else ip_of(alert.get("src_ap"))
    dst = ip_of(alert.get("dst_addr")) if alert.get("dst_addr") else ip_of(alert.get("dst_ap"))
    if not src or not dst:
        return []
    reason = f"{alert.get('rule', '?')} {alert.get('msg', '')[:90]} ({src} -> {dst})"
    actions = []
    # Quarantine only for whoever ORIGINATES the alert (a home device doing something bad);
    # a home device that is only the destination is the victim: the external side is blocked.
    if is_home(src) and not protected(src):
        actions.append((QUARANTINE, src, reason))
    sessionless = str(alert.get("proto", "")).upper() != "TCP"
    for ip in (src, dst):
        if ip.is_global and not protected(ip):
            actions.append((BLOCK, ip, reason + (f" {SESSIONLESS_TAG}" if sessionless else "")))
    return actions


def apply(router, state, alias, ip, reason, tg=None):
    key = f"{alias}|{ip}"
    now = time.time()
    pardoned = state.setdefault("pardoned", {})
    if pardoned.get(str(ip), 0) > now:
        return
    if key in state["active"]:
        state["active"][key]["until"] = now + BLOCK_HOURS * 3600   # extends it, does not count as new
        return
    # Limit per list: a flood of external blocks (forged alerts, for example)
    # does not use up the quarantine budget, and vice versa.
    actions = state["actions"] if isinstance(state["actions"], dict) else {}
    recent = [t for t in actions.get(alias, []) if t > now - 3600]
    counter = alias
    if alias == BLOCK and reason.endswith(SESSIONLESS_TAG):
        counter = SESSIONLESS
        recent = [t for t in actions.get(counter, []) if t > now - 3600]
    limit = MAX_PER_HOUR_LIST.get(counter, MAX_PER_HOUR)
    if len(recent) >= limit:
        log(f"LIMIT {limit}/h reached on {alias}: did not add {ip} — {reason}")
        if tg:
            tg.limit(alias, limit)
        return
    if not DRY_RUN:
        # Only counts as applied when the router confirms it.
        try:
            answer = router.add(alias, ip)
        except (urllib.error.URLError, OSError) as e:
            log(f"ERROR adding {ip} to {alias}: {e}")
            return
        if answer.get("status") != "done":
            log(f"ERROR adding {ip} to {alias}: the router answered {answer}")
            return
    state["active"][key] = {"alias": alias, "ip": str(ip), "until": now + BLOCK_HOURS * 3600, "reason": reason}
    actions[counter] = recent + [now]
    state["actions"] = actions
    log(f"{'WOULD ADD' if DRY_RUN else 'ADDED'} {ip} to {alias} for {BLOCK_HOURS:g} h — {reason}")
    if tg and not DRY_RUN:
        tg.blocked(alias, ip, reason)


def expire(router, state):
    now = time.time()
    for key, a in list(state["active"].items()):
        if a["until"] <= now:
            if not DRY_RUN:
                try:
                    router.remove(a["alias"], a["ip"])
                except (urllib.error.URLError, OSError) as e:
                    log(f"ERROR removing {a['ip']} from {a['alias']}: {e}; will retry")
                    continue
            del state["active"][key]
            log(f"{'WOULD REMOVE' if DRY_RUN else 'REMOVED'} {a['ip']} from {a['alias']} (expired)")


def follow(path):
    """tail -F: starts at the end; when the file is rotated or truncated, reads the new one from the start."""
    f, ino = None, None
    while True:
        try:
            st = os.stat(path)
        except OSError:
            time.sleep(2)
            continue
        if f is None:
            f, ino = open(path, errors="replace"), st.st_ino
            f.seek(0, os.SEEK_END)                 # at start-up, new alerts only
        elif st.st_ino != ino or st.st_size < f.tell():
            f.close()
            f, ino = open(path, errors="replace"), st.st_ino
        line = f.readline()
        if line:
            yield line
        else:
            yield None
            time.sleep(0.5)


# ── Telegram: a message for every block with an "Unblock" button ──────────────
class Telegram:
    def __init__(self, path, router, state, lock):
        d = dict(l.strip().split("=", 1) for l in open(path) if "=" in l)
        self.url = f"https://api.telegram.org/bot{d['TELEGRAM_TOKEN']}/"
        self.chat = str(d["CHAT_ID"])
        # POLL_UPDATES=0 when the bot is shared: another program receives the button taps and
        # forwards them through the HTTP bridge; only one program can call getUpdates per bot.
        self.polling = d.get("POLL_UPDATES", "1") != "0"
        self.bridge_key = d.get("BRIDGE_KEY", "")
        self.bridge_port = int(d.get("BRIDGE_PORT", "8766"))
        self.bridge_origins = {x.strip() for x in d.get("BRIDGE_ORIGINS", "").split(",") if x.strip()}
        self.bridge_listen = d.get("BRIDGE_LISTEN", "")    # this host's IP on the bot's network; never 0.0.0.0 by default
        self.router, self.state, self.lock = router, state, lock
        self.notified, self.summary, self.limits = [], 0, {}

    def _api(self, method, body, timeout=15):
        req = urllib.request.Request(self.url + method, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)

    def send(self, text, buttons=None):
        body = {"chat_id": self.chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
        if buttons:
            body["reply_markup"] = {"inline_keyboard": buttons}
        try:
            self._api("sendMessage", body)
        except (urllib.error.URLError, OSError, ValueError) as e:
            log(f"ERROR Telegram: {e}")

    def blocked(self, alias, ip, reason):
        now = time.time()
        if alias == BLOCK:
            # External blocks can come by the hundred: up to NOTIFY_PER_HOUR per hour, the rest in a summary.
            self.notified = [t for t in self.notified if t > now - 3600]
            if len(self.notified) >= NOTIFY_PER_HOUR:
                self.summary += 1
                return
            self.notified.append(now)
        title = "🚨 Home device QUARANTINED" if alias == QUARANTINE else "⛔ External IP blocked"
        text = (f"<b>{title}</b>\n\n<code>{ip}</code> for {BLOCK_HOURS:g} h\n"
                f"{html.escape(reason)}")
        self.send(text, [[{"text": "🔓 Unblock", "callback_data": f"unblock|{alias}|{ip}"}]])

    def limit(self, alias, limit):
        hour = time.strftime("%Y%m%d%H")
        if self.limits.get(alias) == hour:
            return
        self.limits[alias] = hour
        self.send(f"⚠️ <b>Limit of {limit}/h reached on {alias}</b>\n"
                  f"Further alerts this hour are only logged. Check SnortVision.")

    def hourly_summary(self):
        if self.summary:
            n, self.summary = self.summary, 0
            self.send(f"⛔ <b>{n}</b> more external IPs blocked in the last hour (no individual message). "
                      f"See <code>{html.escape(LOG_FILE)}</code>.")

    def poll(self):
        """Separate thread: receives button taps (only from CHAT_ID) and unblocks."""
        offset = 0
        while True:
            try:
                r = self._api("getUpdates", {"offset": offset, "timeout": 30,
                                             "allowed_updates": ["callback_query"]}, timeout=40)
            except (urllib.error.URLError, OSError, ValueError):
                time.sleep(10)
                continue
            for u in r.get("result", []):
                offset = u["update_id"] + 1
                cq = u.get("callback_query")
                if cq:
                    self.tap(cq)

    def tap(self, cq):
        parts = (cq.get("data") or "").split("|")
        chat = str(cq.get("message", {}).get("chat", {}).get("id"))
        if chat != self.chat or len(parts) != 3 or parts[0] != "unblock" or parts[1] not in (QUARANTINE, BLOCK):
            self._answer(cq, "Not authorised")
            return
        who = cq.get("from", {}).get("first_name", "?")
        ok, text = self.release(parts[1], parts[2], who)
        self._answer(cq, text)
        if not ok:
            return
        try:
            msg = cq["message"]
            self._api("editMessageText", {"chat_id": msg["chat"]["id"], "message_id": msg["message_id"],
                                          "parse_mode": "HTML",
                                          "text": html.escape(msg.get("text", "")) +
                                          f"\n\n✅ <b>Unblocked by {html.escape(who)}</b> at {time.strftime('%H:%M')}"})
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            pass

    def release(self, alias, ip_text, who):
        """Removes the IP from the router and pardons it for PARDON_HOURS. Returns (ok, text)."""
        if alias not in (QUARANTINE, BLOCK):
            return False, "Invalid list"
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return False, "Invalid IP"
        with self.lock:
            # Only what is really blocked can be unblocked (and pardoned): no pardons in advance.
            if f"{alias}|{ip}" not in self.state["active"]:
                return False, "This IP is no longer blocked"
            try:
                answer = self.router.remove(alias, ip)
            except (urllib.error.URLError, OSError) as e:
                return False, f"Failed: {e}"
            if answer.get("status") != "done":
                return False, f"The router answered {answer}"
            self.state["active"].pop(f"{alias}|{ip}", None)
            self.state.setdefault("pardoned", {})[str(ip)] = time.time() + PARDON_HOURS * 3600
            save_state(self.state)
        log(f"UNBLOCKED {ip} from {alias} on Telegram by {who} (no new block for {PARDON_HOURS:g} h)")
        return True, "Unblocked"

    def bridge(self):
        """Separate thread: POST /unblock {alias, ip, who} from the program that owns the bot, signed with the shared key."""
        tg = self

        class Handler(http.server.BaseHTTPRequestHandler):
            timeout = 5            # a slow client cannot hold the bridge

            def log_message(self, *a):
                pass

            def reply(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                origin = self.client_address[0]
                if origin not in tg.bridge_origins:          # before reading anything
                    log(f"BRIDGE refused from {origin} ({self.path})")
                    return self.reply(403, {"ok": False, "text": "Forbidden"})
                try:
                    n = int(self.headers.get("Content-Length", ""))
                    stamp = int(self.headers.get("X-Timestamp", "0"))
                except ValueError:
                    return self.reply(400, {"ok": False, "text": "Invalid request"})
                if not 0 <= n <= 4096:
                    return self.reply(413, {"ok": False, "text": "Request too large"})
                body = self.rfile.read(n)
                # HMAC-SHA256 signature of "<timestamp>.<body>" with the shared key; valid for 60 s.
                expected = hmac.new(tg.bridge_key.encode(), f"{stamp}.".encode() + body, hashlib.sha256).hexdigest()
                if (self.path != "/unblock" or origin not in tg.bridge_origins or abs(time.time() - stamp) > 60
                        or not hmac.compare_digest(self.headers.get("X-Signature", "").encode(), expected.encode())):
                    log(f"BRIDGE refused from {origin} ({self.path})")
                    return self.reply(403, {"ok": False, "text": "Forbidden"})
                try:
                    d = json.loads(body or b"{}")
                    ok, text = tg.release(str(d.get("alias", "")), str(d.get("ip", "")), str(d.get("who", "?"))[:40])
                except (ValueError, TypeError):
                    ok, text = False, "Invalid request"
                self.reply(200 if ok else 400, {"ok": ok, "text": text})

        http.server.ThreadingHTTPServer((self.bridge_listen, self.bridge_port), Handler).serve_forever()

    def _answer(self, cq, text):
        try:
            self._api("answerCallbackQuery", {"callback_query_id": cq["id"], "text": text})
        except (urllib.error.URLError, OSError, ValueError):
            pass


def main():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    router = Router(API_KEY_FILE)
    try:
        q, b = router.list(QUARANTINE), router.list(BLOCK)
        log(f"start: API ok, {QUARANTINE}={len(q)} {BLOCK}={len(b)}, block time {BLOCK_HOURS:g} h, "
            f"max {MAX_PER_HOUR_LIST[QUARANTINE]}/h home and {MAX_PER_HOUR_LIST[BLOCK]}/h external")
    except (urllib.error.URLError, OSError, ValueError) as e:
        log(f"start: router API failed ({e}); carrying on, actions fail until it is back")
    state = load_state()
    lock = threading.Lock()
    resolve_protected()
    tg = None
    if os.path.exists(TELEGRAM_FILE):
        try:
            tg = Telegram(TELEGRAM_FILE, router, state, lock)
            if tg.polling:
                threading.Thread(target=tg.poll, daemon=True).start()
            bridge_ok = len(tg.bridge_key) >= 32 and tg.bridge_origins and tg.bridge_listen
            if bridge_ok:
                threading.Thread(target=tg.bridge, daemon=True).start()
            elif tg.bridge_key:
                log("Bridge off: needs BRIDGE_KEY (32+ chars), BRIDGE_ORIGINS and BRIDGE_LISTEN")
            log(f"Telegram on: notifications; buttons {'here' if tg.polling else 'through the shared bot'}"
                f"{f', bridge on {tg.bridge_listen}:{tg.bridge_port}' if bridge_ok else ''}")
        except (OSError, KeyError, ValueError) as e:
            log(f"Telegram off ({e})")
    last_expire = last_hour = 0
    for line in follow(ALERT_LOG):
        if line:
            try:
                alert = json.loads(line)
            except ValueError:
                continue
            with lock:
                for alias, ip, reason in decide(alert):
                    try:
                        apply(router, state, alias, ip, reason, tg)
                    except (urllib.error.URLError, OSError) as e:
                        log(f"ERROR adding {ip} to {alias}: {e}")
                save_state(state)
        if time.time() - last_expire > 60:
            with lock:
                expire(router, state)
                now = time.time()
                state["pardoned"] = {k: v for k, v in state.get("pardoned", {}).items() if v > now}
                save_state(state)
            last_expire = time.time()
        if time.time() - last_hour > 3600:
            resolve_protected()
            if tg:
                tg.hourly_summary()
            last_hour = time.time()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
