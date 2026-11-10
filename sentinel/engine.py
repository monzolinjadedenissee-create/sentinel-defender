"""
The Sentinel detection engine — the brain of the defender.

Model, in plain terms:
  * Each hostile signal from an IP adds "heat". If an IP's heat reaches the fail
    limit inside the sliding window, the IP is BLOCKED. Repeat offenders are
    blocked for twice as long each time, capped at the max.
  * Separately, repeated failures against a single ACCOUNT (from any IP) LOCK
    that account for a cooldown, so a spread-out attack on one username is caught.
  * Trusted CIDRs are never blocked and never accrue heat.

Nothing here touches Flask — it takes a Store session and returns decisions,
which keeps it easy to test and reuse.
"""

import json
import re
import secrets
import threading
import time
import urllib.request
from datetime import datetime, timezone

from . import geo

# Device fields a login page may volunteer (all optional, short plain strings).
CLIENT_FIELDS = ("model", "platform", "platform_version", "mobile", "browser", "tz", "screen", "language")


def clean_client(raw):
    """Keep only known device fields as short, sanitised strings; return a JSON string or ''."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return ""
    if not isinstance(raw, dict):
        return ""
    out = {}
    for k in CLIENT_FIELDS:
        v = raw.get(k)
        if isinstance(v, (str, int, float, bool)) and str(v).strip():
            out[k] = re.sub(r"[^\w .,:;/()+\-x?]", "", str(v))[:80]
    return json.dumps(out)[:1000] if out else ""


# Signal kinds the engine understands. The three "hostile" ones build heat.
HOSTILE = ("fail", "rate_limited", "suspicious")
KNOWN_KINDS = set(HOSTILE) | {"success", "blocked_attempt", "account_locked", "ip_blocked"}


def normalize_kind(raw):
    kind = str(raw or "fail").strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "failed_login": "fail", "failure": "fail", "bad_login": "fail",
        "ratelimit": "rate_limited", "rate_limit": "rate_limited", "throttled": "rate_limited",
        "successful_login": "success", "ok": "success",
        "blocked": "blocked_attempt", "denied": "blocked_attempt",
    }
    kind = aliases.get(kind, kind)
    return kind if kind in KNOWN_KINDS else "suspicious"


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def _alert(cfg, text):
    """Fire-and-forget webhook (Discord 'content' / Slack 'text'). Never blocks."""
    if not cfg.alert_webhook:
        return

    def send():
        try:
            body = json.dumps({"content": text, "text": text}).encode()
            req = urllib.request.Request(
                cfg.alert_webhook, data=body,
                headers={"Content-Type": "application/json", "User-Agent": "Sentinel"})
            urllib.request.urlopen(req, timeout=5).close()
        except Exception:
            pass

    threading.Thread(target=send, daemon=True).start()


# --- Read helpers --------------------------------------------------------------

def is_trusted(s, ip):
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for row in s.rows("SELECT cidr FROM sn_trusted"):
        try:
            if addr in ipaddress.ip_network(row["cidr"], strict=False):
                return True
        except ValueError:
            pass
    return False


def active_block(s, ip):
    return s.row(
        "SELECT * FROM sn_blocks WHERE ip=? AND (expires IS NULL OR expires>?)",
        (ip, time.time()))


def active_lock(s, account):
    if not account:
        return None
    return s.row(
        "SELECT * FROM sn_locks WHERE account=? AND expires>?",
        (account.lower(), time.time()))


# --- Writes --------------------------------------------------------------------

def record(s, ip, kind, route="-", method="-", ua="-", account="", note="", client=""):
    ts = time.time()
    country, city, lat, lon = geo.locate(ip)
    row = {
        "id": secrets.token_hex(5), "ts": ts, "iso": _iso(ts), "ip": ip, "kind": kind,
        "route": (route or "-")[:200], "method": (method or "-")[:10], "ua": (ua or "-")[:300],
        "account": (account or "")[:120], "note": (note or "")[:300],
        "country": country, "city": city, "lat": lat, "lon": lon, "client": clean_client(client),
    }
    s.write(
        "INSERT INTO sn_events (id, ts, iso, ip, kind, route, method, ua, account, note, "
        "country, city, lat, lon, client) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (row["id"], row["ts"], row["iso"], row["ip"], row["kind"],
         row["route"], row["method"], row["ua"], row["account"], row["note"],
         row["country"], row["city"], row["lat"], row["lon"], row["client"]))
    return row


def block_ip(cfg, s, ip, reason, seconds=None, manual=False):
    """Block an IP. Automatic blocks escalate x2 per strike up to the cap; seconds=0 = permanent."""
    prior = s.row("SELECT strikes FROM sn_blocks WHERE ip=?", (ip,))
    strikes = (prior["strikes"] if prior else 0) + 1
    if seconds is None:
        seconds = min(cfg.block_seconds * (2 ** (strikes - 1)), cfg.max_block_seconds)
    now = time.time()
    expires = None if seconds == 0 else now + seconds
    # REPLACE/UPSERT that works on both engines.
    if cfg.use_mysql:
        s.write(
            "REPLACE INTO sn_blocks (ip, reason, created, expires, strikes, manual) VALUES (?,?,?,?,?,?)",
            (ip, reason[:200], now, expires, strikes, int(manual)))
    else:
        s.write(
            "INSERT INTO sn_blocks (ip, reason, created, expires, strikes, manual) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, created=excluded.created, "
            "expires=excluded.expires, strikes=excluded.strikes, manual=excluded.manual",
            (ip, reason[:200], now, expires, strikes, int(manual)))
    span = "permanently" if expires is None else f"for {seconds // 60} min"
    record(s, ip, "ip_blocked", note=f"{reason} — blocked {span} (strike {strikes})")
    _alert(cfg, f"\U0001f6e1️ Sentinel blocked {ip} {span}. Reason: {reason}")
    return {"action": "ip_blocked", "ip": ip, "seconds": seconds, "strikes": strikes}


def lock_account(cfg, s, account, count):
    now = time.time()
    expires = now + cfg.lock_seconds
    acct = account.lower()
    if cfg.use_mysql:
        s.write("REPLACE INTO sn_locks (account, created, expires) VALUES (?,?,?)", (acct, now, expires))
    else:
        s.write(
            "INSERT INTO sn_locks (account, created, expires) VALUES (?,?,?) "
            "ON CONFLICT(account) DO UPDATE SET created=excluded.created, expires=excluded.expires",
            (acct, now, expires))
    record(s, "-", "account_locked", account=account,
           note=f"{count} failed logins on this account in {cfg.fail_window // 60} min")
    _alert(cfg, f"\U0001f512 Sentinel locked account \"{account}\" for {cfg.lock_seconds // 60} min.")
    return {"action": "account_locked", "account": account, "seconds": cfg.lock_seconds}


# --- The two public entry points ----------------------------------------------

def decide(cfg, s, ip, account=None):
    """Read-only: may this IP / account proceed right now?"""
    if is_trusted(s, ip):
        return {"allowed": True, "verdict": "trusted", "retry_after": 0}
    block = active_block(s, ip)
    if block:
        retry = None if block["expires"] is None else int(block["expires"] - time.time())
        return {"allowed": False, "verdict": "ip_blocked", "retry_after": retry}
    lock = active_lock(s, account)
    if lock:
        return {"allowed": False, "verdict": "account_locked", "retry_after": int(lock["expires"] - time.time())}
    return {"allowed": True, "verdict": "clear", "retry_after": 0}


def ingest(cfg, s, ip, kind, route="/login", method="POST", ua="-", account="", client=""):
    """Record one signal, apply the block/lock rules, and return (event, actions, decision)."""
    account = (account or "")[:120]
    actions = []
    event = record(s, ip, kind, route, method, ua, account, client=client)
    now = time.time()

    if kind in HOSTILE and not is_trusted(s, ip) and not active_block(s, ip):
        last = s.row("SELECT expires FROM sn_blocks WHERE ip=?", (ip,))
        floor = max(now - cfg.fail_window, (last["expires"] or 0) if last else 0)
        placeholders = ",".join("?" for _ in HOSTILE)
        heat = s.scalar(
            f"SELECT COUNT(*) AS n FROM sn_events WHERE ip=? AND ts>? AND kind IN ({placeholders})",
            (ip, floor, *HOSTILE), key="n")
        if heat >= cfg.fail_limit:
            actions.append(block_ip(cfg, s, ip, f"{heat} hostile signals in {cfg.fail_window // 60} min"))

    if account and kind == "fail" and not active_lock(s, account):
        tries = s.scalar(
            "SELECT COUNT(*) AS n FROM sn_events WHERE LOWER(account)=LOWER(?) AND ts>? AND kind='fail'",
            (account, now - cfg.fail_window), key="n")
        if tries >= cfg.account_limit:
            actions.append(lock_account(cfg, s, account, tries))

    return event, actions, decide(cfg, s, ip, account)
