"""
HTTP surface for Sentinel.

Two audiences:
  * The console (dashboard) and admin actions  -> a username/password login session.
  * The ingestion API your login backend calls  -> guarded by X-Sentinel-Signal.

API lives under /api/v1. The dashboard is a single page at /, behind /login.
"""

import csv
import io
import time

from flask import (Blueprint, render_template, request, jsonify, Response,
                   session, redirect, url_for)

from . import engine, auth, geo
from .security import require_login, require_signal, current_admin, caller_ip, valid_ip, valid_cidr


def build_blueprint(cfg, store):
    bp = Blueprint("sentinel", __name__)

    # ---- Login / logout (admin console lives under a hidden /admin path) ------
    @bp.get("/admin/login")
    def login_page():
        if current_admin():
            return redirect(url_for("sentinel.console"))
        return render_template("login.html"), 200, {"Cache-Control": "no-cache"}

    @bp.post("/admin/login")
    def login_submit():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if auth.verify_admin(store, username, password):
            session.clear()
            session["admin"] = username
            session.permanent = True
            return redirect(url_for("sentinel.console"))
        return render_template("login.html", error="Wrong username or password."), 401

    @bp.post("/admin/logout")
    def logout():
        session.clear()
        return jsonify({"ok": True})

    @bp.get("/admin/logout")
    def logout_get():
        session.clear()
        return redirect(url_for("sentinel.login_page"))

    # ---- Dashboard page (hidden admin console) -------------------------------
    @bp.get("/admin")
    def console():
        if not current_admin():
            return redirect(url_for("sentinel.login_page"))
        return render_template("console.html", admin=current_admin()), 200, {"Cache-Control": "no-cache"}

    @bp.get("/healthz")
    def healthz():
        return jsonify({"service": "sentinel", "status": "ok", "storage": cfg.as_rules()["storage"]})

    # ---- Ingestion API (called by your login system) -------------------------
    @bp.post("/api/v1/gate")
    @require_signal
    def gate():
        """Ask before processing a login: may this IP / account try? Body: {ip?, account?}."""
        body = request.get_json(silent=True) or {}
        ip = valid_ip(body["ip"]) if "ip" in body else caller_ip()
        if not ip:
            return jsonify({"error": "Invalid ip"}), 400
        account = (str(body.get("account", "")) or None)
        with store.session() as s:
            return jsonify(engine.decide(cfg, s, ip, account))

    @bp.post("/api/v1/signal")
    @require_signal
    def signal():
        """Report a login attempt AFTER you handled it. Never send passwords.

        Body: {kind, route?, method?, account?, ip?, ua?}. kind is one of
        fail | success | rate_limited | suspicious | blocked_attempt.
        Response carries allowed:false once the IP is blocked or the account locked.
        """
        body = request.get_json(silent=True) or {}
        if "ip" in body and not valid_ip(body["ip"]):
            return jsonify({"error": "Invalid ip"}), 400
        ip = valid_ip(body["ip"]) if "ip" in body else caller_ip()
        kind = engine.normalize_kind(body.get("kind"))
        method = str(body.get("method", "POST")).upper()[:10]
        with store.session() as s:
            event, actions, decision = engine.ingest(
                cfg, s, ip, kind,
                route=str(body.get("route", "/login"))[:200],
                method=method if method.isalpha() else "POST",
                ua=str(body.get("ua") or request.headers.get("User-Agent", "-"))[:300],
                account=str(body.get("account", "")),
                client=body.get("client", ""))
        return jsonify({"ok": True, "event_id": event["id"], "actions": actions, **decision}), 201

    # ---- Console API ---------------------------------------------------------
    @bp.get("/api/v1/snapshot")
    @require_login
    def snapshot():
        now = time.time()
        day = now - 86400
        with store.session() as s:
            store.prune(s)
            events = s.rows(
                "SELECT id, iso, ts, ip, kind, route, method, ua, account, note, "
                "country, city, lat, lon, client "
                "FROM sn_events ORDER BY ts DESC LIMIT 250")
            located = s.rows(
                "SELECT ip, country, city, lat, lon, "
                "COUNT(*) AS hits, MAX(ts) AS last_ts "
                "FROM sn_events WHERE ts>? AND lat IS NOT NULL AND kind!='ip_blocked' "
                "GROUP BY ip, country, city, lat, lon ORDER BY hits DESC LIMIT 500", (day,))
            blocks = s.rows("SELECT * FROM sn_blocks WHERE expires IS NULL OR expires>? ORDER BY created DESC", (now,))
            locks = s.rows("SELECT * FROM sn_locks WHERE expires>? ORDER BY created DESC", (now,))
            trusted = s.rows("SELECT * FROM sn_trusted ORDER BY created DESC")
            totals = s.row(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN kind='fail' THEN 1 ELSE 0 END) AS fails, "
                "SUM(CASE WHEN kind='success' THEN 1 ELSE 0 END) AS wins, "
                "COUNT(DISTINCT ip) AS ips "
                "FROM sn_events WHERE ts>? AND kind!='ip_blocked'", (day,))
            recent = s.rows(
                "SELECT ts FROM sn_events WHERE ts>? AND kind IN ('fail','rate_limited','suspicious')",
                (now - 3600,))
            offenders = s.rows(
                "SELECT ip, COUNT(*) AS hits, MAX(ts) AS last_ts, MAX(iso) AS last "
                "FROM sn_events WHERE ts>? AND kind IN ('fail','rate_limited','suspicious') "
                "GROUP BY ip ORDER BY hits DESC LIMIT 12", (day,))

        # 60 minutes split into twelve 5-minute buckets, oldest first.
        buckets = [0] * 12
        for r in recent:
            idx = min(11, max(0, 11 - int((now - r["ts"]) // 300)))
            buckets[idx] += 1

        blocked_ips = {b["ip"] for b in blocks}
        for o in offenders:
            o["blocked"] = o["ip"] in blocked_ips

        # Map points: one pin per located IP, flagged if currently blocked.
        points = []
        for p in located:
            points.append({
                "ip": p["ip"], "lat": p["lat"], "lon": p["lon"],
                "country": p["country"], "city": p["city"],
                "hits": int(p["hits"]), "blocked": p["ip"] in blocked_ips,
            })

        return jsonify({
            "now": now,
            "geo": {"enabled": geo.enabled, "source": geo.GEO_SOURCE},
            "points": points,
            "stats": {
                "total": int(totals["total"] or 0),
                "fails": int(totals["fails"] or 0),
                "wins": int(totals["wins"] or 0),
                "ips": int(totals["ips"] or 0),
                "blocks": len(blocks),
                "locks": len(locks),
            },
            "events": events,
            "blocks": blocks,
            "locks": locks,
            "trusted": trusted,
            "offenders": offenders,
            "buckets": buckets,
            "rules": cfg.as_rules(),
        })

    @bp.get("/api/v1/stream.csv")
    @require_login
    def stream_csv():
        fields = ["id", "iso", "ip", "kind", "route", "method", "account", "ua", "note"]
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        with store.session() as s:
            writer.writerows(s.rows(f"SELECT {','.join(fields)} FROM sn_events ORDER BY ts DESC"))
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=sentinel-events.csv"})

    @bp.delete("/api/v1/events")
    @require_login
    def clear_events():
        everything = request.args.get("all") == "1"
        with store.session() as s:
            s.write("DELETE FROM sn_events")
            if everything:
                s.write("DELETE FROM sn_blocks")
                s.write("DELETE FROM sn_locks")
        return jsonify({"ok": True, "reset": everything})

    @bp.post("/api/v1/blocks")
    @require_login
    def add_block():
        body = request.get_json(silent=True) or {}
        ip = valid_ip(body.get("ip", ""))
        if not ip:
            return jsonify({"error": "Enter a valid IP address"}), 400
        try:
            minutes = int(body.get("minutes", 60))
        except (TypeError, ValueError):
            return jsonify({"error": "Minutes must be a number"}), 400
        if not 0 <= minutes <= 525600:
            return jsonify({"error": "Minutes must be 0 (permanent) to 525600"}), 400
        with store.session() as s:
            if engine.is_trusted(s, ip):
                return jsonify({"error": "That IP is trusted — remove it from the trusted list first"}), 409
            result = engine.block_ip(cfg, s, ip, str(body.get("reason") or "Manual block"),
                                     seconds=minutes * 60, manual=True)
        return jsonify({"ok": True, **result}), 201

    @bp.delete("/api/v1/blocks/<ip>")
    @require_login
    def drop_block(ip):
        with store.session() as s:
            # Keep the row (strike history) but expire it now, so escalation still remembers.
            updated = s.write("UPDATE sn_blocks SET expires=? WHERE ip=? AND (expires IS NULL OR expires>?)",
                              (time.time(), ip, time.time()))
        return (jsonify({"ok": True}), 200) if updated else (jsonify({"ok": False}), 404)

    @bp.delete("/api/v1/locks/<path:account>")
    @require_login
    def drop_lock(account):
        with store.session() as s:
            updated = s.write("UPDATE sn_locks SET expires=? WHERE account=? AND expires>?",
                              (time.time(), account.lower(), time.time()))
        return (jsonify({"ok": True}), 200) if updated else (jsonify({"ok": False}), 404)

    @bp.post("/api/v1/trusted")
    @require_login
    def add_trusted():
        body = request.get_json(silent=True) or {}
        cidr = valid_cidr(body.get("cidr", ""))
        if not cidr:
            return jsonify({"error": "Enter an IP or CIDR range, e.g. 203.0.113.0/24"}), 400
        with store.session() as s:
            if cfg.use_mysql:
                s.write("REPLACE INTO sn_trusted (cidr, label, created) VALUES (?,?,?)",
                        (cidr, str(body.get("label", ""))[:120], time.time()))
            else:
                s.write("INSERT INTO sn_trusted (cidr, label, created) VALUES (?,?,?) "
                        "ON CONFLICT(cidr) DO UPDATE SET label=excluded.label, created=excluded.created",
                        (cidr, str(body.get("label", ""))[:120], time.time()))
        return jsonify({"ok": True, "cidr": cidr}), 201

    @bp.delete("/api/v1/trusted")
    @require_login
    def drop_trusted():
        with store.session() as s:
            removed = s.write("DELETE FROM sn_trusted WHERE cidr=?", (request.args.get("cidr", ""),))
        return (jsonify({"ok": True}), 200) if removed else (jsonify({"ok": False}), 404)

    return bp
