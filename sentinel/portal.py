"""
The *target* site — a deliberately ordinary public login that an attacker would
try to brute-force. It is NOT the defender. On every attempt it reports to the
Sentinel engine (same process, same store), so the admin console sees the attack
— IP, username tried, user-agent, timing, and any resulting block/lock — live.

This is a lab target for AUTHORIZED security testing only. "Aurora Vault" is an
entirely fictional bank and holds no real data. The weak demo passwords below
exist so the lab is easy to drive; never ship credentials like this.
"""

from flask import (Blueprint, render_template, request, session,
                    redirect, url_for)

from . import engine
from .security import caller_ip


# One "real" customer plus a second account; every other guess fails — which is
# exactly what a brute-force run looks like to the engine.
DEMO_ACCOUNTS = {
    "jayray": "Summer",
    "j.castillo": "Summer2024!",
    "m.reyes": "Aurora#7road",
}

BRAND = "Aurora Vault"


def build_portal(cfg, store):
    # The public target site is the default page at the site root; the Sentinel
    # admin console is tucked away under /admin.
    bp = Blueprint("portal", __name__)

    def _ua():
        return request.headers.get("User-Agent", "-")

    @bp.get("/")
    def login_page():
        if session.get("portal_user"):
            return redirect(url_for("portal.account"))
        return render_template("portal/login.html", brand=BRAND), 200, {"Cache-Control": "no-cache"}

    @bp.post("/")
    def login_submit():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        client = request.form.get("client") or ""   # device fingerprint collected by the page
        ip = caller_ip()

        with store.session() as s:
            # 1) Ask Sentinel first: is this IP / account even allowed to try?
            verdict = engine.decide(cfg, s, ip, account=username)
            if not verdict["allowed"]:
                engine.ingest(cfg, s, ip, "blocked_attempt",
                              route="/", method="POST", ua=_ua(), account=username, client=client)
                retry = verdict.get("retry_after")
                mins = f" (~{max(1, retry // 60)} min)" if retry else ""
                return render_template(
                    "portal/login.html", brand=BRAND, locked=True,
                    error=f"Access from your location is temporarily restricted{mins}."), 429

            # 2) Check the (fake) credentials.
            ok = bool(password) and DEMO_ACCOUNTS.get(username.lower()) == password

            # 3) Report the outcome to Sentinel — never the password itself.
            engine.ingest(cfg, s, ip, "success" if ok else "fail",
                          route="/", method="POST", ua=_ua(), account=username, client=client)

        if ok:
            session["portal_user"] = username
            session.permanent = True
            return redirect(url_for("portal.account"))
        return render_template(
            "portal/login.html", brand=BRAND,
            error="The username or password you entered is incorrect."), 401

    @bp.get("/account")
    def account():
        user = session.get("portal_user")
        if not user:
            return redirect(url_for("portal.login_page"))
        return render_template("portal/account.html", brand=BRAND, user=user), 200, {"Cache-Control": "no-cache"}

    @bp.get("/logout")
    def logout():
        session.pop("portal_user", None)
        return redirect(url_for("portal.login_page"))

    return bp
