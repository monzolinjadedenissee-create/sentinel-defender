"""
Sentinel — a standalone brute-force defender.

Application factory: `create_app()` wires the config, storage and routes together
and returns a WSGI Flask app. The Vercel entrypoint (api/index.py) and the local
runner (serve.py) both call it.
"""

from datetime import timedelta
from pathlib import Path

from flask import Flask

from . import auth
from .config import Config
from .store import Store
from .routes import build_blueprint
from .portal import build_portal

__version__ = "1.1.0"


def create_app(env=None):
    base = Path(__file__).resolve().parent.parent          # the project root
    app = Flask(
        __name__,
        template_folder=str(base / "templates"),
        static_folder=str(base / "static"),
        static_url_path="/static",
    )

    cfg = Config(env)

    # Session cookie (signed, HttpOnly). Secure flag on when served over HTTPS (Vercel).
    app.secret_key = cfg.secret_key
    app.config.update(
        PERMANENT_SESSION_LIFETIME=timedelta(days=cfg.session_days),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=bool(env.get("VERCEL")) if env else _is_vercel(),
    )

    store = Store(cfg)
    try:
        store.ensure_schema()
        auth.seed_if_empty(store, cfg.admin_user, cfg.admin_password)
    except Exception as exc:                                # don't crash cold start if DB is briefly unreachable
        app.logger.warning("Schema/seed deferred: %s", exc)

    app.config["MZ"] = cfg
    app.config["STORE"] = store
    app.register_blueprint(build_blueprint(cfg, store))   # defender console + API
    app.register_blueprint(build_portal(cfg, store))      # public target site (/portal)
    return app


def _is_vercel():
    import os
    return bool(os.environ.get("VERCEL"))
