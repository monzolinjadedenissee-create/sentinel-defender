"""
Runtime configuration for Sentinel, read once from environment variables.

Everything is namespaced under SENTINEL_* / SN_* so this app can live on its own
Vercel project and its own TiDB account without colliding with anything else.
Storage auto-selects: TiDB/MySQL when TIDB_HOST is set, otherwise a local SQLite file.
"""

import os
import tempfile


def _int(name, default, minimum=1):
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


class Config:
    def __init__(self, env=None):
        env = env if env is not None else os.environ

        # --- Storage -------------------------------------------------------
        self.use_mysql = bool(env.get("TIDB_HOST"))
        self.tidb = {
            "host": env.get("TIDB_HOST", ""),
            "port": int(env.get("TIDB_PORT", 4000)),   # TiDB Cloud defaults to 4000
            "user": env.get("TIDB_USER", "root"),
            "password": env.get("TIDB_PASSWORD", ""),
            "database": env.get("TIDB_DATABASE", "sentinel"),
            "ssl_ca": env.get("TIDB_SSL_CA", "/etc/ssl/cert.pem"),
        }
        self.db_path = env.get("SN_DB_PATH") or self._default_sqlite(env)

        # --- Console login (dashboard) -------------------------------------
        # The dashboard is protected by a real username/password login, not an
        # API key. Sessions are signed with this secret — set a stable random
        # value in production, or everyone is logged out on each cold start.
        self.secret_key = env.get("SENTINEL_SECRET_KEY", "sentinel-dev-secret-change-me")
        # First admin, seeded once on an empty database. After that, manage
        # admins with tools/create_admin.py. Never overwritten if it exists.
        self.admin_user = env.get("SENTINEL_ADMIN_USER", "admin" if not self.use_mysql else "")
        self.admin_password = env.get("SENTINEL_ADMIN_PASSWORD", "sentinel123" if not self.use_mysql else "")
        self.session_days = _int("SN_SESSION_DAYS", 7)

        # --- Signal key (machine-to-machine ingestion) ---------------------
        # Guards /api/v1/signal and /api/v1/gate, which your login backend calls.
        self.signal_key = env.get("SENTINEL_SIGNAL_KEY", "sentinel-dev-signal-key")

        # --- Client IP resolution -----------------------------------------
        # On Vercel the real visitor IP arrives in a forwarded header.
        self.ip_header = env.get("SN_IP_HEADER", "X-Forwarded-For")
        self.trust_proxy = env.get("SN_TRUST_PROXY", "1" if env.get("VERCEL") else "0") == "1"

        # --- Detection thresholds -----------------------------------------
        self.fail_limit = _int("SN_FAIL_LIMIT", 5)          # bad tries from one IP...
        self.fail_window = _int("SN_FAIL_WINDOW", 600)      # ...within this many seconds -> block
        self.block_seconds = _int("SN_BLOCK_SECONDS", 900)  # first block; doubles each repeat
        self.max_block_seconds = _int("SN_MAX_BLOCK", 86400)
        self.account_limit = _int("SN_ACCOUNT_LIMIT", 10)   # bad tries on one account (any IP) -> lock
        self.lock_seconds = _int("SN_LOCK_SECONDS", 900)
        self.retention_days = _int("SN_RETENTION_DAYS", 30)

        self.alert_webhook = env.get("SN_ALERT_WEBHOOK", "")  # Discord/Slack incoming webhook (optional)

    @staticmethod
    def _default_sqlite(env):
        # Vercel's filesystem is read-only except /tmp, and that is ephemeral.
        if env.get("VERCEL"):
            return os.path.join(tempfile.gettempdir(), "sentinel.db")
        return "sentinel.db"

    def as_rules(self):
        """The subset the dashboard shows as the active policy."""
        return {
            "fail_limit": self.fail_limit,
            "fail_window": self.fail_window,
            "block_seconds": self.block_seconds,
            "max_block_seconds": self.max_block_seconds,
            "account_limit": self.account_limit,
            "lock_seconds": self.lock_seconds,
            "retention_days": self.retention_days,
            "storage": "TiDB / MySQL" if self.use_mysql else "SQLite (local)",
            "alerts": bool(self.alert_webhook),
        }
