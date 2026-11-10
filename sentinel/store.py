"""
Storage layer.

A thin abstraction that speaks the same `?`-placeholder dialect to both SQLite
(local dev) and TiDB/MySQL (production). Unlike a single global connection, each
unit of work opens a short-lived Session via `with store.session() as s:` and the
session is committed and closed for you.

Tables are prefixed `sn_` so Sentinel owns a clean namespace on a fresh database.
"""

import sqlite3
import time
from contextlib import contextmanager


SCHEMA = {
    "sqlite": [
        """CREATE TABLE IF NOT EXISTS sn_events (
            id TEXT PRIMARY KEY, ts REAL, iso TEXT, ip TEXT, kind TEXT, route TEXT,
            method TEXT, ua TEXT, account TEXT, note TEXT,
            country TEXT, city TEXT, lat REAL, lon REAL, client TEXT)""",
        "CREATE INDEX IF NOT EXISTS sn_events_ts ON sn_events(ts)",
        "CREATE INDEX IF NOT EXISTS sn_events_ip ON sn_events(ip, ts)",
        "CREATE INDEX IF NOT EXISTS sn_events_acct ON sn_events(account, ts)",
        """CREATE TABLE IF NOT EXISTS sn_blocks (
            ip TEXT PRIMARY KEY, reason TEXT, created REAL, expires REAL,
            strikes INTEGER DEFAULT 0, manual INTEGER DEFAULT 0)""",
        "CREATE TABLE IF NOT EXISTS sn_locks (account TEXT PRIMARY KEY, created REAL, expires REAL)",
        "CREATE TABLE IF NOT EXISTS sn_trusted (cidr TEXT PRIMARY KEY, label TEXT, created REAL)",
        "CREATE TABLE IF NOT EXISTS sn_config (name TEXT PRIMARY KEY, value TEXT)",
        "CREATE TABLE IF NOT EXISTS sn_admins (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, created REAL)",
    ],
    "mysql": [
        """CREATE TABLE IF NOT EXISTS sn_events (
            id VARCHAR(16) PRIMARY KEY, ts DOUBLE, iso VARCHAR(40), ip VARCHAR(64), kind VARCHAR(32),
            route VARCHAR(200), method VARCHAR(10), ua VARCHAR(300), account VARCHAR(120), note VARCHAR(300),
            country VARCHAR(100), city VARCHAR(100), lat DOUBLE, lon DOUBLE, client VARCHAR(1000),
            INDEX sn_events_ts (ts), INDEX sn_events_ip (ip, ts), INDEX sn_events_acct (account, ts))""",
        """CREATE TABLE IF NOT EXISTS sn_blocks (
            ip VARCHAR(64) PRIMARY KEY, reason VARCHAR(200), created DOUBLE, expires DOUBLE NULL,
            strikes INT DEFAULT 0, manual INT DEFAULT 0)""",
        "CREATE TABLE IF NOT EXISTS sn_locks (account VARCHAR(120) PRIMARY KEY, created DOUBLE, expires DOUBLE)",
        "CREATE TABLE IF NOT EXISTS sn_trusted (cidr VARCHAR(64) PRIMARY KEY, label VARCHAR(120), created DOUBLE)",
        "CREATE TABLE IF NOT EXISTS sn_config (name VARCHAR(60) PRIMARY KEY, value VARCHAR(2000))",
        "CREATE TABLE IF NOT EXISTS sn_admins (username VARCHAR(30) PRIMARY KEY, password_hash VARCHAR(255) NOT NULL, created DOUBLE)",
    ],
}


class Session:
    """One connection's worth of work. Returns rows as plain dicts either way."""

    def __init__(self, conn, use_mysql):
        self._conn = conn
        self._mysql = use_mysql

    def _run(self, sql, params):
        cur = self._conn.cursor()
        cur.execute(sql.replace("?", "%s") if self._mysql else sql, tuple(params or ()))
        return cur

    def write(self, sql, params=()):
        cur = self._run(sql, params)
        count = cur.rowcount
        if self._mysql:
            cur.close()
        return count

    def rows(self, sql, params=()):
        cur = self._run(sql, params)
        data = cur.fetchall()
        if self._mysql:
            cur.close()
            return list(data)                       # DictCursor already yields dicts
        return [dict(r) for r in data]

    def row(self, sql, params=()):
        found = self.rows(sql, params)
        return found[0] if found else None

    def scalar(self, sql, params=(), key=None):
        r = self.row(sql, params)
        if r is None:
            return None
        return r[key] if key is not None else next(iter(r.values()))


class Store:
    def __init__(self, config):
        self.cfg = config

    def _connect(self):
        if self.cfg.use_mysql:
            import pymysql
            import pymysql.cursors
            t = self.cfg.tidb
            local = t["host"] in ("localhost", "127.0.0.1")
            return pymysql.connect(
                host=t["host"], port=t["port"], user=t["user"], password=t["password"],
                database=t["database"], charset="utf8mb4",
                cursorclass=pymysql.cursors.DictCursor, connect_timeout=10,
                ssl=None if local else {"ca": t["ssl_ca"]})
        conn = sqlite3.connect(self.cfg.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def session(self):
        conn = self._connect()
        s = Session(conn, self.cfg.use_mysql)
        try:
            yield s
            conn.commit()
        finally:
            conn.close()

    # Columns added after the first release — created on older databases so upgrades don't need a reset.
    _ADDED_COLUMNS = [
        ("country", "country VARCHAR(100)", "country TEXT"),
        ("city", "city VARCHAR(100)", "city TEXT"),
        ("lat", "lat DOUBLE", "lat REAL"),
        ("lon", "lon DOUBLE", "lon REAL"),
        ("client", "client VARCHAR(1000)", "client TEXT"),
    ]

    def _ensure_column(self, s, table, column, mysql_def, sqlite_def):
        if self.cfg.use_mysql:
            exists = s.scalar(
                "SELECT COUNT(*) AS n FROM information_schema.columns "
                "WHERE table_schema=DATABASE() AND table_name=? AND column_name=?",
                (table, column), key="n")
        else:
            exists = any(r["name"] == column for r in s.rows(f"PRAGMA table_info({table})"))
        if not exists:
            s.write(f"ALTER TABLE {table} ADD COLUMN {mysql_def if self.cfg.use_mysql else sqlite_def}")

    def ensure_schema(self):
        statements = SCHEMA["mysql" if self.cfg.use_mysql else "sqlite"]
        with self.session() as s:
            if not self.cfg.use_mysql:
                s.write("PRAGMA journal_mode=WAL")
            for stmt in statements:
                s.write(stmt)
            for col, my, lite in self._ADDED_COLUMNS:
                self._ensure_column(s, "sn_events", col, my, lite)
            self.prune(s)

    def prune(self, s):
        cutoff = time.time() - self.cfg.retention_days * 86400
        s.write("DELETE FROM sn_events WHERE ts < ?", (cutoff,))
