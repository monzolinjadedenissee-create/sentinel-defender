"""
Console authentication: admin accounts stored in the `sn_admins` table with
salted password hashes (Werkzeug's PBKDF2 — ships with Flask, no extra deps).

Used by the login routes and by tools/create_admin.py.
"""

import re
import time

from werkzeug.security import generate_password_hash, check_password_hash

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")


def username_problem(username):
    if not USERNAME_RE.match(username or ""):
        return "Usernames are 3–30 characters: letters, numbers, dots, dashes or underscores."
    return None


def password_problem(password):
    if not (8 <= len(password or "") <= 128):
        return "Passwords must be 8–128 characters."
    return None


def count_admins(store):
    with store.session() as s:
        row = s.row("SELECT COUNT(*) AS n FROM sn_admins")
    return int(row["n"]) if row else 0


def list_admins(store):
    with store.session() as s:
        return [r["username"] for r in s.rows("SELECT username FROM sn_admins ORDER BY username")]


def upsert_admin(store, username, password):
    """Create an admin, or reset the password if the username already exists."""
    problem = username_problem(username) or password_problem(password)
    if problem:
        raise ValueError(problem)
    digest = generate_password_hash(password)
    now = time.time()
    with store.session() as s:
        exists = s.row("SELECT 1 FROM sn_admins WHERE username=?", (username,))
        if exists:
            s.write("UPDATE sn_admins SET password_hash=? WHERE username=?", (digest, username))
            return "reset"
        s.write("INSERT INTO sn_admins (username, password_hash, created) VALUES (?,?,?)",
                (username, digest, now))
        return "created"


def delete_admin(store, username):
    with store.session() as s:
        return bool(s.write("DELETE FROM sn_admins WHERE username=?", (username,)))


def verify_admin(store, username, password):
    """Return True if the username/password pair is valid. Constant-ish time."""
    with store.session() as s:
        row = s.row("SELECT password_hash FROM sn_admins WHERE username=?", (username or "",))
    if not row:
        # Run a dummy check so a missing user and a wrong password take similar time.
        check_password_hash("pbkdf2:sha256:600000$x$" + "0" * 64, password or "")
        return False
    return check_password_hash(row["password_hash"], password or "")


def seed_if_empty(store, username, password):
    """Create the very first admin from env, only when no admins exist yet."""
    if not username or not password:
        return False
    if count_admins(store) > 0:
        return False
    try:
        upsert_admin(store, username, password)
        return True
    except ValueError:
        return False
