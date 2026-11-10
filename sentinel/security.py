"""
Request-side helpers: key checks, client IP resolution, and input validation.
Kept separate from the detection logic so the policy engine stays pure.
"""

import ipaddress
import secrets
from functools import wraps

from flask import request, jsonify, current_app, session


def _const_eq(a, b):
    return secrets.compare_digest(str(a).encode(), str(b).encode())


def _config():
    return current_app.config["MZ"]


def current_admin():
    return session.get("admin")


def require_login(view):
    """Guards the admin API. The caller must have an active console session.
    Returns 401 JSON so the front-end can redirect to the login page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return jsonify({"error": "Login required", "login": True}), 401
        return view(*args, **kwargs)
    return wrapped


def require_signal(view):
    """Guards the ingestion API your login system calls. Header: X-Sentinel-Signal."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _const_eq(request.headers.get("X-Sentinel-Signal", ""), _config().signal_key):
            return jsonify({"error": "Unauthorized — send a valid X-Sentinel-Signal header."}), 401
        return view(*args, **kwargs)
    return wrapped


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except (ValueError, TypeError):
        return None


def valid_cidr(value):
    try:
        return str(ipaddress.ip_network(str(value).strip(), strict=False))
    except (ValueError, TypeError):
        return None


def caller_ip():
    cfg = _config()
    if cfg.trust_proxy:
        forwarded = request.headers.get(cfg.ip_header, "").split(",")[0].strip()
        clean = valid_ip(forwarded)
        if clean:
            return clean
    return (request.remote_addr or "unknown")[:64]
