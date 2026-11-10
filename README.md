# Sentinel — Brute-Force Defender

A **standalone** brute-force defense service with a web console. It watches login
attempts reported by your app, automatically **blocks** abusive IPs and **locks**
accounts under attack, and gives you a live dashboard to see and manage it all.

It is fully independent — its own code, its own API, its own `sn_` database tables,
and its own environment variables — so it runs on its **own Vercel project** and
its **own TiDB account** without touching anything else you own.

> Not the same app as the bundled `defender/`. Different structure (a Python
> package, not one file), different design (top-tab console, no map), different
> API (`/api/v1/…`), and no coupling to any vault database.

---

## How it works

- Your login backend sends Sentinel a **signal** after each attempt
  (`fail`, `success`, `rate_limited`, `suspicious`, `blocked_attempt`).
  **Passwords are never sent.**
- **IP block:** `SN_FAIL_LIMIT` hostile signals from one IP within `SN_FAIL_WINDOW`
  → the IP is blocked. Repeat offenders are blocked **twice as long each time**,
  capped at `SN_MAX_BLOCK`.
- **Account lock:** `SN_ACCOUNT_LIMIT` failed logins against one account (from any
  IP) within the window → that account is locked for `SN_LOCK_SECONDS`.
- **Trusted ranges** (IPs/CIDRs) are never blocked and never build heat.
- Optionally ask Sentinel **before** processing a login via `/api/v1/gate`.

Defaults: **5 fails / 10 min → 15-minute block (doubling)**, **10 account fails →
15-minute lock**. All tunable by environment variable.

---

## Project layout

```
bruteforce_sentinel/
├── api/index.py        # Vercel entrypoint -> exposes WSGI `app`
├── sentinel/           # the package
│   ├── __init__.py     # create_app() factory
│   ├── config.py       # all settings from env
│   ├── store.py        # SQLite / TiDB storage (one dialect, `?` placeholders)
│   ├── engine.py       # detection: blocks, locks, escalation
│   ├── auth.py        # admin accounts + password hashing (login)
│   ├── security.py     # session guard, signal-key guard, client-IP resolution
│   └── routes.py       # /api/v1 + dashboard + login/logout
├── templates/login.html, console.html
├── static/sentinel.css, sentinel.js
├── tools/create_admin.py  # create/reset a console admin
├── serve.py            # local runner (python serve.py)
├── requirements.txt
├── vercel.json
└── .env.example
```

---

## Signing in

The dashboard is behind a **username + password login** (not an API key). Admin
accounts live in the `sn_admins` table with hashed passwords.

- **First admin** is seeded from `SENTINEL_ADMIN_USER` / `SENTINEL_ADMIN_PASSWORD`
  the first time the database is empty. Locally, if you set nothing, it defaults
  to **`admin` / `sentinel123`** — change it.
- **Add or reset** admins any time:
  `python tools/create_admin.py <username> <password>` (works against SQLite or
  your TiDB, depending on your environment). `--list` shows existing admins.
- Sessions are signed with `SENTINEL_SECRET_KEY` — set a stable random value in
  production or logins drop on each cold start.

---

## Run locally

```bash
cd bruteforce_sentinel
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r requirements.txt
python serve.py
```

Open http://127.0.0.1:7000 and sign in with **`admin` / `sentinel123`** (the local
default). With no `TIDB_HOST` it uses a local `sentinel.db` SQLite file; the
default signal key is `sentinel-dev-signal-key`.

Smoke-test the ingestion API (this is machine-to-machine, so it uses the signal
key, not the login):

```bash
# send a failed-login signal
curl -X POST http://127.0.0.1:7000/api/v1/signal \
  -H "X-Sentinel-Signal: sentinel-dev-signal-key" \
  -H "Content-Type: application/json" \
  -d '{"kind":"fail","ip":"203.0.113.9","account":"admin"}'
```

---

## Deploy to Vercel (new Vercel + new TiDB account)

1. **TiDB Cloud** → create a (free Serverless) cluster on your new account →
   **Connect** → copy host, port (`4000`), user, password. Create a database
   named `sentinel` (or set `TIDB_DATABASE`). Sentinel creates its own tables on
   first start.
2. **Vercel** (your new account) → **Add New → Project** → import this repo.
   Set the **Root Directory** to `bruteforce_sentinel`.
3. In the project's **Settings → Environment Variables**, add the values from
   `.env.example` — at minimum `SENTINEL_SECRET_KEY`, `SENTINEL_ADMIN_USER`,
   `SENTINEL_ADMIN_PASSWORD`, `SENTINEL_SIGNAL_KEY`, and the five `TIDB_*` values.
4. **Deploy.** Open the URL and sign in with the admin user/password you set.
   Health check: `GET /healthz`.

`vercel.json` already pins the `@vercel/python` build and bundles the package,
templates and static files.

---

## API reference (all under `/api/v1`)

Ingestion — header `X-Sentinel-Signal`:

| Method | Path       | Body | Purpose |
|--------|------------|------|---------|
| POST   | `/signal`  | `{kind, ip?, account?, route?, method?, ua?}` | Record an attempt; returns the current verdict |
| POST   | `/gate`    | `{ip?, account?}` | Ask if an attempt may proceed (read-only) |

Console/admin — requires a login session (sign in at `/login`):

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/snapshot` | Dashboard data |
| GET    | `/stream.csv` | Export all events |
| DELETE | `/events[?all=1]` | Clear history (and blocks/locks with `all=1`) |
| POST   | `/blocks` | Manual block `{ip, minutes, reason}` (minutes 0 = permanent) |
| DELETE | `/blocks/<ip>` | Lift a block |
| DELETE | `/locks/<account>` | Release an account |
| POST   | `/trusted` | Trust `{cidr, label}` |
| DELETE | `/trusted?cidr=…` | Untrust |

A `gate`/`signal` response includes `allowed` (bool), `verdict`
(`trusted` · `clear` · `ip_blocked` · `account_locked`) and `retry_after` seconds.
