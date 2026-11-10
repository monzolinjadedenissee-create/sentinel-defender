"""
Create or reset a Sentinel console admin.

    python tools/create_admin.py <username> <password>
    python tools/create_admin.py --list

Uses the same storage as the app (SQLite locally, or TiDB when the TIDB_*
environment variables are set). Run it from the project root.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel import auth                      # noqa: E402
from sentinel.config import Config             # noqa: E402
from sentinel.store import Store               # noqa: E402


def main(argv):
    store = Store(Config())
    store.ensure_schema()

    if argv[:1] == ["--list"]:
        admins = auth.list_admins(store)
        print("Admins:", ", ".join(admins) if admins else "(none)")
        return 0

    if len(argv) != 2:
        print("Usage: python tools/create_admin.py <username> <password>")
        print("       python tools/create_admin.py --list")
        return 1

    username, password = argv
    try:
        action = auth.upsert_admin(store, username, password)
    except ValueError as exc:
        print("Error:", exc)
        return 1
    print(f"Admin '{username}' {action}. You can now sign in to the console.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
