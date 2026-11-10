"""
Attack simulator for the Sentinel lab — populates the console (and the map) with
attempts that appear to come from IPs around the world, so you can see detection,
blocking and the attack map working without needing real remote traffic.

It talks to the public signal API exactly like a real login backend would; it does
NOT attack anything real. For your own lab only.

Usage (with the server running):
    python tools/simulate_attack.py
    python tools/simulate_attack.py --rounds 40 --url http://127.0.0.1:7000

Env: SENTINEL_URL, SENTINEL_SIGNAL_KEY (defaults match local dev).
"""

import argparse
import json
import os
import random
import time
import urllib.request

# Real, routable public IPs across the world so the map spreads out. These are
# well-known infrastructure addresses used only as plausible map coordinates.
SOURCES = [
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",      # US
    "77.88.8.8", "95.108.213.1",                              # Russia
    "180.76.76.76", "223.5.5.5",                              # China
    "139.130.4.5", "1.0.0.1",                                 # Australia
    "196.25.1.1",                                             # South Africa
    "200.40.30.245",                                          # Uruguay
    "193.0.14.129",                                           # Netherlands
    "203.50.2.71",                                            # Australia (Telstra)
    "212.58.244.22",                                          # UK
]
USERNAMES = ["admin", "root", "administrator", "j.castillo", "test", "backup", "oracle", "ubnt"]
UAS = [
    "python-requests/2.31", "curl/8.4.0", "Hydra/9.5",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Go-http-client/1.1",
]


def send(url, key, ip, kind, username, ua):
    body = json.dumps({
        "kind": kind, "ip": ip, "account": username, "route": "/", "method": "POST", "ua": ua,
        "client": {"platform": random.choice(["Windows", "Linux", "Android"]),
                   "browser": random.choice(["Chrome", "Firefox", ""]),
                   "tz": random.choice(["UTC", "Europe/Moscow", "Asia/Shanghai"])},
    }).encode()
    req = urllib.request.Request(url.rstrip("/") + "/api/v1/signal", data=body,
                                 headers={"Content-Type": "application/json", "X-Sentinel-Signal": key})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read())
    except Exception as e:
        print("  ! request failed:", e)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.environ.get("SENTINEL_URL", "http://127.0.0.1:7000"))
    ap.add_argument("--key", default=os.environ.get("SENTINEL_SIGNAL_KEY", "sentinel-dev-signal-key"))
    ap.add_argument("--rounds", type=int, default=30, help="how many attempts to fire")
    ap.add_argument("--delay", type=float, default=0.15, help="seconds between attempts")
    args = ap.parse_args()

    print(f"Simulating {args.rounds} attempts against {args.url} ...")
    # Pick one IP to be the heavy attacker so it trips an auto-block (red pin).
    heavy = random.choice(SOURCES)
    blocked = False
    for i in range(args.rounds):
        ip = heavy if (i < 7 or random.random() < 0.3) else random.choice(SOURCES)
        kind = "success" if random.random() < 0.08 else "fail"
        res = send(args.url, args.key, ip, kind, random.choice(USERNAMES), random.choice(UAS))
        actions = (res or {}).get("actions") or []
        if actions:
            for a in actions:
                print(f"  → {a.get('action')} {a.get('ip', a.get('account', ''))}")
                if a.get("action") == "ip_blocked":
                    blocked = True
        time.sleep(args.delay)

    print("Done.", "An IP was auto-blocked — look for the red pin." if blocked
          else "Open the Attack map tab to see the pins.")


if __name__ == "__main__":
    main()
