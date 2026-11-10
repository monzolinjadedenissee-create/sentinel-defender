"""
Approximate IP geolocation + network (ASN) lookup, ported from the rbx-rewards
defender. Reads local MaxMind GeoLite2 or DB-IP Lite `.mmdb` files — no network
calls, no third-party API. An IP identifies a *network / broad region*, never a
person or an exact address.

Drop a city database next to this file (or set GEOIP_DB):
  * GeoLite2-City.mmdb      (MaxMind, account needed) — preferred, or
  * dbip-city-lite.mmdb     (DB-IP, free, no account)
and optionally an ASN database (GeoLite2-ASN.mmdb / dbip-asn-lite.mmdb, env ASN_DB).
Run tools/fetch_geo.sh to download them. Without a database, geolocation is simply
disabled and the rest of Sentinel keeps working.
"""

import ipaddress
import os
from functools import lru_cache

try:
    import maxminddb
except ImportError:
    maxminddb = None


def _open(names, env):
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    candidates = [os.environ.get(env, "")] + [
        os.path.join(folder, name)
        for name in names
        for folder in (here, root, os.path.join(root, "geo"), "/opt/geo")
    ]
    for path in candidates:
        if maxminddb and path and os.path.exists(path):
            try:
                reader = maxminddb.open_database(path)
                kind = reader.metadata().database_type
                return reader, ("DB-IP Lite" if "DBIP" in kind.upper() else "MaxMind GeoLite2")
            except Exception:
                pass
    return None, None


geo_reader, GEO_SOURCE = _open(("GeoLite2-City.mmdb", "dbip-city-lite.mmdb"), "GEOIP_DB")
asn_reader, ASN_SOURCE = _open(("GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb"), "ASN_DB")

# Fallback for hosts without the (large) local database, e.g. Vercel: a free HTTPS
# lookup (ipwho.is, no key). Turn off with SN_GEO_API=0.
USE_API = geo_reader is None and os.environ.get("SN_GEO_API", "1") != "0"
if USE_API:
    GEO_SOURCE = "ipwho.is (online)"

enabled = geo_reader is not None or USE_API


@lru_cache(maxsize=4096)
def _api(addr):
    import json
    import urllib.request
    try:
        req = urllib.request.Request(f"https://ipwho.is/{addr}", headers={"User-Agent": "Sentinel"})
        with urllib.request.urlopen(req, timeout=3) as r:
            d = json.loads(r.read())
        return d if d.get("success") else {}
    except Exception:
        return {}

# Organisation names that signal a datacentre / cloud / VPN rather than a home ISP.
HOSTING_HINTS = (
    "amazon", "aws", "google cloud", "google llc", "microsoft", "azure", "digitalocean", "ovh",
    "hetzner", "linode", "akamai", "vultr", "choopa", "m247", "leaseweb", "contabo", "oracle",
    "alibaba", "tencent", "cloudflare", "fastly", "scaleway", "hostinger", "godaddy", "ionos",
    "colocrossing", "quadranet", "nordvpn", "expressvpn", "surfshark", "mullvad", "proton",
    "hosting", "datacenter", "data center", "server", "cloud", "vps", "vpn",
)


def _valid(ip):
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except (ValueError, TypeError):
        return None


def locate(ip):
    """Return (country, city, lat, lon). Country doubles as a status string when unknown."""
    addr = _valid(ip)
    if not addr:
        return "Unknown", "—", None, None
    if not ipaddress.ip_address(addr).is_global:
        return "Private/reserved", "—", None, None
    if not geo_reader:
        if USE_API:
            d = _api(addr)
            if d:
                return d.get("country") or "Unknown", d.get("city") or "—", d.get("latitude"), d.get("longitude")
        return "Not resolved", "—", None, None
    try:
        r = geo_reader.get(addr) or {}
    except Exception:
        r = {}
    if not r:
        return "Not in database", "—", None, None
    name = lambda key: (r.get(key) or {}).get("names", {}).get("en")
    where = r.get("location") or {}
    return name("country") or "Unknown", name("city") or "—", where.get("latitude"), where.get("longitude")


def network_type(ip, org):
    if org and any(h in org.lower() for h in HOSTING_HINTS):
        return "hosting"
    return "isp" if org else None


@lru_cache(maxsize=4096)
def details(ip):
    """Everything the local databases know about an IP: region, continent, timezone, ASN, org, network type."""
    d = {"scope": "public", "version": None, "country": None, "country_code": None, "region": None,
         "city": None, "continent": None, "postal": None, "timezone": None, "accuracy_km": None,
         "lat": None, "lon": None, "asn": None, "org": None, "network": None}
    addr = _valid(ip)
    if not addr:
        d["scope"] = "invalid"
        return d
    ipo = ipaddress.ip_address(addr)
    d["version"] = ipo.version
    if not ipo.is_global:
        d["scope"] = "private"
        return d
    if geo_reader:
        try:
            r = geo_reader.get(addr) or {}
        except Exception:
            r = {}
        name = lambda part: (part or {}).get("names", {}).get("en")
        where, regions = r.get("location") or {}, r.get("subdivisions") or []
        d.update(country=name(r.get("country")), country_code=(r.get("country") or {}).get("iso_code"),
                 region=name(regions[0]) if regions else None, city=name(r.get("city")),
                 continent=name(r.get("continent")), postal=(r.get("postal") or {}).get("code"),
                 timezone=where.get("time_zone"), accuracy_km=where.get("accuracy_radius"),
                 lat=where.get("latitude"), lon=where.get("longitude"))
    elif USE_API:
        a = _api(addr)
        if a:
            conn = a.get("connection") or {}
            d.update(country=a.get("country"), country_code=a.get("country_code"), region=a.get("region"),
                     city=a.get("city"), continent=a.get("continent"), postal=a.get("postal"),
                     timezone=(a.get("timezone") or {}).get("id"), lat=a.get("latitude"),
                     lon=a.get("longitude"), asn=conn.get("asn"), org=conn.get("org") or conn.get("isp"))
    if asn_reader:
        try:
            r = asn_reader.get(addr) or {}
        except Exception:
            r = {}
        d.update(asn=r.get("autonomous_system_number"), org=r.get("autonomous_system_organization"))
    d["network"] = network_type(addr, d["org"])
    return d
