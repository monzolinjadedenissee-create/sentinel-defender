#!/bin/sh
# Downloads the IP databases into $1 for the attack map and IP details. Never fails the build.
#   City (location) and ASN (internet provider) databases:
#   MaxMind GeoLite2 when MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY are set,
#   otherwise DB-IP Lite (free, CC BY 4.0, no account needed).

dir="$1"
mkdir -p "$dir" && cd "$dir" || exit 0

year=$(date +%Y)
month=$(date +%m | sed 's/^0//')
if [ "$month" -eq 1 ]; then
    previous="$((year - 1))-12"
else
    previous="$year-$(printf %02d $((month - 1)))"
fi

# fetch_maxmind City|ASN
fetch_maxmind() {
    [ -n "$MAXMIND_ACCOUNT_ID" ] && [ -n "$MAXMIND_LICENSE_KEY" ] || return 1
    if curl -fsSL -u "$MAXMIND_ACCOUNT_ID:$MAXMIND_LICENSE_KEY" -o "geolite-$1.tar.gz" \
        "https://download.maxmind.com/geoip/databases/GeoLite2-$1/download?suffix=tar.gz" \
        && tar -xzf "geolite-$1.tar.gz" \
        && mv GeoLite2-"$1"_*/GeoLite2-"$1".mmdb "./GeoLite2-$1.mmdb"; then
        rm -rf "geolite-$1.tar.gz" GeoLite2-"$1"_*
        echo "IP database: MaxMind GeoLite2-$1"
        return 0
    fi
    rm -rf "geolite-$1.tar.gz" GeoLite2-"$1"_*
    echo "WARNING: GeoLite2-$1 download failed (check the account ID and license key); using DB-IP Lite" >&2
    return 1
}

# fetch_dbip city|asn  (the new month's file appears on the 1st; fall back to last month's)
fetch_dbip() {
    for edition in "$(date +%Y-%m)" "$previous"; do
        if curl -fsSL -o "dbip-$1.mmdb.gz" "https://download.db-ip.com/free/dbip-$1-lite-$edition.mmdb.gz" \
            && gunzip -f "dbip-$1.mmdb.gz" && mv "dbip-$1.mmdb" "dbip-$1-lite.mmdb"; then
            echo "IP database: DB-IP $1 Lite $edition"
            return 0
        fi
        rm -f "dbip-$1.mmdb.gz" "dbip-$1.mmdb"
    done
    echo "WARNING: could not download the DB-IP $1 database" >&2
    return 1
}

fetch_maxmind City || fetch_dbip city
fetch_maxmind ASN || fetch_dbip asn
exit 0
