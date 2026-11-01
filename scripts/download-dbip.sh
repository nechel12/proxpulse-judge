#!/usr/bin/env bash
# Downloads DB-IP Lite (City + ASN) without keys.
# LICENSE: the databases are distributed under CC BY 4.0 — when showing results,
# attribution with a link to https://db-ip.com is required
# (details: https://db-ip.com/db/lite.php).
# They are released monthly and DO NOT UPDATE THEMSELVES: run the script manually or
# via cron, then restart the container (docker compose restart judge).
# Target directory: $GEO_DIR, otherwise ../geo relative to the script.
# The container entrypoint calls this script itself when $GEO_DIR has no .mmdb.
set -euo pipefail

# try the current month first; in the first days of a month the file may be missing —
# then take the previous one (anchoring to the 15th avoids GNU date overflowing
# on the 31st into 28–30-day months; -v-1m is the BSD/macOS date fallback)
PREV_MONTH="$(date -d "$(date +%Y-%m-15) -1 month" +%Y-%m 2>/dev/null || date -v-1m +%Y-%m 2>/dev/null || true)"
MONTHS="$(date +%Y-%m) $PREV_MONTH"
if [ $# -ge 1 ]; then MONTHS="$1"; fi   # a month such as 2026-08 can be passed manually

DIR="${GEO_DIR:-$(dirname "$0")/../geo}"
mkdir -p "$DIR"

TMP="$(mktemp -d "$DIR/.dbip.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# --retry covers transient CDN/network failures; --max-time prevents a
# hung connection from blocking container startup forever.
CURL=(
  curl --fail --location --silent --show-error
  --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 300
)

GOT=""
for M in $MONTHS; do
  echo "== trying DB-IP Lite $M"
  if "${CURL[@]}" -o "$TMP/city.gz" \
      "https://download.db-ip.com/free/dbip-city-lite-${M}.mmdb.gz" \
    && "${CURL[@]}" -o "$TMP/asn.gz" \
      "https://download.db-ip.com/free/dbip-asn-lite-${M}.mmdb.gz"; then
    GOT="$M"
    break
  fi
  echo "== $M not found, trying previous"
done

if [ -z "$GOT" ]; then
  echo "error: could not download DB-IP Lite for any month" >&2
  exit 1
fi

# Validate gzip before touching existing files, then move finished files
# into place atomically. A failed download never leaves a partial .mmdb.
gunzip -t "$TMP/city.gz" "$TMP/asn.gz"
gunzip -c "$TMP/city.gz" > "$TMP/dbip-city-lite.mmdb"
gunzip -c "$TMP/asn.gz" > "$TMP/dbip-asn-lite.mmdb"
[ -s "$TMP/dbip-city-lite.mmdb" ] && [ -s "$TMP/dbip-asn-lite.mmdb" ] || {
  echo "error: downloaded DB is empty" >&2
  exit 1
}

# Full structural validation before replacing the files used by the
# service. Skipped when the judge binary is not available (host-only run).
BIN="${JUDGE_BIN:-/app/proxpulse-judge}"
if [ -x "$BIN" ]; then
  echo "== validating downloaded databases"
  if ! GEO_DIR="$TMP" "$BIN" --check-geo; then
    echo "error: downloaded DB failed validation" >&2
    exit 1
  fi
fi

mv -f "$TMP/dbip-city-lite.mmdb" "$DIR/dbip-city-lite.mmdb"
mv -f "$TMP/dbip-asn-lite.mmdb" "$DIR/dbip-asn-lite.mmdb"
chmod 0644 "$DIR/dbip-city-lite.mmdb" "$DIR/dbip-asn-lite.mmdb"

echo "== got $GOT"
ls -la "$DIR"
echo OK
