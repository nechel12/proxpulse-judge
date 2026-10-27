#!/usr/bin/env bash
# Качает DB-IP Lite (City + ASN) без ключей.
# ЛИЦЕНЗИЯ: базы распространяются под CC BY 4.0 — при показе результатов
# нужно указание авторства со ссылкой https://db-ip.com
# (подробности: https://db-ip.com/db/lite.php).
# Выходят раз в месяц, САМИ НЕ ОБНОВЛЯЮТСЯ: запускай скрипт руками или
# по cron, после чего перезапусти контейнер (docker compose restart judge).
# Каталог назначения: $GEO_DIR, иначе ../geo относительно скрипта.
# Entrypoint контейнера сам зовёт этот скрипт, если в $GEO_DIR нет .mmdb.
set -euo pipefail

# сначала пробуем текущий месяц, в первые дни месяца файла может не быть —
# тогда берём прошлый (на VPS Linux с GNU date)
MONTHS="$(date +%Y-%m) $(date -d 'last month' +%Y-%m 2>/dev/null || true)"
if [ $# -ge 1 ]; then MONTHS="$1"; fi   # можно передать 2026-08 вручную

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
