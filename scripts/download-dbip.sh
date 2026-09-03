#!/usr/bin/env bash
# DB-IP Lite: скачивание без ключей (City + ASN, помесячные файлы).
set -euo pipefail
# сначала пробуем текущий месяц, в первые дни месяца файла может не быть —
# тогда берём прошлый (на VPS Linux с GNU date)
MONTHS="$(date +%Y-%m) $(date -d 'last month' +%Y-%m 2>/dev/null || true)"
if [ $# -ge 1 ]; then MONTHS="$1"; fi   # можно передать 2026-08 вручную
DIR="$(dirname "$0")/../geo"
mkdir -p "$DIR"
for M in $MONTHS; do
  echo "== trying DB-IP Lite $M"
  if curl -fL -o "$DIR/dbip-city-lite.mmdb.gz" \
      "https://download.db-ip.com/free/dbip-city-lite-${M}.mmdb.gz" \
    && curl -fL -o "$DIR/dbip-asn-lite.mmdb.gz" \
      "https://download.db-ip.com/free/dbip-asn-lite-${M}.mmdb.gz"; then
    echo "== got $M"
    break
  fi
  echo "== $M not found, trying previous"
done
gunzip -f "$DIR/dbip-city-lite.mmdb.gz" "$DIR/dbip-asn-lite.mmdb.gz"
ls -la "$DIR"
echo OK
