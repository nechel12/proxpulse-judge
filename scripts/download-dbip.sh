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
