#!/usr/bin/env bash
# DB-IP Lite: скачивание без ключей (City + ASN, помесячные файлы).
set -euo pipefail
M="${1:-$(date +%Y-%m)}"          # можно передать 2026-08 вручную
DIR="$(dirname "$0")/../geo"
mkdir -p "$DIR"
echo "== DB-IP Lite $M -> $DIR"
curl -fL -o "$DIR/dbip-city-lite.mmdb.gz" \
  "https://download.db-ip.com/free/dbip-city-lite-${M}.mmdb.gz"
curl -fL -o "$DIR/dbip-asn-lite.mmdb.gz" \
  "https://download.db-ip.com/free/dbip-asn-lite-${M}.mmdb.gz"
gunzip -f "$DIR/dbip-city-lite.mmdb.gz" "$DIR/dbip-asn-lite.mmdb.gz"
ls -la "$DIR"
echo OK
