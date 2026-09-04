#!/usr/bin/env bash
# Entrypoint judge-контейнера.
# Приоритет баз: что лежит в $GEO_DIR (смонтированный volume с MaxMind
# или DB-IP, либо вшитые в образ базы) — то и используется. Если .mmdb
# нет вообще (забыли скачать), сам качает бесплатный DB-IP Lite fallback.
# Сервис работает и без баз (гео-поля пустые), поэтому провал скачивания
# не роняет контейнер — только предупреждение в лог.
set -u
GEO_DIR="${GEO_DIR:-/app/geo}"
SCRIPT_DIR="$(dirname "$0")"
BIN="${JUDGE_BIN:-/app/proxpulse-judge}"
mkdir -p "$GEO_DIR"
if ls "$GEO_DIR"/*.mmdb >/dev/null 2>&1; then
  echo "[entrypoint] geo DBs present in $GEO_DIR, skipping download"
else
  echo "[entrypoint] no .mmdb in $GEO_DIR — downloading DB-IP Lite fallback..."
  if GEO_DIR="$GEO_DIR" bash "$SCRIPT_DIR/download-dbip.sh"; then
    echo "[entrypoint] fallback DBs ready"
  else
    echo "[entrypoint] WARNING: fallback download failed, starting without geo (geo fields will be empty)" >&2
  fi
fi
exec "$BIN" "$@"
