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

mkdir -p "$GEO_DIR" 2>/dev/null || true

# Валидный .mmdb намного больше 1 КиБ; это также игнорирует оставшиеся
# пустые/частичные файлы, которые иначе навсегда подавляли бы запасной вариант.
has_mmdb() {
  find "$GEO_DIR" -maxdepth 1 -type f -name '*.mmdb' -size +1k -print -quit 2>/dev/null \
    | grep -q .
}

if has_mmdb; then
  echo "[entrypoint] geo DBs present in $GEO_DIR, skipping download"
elif [ ! -w "$GEO_DIR" ]; then
  echo "[entrypoint] WARNING: $GEO_DIR is not writable (read-only mount?) — skipping DB-IP fallback; geo fields will be empty" >&2
else
  echo "[entrypoint] no .mmdb in $GEO_DIR — downloading DB-IP Lite fallback..."
  # Не держать запуск контейнера вечно при «чёрной дыре» соединения.
  if GEO_DIR="$GEO_DIR" timeout 600 bash "$SCRIPT_DIR/download-dbip.sh"; then
    echo "[entrypoint] fallback DBs ready"
  else
    echo "[entrypoint] WARNING: fallback download failed, starting without geo (geo fields will be empty)" >&2
  fi
fi

exec "$BIN" "$@"
