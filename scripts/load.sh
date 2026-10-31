#!/usr/bin/env bash
# Небольшая проверка нагрузки без зависимостей. Использование: scripts/load.sh [base-url] [requests] [concurrency]
set -euo pipefail

BASE="${1:-http://127.0.0.1:8000}"
REQUESTS="${2:-500}"
CONCURRENCY="${3:-32}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

seq 1 "$REQUESTS" \
  | xargs -P "$CONCURRENCY" -I{} curl -s -o /dev/null -w '%{http_code}\n' "$BASE/generate_204" \
  > "$TMP/codes"

TOTAL="$(wc -l < "$TMP/codes" | tr -d ' ')"
OK="$(grep -c '^204$' "$TMP/codes" || true)"
if [ "$TOTAL" -ne "$REQUESTS" ] || [ "$OK" -ne "$REQUESTS" ]; then
  echo "load: not all requests returned 204" >&2
  sort "$TMP/codes" | uniq -c >&2
  exit 1
fi

echo "load: OK $REQUESTS requests at concurrency $CONCURRENCY"
