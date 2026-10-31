#!/usr/bin/env bash
# Запустить образ, дождаться /healthz, затем выполнить smoke.sh и load.sh против него.
# Использование: scripts/container-smoke.sh <image> [дополнительные аргументы docker run...]
# SMOKE_EXPECT_GEO=1 передаётся в smoke.sh (требуется TRUST_PROXY=1).
set -euo pipefail

IMAGE="${1:?usage: $0 <image> [docker run args...]}"
shift
NAME="judge-smoke-$$"
PORT="${SMOKE_PORT:-8000}"
BASE="http://127.0.0.1:$PORT"
DIR="$(dirname "$0")"

docker run -d --rm --name "$NAME" -p "127.0.0.1:$PORT:8000" "$@" "$IMAGE" >/dev/null
trap 'docker logs "$NAME" || true; docker stop "$NAME" >/dev/null || true' EXIT

for _ in $(seq 1 30); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then break; fi
  sleep 1
done

bash "$DIR/smoke.sh" "$BASE"
bash "$DIR/load.sh" "$BASE" 300 32
