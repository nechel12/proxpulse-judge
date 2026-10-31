#!/usr/bin/env bash
# Start an image, wait for /healthz, then run smoke.sh and load.sh against it.
# Usage: scripts/container-smoke.sh <image> [extra docker run args...]
# SMOKE_EXPECT_GEO=1 is passed through to smoke.sh (needs TRUST_PROXY=1).
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
