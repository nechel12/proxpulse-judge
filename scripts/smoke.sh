#!/usr/bin/env bash
# Smoke-test a running judge instance. Usage: scripts/smoke.sh [base-url]
set -euo pipefail

BASE="${1:-http://127.0.0.1:8000}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

get() {
  curl -fsS -o "$TMP/body" "$BASE$1" || fail "$1: request failed"
}

get /healthz
grep -q '"ok":true' "$TMP/body" || fail "/healthz: missing ok"

get /readyz
grep -q '"geo_ready"' "$TMP/body" || fail "/readyz: missing geo_ready"

get /ip
grep -q '"ip"' "$TMP/body" || fail "/ip: missing ip"

get /geo
grep -q '"attribution"' "$TMP/body" || fail "/geo: missing attribution"

get /judge
grep -q '"anonymity"' "$TMP/body" || fail "/judge: missing anonymity"
grep -q '"content_sha256"' "$TMP/body" || fail "/judge: missing content_sha256"

get /metrics
grep -q 'proxpulse_requests_total' "$TMP/body" || fail "/metrics: missing counter"
grep -q 'proxpulse_build_info' "$TMP/body" || fail "/metrics: missing build info"

code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/generate_204")"
[ "$code" = "204" ] || fail "/generate_204: got $code"

code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/content")"
[ "$code" = "200" ] || fail "/content: got $code"

curl -fsS -D "$TMP/headers" -o /dev/null "$BASE/ip"
grep -qi '^cache-control: no-store' "$TMP/headers" || fail "/ip: no-store missing"

curl -fsS -D "$TMP/headers" -o /dev/null "$BASE/content"
if grep -qi '^cache-control:' "$TMP/headers"; then
  fail "/content: unexpected cache-control"
fi

echo "smoke: OK ($BASE)"
