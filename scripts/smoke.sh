#!/usr/bin/env bash
# Проверить запущенный экземпляр judge. Использование: scripts/smoke.sh [base-url]
# SMOKE_EXPECT_GEO=1 дополнительно требует загруженные базы геоданных и реальный
# поиск. Проверяемый IP передаётся в X-Forwarded-For, поэтому локальному контейнеру
# нужен TRUST_PROXY=1; за обратным прокси используется собственный публичный IP вызывающего.
# SMOKE_METRICS_TOKEN отправляется в /metrics, если на экземпляре задан METRICS_TOKEN.
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

AUTH=()
if [ -n "${SMOKE_METRICS_TOKEN:-}" ]; then
  AUTH=(-H "Authorization: Bearer $SMOKE_METRICS_TOKEN")
fi
# `${AUTH[@]+...}`: пустой массив считается «unbound» при `set -u` в bash < 4.4 (macOS)
curl -fsS ${AUTH[@]+"${AUTH[@]}"} -o "$TMP/body" "$BASE/metrics" || fail "/metrics: request failed"
grep -q 'proxpulse_requests_total' "$TMP/body" || fail "/metrics: missing counter"
grep -q 'proxpulse_build_info' "$TMP/body" || fail "/metrics: missing build info"

code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/generate_204")"
[ "$code" = "204" ] || fail "/generate_204: got $code"

code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/content")"
[ "$code" = "200" ] || fail "/content: got $code"

curl -fsS -D "$TMP/headers" -o /dev/null "$BASE/ip"
grep -qi '^cache-control: no-store' "$TMP/headers" || fail "/ip: no-store missing"
grep -qi '^x-content-type-options: nosniff' "$TMP/headers" || fail "/ip: nosniff missing"

curl -fsS -D "$TMP/headers" -o /dev/null "$BASE/content"
if grep -qi '^cache-control:' "$TMP/headers"; then
  fail "/content: unexpected cache-control"
fi

if [ "${SMOKE_EXPECT_GEO:-0}" = "1" ]; then
  get /readyz
  grep -q '"geo_ready":true' "$TMP/body" || fail "/readyz: geo databases not loaded"
  curl -fsS -H 'X-Forwarded-For: 1.1.1.1' -o "$TMP/body" "$BASE/geo" \
    || fail "/geo: request failed"
  grep -q '"country_code":"' "$TMP/body" || fail "/geo: no country_code from the databases"
  grep -q '"asn":[0-9]' "$TMP/body" || fail "/geo: no asn from the databases"
fi

echo "smoke: OK ($BASE)"
