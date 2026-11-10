#!/usr/bin/env bash
# Entrypoint of the judge container.
# Database priority: whatever is in $GEO_DIR (a mounted volume with MaxMind
# or DB-IP, or databases baked into the image) wins. If there is no .mmdb
# at all (none was downloaded), the script fetches the free DB-IP Lite fallback.
# The service works without databases too (empty geo fields), so a failed download
# does not kill the container — only a warning in the log.
set -u
GEO_DIR="${GEO_DIR:-/app/geo}"
SCRIPT_DIR="$(dirname "$0")"
BIN="${JUDGE_BIN:-/app/proxpulse-judge}"

mkdir -p "$GEO_DIR" 2>/dev/null || true

# A database the service would load: a .mmdb named for a city, country or
# ASN database (dated and custom names included, as in src/geo.rs), of a real
# size. Any leftover or broken *.mmdb would otherwise suppress the fallback
# forever, and a fallback downloaded next to a custom-named database would
# take precedence over it.
has_mmdb() {
  [ -n "$(find "$GEO_DIR" -maxdepth 1 -type f -size +1M \
    \( -iname '*city*.mmdb' -o -iname '*country*.mmdb' -o -iname '*asn*.mmdb' \) \
    -print -quit 2>/dev/null)" ]
}

# A download interrupted by a previous stop leaves its temporary folder.
rm -rf "${GEO_DIR:?}"/.dbip.* 2>/dev/null || true

if has_mmdb; then
  echo "[entrypoint] geo DBs present in $GEO_DIR, skipping download"
elif [ ! -w "$GEO_DIR" ]; then
  echo "[entrypoint] WARNING: $GEO_DIR is not writable (read-only mount?) — skipping DB-IP fallback; geo fields will be empty" >&2
else
  echo "[entrypoint] no .mmdb in $GEO_DIR — downloading DB-IP Lite fallback..."
  # Do not hold container startup forever on a black-holed connection. The
  # download runs in the background so that `docker stop` (SIGTERM to this
  # PID 1, which ignores signals it has no trap for) ends it at once.
  GEO_DIR="$GEO_DIR" timeout 600 bash "$SCRIPT_DIR/download-dbip.sh" &
  download=$!
  trap 'kill "$download" 2>/dev/null; exit 143' TERM INT
  if wait "$download"; then
    trap - TERM INT
    echo "[entrypoint] fallback DBs ready"
  else
    trap - TERM INT
    echo "[entrypoint] WARNING: fallback download failed, starting without geo (geo fields will be empty)" >&2
  fi
fi

exec "$BIN" "$@"
