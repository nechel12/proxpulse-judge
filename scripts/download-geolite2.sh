#!/usr/bin/env bash
# Downloads MaxMind GeoLite2 (City + ASN + Country) with a key.
# LICENSE: downloading accepts the GeoLite EULA
# (https://www.maxmind.com/en/geolite/eula, includes aspects of CC BY-SA 4.0)
# + mandatory MaxMind attribution. A free account is required:
# https://www.maxmind.com/en/geolite2/signup → the "Manage License Keys" section.
set -euo pipefail
if [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
  echo "error: set MAXMIND_LICENSE_KEY (a key from your MaxMind account)" >&2
  echo "  export MAXMIND_LICENSE_KEY=xxxx && bash $0" >&2
  exit 1
fi

DIR="${GEO_DIR:-$(dirname "$0")/../geo}"
mkdir -p "$DIR"

TMP="$(mktemp -d "$DIR/.geolite2.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

CURL=(
  curl --fail --location --silent --show-error
  --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 300
)

for EDITION in GeoLite2-City GeoLite2-ASN GeoLite2-Country; do
  echo "== $EDITION"
  TAR="$TMP/${EDITION}.tar.gz"
  # Pass the URL via stdin config so MAXMIND_LICENSE_KEY does not appear in ps/cmdline.
  "${CURL[@]}" -o "$TAR" --config - <<EOF
url = "https://download.maxmind.com/app/geoip_download?edition_id=${EDITION}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
EOF
  mkdir -p "$TMP/${EDITION}"
  # Extract into a temp dir first; no --wildcards (portable, and a
  # truncated tar cannot clobber the mmdb the service is using).
  tar -xzf "$TAR" -C "$TMP/${EDITION}" --strip-components=1 --no-same-owner
  test -s "$TMP/${EDITION}/${EDITION}.mmdb" || {
    echo "error: ${EDITION}.mmdb missing or empty in archive" >&2
    exit 1
  }

  BIN="${JUDGE_BIN:-/app/proxpulse-judge}"
  if [ -x "$BIN" ]; then
    echo "== validating ${EDITION}"
    if ! GEO_DIR="$TMP/${EDITION}" "$BIN" --check-geo; then
      echo "error: ${EDITION}.mmdb failed validation" >&2
      exit 1
    fi
  fi

  mv -f "$TMP/${EDITION}/${EDITION}.mmdb" "$DIR/${EDITION}.mmdb"
  chmod 0644 "$DIR/${EDITION}.mmdb"
  rm -f "$TAR"
done

ls -la "$DIR"
echo OK
