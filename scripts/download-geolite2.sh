#!/usr/bin/env bash
# Качает MaxMind GeoLite2 (City + ASN + Country) по ключу.
# ЛИЦЕНЗИЯ: скачиванием ты принимаешь GeoLite EULA
# (https://www.maxmind.com/en/geolite/eula, включает аспекты CC BY-SA 4.0)
# + обязательно указание авторства MaxMind. Нужен бесплатный аккаунт:
# https://www.maxmind.com/en/geolite2/signup -> "Manage License Keys".
set -euo pipefail
if [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
  echo "error: задай MAXMIND_LICENSE_KEY (ключ из личного кабинета MaxMind)" >&2
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
  "${CURL[@]}" -o "$TAR" \
    "https://download.maxmind.com/app/geoip_download?edition_id=${EDITION}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
  mkdir -p "$TMP/${EDITION}"
  # Extract into a temp dir first; no --wildcards (portable, and a
  # truncated tar cannot clobber the mmdb that the service is using).
  tar -xzf "$TAR" -C "$TMP/${EDITION}" --strip-components=1
  test -s "$TMP/${EDITION}/${EDITION}.mmdb" || {
    echo "error: ${EDITION}.mmdb missing or empty in archive" >&2
    exit 1
  }
  mv -f "$TMP/${EDITION}/${EDITION}.mmdb" "$DIR/${EDITION}.mmdb"
  chmod 0644 "$DIR/${EDITION}.mmdb"
  rm -f "$TAR"
done

ls -la "$DIR"
echo OK
