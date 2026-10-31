#!/usr/bin/env bash
# Качает MaxMind GeoLite2 (City + ASN + Country) по ключу.
# ЛИЦЕНЗИЯ: скачиванием ты принимаешь GeoLite EULA
# (https://www.maxmind.com/en/geolite/eula, включает аспекты CC BY-SA 4.0)
# + обязательно указание авторства MaxMind. Нужен бесплатный аккаунт:
# https://www.maxmind.com/en/geolite2/signup → раздел «Manage License Keys».
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
  # Передать URL через stdin-конфиг, чтобы MAXMIND_LICENSE_KEY не появлялся в ps/cmdline.
  "${CURL[@]}" -o "$TAR" --config - <<EOF
url = "https://download.maxmind.com/app/geoip_download?edition_id=${EDITION}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
EOF
  mkdir -p "$TMP/${EDITION}"
  # Сначала распаковать во временный каталог; без --wildcards (переносимо, и
  # усечённый tar не может затереть mmdb, используемую сервисом).
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
