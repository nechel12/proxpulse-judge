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
DIR="$(dirname "$0")/../geo"
mkdir -p "$DIR"
for EDITION in GeoLite2-City GeoLite2-ASN GeoLite2-Country; do
  echo "== $EDITION"
  curl -fL -o "$DIR/${EDITION}.tar.gz" \
    "https://download.maxmind.com/app/geoip_download?edition_id=${EDITION}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
  tar -xzf "$DIR/${EDITION}.tar.gz" -C "$DIR" --strip-components=1 --wildcards "*/${EDITION}.mmdb"
  rm -f "$DIR/${EDITION}.tar.gz"
done
ls -la "$DIR"
echo OK
