# geo/ — каталог .mmdb баз (в контейнер монтируется read-only, в git не идёт).
#
# Быстрее всего без ключей:  bash scripts/download-dbip.sh
# Либо положи сюда GeoLite2-City.mmdb / GeoLite2-ASN.mmdb (нужен аккаунт MaxMind).
# После обновления баз перезапусти контейнер (гео-кэш живёт в памяти).
