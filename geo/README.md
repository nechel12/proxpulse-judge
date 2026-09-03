# Сюда кладутся .mmdb базы (в контейнер монтируются как volume, в git не идут).
#
# Вариант А — без ключей (рекомендую для старта):
#   bash scripts/download-dbip.sh        # dbip-city-lite.mmdb + dbip-asn-lite.mmdb
#
# Вариант Б — MaxMind GeoLite2 (нужен бесплатный аккаунт + ключ):
#   GeoLite2-City.mmdb, GeoLite2-ASN.mmdb (и/или GeoLite2-Country.mmdb)
#
# Сервис сам находит файлы по именам, грузит в ОЗУ (MODE_MEMORY).
# Без баз geo/type вернут null, остальное (ip/headers/judge-анонимность/content) работает.
