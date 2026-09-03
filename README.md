# ProxPulse Judge — self-hosted proxy-check backend.
#
# Один `GET /judge` заменяет пачку внешних сервисов (ip-api, httpbin, ...):
# видит IP выхода прокси, резолвит гео в ЛОКАЛЬНЫХ .mmdb, отдаёт эхо
# заголовков для детекта анонимности и фиксированный контент для
# проверки целостности.
#
# Быстрый старт:
#   bash scripts/download-dbip.sh   # базы без ключей (City + ASN)
#   cp .env.example .env
#   docker compose up -d --build
#   curl http://127.0.0.1:8000/judge | head -c 500
#
# За реверс-прокси (пример в Caddyfile.example):
#   check.lmtunnel.com {
#       reverse_proxy 127.0.0.1:8000
#   }

## Эндпоинты

| Метод | Путь | Ответ |
|---|---|---|
| GET | `/generate_204` | `204` пусто — быстрая проверка живости |
| GET | `/ip` | `{"ip": "203.0.113.7"}` — IP выхода |
| GET | `/headers` | `{"ip", "headers", "xff_chain"}` — эхо заголовков |
| GET | `/geo` | `{"ip", "geo", "source"}` — страна/город/ASN из локальных баз |
| GET | `/type?rdns=1` | `{"ip", "ip_type", "signals"}` — datacenter/mobile/residential/business/unknown |
| GET | `/content` | фиксированные байты — сверка целостности |
| GET | `/judge?direct_ip=...&rdns=1` | всё сразу: ip, headers, anonymity, geo, ip_type, content_sha256 |
| GET | `/healthz` | `{"ok": true}` |

## Как пользоваться из чекера

1. Прямой запрос `GET /ip` → свой IP (`direct_ip`).
2. Тот же `/judge?direct_ip=<свой>` через прокси → `anonymity`:
   `elite` (ничего не палит), `anonymous` (видно что прокси, IP скрыт),
   `transparent` (утёк реальный IP).
3. Целостность: `GET /content` напрямую и через прокси, сравнить байты.
4. Гео/тип — уже в `/judge`, без внешних API и лимитов.

## Базы

Каталог `./geo` монтируется в контейнер read-only. Имена:
`GeoLite2-City.mmdb` / `dbip-city-lite.mmdb`,
`GeoLite2-ASN.mmdb` / `dbip-asn-lite.mmdb`
(плюс `GeoLite2-Country.mmdb` как фолбэк).
Без файлов geo/type вернут `null`, остальное работает.
Базы грузятся в ОЗУ (`MODE_MEMORY`), лукапы кэшируются (LRU 65536).

## Важно про TRUST_PROXY

За Caddy ставь `TRUST_PROXY=1` (по умолчанию): IP берётся из последней
записи `X-Forwarded-For` (её дописал сам Caddy), а Caddy-заголовки
(`X-Forwarded-Proto/Host`) исключены из детекта анонимности.
Напрямую наружу — `TRUST_PROXY=0`.

## Стек и оптимизации

- `uvicorn --loop uvloop --http httptools` (~x2 к stock asyncio/h11).
- `orjson` вместо stdlib json.
- Один воркер достаточен: логика I/O-bound, базы общие через mmap/LRU.
  Два воркера — если захочешь упереться в CPU на тысячах rps.
- Если перерастёшь Python — тот же API легко переписать на Go (stdlib)
  или Rust (axum + maxminddb): контракт уже зафиксирован тестами.
