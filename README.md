# ProxPulse Judge

Self-hosted backend для проверки прокси. Один запрос `GET /judge` заменяет
пачку внешних сервисов (ip-api, httpbin): видит IP выхода прокси, резолвит
гео в **локальных** `.mmdb`, отдаёт эхо заголовков для детекта анонимности
и фиксированный контент для проверки целостности.

Стек: **Rust + axum + tokio**, базы в ОЗУ, LRU-кэш лукапов. Никаких внешних
API, никаких лимитов, один статический бинарь в `debian:slim`.

## Быстрый старт

```sh
bash scripts/download-dbip.sh   # базы без ключей (City + ASN)
cp .env.example .env
docker compose up -d --build
curl http://127.0.0.1:8000/judge
```

За реверс-прокси (пример в `Caddyfile.example`):

```caddy
check.lmtunnel.com {
    reverse_proxy 127.0.0.1:8000
}
```

## Эндпоинты

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/generate_204` | `204` пусто — быстрая проверка живости |
| GET | `/ip` | `{"ip": "..."}` — IP выхода |
| GET | `/headers` | `{"ip", "headers", "xff_chain"}` — эхо заголовков |
| GET | `/geo` | `{"ip", "geo", "source"}` — страна/город/ASN из локальных баз |
| GET | `/type?rdns=1` | `{"ip", "ip_type", "signals"}` — тип IP с объяснением |
| GET | `/content` | фиксированные байты — эталон целостности |
| GET | `/judge?direct_ip=...&rdns=1` | всё сразу + `anonymity`, `content_sha256` |
| GET | `/healthz` | `{"ok": true}` — для Docker/Caddy |

Пример ответа `/judge`:

```json
{
  "ip": "203.0.113.7",
  "anonymity": "elite",
  "geo": {"country": "Germany", "country_code": "DE", "city": "Frankfurt", "asn": 9009},
  "ip_type": "datacenter",
  "content_sha256": "1a05…"
}
```

## Как пользоваться из чекера

1. Прямой запрос `GET /ip` — свой IP (`direct_ip`).
2. `GET /judge?direct_ip=<свой>` через прокси — поле `anonymity`:
   `elite` (ничего не палит), `anonymous` (видно что прокси, IP скрыт),
   `transparent` (утёк реальный IP).
3. Целостность: `GET /content` напрямую и через прокси, сравнить байты
   (или `content_sha256` из `/judge`).
4. Гео и тип уже лежат в `/judge`.

## Базы

Каталог `./geo` монтируется в контейнер read-only. Сервис сам находит файлы:

- `GeoLite2-City.mmdb` или `dbip-city-lite.mmdb`
- `GeoLite2-ASN.mmdb` или `dbip-asn-lite.mmdb`
- `GeoLite2-Country.mmdb` — фолбэк, если нет City

Без файлов `geo`/`type` вернут `null`, остальное работает.
После обновления баз **перезапусти контейнер** — гео-кэш живёт в памяти.

## Конфигурация

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `PORT` | `8000` | порт HTTP |
| `GEO_DIR` | `/app/geo` | каталог `.mmdb` |
| `TRUST_PROXY` | `1` | `1` — за Caddy (IP из конца `X-Forwarded-For`), `0` — напрямую (IP из сокета) |
| `RDNS_TIMEOUT` | `1.5` | таймаут reverse-DNS для `?rdns=1`, сек |
| `RUST_LOG` | `info` | уровень логов |

## Почему так, а не иначе

- **Почему не Python/FastAPI.** Первая версия была на FastAPI — работала,
  но Rust даёт один бинарь без рантайма, образ `~30 МБ` вместо `~200 МБ`,
  и нет GIL: тысячи параллельных проверок на одном потоковом пуле tokio.
- **Почему IP из конца XFF.** Caddy дописывает адрес клиента в конец
  цепочки — только последняя запись достоверна. Собственные заголовки
  Caddy (`X-Forwarded-Proto/Host`) исключены из детекта анонимности,
  иначе за реверс-прокси все были бы «anonymous».
- **Почему тип IP — эвристика.** Локальные данные не доказывают
  residential-vs-business как платные ASN-базы. Поэтому ответ содержит
  `signals` (какие ключевые слова и где сработали) — видно *почему*.
- **Почему нет TLS/JA3.** TLS терминирует Caddy, judge видит только HTTP.
  Сверка сертификата остаётся на стороне чекера (прямое vs через прокси).

## Разработка

```sh
cargo test        # 21 тест: логика, geo-парсинг, API
cargo run         # PORT=8000 GEO_DIR=./geo TRUST_PROXY=0
```

Структура: `src/main.rs` (HTTP), `src/geo.rs` (пул `.mmdb` + LRU),
`src/logic.rs` (анонимность, тип IP, фикс-контент).
