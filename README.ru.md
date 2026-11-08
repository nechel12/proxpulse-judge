# ProxPulse Judge

[English](README.md) | **Русский**

[![CI](https://github.com/nechel12/proxpulse-judge/actions/workflows/docker.yml/badge.svg?branch=main)](https://github.com/nechel12/proxpulse-judge/actions/workflows/docker.yml)
[![Release](https://img.shields.io/github/v/release/nechel12/proxpulse-judge)](https://github.com/nechel12/proxpulse-judge/releases)
[![License](https://img.shields.io/github/license/nechel12/proxpulse-judge)](LICENSE)
[![GHCR](https://img.shields.io/badge/ghcr.io-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)](https://github.com/nechel12/proxpulse-judge/pkgs/container/proxpulse-judge)

Свой judge для проверки прокси — для [ProxPulse](https://github.com/nechel12/proxpulse)
и других чекеров. Один запрос `GET /judge` через прокси возвращает IP выхода,
анонимность (`elite`, `anonymous`, `transparent`), гео и ASN из **локальных**
`.mmdb`, тип IP и хэш фиксированного контента для проверки целостности, с
подписью Ed25519. Один бинарь на Rust (axum, tokio); при ответе никакие
сторонние API не вызываются.

> Статус: pre-1.0. Документированные HTTP-эндпоинты считаются стабильными,
> но поведение может меняться в минорных релизах.

## Содержание

- [Быстрый старт](#быстрый-старт) · [Развёртывание](#развёртывание)
- [Эндпоинты](#эндпоинты) · [Как выносится вердикт](#как-выносится-вердикт) ·
  [Как пользоваться из чекера](#как-пользоваться-из-чекера)
- [Публичные инстансы](#публичные-инстансы) · [Базы](#базы) ·
  [Конфигурация](#конфигурация)
- [Мониторинг](#мониторинг) · [Частые проблемы](#частые-проблемы) ·
  [Ограничения](#ограничения) · [Безопасность](#безопасность)
- Руководства: [развёртывание](docs/deploy.ru.md) · [подпись ответов](docs/signing.ru.md)

## Быстрый старт

```sh
docker run -d --name proxpulse-judge -p 8000:8000 ghcr.io/nechel12/proxpulse-judge:latest
curl http://127.0.0.1:8000/judge
```

В образе уже есть базы DB-IP Lite. На запрос с той же машины judge видит шлюз
Docker (`"ip": "172.17.0.1"`): в `geo` будет `"error": "not found"`,
`ip_type` — `unknown`, а `anonymity` — `elite`. Для локального запроса так и
должно быть; через прокси ответ описывает выход прокси, как в
[примере ниже](#эндпоинты).

Из исходников, со своими базами в `./geo` (скрипту скачивания нужны `bash`,
`curl` и `gzip`; сборке без Docker — [Rust](https://rustup.rs/) 1.88 или
новее):

```sh
git clone https://github.com/nechel12/proxpulse-judge.git
cd proxpulse-judge
bash scripts/download-dbip.sh   # City + ASN, без ключей
cp .env.example .env
docker compose up -d --build
```

Бинарники релизов, теги образа и их проверка описаны в
[docs/deploy.ru.md](docs/deploy.ru.md#готовый-образ-и-бинарники).

## Развёртывание

Чекеру judge нужен на публичном адресе, а для вердикта анонимности `/judge`
должен отвечать по **обычному HTTP**: внутри HTTPS-туннеля прокси не может
добавить заголовки.

| Вариант | Что нужно | Вердикт анонимности |
|---|---|---|
| [А — Caddy или nginx на VPS](docs/deploy.ru.md#вариант-а--caddy-реверс-прокси) | домен, порты 80 и 443 | да |
| [Б — Cloudflare Tunnel](docs/deploy.ru.md#вариант-б--cloudflare-tunnel-без-caddy-и-открытых-портов) | домен в Cloudflare, без открытых портов | да, при выключенном Always Use HTTPS |
| [В — Render](docs/deploy.ru.md#вариант-в--render-бесплатный-хостинг-без-vps) | бесплатный аккаунт, без сервера | нет: Render отвечает только по HTTPS |

Настройки доверия должны соответствовать тому, что стоит перед judge. От них
зависит, откуда берётся адрес клиента; неверная позволяет любому клиенту
подделать свой IP, гео и ключ rate-limit:

| Перед judge | `TRUST_PROXY` | `TRUST_CF` |
|---|---|---|
| ничего (`docker run -p`, по умолчанию) | `0` | `0` |
| Caddy или nginx на том же хосте (А) | `1` | `0` |
| Cloudflare, за ним Caddy или nginx | `1` | `1` |
| Cloudflare Tunnel (Б), Render (В) | `1` | `1` (`render.yaml` ставит оба) |

`TRUST_CF=1` безопасен, только если все запросы идут через Cloudflare.
Реверс-прокси, который сам добавляет `X-Real-IP`, `Via` или `Forwarded`,
перечисляет их в `EDGE_HEADERS`, иначе любой прокси выглядит `anonymous`.

## Эндпоинты

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/` | сервис, версия, репозиторий, источники гео, лицензии |
| GET | `/generate_204` | `204` пусто — быстрая проверка живости |
| GET | `/ip` | `{"ip": "..."}` — IP выхода |
| GET | `/headers` | `{"ip", "headers", "xff_chain"}` — эхо заголовков |
| GET | `/geo` | `{"ip", "geo", "source", "attribution"}` — страна/город/ASN из локальных баз |
| GET | `/type` | `{"ip", "ip_type", "signals"}` — тип IP с объяснением |
| GET | `/content` | фиксированные байты — эталон целостности |
| GET | `/judge?direct_ip=...&nonce=...` | всё сразу + `anonymity`, `content_sha256`; с подписью, см. [Подпись ответов](docs/signing.ru.md#подпись-ответов) |
| GET | `/key` | `{"alg", "key_id", "public_key"}` — публичный ключ, которым подписан `/judge` |
| GET | `/healthz` | `{"ok": true}` — liveness |
| GET | `/readyz` | `{"ok", "geo_ready", "geo_sources"}` — readiness |
| GET | `/metrics` | счётчики в формате Prometheus (можно закрыть `METRICS_TOKEN`) |

`/headers` и `/judge` возвращают заголовки такими, какими их отправил
проверяемый прокси: записи `X-Forwarded-For`, которые дописал реверс-прокси
на стороне развёртывания, и `EDGE_HEADERS` убираются. То, что пограничный
прокси добавляет сам (`Host`, `X-Forwarded-Proto`, `cf-*` от Cloudflare),
всё равно видно в ответе, но вердикт не ставит это в вину прокси.

Пример ответа `/judge` через анонимный прокси, с базами DB-IP:

```json
{
  "ip": "203.0.113.7",
  "anonymity": "anonymous",
  "xff_chain": [],
  "headers": {
    "host": "check.yourdomain.com",
    "user-agent": "curl/8.10.1",
    "via": "1.1 squid",
    "x-forwarded-proto": "https"
  },
  "geo": {
    "ip": "203.0.113.7",
    "country": "Germany",
    "country_code": "DE",
    "city": "Frankfurt am Main",
    "latitude": 50.1155,
    "longitude": 8.6842,
    "asn": 24940,
    "aso": "Hetzner Online GmbH"
  },
  "geo_source": {"asn": "dbip-asn-lite.mmdb", "city": "dbip-city-lite.mmdb"},
  "attribution": ["IP Geolocation by DB-IP (https://db-ip.com)"],
  "ip_type": "datacenter",
  "type_signals": {
    "org": "Hetzner Online GmbH",
    "rdns": null,
    "hosting_kw": [],
    "hosting_vendor": ["hetzner"],
    "mobile_kw": [],
    "residential_kw": [],
    "business_kw": []
  },
  "content_version": 1,
  "content_sha256": "1a0525d8797ca470e7b4a7c47622a89b011760f9db2d587ce7a5e06e99c1bcb9"
}
```

## Как выносится вердикт

| `anonymity` | Значение |
|---|---|
| `transparent` | `direct_ip` проверяющего найден в цепочке форвардинга или в значении любого другого заголовка, кроме `Host` (в любой записи IPv4/IPv6, в том числе в URL-кодировке): прокси сливает реальный IP. |
| `anonymous` | Утечки нет, но прокси себя выдаёт: свои записи `X-Forwarded-For` (даже `unknown`; при `TRUST_PROXY=0` даже пустой заголовок) или заголовок, который добавляют только прокси: `Via`, `Forwarded`, `Forwarded-For`, `Forwarded-For-IP`, `X-Forwarded`, любой другой `X-Forwarded-*` и `X-Real-Port`, когда перед judge никого нет (`TRUST_PROXY=0`), `X-Real-IP`, `Client-IP`, `X-Client-IP`, `X-Originating-IP`, `X-Cluster-Client-IP`, `X-Remote-IP`, `X-Remote-Addr`, `Coming-From`, `X-Coming-From`, `Xroxy-Connection`, `Proxy-*`, `X-Proxy*`. |
| `elite` | Ни того, ни другого: запрос выглядит как прямой. |

Без `direct_ip` утечку не отличить от обычного форвардинга, поэтому результат
будет не хуже `anonymous`. `ip_type` — `mobile`, `datacenter`, `business`,
`residential` или `unknown`; определяется по организации ASN (и по PTR, если
организация неизвестна), а `type_signals` показывает, какие ключевые слова
сработали.

## Как пользоваться из чекера

[ProxPulse](https://github.com/nechel12/proxpulse) узнаёт свой IP напрямую
(`api.ipify.org` или `/ip` этого judge по HTTPS), затем через каждый прокси
запрашивает `GET /judge?direct_ip=<его IP>&nonce=<случайное>`. Для
целостности он сравнивает `content_sha256` с `/content`, полученным напрямую,
а для проверки живости хватает пустого `GET /generate_204`. Параметра для
rDNS нет: сервер сам резолвит PTR, только когда организация ASN неизвестна,
не больше 16 одновременно, с кэшем на час.

По обычному HTTP прокси мог бы и переписать ответ, поэтому каждый ответ `200`
от `/judge` подписан Ed25519 по телу, `nonce` и `direct_ip`; открытый ключ
лежит на `/key`, и брать его нужно напрямую и по HTTPS. Ключ создаётся при
запуске, если его не задаёт `SIGNING_KEY`. Что подписано, как клиенту
проверять подпись и когда закреплять ключ:
[docs/signing.ru.md](docs/signing.ru.md).

## Публичные инстансы

Это общие инстансы, работающие по мере возможности и без гарантии
доступности. Для регулярных измерений требуется собственный инстанс
(варианты А–В выше).

- **https://proxycheck.lmtunnel.com** — встроенный judge чекера. Отвечает и
  по обычному HTTP, поэтому даёт вердикт анонимности. Настроен лимит
  1000 запросов в минуту с одного клиента (при превышении — 429 +
  `Retry-After`; в конфиге по умолчанию — 6000, таблица ниже).
- **https://proxpulse-judge.onrender.com** — бесплатный Render, базы
  DB-IP Lite, образ обновляется каждый месяц. Только HTTPS, поэтому без
  вердикта анонимности. На free-плане сервис
  засыпает после 15 минут без трафика (пробуждение около минуты) и
  ограничен примерно 750 часами в месяц, поэтому в конце месяца может
  быть недоступен до обновления квоты.

Нагрузку следует держать в разумных пределах: reverse-DNS выполняется
сервером только при неизвестной ASN-орге, отдельных запросов от клиента
не требуется.

## Базы

Файлы в `GEO_DIR` (`./geo`, который `docker-compose.yml` монтирует только для
чтения) сервис находит сам: `GeoLite2-City.mmdb` или `dbip-city-lite.mmdb`,
`GeoLite2-ASN.mmdb` или `dbip-asn-lite.mmdb` и база Country как запасной
вариант, если City нет. Без файлов гео-поля пустые (`"error": "no db"`), всё
остальное работает.

У каждой базы свои условия, и её атрибуция обязательна везде, где
показываются её результаты:

- **DB-IP Lite** — [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/),
  атрибуция `IP Geolocation by DB-IP` со ссылкой на <https://db-ip.com>;
  обновляется раз в месяц; встроена в публикуемый образ.
- **MaxMind GeoLite2** — бесплатный аккаунт и ключ,
  [GeoLite EULA](https://www.maxmind.com/en/geolite/eula); атрибуция
  `This product includes GeoLite2 Data created by MaxMind, available from
  https://www.maxmind.com`. В публикуемом образе её нет никогда.

Сами базы не обновляются: `scripts/download-dbip.sh` или
`scripts/download-geolite2.sh` (с `MAXMIND_LICENSE_KEY`), затем перезапуск.
Строка для ежемесячного cron и запасное скачивание самим образом — в
[docs/deploy.ru.md](docs/deploy.ru.md#базы-сами-обновляются-нет).

## Конфигурация

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `PORT` | `8000` | порт HTTP |
| `BIND_ADDR` | `0.0.0.0` | адрес прослушивания; `::` принимает и IPv6, если хост поддерживает dual-stack |
| `GEO_DIR` | `/app/geo` | каталог `.mmdb` |
| `TRUST_PROXY` | `0` | `1` — за реверс-прокси (IP из конца `X-Forwarded-For`), `0` — напрямую (IP из сокета, заголовки не доверяем); в `.env.example` явно задано `1` |
| `TRUST_CF` | `0` | `1` — верить `CF-Connecting-IP`; только за Cloudflare/Tunnel и только вместе с `TRUST_PROXY=1`. `0` — игнорировать (безопасно для Caddy/VPS) |
| `EDGE_HEADERS` | пусто | заголовки через запятую, которые добавляет реверс-прокси на стороне развёртывания (например, `x-real-ip,via`); они не анализируются и не отдаются в эхо. Только при `TRUST_PROXY=1`; `x-forwarded-for` указывать нельзя |
| `RDNS_TIMEOUT` | `1.5` | таймаут серверного rDNS, сек, от `0` (rDNS выключен) до `10` |
| `RATE_LIMIT_PER_MINUTE` | `6000` | token bucket: burst и средний темп запросов с клиента в минуту (IPv4-адрес или IPv6-сеть `/64`), `0` — без лимита |
| `METRICS_TOKEN` | пусто | если задан, `/metrics` требует `Authorization: Bearer <token>`; передавать только по HTTPS |
| `SIGNING_KEY` | пусто | постоянный ключ подписи ответов `/judge`: 32 байта в base64 (`openssl rand -base64 32`); пусто — ключ генерируется при запуске, см. [Подпись ответов](docs/signing.ru.md#подпись-ответов); неверный ключ останавливает запуск |
| `RUST_LOG` | `info` | уровень логов |

`TRUST_PROXY` и `TRUST_CF` принимают `1`/`0`, `true`/`false`, `yes`/`no`,
`on`/`off`. Любое другое значение, `PORT`, `RDNS_TIMEOUT` или
`RATE_LIMIT_PER_MINUTE`, которые не являются числом в допустимых пределах,
некорректный `BIND_ADDR` или ошибка в `EDGE_HEADERS` останавливают сервис при
старте, а не подменяются молча значением по умолчанию и не меняют то, каким
заголовкам он доверяет. `TRUST_CF=1` без `TRUST_PROXY=1` игнорируется с
предупреждением в логе.

При `TRUST_PROXY=1` IP клиента берётся из **последней** записи
`X-Forwarded-For`. Caddy 2.5+ по умолчанию заменяет входящий XFF адресом
непосредственного клиента; `Caddyfile.example` включает `trusted_proxies`,
чтобы сохранить цепочку проверяемого прокси — тогда Caddy дописывает адрес
клиента в конец. nginx (`proxy_add_x_forwarded_for`) и Cloudflare также
дописывают в конец. При `TRUST_PROXY=1` заголовки реверс-прокси вроде
`X-Forwarded-Proto`/`Host` не считаются заголовками прокси, иначе за
реверс-прокси все были бы `anonymous`; их значения всё равно проверяются на
утечку. При `TRUST_PROXY=0` перед judge никого нет, поэтому они выдают прокси,
как любой другой `X-Forwarded-*`. При `TRUST_CF=1` приоритет у
`CF-Connecting-IP`.

## Мониторинг

- `GET /healthz` — liveness.
- `GET /readyz` — readiness плюс `geo_ready` и загруженные `geo_sources`.
- `GET /metrics` — счётчики в формате Prometheus (запросы, 4xx/5xx,
  rate-limit, rDNS, build info). На публичном инстансе задаётся
  `METRICS_TOKEN` (или путь закрывается на реверс-прокси).

Заголовки запроса должны прийти за 10 секунд, одновременно открыто не больше
4096 соединений, запрос ограничен 20 секундами и 512 одновременными
запросами. Эндпоинты мониторинга исключены из rate/concurrency-лимитов;
метрики живут в памяти процесса и сбрасываются при рестарте.

## Частые проблемы

| Симптом | Причина и решение |
|---|---|
| Все проверки `anonymous`, даже elite-прокси | Реверс-прокси или хостинг на стороне развёртывания сам добавляет заголовок прокси: `X-Real-IP`, `Via` или `Forwarded` (типично для nginx), `Client-IP` или `X-Client-IP` (Azure App Service). Такие заголовки удаляются из конфигурации прокси или перечисляются в `EDGE_HEADERS`. Прямой `GET /headers` покажет, что доходит до judge. |
| Прямая проверка (без прокси) — `transparent`, а `/ip` показывает `127.0.0.1` или `172.x` | Judge стоит за реверс-прокси с `TRUST_PROXY=0`: требуется `TRUST_PROXY=1`. |
| Заведомо «текущий» прокси за Caddy получает `elite` | Caddy отбрасывает входящий `X-Forwarded-For`: требуется `trusted_proxies`, как в `Caddyfile.example`. Кроме того, `/judge` должен быть доступен по обычному HTTP, как блок `http://` в `Caddyfile.example`. |
| Чекер вообще не показывает анонимность (`—`) с этим judge | `http://<хост>/judge` перенаправляется на HTTPS (Render, Caddy без блока `http://`, Always Use HTTPS у Cloudflare). Анонимность видна только по обычному HTTP; `curl -sI http://<хост>/judge` должен отвечать `200`, а не `301`/`308`. |
| `/ip` показывает адрес Cloudflare (`172.64.x`, `162.158.x`, …) | Трафик идёт через Cloudflare, а `TRUST_CF=0`: требуются `TRUST_CF=1` и `TRUST_PROXY=1`. |
| Гео пустое с `"error": "no db"`; в `/readyz` `"geo_ready": false` | В `./geo` нет `.mmdb`. Требуется выполнить `bash scripts/download-dbip.sh` и перезапустить контейнер. |
| Контейнер завершается с `invalid configuration` | Опечатка в значении `TRUST_*`, некорректный `BIND_ADDR`, `x-forwarded-for` в `EDGE_HEADERS` или неверный `SIGNING_KEY`; переменная указана в логе. |
| `/metrics` отвечает `401` | Задан `METRICS_TOKEN`: запрос должен содержать `Authorization: Bearer <token>`. |
| Render: первый запрос после паузы падает по таймауту | Free-план засыпает через 15 минут; помогает повторный запрос примерно через минуту. |

## Ограничения

- Анонимность и тип IP — эвристики. Прокси может не передавать или
  подделывать заголовки, а локальные данные не доказывают
  residential-vs-business так, как платные ASN-базы.
- TLS/JA3 не анализируется: TLS терминируется на Caddy, Cloudflare,
  Render или другом реверс-прокси.
- Точность гео зависит от локальной базы и частоты её обновления.
- Hop-by-hop-заголовки (`Proxy-Connection`, `Proxy-Authorization`,
  `Connection`, `Keep-Alive`) за Caddy и nginx до judge не доходят: они их
  отбрасывают, поэтому прокси, который их передаёт, по ним не поймать.
- Публичные инстансы общие и работают по мере возможности; для надёжных
  измерений требуется собственный инстанс.

## Безопасность

Сообщения об уязвимостях — через [SECURITY.md](SECURITY.md).

Judge — диагностический инструмент, а не граница безопасности. Он не
аутентифицирует клиентов и не может заставить прокси раскрыть заголовки;
вердикты приблизительные. Его следует запускать за реверс-прокси с TLS,
держать HTTP-порт на loopback, настроить rate-limit и привести
`TRUST_PROXY`/`TRUST_CF` в соответствие с фактической топологией. Неверно
настроенный доверенный заголовок позволяет подделать IP/гео и ключ
rate-limit.

## Разработка

```sh
cargo test
PORT=8000 GEO_DIR=./geo TRUST_PROXY=0 cargo run
bash scripts/smoke.sh http://127.0.0.1:8000
```

Устройство кода, проверки перед изменением и порядок выпуска релизов — в
[CONTRIBUTING.md](CONTRIBUTING.md) и [RELEASING.md](RELEASING.md); история
изменений — в [CHANGELOG.md](CHANGELOG.md). Баг-репорты и PR приветствуются
по [Кодексу поведения](CODE_OF_CONDUCT.md); об уязвимостях сообщают через
[SECURITY.md](SECURITY.md), а не в публичный issue.

## Связанные проекты

- [proxpulse](https://github.com/nechel12/proxpulse) — десктопный чекер
  прокси (Tauri 2), использует judge как backend для проверок; публичный
  инстанс выше встроен в него по умолчанию.

## Лицензия

Код распространяется под Apache-2.0; текст лицензии — в [LICENSE](LICENSE). Базы
геоданных не входят в лицензию кода: DB-IP Lite — CC BY 4.0, MaxMind
GeoLite2 — GeoLite2 EULA. Файлы баз скачиваются отдельно или вшиваются
в DB-IP-образ с указанием авторства.

---

## Поддержать проект

ProxPulse Judge — бесплатный проект с открытым исходным кодом. Если он
экономит время, поддержать разработку можно здесь:

<p align="center">
  <a href="https://boosty.to/nechel12/donate">
    <img src="https://img.shields.io/badge/Boosty-Donate-F15F2C?style=for-the-badge&logo=boosty&logoColor=white" alt="Поддержать на Boosty">
  </a>
</p>

### Криптовалюта

| Сеть | Адрес |
|:-----|:------|
| **TRON** | `TMM2Cdm4tJx1nKRRq5RCBcdwfn9cHuJZy9` |
| **TON** | `UQBlVvOfTleWn4pkY384mYWiGyhdHBryoC_N1Si1OSWAxPKl` |
| **Bitcoin** | `bc1qagjtnutjya2rss3u3ls8ur7qk0u7zutc6t6fwc` |
| **BNB Smart Chain** | `0x423aF840f67355371bf32480744A84069dfab5ff` |

> [!WARNING]
> Допускается отправка только соответствующего актива в указанной сети.
> Переводы в другую сеть восстановить невозможно.
