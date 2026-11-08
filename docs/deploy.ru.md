# Развёртывание

[English](deploy.md) | **Русский**

Как запустить judge там, где до него дотянется чекер. Выбор
варианта и настройки доверия для каждого кратко собраны в
[README](../README.ru.md#развёртывание).

## Готовый образ и бинарники

CI публикует в GHCR мультиархитектурный образ (`linux/amd64`, `linux/arm64`)
со вшитыми базами DB-IP Lite:

```sh
docker pull ghcr.io/nechel12/proxpulse-judge:latest
```

`:latest` — это всегда последний подписанный релиз, а не невыпущенный код из
`main`. Ежемесячные плановые сборки пересобирают этот релиз со свежими базами
и обновляют теги `:latest` и `:YYYYMM`; подписанный релизный тег `vX.Y.Z`
дополнительно публикует `:vX.Y.Z`, который никогда не перезаписывается. Каждый образ перед публикацией проходит
smoke-тест со вшитыми базами и скан Trivy и несёт подписанную attestation о
происхождении сборки:

```sh
gh attestation verify oci://ghcr.io/nechel12/proxpulse-judge:latest --owner nechel12
```

Данных MaxMind в образах нет. На VPS
[`docker-compose.ghcr.yml`](../docker-compose.ghcr.yml) запускает образ с теми же
ограничениями, что и `docker-compose.yml`, но без тома `./geo`, который
закрыл бы вшитые базы:

```sh
cp .env.example .env
docker compose -f docker-compose.ghcr.yml up -d
# обновление до нового релиза или ежемесячных баз:
docker compose -f docker-compose.ghcr.yml pull && docker compose -f docker-compose.ghcr.yml up -d
```

Со своими файлами MaxMind или DB-IP собирается цель `Dockerfile` по умолчанию
и монтируется `./geo` (`docker-compose.yml`), как описано ниже.

К каждому [релизу на GitHub](https://github.com/nechel12/proxpulse-judge/releases)
прикладываются статические Linux-бинарники (`x86_64`, `aarch64`) с
`SHA256SUMS` и attestation. В архиве — бинарник, `.env.example` и
`download-dbip.sh`. Файл `.env` бинарник не читает: настройки берутся из
окружения, например из юнита systemd:

```sh
GEO_DIR=/opt/proxpulse-judge/geo JUDGE_BIN=./proxpulse-judge bash download-dbip.sh
```

```ini
# /etc/systemd/system/proxpulse-judge.service
[Service]
ExecStart=/opt/proxpulse-judge/proxpulse-judge
Environment=GEO_DIR=/opt/proxpulse-judge/geo TRUST_PROXY=1 BIND_ADDR=127.0.0.1
DynamicUser=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

> [!IMPORTANT]
> По умолчанию в образе `TRUST_PROXY=0` и `TRUST_CF=0`: IP клиента берётся из
> сокета. Оба параметра задаются в соответствии с фактической топологией
> (`render.yaml` уже устанавливает `1` для Render). `TRUST_CF=1` безопасен
> только когда каждый запрос приходит в контейнер через Cloudflare: иначе
> любой клиент может подделать IP, гео и ключ rate-limit заголовком
> `CF-Connecting-IP`.

## Вариант А — Caddy (реверс-прокси)

Требуется **отдельный домен** (без него HTTPS-сертификат не выпускается).
Поддомен может быть любым, например `check.yourdomain.com`: в DNS-панели
регистратора создаётся **A-запись** поддомена на IP сервера, а порты
**80 и 443** должны быть доступны извне. Пример в `Caddyfile.example`:

```caddy
(judge) {
    reverse_proxy 127.0.0.1:8000 {
        trusted_proxies 0.0.0.0/0 ::/0
    }
}

check.yourdomain.com {
    import judge
}

http://check.yourdomain.com {
    @plain path /judge /content /headers /ip
    handle @plain {
        import judge
    }
    handle {
        redir https://{host}{uri} 308
    }
}
```

Caddy сам выпустит сертификат Let's Encrypt. Блок `http://` оставляет
`/judge`, `/content`, `/headers` и `/ip` на обычном HTTP, а всё остальное,
включая `/key`, перенаправляет на HTTPS: анонимность видна только по обычному
HTTP (см. [Подпись ответов](signing.ru.md#подпись-ответов)), а без этого блока Caddy
перенаправляет весь порт 80. Проверка:

```sh
curl https://check.yourdomain.com/healthz
curl -s http://check.yourdomain.com/judge | head -c 200; echo   # JSON, а не редирект
```

`Caddyfile.example` включает `trusted_proxies`: с Caddy 2.5+ без этого
входящий `X-Forwarded-For` проверяемого прокси отбрасывается, и judge
не увидит утечку реального IP через XFF. Доверять XFF всем клиентам
можно только потому, что judge слушает `127.0.0.1` и доступен лишь
через Caddy. Для этого варианта `TRUST_CF` должен оставаться `0`
(дефолт): Cloudflare здесь нет, а CF-заголовки легко подделать. С ним judge
никогда не берёт адрес клиента из `CF-Connecting-IP` или `True-Client-IP`, а
только ищет в них настоящий IP чекера, как в любом другом заголовке, поэтому
примеры пропускают их.

Если Cloudflare стоит **перед** Caddy, `trusted_proxies` задаётся диапазонами Cloudflare вместо `0.0.0.0/0`, порты
80/443 ограничиваются IP-диапазонами Cloudflare (либо включается
Authenticated Origin Pulls, поскольку `trusted_proxies` контролирует только
`X-Forwarded-*`, но не `CF-Connecting-IP`); также требуются `TRUST_CF=1`
и `TRUST_PROXY=1`.

### nginx вместо Caddy

[`nginx.conf.example`](../nginx.conf.example) — аналогичная конфигурация с тем же
`location` для `/judge`, `/content`, `/headers` и `/ip` по обычному HTTP на
порту 80. Главное в ней:

```nginx
location ~ ^/(judge|content|headers|ip)$ { ... }   # порт 80, без редиректа
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

nginx дописывает адрес подключившегося к `X-Forwarded-For` прокси, поэтому
`TRUST_PROXY=1` работает так же, как с Caddy. Заголовки `X-Real-IP`, `Via`
и `Forwarded` в этой конфигурации **не добавляются** (во многих шаблонах
nginx они есть): judge считает их признаками прокси, и каждая проверка выйдет
`anonymous`. Если без них обойтись нельзя, они перечисляются в `EDGE_HEADERS`
(например, `EDGE_HEADERS=x-real-ip`), чтобы не приписываться проверяемому
прокси.

## Вариант Б — Cloudflare Tunnel (без Caddy и открытых портов)

```sh
cloudflared tunnel --url http://127.0.0.1:8000
```

или вообще без команд в конфигах — через сайт Cloudflare:
**Zero Trust → Networks → Tunnels → Create a tunnel**; в туннеле задаётся
имя, а на вкладке **Public Hostname** указываются: subdomain `check`,
домен `yourdomain.com` (вместе `check.yourdomain.com`),
service `http://proxpulse-judge:8000` (контейнер в общей сети; подробности ниже)
или `http://127.0.0.1:8000` (cloudflared на хосте). Токен из сайта
передаётся в контейнер коннектора:

```sh
docker run -d --name cf-tunnel --restart unless-stopped \
  --network proxpulse-net \
  cloudflare/cloudflared:latest tunnel --no-autoupdate run --token <TOKEN>
```

или именованный туннель с DNS на `check.yourdomain.com` и ingress:

```yaml
tunnel: <id>
credentials-file: /root/.cloudflared/<id>.json
ingress:
  - hostname: check.yourdomain.com
    service: http://127.0.0.1:8000
  - service: http_status:404
```

> Важно, если cloudflared крутится **в docker**: `localhost` внутри его
> контейнера — это он сам, а имя `proxpulse-judge` видно только в общей
> сети. Поэтому контейнер туннеля должен сидеть в одной сети с judge —
> сеть `proxpulse-net` из `docker-compose.yml` создаётся автоматически.
> Команда выше уже запускает туннель в ней; туннель, запущенный без
> `--network proxpulse-net`, подключается так:
>
> ```sh
> docker network connect proxpulse-net cf-tunnel
> docker network inspect proxpulse-net --format '{{range .Containers}}{{.Name}} {{end}}'
> # должны быть видны оба: proxpulse-judge и cf-tunnel
> ```
>
> и в ingress/service тогда `http://proxpulse-judge:8000`.
> cloudflared на самом хосте ходит просто на `http://127.0.0.1:8000`.

В этом варианте нужно явно выставить `TRUST_CF=1` и оставить
`TRUST_PROXY=1`; `TRUST_CF` по умолчанию `0` — это безопасно для Caddy/VPS.
Сервис возьмёт реальный IP из `CF-Connecting-IP` (его ставит сам
Cloudflare, приоритет выше `X-Forwarded-For`). Известные инфраструктурные
заголовки Cloudflare исключаются из детекта анонимности, а неизвестные `cf-*`
по-прежнему проверяются на утечку `direct_ip`. Проверка:

```sh
MYIP=$(curl -s https://api.ipify.org)
curl -s "http://check.yourdomain.com/judge?direct_ip=$MYIP" | head -c 300; echo
# ждём "anonymity":"elite"
```

Для анонимности хост должен отвечать по обычному HTTP: настройка Cloudflare
**Always Use HTTPS** (SSL/TLS → Edge Certificates) для него остаётся
выключенной, иначе каждый HTTP-запрос перенаправляется и чекер не получает
вердикта анонимности.

## Вариант В — Render (бесплатный хостинг, без VPS)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/nechel12/proxpulse-judge)

Готовый образ со вшитыми DB-IP Lite собирается сам каждый месяц
(`.github/workflows/docker.yml` → `ghcr.io/nechel12/proxpulse-judge:latest`),
диск не нужен. Кнопка создаёт сервис по `render.yaml` с бесплатным доменом
`https://<имя>.onrender.com`. Полученный URL указывается в чекере.
Cloudflare Tunnel в этом варианте не требуется: TLS и домен
предоставляет Render. Render перенаправляет весь обычный HTTP на HTTPS,
поэтому такой инстанс даёт IP, гео и тип IP, но **не вердикт анонимности**;
для него нужен вариант А или Б.

Особенности free-плана:

- Сервис засыпает после 15 минут без трафика, пробуждение занимает
  около минуты. Первая проверка после простоя может частично завершиться
  по таймауту — достаточно повторить её. Один сервис примерно соответствует
  лимиту бесплатных 750 ч/мес.
- Файловая система эфемерна, но это не страшно: базы вшиты в образ.
- `TRUST_PROXY=1` и `TRUST_CF=1` обязательны (трафик Render проходит
  через Cloudflare, реальный IP извлекается из `CF-Connecting-IP`).
  `render.yaml` задаёт оба; в самом образе по умолчанию `0`, поэтому
  сервису, созданному вручную, нужно добавить обе переменные в дашборде
  Render (Environment). Переменная `PORT` задаётся самим Render и не
  должна переопределяться.
- `render.yaml` также генерирует случайный `METRICS_TOKEN`, поэтому `/metrics`
  публичного инстанса не открыт; токен виден в Environment.
- В образе только DB-IP Lite: GeoLite2 EULA ограничивает публичное
  распространение, поэтому данные MaxMind не вшиваются в публикуемый
  образ. Для MaxMind используется вариант с VPS + volume выше.

Обновление баз (образ пересобирается 3-го числа каждого месяца):

1. **Форк + автохук.** Создаётся форк репозитория, включаются workflows
   во вкладке Actions форка (по умолчанию отключены), добавляется секрет
   `RENDER_DEPLOY_HOOK` (Render dashboard → сервис → Settings →
   Deploy Hook), а в `render.yaml` форка указывается собственный образ
   `ghcr.io/<владелец>/proxpulse-judge:latest`. После этого свежие образы
   публикуются в GHCR форка и автоматически запускают редеплой. Форк
   собирает свой `main`, а не последний релиз, поэтому его синхронизируют
   с этим репозиторием (Sync fork). Ограничение: расписание отключается после 60 дней без активности
   в форке — требуется периодический ручной запуск workflow (Run workflow).
2. **Вручную.** Render dashboard → сервис → Manual Deploy →
   Deploy latest reference. Геоданные меняются медленно, поэтому
   ручного обновления обычно достаточно.
3. **Собственный планировщик без форка.** Сервис может использовать
   `ghcr.io/nechel12/proxpulse-judge:latest` напрямую, а deploy hook —
   вызываться раз в месяц любым внешним планировщиком (собственный
   сервер, cron-job.org и т.п.).

Образ совместим с другими хостингами контейнеров: требуются проброс
`$PORT` и `/healthz` в качестве health-check.

## Базы сами обновляются? Нет

`scripts/download-dbip.sh` (без ключей) или `scripts/download-geolite2.sh`
(нужен `MAXMIND_LICENSE_KEY` из бесплатного аккаунта) — ручные: после
скачивания файлы размещаются в `./geo`, затем **требуется перезапуск
контейнера** (гео-кэш живёт в памяти, без рестарта новые файлы не
подхватятся). Для автоматизации — cron раз в месяц + рестарт:

```cron
0 4 3 * * cd /opt/proxpulse-judge && bash scripts/download-dbip.sh >/tmp/dbip.log 2>&1 && docker compose restart judge
```

В docker-compose каталог `./geo` смонтирован **read-only**, поэтому
entrypoint не может туда писать: для compose базы скачиваются на хосте
(`bash scripts/download-dbip.sh`) или используются образы с вшитыми
базами (Render). Автоскачивание в entrypoint работает, только если
`GEO_DIR` доступен на запись (например, `docker run` без read-only
mount); иначе в лог пишется warning и сервис стартует без гео.
Собственные файлы (MaxMind или DB-IP) имеют приоритет — фолбэк
срабатывает только когда валидных `.mmdb` нет.

## Обслуживание: логи

Сервис пишет логи в stdout. Драйвер Docker `json-file` по умолчанию
хранит их без ограничения размера, поэтому в `docker-compose.yml`
заданы лимиты (`max-size: 10m`, `max-file: 3` — до ~30 МБ на контейнер).
При запуске через compose дополнительная настройка не требуется. Кроме того,
сервис в compose работает с read-only корневой ФС, без capabilities, с
`no-new-privileges` и лимитом памяти 512 МБ.

Без Docker бинарник тоже пишет логи в stdout: под systemd их хранит и
ротирует journald (`journalctl -u proxpulse-judge`).
