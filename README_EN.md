# ProxPulse Judge

[![License](https://img.shields.io/github/license/nechel12/proxpulse-judge)](LICENSE) [![Last commit](https://img.shields.io/github/last-commit/nechel12/proxpulse-judge)](https://github.com/nechel12/proxpulse-judge/commits/main) ![Rust](https://img.shields.io/badge/backend-Rust-orange?logo=rust&logoColor=white)

*([Русская версия](README.md))*

Self-hosted backend for proxy checking. A single `GET /judge` request replaces
a bunch of third-party services (ip-api, httpbin): it sees the proxy exit IP,
resolves geo from **local** `.mmdb` files, echoes request headers for anonymity
detection, and serves fixed content for tamper checks.

Stack: **Rust + axum + tokio**, databases in RAM, lookup LRU cache. No external
APIs, no limits, a single runtime-free binary in `debian:slim`.

## Quickstart

Requires [Docker](https://docs.docker.com/get-docker/) with Compose and `bash`
(the database download script). For Docker-free development — [Rust](https://rustup.rs/).

```sh
git clone https://github.com/nechel12/proxpulse-judge.git
cd proxpulse-judge
bash scripts/download-dbip.sh   # downloads City + ASN, no keys needed
cp .env.example .env
docker compose up -d --build

curl http://127.0.0.1:8000/judge
```

## Variant A — Caddy (reverse proxy)

You need **your own domain** (no HTTPS certificate without one).
The subdomain can be anything, e.g. `check.yourdomain.com`:
in your registrar's DNS panel create an **A-record** for the subdomain
pointing at the server IP; ports **80 and 443** must face the internet.
Example in `Caddyfile.example`:

```caddy
check.yourdomain.com {
    reverse_proxy 127.0.0.1:8000
}
```

Caddy issues a Let's Encrypt certificate automatically on first request.
Check:

```sh
curl https://check.yourdomain.com/healthz
```

## Variant B — Cloudflare Tunnel (no Caddy, no open ports)

```sh
cloudflared tunnel --url http://127.0.0.1:8000
```

or no config-file commands at all — via the Cloudflare website:
**Zero Trust → Networks → Tunnels → Create a tunnel**, pick a name,
on the **Public Hostname** tab add: subdomain `check`, your domain,
service `http://proxpulse-judge:8000` (container on the shared network, see below)
or `http://127.0.0.1:8000` (cloudflared on the host). Pass the token from
the website into the connector container:

```sh
docker run -d --name cf-tunnel --restart unless-stopped \
  --network proxpulse-net \
  cloudflare/cloudflared:latest tunnel --no-autoupdate run --token <TOKEN>
```

or a named tunnel with DNS on `check.yourdomain.com` and ingress:

```yaml
tunnel: <id>
credentials-file: /root/.cloudflared/<id>.json
ingress:
  - hostname: check.yourdomain.com
    service: http://127.0.0.1:8000
  - service: http_status:404
```

> Important: if cloudflared runs **in docker**, `localhost` inside its
> container is itself, and the name `proxpulse-judge` is only visible on the
> shared network. So the tunnel container must sit on the same network as
> judge — the `proxpulse-net` network from `docker-compose.yml` is created
> automatically:
>
> ```sh
> docker network connect proxpulse-net cf-tunnel
> docker network inspect proxpulse-net --format '{{range .Containers}}{{.Name}} {{end}}'
> # both must be visible: proxpulse-judge and cf-tunnel
> ```
>
> and in ingress/service use `http://proxpulse-judge:8000`.
> cloudflared on the host itself simply goes to `http://127.0.0.1:8000`.

No judge changes needed: `TRUST_CF=1` by default, the service takes the
real IP from `CF-Connecting-IP` (set by Cloudflare itself, takes priority
over `X-Forwarded-For`), and all `cf-*`/`cdn-loop` headers are excluded from
anonymity detection — otherwise a direct check through the tunnel would give
a false `transparent`. Check:

```sh
MYIP=$(curl -s https://api.ipify.org)
curl -s "https://check.yourdomain.com/judge?direct_ip=$MYIP" | head -c 300; echo
# expect "anonymity":"elite"
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/generate_204` | `204` empty — cheap liveness check |
| GET | `/ip` | `{"ip": "..."}` — exit IP |
| GET | `/headers` | `{"ip", "headers", "xff_chain"}` — header echo |
| GET | `/geo` | `{"ip", "geo", "source"}` — country/city/ASN from local DBs |
| GET | `/type` | `{"ip", "ip_type", "signals"}` — IP type with reasoning |
| GET | `/content` | fixed bytes — integrity reference |
| GET | `/judge?direct_ip=...` | everything at once + `anonymity`, `content_sha256` |
| GET | `/healthz` | `{"ok": true}` — for Docker |

Example `/judge` response:

```json
{
  "ip": "203.0.113.7",
  "anonymity": "elite",
  "geo": {"country": "Germany", "country_code": "DE", "city": "Frankfurt", "asn": 9009},
  "ip_type": "datacenter",
  "content_sha256": "1a05…"
}
```

## Using it from the checker

1. Direct `GET /ip` request — your own IP (`direct_ip`).
2. `GET /judge?direct_ip=<yours>` through a proxy — the `anonymity` field:
   `elite` (leaks nothing), `anonymous` (proxy visible, IP hidden),
   `transparent` (real IP leaked).
3. Integrity: `GET /content` directly and through the proxy, compare bytes
   (or `content_sha256` from `/judge`).
4. Geo and type are already inside `/judge`. There is no rDNS parameter:
   the server resolves PTR itself, only when the ASN org is unknown (otherwise
   it changes nothing), at most 16 resolutions in parallel, answers cached
   for an hour.
5. A liveness check is just `GET /generate_204` (empty 204, the cheapest request).

## Public instance

Live instance: **https://proxycheck.lmtunnel.com** — can be embedded
in the checker by default.

Limits are counted separately per IP:

| Scope | Limit | On exceed |
|---|---|---|
| all endpoints except `/healthz` | `RATE_LIMIT_PER_MINUTE` requests / sliding minute (default 6000, `0` — off) | 429 + `Retry-After` |

In practice: an ordinary check even on hundreds of threads is tens of
requests per second, passes freely. Limits only cut floods and bots.
`/healthz` is never limited.

Please keep load reasonable: reverse-DNS is done by the server itself and
only for unknown ASN orgs, no client-side requests needed — just don't flood.

## Databases

The `./geo` directory is mounted into the container read-only. The service
finds files by itself:

- `GeoLite2-City.mmdb` or `dbip-city-lite.mmdb`
- `GeoLite2-ASN.mmdb` or `dbip-asn-lite.mmdb`
- `GeoLite2-Country.mmdb` — fallback if there is no City

Without files, geo fields come back empty (`"error": "no db"`, type is
`unknown`); everything else works.

### Database licenses (important)

The files themselves are not in the repository — you download them, and each
database has its own terms:

- **DB-IP Lite** — [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
  Attribution is required — an `IP Geolocation by DB-IP` link
  to <https://db-ip.com> wherever results from the database are shown.
  Updated **monthly**. Details: <https://db-ip.com/db/lite.php>
- **MaxMind GeoLite2** (City / ASN / Country) — needs a free account
  and key. Usage is governed by the
  [GeoLite EULA](https://www.maxmind.com/en/geolite/eula) (incorporates aspects
  of [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)).
  Attribution is required: `This product includes GeoLite2 Data
  created by MaxMind, available from https://www.maxmind.com`.

### Do databases update themselves? No

`scripts/download-dbip.sh` (no keys) or `scripts/download-geolite2.sh`
(needs `MAXMIND_LICENSE_KEY` from a free account) are manual: download →
files land in `./geo` → **restart the container** (the geo cache lives in
memory, new files are not picked up without a restart). For automation —
monthly cron + restart:

```cron
0 4 3 * * cd /opt/proxpulse-judge && bash scripts/download-dbip.sh >/tmp/dbip.log 2>&1 && docker compose restart judge
```

## Maintenance: logs

The service logs to stdout. Docker's `json-file` driver stores them with no
size limit by default, so `docker-compose.yml` sets limits (`max-size: 10m`,
`max-file: 3` — up to ~30 MB per container). With a compose setup no further
configuration is needed.

For running without Docker with logs in a file — example
`/etc/logrotate.d/proxpulse-judge`:

```
/opt/proxpulse-judge/*.log /var/log/proxpulse-judge/*.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    copytruncate
}
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8000` | HTTP port |
| `GEO_DIR` | `/app/geo` | `.mmdb` directory |
| `TRUST_PROXY` | `1` | `1` — behind Caddy (IP from the end of `X-Forwarded-For`), `0` — directly exposed (IP from socket) |
| `TRUST_CF` | `1` | `1` — trust `CF-Connecting-IP` (Cloudflare Tunnel), `0` — ignore |
| `RDNS_TIMEOUT` | `1.5` | server-side rDNS timeout, sec |
| `RATE_LIMIT_PER_MINUTE` | `6000` | requests per IP per sliding minute, `0` — no limit |
| `RUST_LOG` | `info` | log level |

## Why it is the way it is

- **Why not Python/FastAPI.** The first version was FastAPI — it worked,
  but Rust gives a single runtime-free binary, a compact `debian:slim` image,
  and no GIL: hundreds of parallel checks on one tokio thread pool.
- **Why IP from the end of XFF.** Caddy appends the client address to the end
  of the chain — only the last entry is trustworthy. Caddy's own headers
  (`X-Forwarded-Proto/Host`) are excluded from anonymity detection,
  otherwise everything behind a reverse proxy would look «anonymous».
- **Why IP type is a heuristic.** Local data cannot prove
  residential-vs-business the way paid ASN DBs do. So the response carries
  `signals` (which keywords matched and where) — you can see *why*.
- **Why no TLS/JA3.** Caddy terminates TLS, the judge only sees HTTP.
  Certificate comparison stays on the checker side (direct vs through proxy).

## Development

```sh
cargo test        # 34 tests: logic, geo parsing, API, limits
cargo run         # PORT=8000 GEO_DIR=./geo TRUST_PROXY=0
```

Structure: `src/main.rs` (HTTP), `src/geo.rs` (`.mmdb` pool + LRU),
`src/logic.rs` (anonymity, IP type, fixed content).

## Related projects

- [proxpulse](https://github.com/nechel12/proxpulse) — desktop proxy
  checker (Tauri 2) that uses the judge as its check backend; the public
  instance above is embedded in it by default.

## Contributing

Bug reports and PRs are welcome. Before sending, run `cargo test`.

## License

Apache-2.0, see [LICENSE](LICENSE).
