# ProxPulse Judge

**English** | [Русский](README.ru.md)

[![CI](https://github.com/nechel12/proxpulse-judge/actions/workflows/docker.yml/badge.svg?branch=main)](https://github.com/nechel12/proxpulse-judge/actions/workflows/docker.yml)
[![Release](https://img.shields.io/github/v/release/nechel12/proxpulse-judge)](https://github.com/nechel12/proxpulse-judge/releases)
[![License](https://img.shields.io/github/license/nechel12/proxpulse-judge)](LICENSE)
[![GHCR](https://img.shields.io/badge/ghcr.io-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)](https://github.com/nechel12/proxpulse-judge/pkgs/container/proxpulse-judge)

A self-hosted proxy judge for [ProxPulse](https://github.com/nechel12/proxpulse)
and other checkers. One `GET /judge` through a proxy returns its exit IP,
anonymity (`elite`, `anonymous`, `transparent`), geo and ASN from **local**
`.mmdb` files, the IP type, and a hash of fixed content for tamper checks,
with an Ed25519 signature. A single Rust binary (axum, tokio); no third-party
API is called while answering.

> Status: pre-1.0. The documented HTTP endpoints are intended to be stable,
> but behavior may change in minor releases.

## Contents

- [Quickstart](#quickstart) · [Deployment](#deployment)
- [Endpoints](#endpoints) · [How verdicts are decided](#how-verdicts-are-decided) ·
  [Using it from the checker](#using-it-from-the-checker)
- [Public instances](#public-instances) · [Databases](#databases) ·
  [Configuration](#configuration)
- [Monitoring](#monitoring) · [Troubleshooting](#troubleshooting) ·
  [Limitations](#limitations) · [Security](#security)
- Guides: [deployment](docs/deploy.md) · [signed answers](docs/signing.md)

## Quickstart

```sh
docker run -d --name proxpulse-judge -p 8000:8000 ghcr.io/nechel12/proxpulse-judge:latest
curl http://127.0.0.1:8000/judge
```

The image carries the DB-IP Lite databases. Asked from the same machine, the
judge sees Docker's gateway (`"ip": "172.17.0.1"`): `geo` says
`"error": "not found"`, `ip_type` is `unknown` and `anonymity` is `elite`.
That is right for a local request; through a proxy the answer describes the
proxy's exit, as in the [example below](#endpoints).

From source, with your own databases in `./geo` (the download script needs
`bash`, `curl` and `gzip`; a build without Docker needs
[Rust](https://rustup.rs/) 1.88 or newer):

```sh
git clone https://github.com/nechel12/proxpulse-judge.git
cd proxpulse-judge
bash scripts/download-dbip.sh   # City + ASN, no keys needed
cp .env.example .env
docker compose up -d --build
```

Release binaries, image tags and their verification are described in
[docs/deploy.md](docs/deploy.md#prebuilt-image-and-binaries).

## Deployment

A checker needs the judge on a public address, and for an anonymity verdict
`/judge` must answer **plain HTTP**: inside an HTTPS tunnel a proxy cannot
add headers.

| Variant | Needs | Anonymity verdict |
|---|---|---|
| [A — Caddy or nginx on a VPS](docs/deploy.md#variant-a--caddy-reverse-proxy) | a domain, ports 80 and 443 | yes |
| [B — Cloudflare Tunnel](docs/deploy.md#variant-b--cloudflare-tunnel-no-caddy-no-open-ports) | a domain on Cloudflare, no open ports | yes, with Always Use HTTPS off |
| [C — Render](docs/deploy.md#variant-c--render-free-hosting-no-vps) | a free account, no server | no: Render answers HTTPS only |

The trust settings must match what stands in front of the judge. They decide
where the client address comes from; a wrong one lets any client spoof its
IP, geo and rate-limit key:

| In front of the judge | `TRUST_PROXY` | `TRUST_CF` |
|---|---|---|
| nothing (`docker run -p`, the default) | `0` | `0` |
| Caddy or nginx on the same host (A) | `1` | `0` |
| Cloudflare, then Caddy or nginx | `1` | `1` |
| Cloudflare Tunnel (B), Render (C) | `1` | `1` (`render.yaml` sets both) |

`TRUST_CF=1` is safe only when every request comes through Cloudflare. A
reverse proxy that adds `X-Real-IP`, `Via` or `Forwarded` itself lists them in
`EDGE_HEADERS`, or every proxy looks `anonymous`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | service, version, repository, geo sources, licenses |
| GET | `/generate_204` | `204` empty — cheap liveness check |
| GET | `/ip` | `{"ip": "..."}` — exit IP |
| GET | `/headers` | `{"ip", "headers", "xff_chain"}` — header echo |
| GET | `/geo` | `{"ip", "geo", "source", "attribution"}` — country/city/ASN from local DBs |
| GET | `/type` | `{"ip", "ip_type", "signals"}` — IP type with reasoning |
| GET | `/content` | fixed bytes — integrity reference |
| GET | `/judge?direct_ip=...&nonce=...` | everything at once + `anonymity`, `content_sha256`; signed, see [Signed answers](docs/signing.md#signed-answers) |
| GET | `/key` | `{"alg", "key_id", "public_key"}` — the public key that signs `/judge` |
| GET | `/healthz` | `{"ok": true}` — liveness probe |
| GET | `/readyz` | `{"ok", "geo_ready", "geo_sources"}` — readiness |
| GET | `/metrics` | Prometheus text counters (optionally behind `METRICS_TOKEN`) |

`/headers` and `/judge` echo the headers as the checked proxy sent them: the
`X-Forwarded-For` hops appended by the deployment's reverse proxy and
`EDGE_HEADERS` are removed. What the edge adds on its own (`Host`,
`X-Forwarded-Proto`, Cloudflare's `cf-*`) is still shown; the verdict does not
blame the proxy for it.

Example `/judge` response through an anonymous proxy, with DB-IP databases:

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

## How verdicts are decided

| `anonymity` | Meaning |
|---|---|
| `transparent` | The checker's `direct_ip` appears in the forwarded chain or in any other header value but `Host` (in any IPv4/IPv6 spelling, percent-encoded too): the proxy leaks the real client IP. |
| `anonymous` | No leak, but the proxy reveals itself: `X-Forwarded-For` entries of its own (even `unknown`; with `TRUST_PROXY=0`, even an empty header), or a header that only proxies add: `Via`, `Forwarded`, `Forwarded-For`, `Forwarded-For-IP`, `X-Forwarded`, any other `X-Forwarded-*` and `X-Real-Port` when nothing stands in front of the judge (`TRUST_PROXY=0`), `X-Real-IP`, `Client-IP`, `X-Client-IP`, `X-Originating-IP`, `X-Cluster-Client-IP`, `X-Remote-IP`, `X-Remote-Addr`, `Coming-From`, `X-Coming-From`, `Xroxy-Connection`, `Proxy-*`, `X-Proxy*`. |
| `elite` | Neither: the request looks like a direct one. |

Without `direct_ip` a leak cannot be told apart from an ordinary forwarded
address, so the result is never worse than `anonymous`. `ip_type` is `mobile`,
`datacenter`, `business`, `residential`, or `unknown`, derived from the ASN
organization (and the PTR record when the organization is unknown);
`type_signals` lists the keywords that matched.

## Using it from the checker

[ProxPulse](https://github.com/nechel12/proxpulse) learns its own IP directly
(`api.ipify.org`, or this judge's `/ip` over HTTPS), then asks
`GET /judge?direct_ip=<its IP>&nonce=<random>` through each proxy. It compares
`content_sha256` with `/content` fetched directly for integrity, and a bare
`GET /generate_204` is the cheapest liveness check. There is no rDNS
parameter: the server resolves PTR itself, only when the ASN organization is
unknown, at most 16 at a time, cached for an hour.

Over plain HTTP a proxy could also rewrite the answer, so every `200` from
`/judge` is signed with Ed25519 over the body, the `nonce` and `direct_ip`;
the public key is at `/key`, to be fetched directly and over HTTPS. The key is
generated at startup unless `SIGNING_KEY` fixes it. What is signed, how a
client should verify it, and when to pin the key:
[docs/signing.md](docs/signing.md).

## Public instances

These are shared, best-effort instances without an availability guarantee.
For regular measurements, a self-hosted instance is required (variants A–C
above).

- **https://proxycheck.lmtunnel.com** — the checker's built-in judge. Answers
  plain HTTP too, so it gives anonymity verdicts. Configured with a 1000
  requests per minute per client limit (429 + `Retry-After` on exceed; the
  table below lists the code default of 6000).
- **https://proxpulse-judge.onrender.com** — free Render hosting, DB-IP Lite
  databases, image refreshed monthly. HTTPS only, so no anonymity verdict.
  The free plan sleeps after 15 minutes without traffic (waking up takes
  about a minute) and is limited to roughly 750 hours per month, so it may be
  unavailable near the end of the month until the quota resets.

Load is expected to remain reasonable: reverse-DNS is done by the server itself
and only for unknown ASN orgs; no client-side requests are needed.

## Databases

The service finds the files in `GEO_DIR` (`./geo`, mounted read-only by
`docker-compose.yml`) by itself: `GeoLite2-City.mmdb` or
`dbip-city-lite.mmdb`, `GeoLite2-ASN.mmdb` or `dbip-asn-lite.mmdb`, and a
Country database as the fallback when there is no City. Without files the geo
fields are empty (`"error": "no db"`) and everything else works.

Each database has its own terms, and its attribution must be shown wherever
its results are:

- **DB-IP Lite** — [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/),
  attribution `IP Geolocation by DB-IP` linking to <https://db-ip.com>;
  updated monthly; baked into the published image.
- **MaxMind GeoLite2** — a free account and key, the
  [GeoLite EULA](https://www.maxmind.com/en/geolite/eula); attribution
  `This product includes GeoLite2 Data created by MaxMind, available from
  https://www.maxmind.com`. Never in the published image.

The databases do not update themselves: `scripts/download-dbip.sh` or
`scripts/download-geolite2.sh` (with `MAXMIND_LICENSE_KEY`), then a restart.
A monthly cron line and the image's own fallback are in
[docs/deploy.md](docs/deploy.md#do-databases-update-themselves-no).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8000` | HTTP port |
| `BIND_ADDR` | `0.0.0.0` | listen address; `::` also accepts IPv6 where the host allows dual-stack sockets |
| `GEO_DIR` | `/app/geo` | `.mmdb` directory |
| `TRUST_PROXY` | `0` | `1` — behind a reverse proxy (IP from the end of `X-Forwarded-For`), `0` — directly exposed (IP from socket, headers untrusted); `.env.example` explicitly sets `1` |
| `TRUST_CF` | `0` | `1` — trust `CF-Connecting-IP`; only behind Cloudflare/Tunnel and only with `TRUST_PROXY=1`. `0` — ignore (safe for Caddy/VPS) |
| `EDGE_HEADERS` | empty | comma-separated headers the deployment's reverse proxy adds (e.g. `x-real-ip,via`); they are neither analysed nor echoed. Only with `TRUST_PROXY=1`; `x-forwarded-for` is not allowed |
| `RDNS_TIMEOUT` | `1.5` | server-side rDNS timeout, seconds, from `0` (rDNS off) to `10` |
| `RATE_LIMIT_PER_MINUTE` | `6000` | token-bucket burst and sustained requests per client per minute (an IPv4 address or an IPv6 `/64`), `0` — no limit |
| `METRICS_TOKEN` | empty | when set, `/metrics` requires `Authorization: Bearer <token>`; send it over HTTPS only |
| `SIGNING_KEY` | empty | fixed key for signing `/judge` answers: 32 bytes in base64 (`openssl rand -base64 32`); empty — a key generated at startup, see [Signed answers](docs/signing.md#signed-answers); a malformed key stops startup |
| `RUST_LOG` | `info` | log level |

`TRUST_PROXY` and `TRUST_CF` accept `1`/`0`, `true`/`false`, `yes`/`no`,
`on`/`off`. Any other value, a `PORT`, `RDNS_TIMEOUT` or
`RATE_LIMIT_PER_MINUTE` that is not a number in range, an invalid `BIND_ADDR`,
or a malformed `EDGE_HEADERS` stops the service at startup instead of silently
falling back to a default or changing which headers are trusted. `TRUST_CF=1`
without `TRUST_PROXY=1` is ignored with a warning in the log.

With `TRUST_PROXY=1`, the client IP is taken from the **last**
`X-Forwarded-For` entry. Caddy 2.5+ replaces the incoming XFF with the
immediate client address by default; `Caddyfile.example` enables
`trusted_proxies` to preserve the checked proxy's chain, so Caddy appends
the client address at the end. nginx (`proxy_add_x_forwarded_for`) and
Cloudflare append as well. With `TRUST_PROXY=1`, reverse-proxy headers such
as `X-Forwarded-Proto`/`Host` do not count as proxy headers, otherwise
everything behind a reverse proxy would look `anonymous`; their values are
still searched for a leak. With `TRUST_PROXY=0` nothing stands in front of the
judge, so they mark a proxy like any other `X-Forwarded-*`. With `TRUST_CF=1`,
`CF-Connecting-IP` takes priority.

## Monitoring

- `GET /healthz` — liveness.
- `GET /readyz` — readiness plus `geo_ready` and the loaded `geo_sources`.
- `GET /metrics` — Prometheus text counters (requests, 4xx/5xx, rate limits,
  rDNS, build info). On a public instance, `METRICS_TOKEN` is set (or the path
  is blocked at the reverse proxy).

Request headers must arrive within 10 seconds, at most 4096 connections are
open at once, and a request is capped at 20 seconds and 512 concurrent
requests. Monitoring endpoints are exempt from the rate and concurrency
limits; metrics are process-local and reset on restart.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Every check is `anonymous`, even an elite proxy | A reverse proxy or hosting platform on the deployment side adds a proxy header itself: `X-Real-IP`, `Via`, or `Forwarded` (typical for nginx), `Client-IP` or `X-Client-IP` (Azure App Service). Such headers are removed from the proxy configuration or listed in `EDGE_HEADERS`. `GET /headers` directly shows what reaches the judge. |
| A direct check (no proxy) is `transparent`, and `/ip` shows `127.0.0.1` or `172.x` | The judge is behind a reverse proxy with `TRUST_PROXY=0`: `TRUST_PROXY=1` is required. |
| A proxy known to leak is reported `elite` behind Caddy | Caddy drops the incoming `X-Forwarded-For`: `trusted_proxies` is required, as in `Caddyfile.example`. `/judge` must also be reached over plain HTTP, like the `http://` block in `Caddyfile.example`. |
| The checker shows no anonymity at all (`—`) with this judge | `http://<host>/judge` is redirected to HTTPS (Render, Caddy without the `http://` block, Cloudflare's Always Use HTTPS). Anonymity is only visible over plain HTTP; `curl -sI http://<host>/judge` must answer `200`, not `301`/`308`. |
| `/ip` shows a Cloudflare address (`172.64.x`, `162.158.x`, …) | Traffic comes through Cloudflare but `TRUST_CF=0`: `TRUST_CF=1` and `TRUST_PROXY=1` are required. |
| Geo fields are empty with `"error": "no db"`; `/readyz` has `"geo_ready": false` | No `.mmdb` in `./geo`. The fix is to run `bash scripts/download-dbip.sh` and restart the container. |
| The container exits with `invalid configuration` | A misspelled `TRUST_*` value, an invalid `BIND_ADDR`, `x-forwarded-for` in `EDGE_HEADERS`, or a malformed `SIGNING_KEY`; the log names the variable. |
| `/metrics` returns `401` | `METRICS_TOKEN` is set: the request must include `Authorization: Bearer <token>`. |
| Render: the first request after a pause times out | The free plan sleeps after 15 minutes; a retry after about a minute resolves it. |

## Limitations

- Anonymity and IP-type results are heuristics. A proxy can withhold or forge
  headers, and local data cannot prove residential-vs-business the way paid
  ASN databases can.
- TLS/JA3 is not inspected: TLS terminates at Caddy, Cloudflare, Render, or
  another reverse proxy.
- Geo accuracy depends on the local database and its update cadence.
- Hop-by-hop headers (`Proxy-Connection`, `Proxy-Authorization`, `Connection`,
  `Keep-Alive`) never reach the judge behind Caddy or nginx, which drop them,
  so a proxy that passes them on is not caught by them.
- The public instances are shared and best-effort; a self-hosted instance is
  required for reliable measurements.

## Security

Vulnerability reporting is described in [SECURITY.md](SECURITY.md).

The judge is a diagnostic tool, not a security boundary. It does not
authenticate clients and cannot force a proxy to reveal headers; verdicts are
best-effort. It should run behind a TLS-terminating reverse proxy, with the HTTP
port bound to loopback, a rate limit configured, and `TRUST_PROXY`/`TRUST_CF`
matching the actual topology. A misconfigured trusted header lets clients spoof
the reported IP/geo and the rate-limit key.

## Development

```sh
cargo test
PORT=8000 GEO_DIR=./geo TRUST_PROXY=0 cargo run
bash scripts/smoke.sh http://127.0.0.1:8000
```

The code layout, the checks a change must pass and the release process are in
[CONTRIBUTING.md](CONTRIBUTING.md) and [RELEASING.md](RELEASING.md); release
notes are in [CHANGELOG.md](CHANGELOG.md). Bug reports and pull requests are
welcome under the [Code of Conduct](CODE_OF_CONDUCT.md); security issues go
through [SECURITY.md](SECURITY.md), not a public issue.

## Related projects

- [proxpulse](https://github.com/nechel12/proxpulse) — desktop proxy
  checker (Tauri 2) that uses the judge as its check backend; the public
  instance above is embedded in it by default.

## License

The code is licensed under Apache-2.0; the license text is in
[LICENSE](LICENSE). Geolocation databases are not part of the code license:
DB-IP Lite is CC BY 4.0, and MaxMind GeoLite2 is governed by the GeoLite2 EULA.
Database files are downloaded separately or baked into the DB-IP image with
attribution.

---

## Support the project

ProxPulse Judge is free and open source. If it saves time, further development
can be supported here:

<p align="center">
  <a href="https://boosty.to/nechel12/donate">
    <img src="https://img.shields.io/badge/Boosty-Donate-F15F2C?style=for-the-badge&logo=boosty&logoColor=white" alt="Donate via Boosty">
  </a>
</p>

### Crypto

| Network | Address |
|:--------|:--------|
| **TRON** | `TMM2Cdm4tJx1nKRRq5RCBcdwfn9cHuJZy9` |
| **TON** | `UQBlVvOfTleWn4pkY384mYWiGyhdHBryoC_N1Si1OSWAxPKl` |
| **Bitcoin** | `bc1qagjtnutjya2rss3u3ls8ur7qk0u7zutc6t6fwc` |
| **BNB Smart Chain** | `0x423aF840f67355371bf32480744A84069dfab5ff` |

> [!WARNING]
> Only the asset matching the specified network may be sent. Transfers to
> another network cannot be recovered.
