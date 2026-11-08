# Deployment

**English** | [Русский](deploy.ru.md)

How to run the judge where a checker can reach it. The choice of
variant and the trust settings for each are summed up in the
[README](../README.md#deployment).

## Prebuilt image and binaries

CI publishes a multi-arch (`linux/amd64`, `linux/arm64`) image with embedded
DB-IP Lite databases to GHCR:

```sh
docker pull ghcr.io/nechel12/proxpulse-judge:latest
```

`:latest` is always the latest signed release, never unreleased code from
`main`. Monthly scheduled builds rebuild that release with fresh databases and
update `:latest` and `:YYYYMM`; signed `vX.Y.Z` release tags additionally
publish `:vX.Y.Z`, which is never overwritten. Every image passes a smoke test with the baked databases
and a Trivy scan before it is pushed, and carries a signed build provenance
attestation:

```sh
gh attestation verify oci://ghcr.io/nechel12/proxpulse-judge:latest --owner nechel12
```

The images contain no MaxMind data. On a VPS,
[`docker-compose.ghcr.yml`](../docker-compose.ghcr.yml) runs the image with the
same limits as `docker-compose.yml`, but without the `./geo` volume, which
would hide the baked databases:

```sh
cp .env.example .env
docker compose -f docker-compose.ghcr.yml up -d
# update to a new release or the monthly databases:
docker compose -f docker-compose.ghcr.yml pull && docker compose -f docker-compose.ghcr.yml up -d
```

With your own MaxMind or DB-IP files, the default `Dockerfile` target is built
and `./geo` is mounted (`docker-compose.yml`), as described below.

Each [GitHub release](https://github.com/nechel12/proxpulse-judge/releases)
also ships static Linux binaries (`x86_64`, `aarch64`) with `SHA256SUMS` and
attestations. An archive holds the binary, `.env.example` and
`download-dbip.sh`. The binary reads no `.env` file: its settings come from
the environment, for example from a systemd unit:

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
> The image defaults to `TRUST_PROXY=0` and `TRUST_CF=0`: the client IP is the
> socket address. Both values must match the deployment topology (`render.yaml`
> already sets them to `1` for Render). `TRUST_CF=1` is safe only when every
> request reaches the container through Cloudflare: otherwise any client can
> spoof its IP, geo and rate-limit key with a `CF-Connecting-IP` header.

## Variant A — Caddy (reverse proxy)

A **dedicated domain** is required (no HTTPS certificate is issued without
one). The subdomain can be anything, e.g. `check.yourdomain.com`: an
**A-record** for the subdomain is created in the registrar's DNS panel,
pointing at the server IP, and ports **80 and 443** must face the internet.
Example in `Caddyfile.example`:

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

Caddy issues a Let's Encrypt certificate automatically. The `http://` block
keeps `/judge`, `/content`, `/headers`, and `/ip` on plain HTTP and redirects
everything else, `/key` included, to HTTPS: anonymity is only visible over
plain HTTP (see [Signed answers](signing.md#signed-answers)), and without that block
Caddy redirects all of port 80. Verification:

```sh
curl https://check.yourdomain.com/healthz
curl -s http://check.yourdomain.com/judge | head -c 200; echo   # JSON, not a redirect
```

`Caddyfile.example` enables `trusted_proxies`: since Caddy 2.5 the incoming
`X-Forwarded-For` from the checked proxy is dropped by default, so the judge
would not see a real-IP leak passed via XFF. Trusting XFF from all clients is
safe only because the judge listens on `127.0.0.1` and is reachable solely
through Caddy. `TRUST_CF=0` (the default) is required for this variant: there
is no Cloudflare here, and CF headers are trivially forgeable. With it the
judge never takes the client address from `CF-Connecting-IP` or
`True-Client-IP`; it only searches them for the checker's real IP, like any
other header, so the examples pass them through.

If Cloudflare sits **in front of** Caddy, `trusted_proxies` is set to Cloudflare's ranges instead of `0.0.0.0/0`, ports
80/443 are restricted to Cloudflare IPs (or Authenticated Origin Pulls is
used, since `trusted_proxies` only governs `X-Forwarded-*`, not
`CF-Connecting-IP`), and both `TRUST_CF=1` and `TRUST_PROXY=1` are required.

### nginx instead of Caddy

[`nginx.conf.example`](../nginx.conf.example) is the equivalent configuration,
with the same plain-HTTP `location` for `/judge`, `/content`, `/headers`, and
`/ip` on port 80. The important parts:

```nginx
location ~ ^/(judge|content|headers|ip)$ { ... }   # port 80, no redirect
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

nginx appends the connecting address to the proxy's `X-Forwarded-For`, so
`TRUST_PROXY=1` works as with Caddy. `X-Real-IP`, `Via`, and `Forwarded` are
**not** added there (many nginx templates do): the judge treats them as proxy
telltales, and every check would come out `anonymous`. If a configuration
requires them, they are listed in `EDGE_HEADERS` (e.g.
`EDGE_HEADERS=x-real-ip`) so they are not attributed to the checked proxy.

## Variant B — Cloudflare Tunnel (no Caddy, no open ports)

```sh
cloudflared tunnel --url http://127.0.0.1:8000
```

or no config-file commands at all — via the Cloudflare website:
**Zero Trust → Networks → Tunnels → Create a tunnel**; a tunnel name is
chosen, and the **Public Hostname** tab contains: subdomain `check`, domain
`yourdomain.com` (together `check.yourdomain.com`), service
`http://proxpulse-judge:8000` (container on the shared network; details below) or
`http://127.0.0.1:8000` (cloudflared on the host). The token from the website
is passed into the connector container:

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
> automatically. The command above starts the tunnel on it already; a tunnel
> started without `--network proxpulse-net` is connected like this:
>
> ```sh
> docker network connect proxpulse-net cf-tunnel
> docker network inspect proxpulse-net --format '{{range .Containers}}{{.Name}} {{end}}'
> # both must be visible: proxpulse-judge and cf-tunnel
> ```
>
> with ingress/service pointing to `http://proxpulse-judge:8000`.
> cloudflared on the host itself simply goes to `http://127.0.0.1:8000`.

`TRUST_CF=1` and `TRUST_PROXY=1` are required explicitly in this variant;
`TRUST_CF` defaults to `0`, which is safe for Caddy/VPS. The service takes
the real IP from `CF-Connecting-IP` (set by Cloudflare itself, takes
priority over `X-Forwarded-For`). Known Cloudflare infrastructure headers are
excluded from anonymity detection, while unknown `cf-*` headers are still checked
for `direct_ip` leaks. Verification:

```sh
MYIP=$(curl -s https://api.ipify.org)
curl -s "http://check.yourdomain.com/judge?direct_ip=$MYIP" | head -c 300; echo
# expect "anonymity":"elite"
```

For anonymity the hostname must answer plain HTTP: Cloudflare's **Always Use
HTTPS** (SSL/TLS → Edge Certificates) stays off for it, otherwise every HTTP
request is redirected and the checker gets no anonymity verdict.

## Variant C — Render (free hosting, no VPS)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/nechel12/proxpulse-judge)

A ready image with embedded DB-IP Lite rebuilds itself every month
(`.github/workflows/docker.yml` → `ghcr.io/nechel12/proxpulse-judge:latest`),
no disk needed. The button creates the service from `render.yaml` with
a free `https://<name>.onrender.com` domain. The resulting URL is used in
the checker. No Cloudflare Tunnel is needed in this setup: Render
provides both TLS and the domain. Render redirects all plain HTTP to HTTPS, so
a Render instance gives IP, geo, and IP type but **no anonymity verdict**; for
that, variant A or B is needed.

Free-plan notes:

- The service sleeps after 15 minutes without traffic; waking up takes
  about a minute. The first check after idle may partially fail on
  timeouts — repeating it is sufficient. A single service approximately
  matches the free 750 h/month allowance.
- The filesystem is ephemeral, but that is fine: the databases are
  baked into the image.
- `TRUST_PROXY=1` and `TRUST_CF=1` are required (Render traffic passes
  through Cloudflare; the real IP is taken from `CF-Connecting-IP`).
  `render.yaml` sets both; the image itself defaults to `0`, so a service
  created by hand needs both variables in the Render dashboard
  (Environment). The `PORT` variable is provided by Render and must not
  be overridden.
- `render.yaml` also generates a random `METRICS_TOKEN`, so `/metrics` of a
  public instance is not open; the token is under Environment.
- The image carries DB-IP Lite only: the GeoLite2 EULA restricts public
  redistribution, so MaxMind data is not baked into the published image.
  MaxMind requires the VPS + volume variant above.

Database updates (the image rebuilds on the 3rd of every month):

1. **Fork + auto-hook.** A fork of the repository is created, workflows are
   enabled in the fork's Actions tab (disabled by default), a
   `RENDER_DEPLOY_HOOK` secret is added (Render dashboard → service →
   Settings → Deploy Hook), and the fork's `render.yaml` points at its own
   `ghcr.io/<owner>/proxpulse-judge:latest`. Fresh images are then published
   to the fork's GHCR and trigger redeploys automatically. A fork builds its
   own `main`, not the latest release, so it is kept in sync (Sync fork).
   Limitation: the schedule is disabled after 60 days without activity in the
   fork — the workflow is run manually from time to time (Run workflow).
2. **Manually.** Render dashboard → service → Manual Deploy →
   Deploy latest reference. Geo data changes slowly, so manual updates
   are usually sufficient.
3. **Own scheduler, no fork.** The service can track
   `ghcr.io/nechel12/proxpulse-judge:latest` directly while any external
   scheduler (own server, cron-job.org, etc.) calls the deploy hook monthly.

The image is compatible with other container hostings: `$PORT`
passthrough and `/healthz` as the health check are required.

## Do databases update themselves? No

`scripts/download-dbip.sh` (no keys) or `scripts/download-geolite2.sh`
(needs `MAXMIND_LICENSE_KEY` from a free account) are manual: after download,
files land in `./geo`, and a container **restart is required** (the geo cache
lives in memory, new files are not picked up without a restart). For
automation — monthly cron + restart:

```cron
0 4 3 * * cd /opt/proxpulse-judge && bash scripts/download-dbip.sh >/tmp/dbip.log 2>&1 && docker compose restart judge
```

`docker-compose` mounts `./geo` **read-only**, so the entrypoint cannot
write there: for compose, the databases are downloaded on the host
(`bash scripts/download-dbip.sh`), or an image with baked databases is used
(Render). The entrypoint fallback only works when `GEO_DIR` is writable
(e.g. `docker run` without a read-only mount); otherwise it logs a warning
and starts without geo. Custom files (MaxMind or DB-IP) take precedence —
the fallback only fires when no valid `.mmdb` is present.

## Maintenance: logs

The service logs to stdout. Docker's `json-file` driver stores them with no
size limit by default, so `docker-compose.yml` sets limits (`max-size: 10m`,
`max-file: 3` — up to ~30 MB per container). With a compose setup no further
configuration is needed. The compose service also runs with a read-only root
filesystem, no capabilities, `no-new-privileges`, and a 512 MB memory limit.

Without Docker the binary logs to stdout too: under systemd, journald keeps
and rotates the log (`journalctl -u proxpulse-judge`).
