# Changelog

## [Unreleased]

### Security

- A setting that is not valid Unicode now stops startup, except `RUST_LOG`.
  Before, it counted as unset, so such a `METRICS_TOKEN` left `/metrics` open.
- A client that connects and sends nothing, or only the start of an HTTP/2
  preface, is now cut off by the 10-second header timeout. Before, it held one
  of the 4096 connection slots forever, so enough of them stopped the service,
  `/healthz` included. The judge now serves HTTP/1 only (every edge in front
  of it talks HTTP/1.1), buffers at most 64 KB per connection while reading
  headers, closes a connection whose response makes no progress for 30
  seconds (a client that stops reading), and closes any connection after 5
  minutes.
- Scheduled and manual image builds rebuild the latest signed release instead
  of `main`'s HEAD, so unreleased code no longer reaches `:latest`, `:YYYYMM`
  or the Render redeploy. Forks still build their own `main`.

### Fixed

- `Client-IP`, `X-Client-IP`, `X-Originating-IP`, `X-Cluster-Client-IP`,
  `Forwarded-For`, `Forwarded-For-IP`, `X-Forwarded`, `X-Remote-IP`,
  `X-Remote-Addr`, `Coming-From`, `X-Coming-From`, and `Xroxy-Connection` now
  mark a proxy, so such a proxy is `anonymous` instead of a false `elite`.
  **Upgrade note:** a platform in front of the judge that adds one of them
  itself (Azure App Service adds `Client-IP` and `X-Client-IP`) needs it in
  `EDGE_HEADERS`, or every check comes out `anonymous`.
- The Caddy and nginx examples serve `/judge`, `/content`, `/headers`, and `/ip`
  over plain HTTP on port 80 and redirect the rest to HTTPS. Before, they
  redirected all HTTP, so no documented deployment gave an anonymity verdict.
  The README now says which deployments and public instances answer plain HTTP.
- Without `TRUST_PROXY`, `X-Forwarded-Proto`, `-Host`, `-Port` and every
  other `X-Forwarded-*` header mark a proxy, as does an empty
  `X-Forwarded-For`; before, they always counted as the judge's own reverse
  proxy and gave `elite`. Their values are now searched for a leak with or
  without `TRUST_PROXY`, so an `X-Forwarded-Host` with the checker's real IP
  is `transparent` (a copy of `Host` our reverse proxy makes is not).
- A leaked address is found in looser notations: `for=1.2.3.4` or
  `"1.2.3.4"` in `X-Forwarded-For`, an address followed by a full stop or
  preceded by a label (`src:2001:db8::1`), and percent-encoded addresses. The
  `Host` header is no longer searched: it names the judge. Behind Cloudflare,
  only `CF-Connecting-IP` and a `True-Client-IP` that repeats it are left
  out of the search; a proxy's value in `CDN-Loop` or its own
  `True-Client-IP` is found.
- A proxy that writes its own exit address into `X-Forwarded-For` is
  `anonymous` behind Cloudflare too, as it already was behind Caddy and nginx;
  only the copy Cloudflare appends is removed.
- The Caddy and nginx examples no longer strip `CF-Connecting-IP` and
  `True-Client-IP`. With `TRUST_CF=0` the judge never takes the client address
  from them, so stripping them only hid proxies that leak the real IP there.
- `--check-geo` fails when a database file it tries cannot be used, not only
  when none loads, and `download-dbip.sh` checks City and ASN each on its
  own. Before, a good City file let a broken ASN download replace a working
  one.
- Of several dated databases of one kind (`dbip-city-lite-2026-11.mmdb`), the
  newest is used instead of the oldest.

## [0.6.1] — 2026-11-07

### Security

- Base image updated to a Debian 13 build with `apt` 3.0.4 (CVE-2026-109518).

### Added

- Signed answers: successful `/judge` answers carry an Ed25519 signature over
  the body, the request's `nonce` and `direct_ip` (`X-Judge-Signature`,
  `X-Judge-Key-Id`), and `/key` serves the public key. A checked proxy that is
  not on the client's direct path to the judge can no longer rewrite or replay
  an answer over plain HTTP unnoticed; the README describes the limits. Signing
  needs no setup: the key is generated at startup unless `SIGNING_KEY` sets a
  fixed one, which several replicas behind one address must share.

## [0.6.0] — 2026-10-31

### Security

- The published image no longer bakes in `TRUST_PROXY=1` and `TRUST_CF=1`.
  Run directly, it trusted `CF-Connecting-IP` from any client, so IP, geo, and
  the rate-limit key could be spoofed. **Upgrade note:** Render services
  created from `render.yaml` already set both variables; services configured
  by hand must add them.
- Rate limiting keys IPv6 clients by their `/64` network, so rotating source
  addresses within one allocation no longer bypasses the limit.
- Request headers must arrive within 10 seconds and at most 4096 connections
  are open at once (`axum::serve` set neither), closing slowloris-style
  connection exhaustion on directly exposed instances.
- Optional `METRICS_TOKEN` protects `/metrics` with a bearer token.
- All responses carry `X-Content-Type-Options: nosniff`.
- `TRUST_PROXY`/`TRUST_CF` accept `true`/`false`, `yes`/`no`, `on`/`off`; an
  unrecognized value now stops startup instead of silently meaning "off".
- Pin all GitHub Actions to commit SHAs, and base images to digests.

### Added

- `EDGE_HEADERS`: headers your own reverse proxy adds (e.g. nginx
  `X-Real-IP`) are no longer attributed to the checked proxy.
  `nginx.conf.example` and a README section cover nginx.
- `BIND_ADDR` to choose the listen address (e.g. `::` for IPv6).
- Multi-arch images (`linux/amd64`, `linux/arm64`), each built on a native
  runner and tested before it is pushed.
- Releases are created from signed tags with static Linux binaries
  (`x86_64`, `aarch64`), `SHA256SUMS`, and attestations.
- Tests read real `.mmdb` files (a minimal test writer), covering
  `maxminddb` open, lookup, decode, verify, and attribution, plus server
  tests for the header timeout and connect info.
- CI checks the minimum supported Rust version (1.88) and caches builds.
- `scripts/container-smoke.sh`, `scripts/release-notes.sh`,
  `SMOKE_EXPECT_GEO=1` and `SMOKE_METRICS_TOKEN` for `scripts/smoke.sh`.
- README: table of contents, verdict rules with a diagram, a full `/judge`
  example, and troubleshooting.

### Changed

- `/judge` and `/headers` echo headers as the checked proxy sent them: the
  `X-Forwarded-For` hops our reverse proxy appended (and `EDGE_HEADERS`) are
  removed, and the `"(stripped)"` placeholder is gone.
- Scheduled and release builds publish only images that passed the smoke
  test with the baked databases and a Trivy scan, with provenance, an SBOM,
  and a signed GitHub attestation.
- `:vX.Y.Z` images are published from signed `vX.Y.Z` tags on `main` that
  match `Cargo.toml` and are never overwritten. Manual workflow runs only
  refresh `:latest` and `:YYYYMM`, and only from `main`.
- One `Dockerfile` with `runtime` (default) and `render` targets replaces
  `Dockerfile.render`; images are based on Debian 13 (trixie), and the
  Render image no longer contains `curl`.
- `docker-compose.yml` runs the service with a read-only root filesystem,
  no capabilities, `no-new-privileges`, and a 512 MB memory limit.
- Rust edition 2024, `rust-version = 1.88`, a size-optimized release
  profile, and minimal tokio features; `src/main.rs` is split into
  `config`, `server`, `app`, `ratelimit`, and `metrics` modules.
- Dependabot groups minor/patch updates.

## [0.5.6] — 2026-10-30

### Added

- Run RustSec audits, actionlint, hadolint, and Trivy image scans in CI.

### Security

- Default `TRUST_PROXY` to `0`; deployments behind a reverse proxy must opt in
  explicitly, so direct exposure cannot spoof client IPs through XFF by default.

### Changed

- Replace per-request rate-limit history with constant-size token buckets while
  preserving the configured burst and sustained per-minute limits.
- Scheduled container builds update only `latest` and `YYYYMM`; immutable
  version tags are published only by manual release builds.

### Fixed

- Check unknown `cf-*` headers for direct-IP leaks instead of treating every
  Cloudflare-prefixed name as infrastructure.
- Classify multi-hop XFF chains without a `direct_ip` match as `anonymous`, not
  `transparent`, and stop treating legal company suffixes as business-IP signals.
- Return an exact token-bucket `Retry-After` delay instead of up to 61 seconds
  for an exhausted one-minute window.

## [0.5.5] — 2026-10-27

### Security

- Skip server-side rDNS lookups for loopback, private, link-local, CGNAT, and
  documentation IP ranges so local/container hostnames and internal PTR records
  are not exposed.
- Canonicalize IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) and normalize IP
  tokens in non-XFF headers (`X-Real-IP`, `Forwarded`, `X-Client-IP`) during
  leak detection.
- Decode header values with `from_utf8_lossy` so non-ASCII bytes cannot blank
  out a header and mask a leaked `direct_ip`.
- Pass `MAXMIND_LICENSE_KEY` download URLs via `curl --config -` stdin and
  extract archives with `--no-same-owner` in `scripts/download-geolite2.sh`.

### Fixed

- Classify non-IP `X-Forwarded-For` placeholders (such as Squid's `unknown`) as
  `anonymous` rather than `elite`, and strip reverse-proxy hops before
  filtering invalid XFF tokens.
- Order `rate_limit_mw` outside `concurrency_mw` so rate-limited requests do
  not consume concurrency permits.
- Fix `scripts/download-dbip.sh` previous-month date calculation on the 31st of
  months following 28–30 day months, and add BSD/macOS `date -v-1m` fallback.
- Check extracted fields in `GeoPool::lookup` before suppressing the country DB
  fallback, and inspect MMDB `database_type` metadata for attribution.
- Isolate CI workflow concurrency by event type, scope `packages: write` to the
  `build` job, and enforce `--locked` in Docker and CI builds.

## [0.5.4] — 2026-10-27

### Changed

- Upgraded `axum` from 0.7 to 0.8; handlers now use the non-optional
  `ConnectInfo` extractor, with the test harness injecting connect info.
- Upgraded `maxminddb` from 0.27 to 0.32 (metadata accessor migration).
- Enabled GitHub CodeQL code scanning for Rust and GitHub Actions.
- Dev dependency `tower` is now 0.5 to match axum 0.8.

## [0.5.3] — 2026-10-27

### Security

- Default `TRUST_CF` is now `0`; CF headers require both `TRUST_CF=1` and
  `TRUST_PROXY=1`. This prevents spoofed client IPs, geo, and rate-limit keys
  on Caddy/VPS deployments.
- CF infrastructure headers are only excluded from anonymity checks when CF
  headers are actually trusted.
- IP comparisons are normalized and exact; prefix collisions and alternate
  IPv6 forms no longer produce false verdicts.
- Duplicate forwarding headers are merged consistently.
- CDN chains are truncated at the last client occurrence, so prepended hops
  cannot hide a leak.
- `RDNS_TIMEOUT` is validated and clamped (0–60s); invalid values cannot panic
  at startup.
- Rate-limit state is bounded and sharded per key; the global sweep was
  removed.
- Dependency updates: `maxminddb` 0.27.3 (fixes
  GHSA-mj73-j457-8x9q), `sha2` 0.11.1, `serde_json` 1.0.154, updated CI
  actions.

### Added

- `GET /readyz` (readiness plus geo state) and `GET /metrics` (Prometheus
  text counters).
- Request timeout (20s) and a 512-request concurrency cap; monitoring
  endpoints are exempt.
- `download-dbip.sh` / `download-geolite2.sh` retries, timeouts, atomic
  replacement, and optional full `.mmdb` validation via `--check-geo`.
- `scripts/smoke.sh` and `scripts/load.sh`; CI now builds the image and runs
  both.
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR templates,
  Dependabot config, and a security/CI badge set.
- `/` exposes the repository URL; `/geo` and `/judge` expose database
  attribution.
- English README is the primary document; Russian README is linked.

### Changed

- Caddy documentation and example explicitly cover `trusted_proxies` and CF
  header stripping; `TRUST_CF` is documented per deployment.
- Public instances are described as shared, best-effort services.
- Geo source metadata, shape fallbacks, and `registered_country` handling were
  improved.

### Fixed

- Caddy 2.5+ XFF handling and nginx/Cloudflare chain semantics.
- Read-only `./geo` fallback behavior is documented and reported clearly.
- Healthcheck parses the status line and stays below the Docker timeout.
- Dynamic responses are `no-store`; only `/content` is cacheable.
- `RUST_LOG` defaults to `info`; bind/serve failures are reported instead of
  panicking.

## Earlier versions

See the git history for 0.5.2 and earlier.

[Unreleased]: https://github.com/nechel12/proxpulse-judge/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/nechel12/proxpulse-judge/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/nechel12/proxpulse-judge/compare/v0.5.6...v0.6.0
[0.5.6]: https://github.com/nechel12/proxpulse-judge/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/nechel12/proxpulse-judge/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/nechel12/proxpulse-judge/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/nechel12/proxpulse-judge/releases/tag/v0.5.3
