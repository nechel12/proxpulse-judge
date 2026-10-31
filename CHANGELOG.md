# Changelog

## Unreleased

### Security

- The published image (`Dockerfile.render`) no longer bakes in
  `TRUST_PROXY=1` and `TRUST_CF=1`. Run directly, it trusted
  `CF-Connecting-IP` from any client, so IP, geo, and the rate-limit key could
  be spoofed. **Upgrade note:** Render services created from `render.yaml`
  already set both variables; services configured by hand must add them.
- Rate limiting keys IPv6 clients by their `/64` network, so rotating source
  addresses within one allocation no longer bypasses the limit.
- Pin all GitHub Actions to commit SHAs.

### Changed

- Scheduled and release builds publish only an image that passed the smoke
  test with the baked databases and a Trivy scan, with provenance, an SBOM,
  and a signed GitHub attestation.
- `:vX.Y.Z` images are published from signed `vX.Y.Z` tags on `main` that
  match `Cargo.toml` and are never overwritten. Manual workflow runs only
  refresh `:latest` and `:YYYYMM`, and only from `main`.

### Added

- Tests read real `.mmdb` files (a minimal test writer), covering
  `maxminddb` open, lookup, decode, verify, and attribution.
- `scripts/container-smoke.sh` and `SMOKE_EXPECT_GEO=1` for `scripts/smoke.sh`.
- Release tag and image verification steps in `RELEASING.md`.

## 0.5.6 — 2026-10-30

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

## 0.5.5 — 2026-10-27

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

## 0.5.4 — 2026-10-27

### Changed

- Upgraded `axum` from 0.7 to 0.8; handlers now use the non-optional
  `ConnectInfo` extractor, with the test harness injecting connect info.
- Upgraded `maxminddb` from 0.27 to 0.32 (metadata accessor migration).
- Enabled GitHub CodeQL code scanning for Rust and GitHub Actions.
- Dev dependency `tower` is now 0.5 to match axum 0.8.

## 0.5.3 — 2026-10-27

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
