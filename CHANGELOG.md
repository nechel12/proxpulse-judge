# Changelog

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
