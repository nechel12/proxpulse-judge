# Contributing

Bug reports and pull requests are welcome. Please keep changes focused and
explain the behavior and tradeoffs in the PR description.

## Development

- Rust stable (via [rustup](https://rustup.rs/)) for the service.
- Docker with Compose if you change container files or deployment examples.
- Before sending a change:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
for f in scripts/*.sh; do bash -n "$f"; done
```

For Docker changes, build the affected image:

```sh
docker build .                   # runtime target (VPS, docker compose)
docker build --target render .   # Render image with baked DB-IP Lite
```

The `render` target downloads the DB-IP Lite databases and is slower; the
default target is enough for most code changes. Base images are pinned by
digest; let Dependabot bump them.

Run the service locally:

```sh
PORT=8000 GEO_DIR=./geo TRUST_PROXY=0 cargo run

bash scripts/smoke.sh http://127.0.0.1:8000
bash scripts/load.sh http://127.0.0.1:8000 300 32
```

## Pull requests

- Add or update tests for logic and HTTP changes.
- Add a line under `## [Unreleased]` in `CHANGELOG.md` for every
  user-visible change.
- Update `README.md` and `README.ru.md` together when behavior or
  configuration changes; a new environment variable also goes into
  `.env.example`, and into `render.yaml` when Render needs it.
- Do not commit secrets, `.env` files, database files, or build artifacts.
- Keep CI green. The `docker` workflow runs formatting, clippy and tests on
  stable and on the MSRV (`rust-version` in `Cargo.toml`), `cargo audit`,
  actionlint, hadolint, a shell syntax check, and builds the image for a smoke
  and load check and a Trivy scan. `scripts/smoke.sh` reads
  `SMOKE_METRICS_TOKEN` when `/metrics` needs a token.

## Reporting security issues

Follow [SECURITY.md](SECURITY.md). Do not open a public issue with exploit
details.

## Releases

See [RELEASING.md](RELEASING.md) and [CHANGELOG.md](CHANGELOG.md).

## Conduct

Be respectful and constructive. Harassment, discrimination, and personal
attacks are not acceptable. By participating, you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under
Apache-2.0, the project's license.
