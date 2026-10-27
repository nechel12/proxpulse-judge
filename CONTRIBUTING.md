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
bash -n scripts/download-dbip.sh scripts/download-geolite2.sh \
  scripts/docker-entrypoint.sh scripts/smoke.sh scripts/load.sh
```

For Docker changes, build the affected image:

```sh
docker build -f Dockerfile .
docker build -f Dockerfile.render .
```

`Dockerfile.render` downloads the DB-IP Lite databases and is slower; the main
`Dockerfile` is enough for most code changes.

Run the service locally:

```sh
PORT=8000 GEO_DIR=./geo TRUST_PROXY=0 cargo run

bash scripts/smoke.sh http://127.0.0.1:8000
bash scripts/load.sh http://127.0.0.1:8000 300 32
```

## Pull requests

- Add or update tests for logic and HTTP changes.
- Update `README.md` and `README.ru.md` when behavior or configuration changes.
- Do not commit secrets, `.env` files, database files, or build artifacts.
- Keep CI green; the workflow runs formatting, clippy, tests, and a
  container smoke/load check.

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
