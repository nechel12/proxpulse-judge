## Summary

<!-- What changes, and why? Keep it focused. -->

## Testing

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `bash -n scripts/download-dbip.sh scripts/download-geolite2.sh scripts/docker-entrypoint.sh scripts/smoke.sh scripts/load.sh`
- [ ] Docker build (if container files changed)

## Checklist

- [ ] Tests added or updated for behavior changes.
- [ ] `README.md` and `README.ru.md` updated for user-visible changes.
- [ ] No secrets, `.env` files, database files, or build artifacts committed.
- [ ] Security issues are reported via `SECURITY.md`, not this PR.
