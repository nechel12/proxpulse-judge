# Releasing

This project has no release automation beyond the container workflow, so a
release is a short manual sequence.

1. **Prepare**
   - Update `CHANGELOG.md`.
   - Bump `version` in `Cargo.toml` and the image tag in
     `docker-compose.yml`; run `cargo check` so `Cargo.lock` updates.
   - Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
     `cargo test`, and `bash -n` on the scripts.

2. **Verify locally**
   - `docker build -t proxpulse-judge:local -f Dockerfile .`
   - Start it with a read-only `./geo` mount and run
     `scripts/smoke.sh http://127.0.0.1:8000`.
   - Run `scripts/load.sh http://127.0.0.1:8000 300 32`.
   - Optionally build `Dockerfile.render` (downloads DB-IP Lite and validates
     it) and run `/geo` for a known public IP.

3. **Publish**
   - Commit and push `main`; wait for the `test` and `smoke` jobs.
   - Run the `docker` workflow manually (`workflow_dispatch`) to build and
     push `ghcr.io/<owner>/proxpulse-judge:{latest,YYYYMM,vX.Y.Z}`.
   - Create an annotated tag: `git tag -a vX.Y.Z -m "vX.Y.Z"`, then
     `git push origin vX.Y.Z`.
   - Create a GitHub release with the changelog notes.

4. **Deploy**
   - VPS: pull the release, run `bash scripts/download-dbip.sh` (or provide
     MaxMind files), then `docker compose up -d --build`.
   - Make sure `.env` matches the topology: Caddy/VPS uses `TRUST_CF=0`; a
     Cloudflare Tunnel or Render uses `TRUST_CF=1` with `TRUST_PROXY=1`.
   - Caddy needs the `trusted_proxies` configuration from
     `Caddyfile.example`; a Cloudflare-in-front-of-Caddy setup needs CF ranges
     instead of `0.0.0.0/0`.
   - Render: deploy the new image reference and keep `TRUST_CF=1`.
   - Run `scripts/smoke.sh https://your-instance.example` against the live
     service.

5. **Rollback**
   - Re-deploy the previous image tag. The `:YYYYMM` and `:vX.Y.Z` tags make
     rollback deterministic.

## MaxMind downloads

`scripts/download-geolite2.sh` needs a real `MAXMIND_LICENSE_KEY`. There is no
key in this repository; test that path with your own key if you use MaxMind
data.
