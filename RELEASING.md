# Releasing

A release is a signed git tag on `main`; the `docker` workflow verifies the
tag, then builds, tests and publishes the container image for it.

1. **Prepare**
   - Update `CHANGELOG.md` (move the `Unreleased` notes under the new
     version).
   - Bump `version` in `Cargo.toml` and the image tag in
     `docker-compose.yml`; run `cargo check` so `Cargo.lock` updates.
   - Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
     `cargo test`, and `bash -n scripts/*.sh`.

2. **Verify locally**
   - `docker build -t proxpulse-judge:local -f Dockerfile .`, then
     `bash scripts/container-smoke.sh proxpulse-judge:local -v "$PWD/geo:/app/geo:ro"`
     (smoke and load checks).
   - Optionally build `Dockerfile.render` (downloads and validates DB-IP
     Lite) and run
     `SMOKE_EXPECT_GEO=1 bash scripts/container-smoke.sh <image> -e TRUST_PROXY=1`.
     CI runs the same check before every publish.

3. **Publish**
   - Merge the release changes into `main`; wait for the `test` and `smoke`
     jobs.
   - Create a signed tag on that `main` commit and push it:

     ```sh
     git tag -s vX.Y.Z -m "vX.Y.Z"
     git push origin vX.Y.Z
     ```

     The tag must be signed with the release key whose public half is
     [`docs/proxpulse-release.pub`](docs/proxpulse-release.pub). One-time
     setup: `git config gpg.format ssh` and
     `git config user.signingkey /path/to/proxpulse-release` (the private key,
     or its `.pub` when the key is loaded into `ssh-agent`).
   - The tag triggers the `docker` workflow. It rejects the tag unless it is
     signed with the release key, points to a commit on `main`, and matches
     the `Cargo.toml` version. It then builds `Dockerfile.render`, runs the
     smoke test with the baked databases and a Trivy scan, refuses to
     overwrite an existing `:vX.Y.Z`, and pushes `:vX.Y.Z`, `:latest`, and
     `:YYYYMM` with provenance, an SBOM, and a signed GitHub attestation.
   - Create a GitHub release for the tag with the changelog notes.

   Scheduled runs and manual runs (`workflow_dispatch`, from `main` only)
   refresh the databases and update only `:latest` and `:YYYYMM`.

4. **Verify the release** (anyone can do this)

   ```sh
   printf 'proxpulse-release namespaces="git" %s\n' \
     "$(cut -d' ' -f1,2 docs/proxpulse-release.pub)" > /tmp/allowed_signers
   git -c gpg.ssh.allowedSignersFile=/tmp/allowed_signers tag -v vX.Y.Z
   gh attestation verify oci://ghcr.io/nechel12/proxpulse-judge:vX.Y.Z --owner nechel12
   ```

5. **Deploy**
   - VPS: pull the release, run `bash scripts/download-dbip.sh` (or provide
     MaxMind files), then `docker compose up -d --build`.
   - Make sure `.env` matches the topology: Caddy/VPS uses `TRUST_CF=0`; a
     Cloudflare Tunnel or Render uses `TRUST_CF=1` with `TRUST_PROXY=1`.
   - Caddy needs the `trusted_proxies` configuration from
     `Caddyfile.example`; a Cloudflare-in-front-of-Caddy setup needs CF ranges
     instead of `0.0.0.0/0` plus origin firewalling (or Authenticated Origin
     Pulls) on ports 80/443 so clients cannot bypass Cloudflare and spoof
     `CF-Connecting-IP`.
   - Render: deploy the new image reference. The service needs
     `TRUST_PROXY=1` and `TRUST_CF=1`; `render.yaml` sets them, the image does
     not.
   - Run `scripts/smoke.sh https://your-instance.example` against the live
     service.

6. **Rollback**
   - Re-deploy the previous image tag. The `:YYYYMM` and `:vX.Y.Z` tags make
     rollback deterministic.

## MaxMind downloads

`scripts/download-geolite2.sh` needs a real `MAXMIND_LICENSE_KEY`. There is no
key in this repository; test that path with your own key if you use MaxMind
data.
