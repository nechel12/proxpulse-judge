# Releasing

A release is a signed git tag on `main`; the `docker` workflow verifies the
tag, publishes the tested multi-arch image, and creates the GitHub release
with Linux binaries.

1. **Prepare** (a pull request or a direct commit on `main`; CI has to be green
   before the tag)
   - Update `CHANGELOG.md`: rename `[Unreleased]` to `[X.Y.Z] — YYYY-MM-DD`,
     add a fresh empty `[Unreleased]`, and update the compare links at the
     bottom. The release notes are taken from this section; a tag without it
     is rejected.
   - Bump `version` in `Cargo.toml`; run `cargo check` so `Cargo.lock`
     updates.
   - Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
     `cargo test`, and
     `for f in scripts/*.sh; do bash -n "$f"; done`.

2. **Verify locally**
   - `docker build -t proxpulse-judge:local .`, then
     `bash scripts/container-smoke.sh proxpulse-judge:local -v "$PWD/geo:/app/geo:ro"`
     (smoke and load checks).
   - Optionally build the Render image
     (`docker build --target render -t proxpulse-judge:render .`, downloads
     and validates DB-IP Lite) and run
     `SMOKE_EXPECT_GEO=1 bash scripts/container-smoke.sh proxpulse-judge:render -e TRUST_PROXY=1`.
     CI runs the same check on both architectures before every publish.

3. **Publish**
   - Land the release commit on `main`; wait for the `test`, `msrv`, and
     `smoke` jobs.
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
     signed with the release key, points to a commit on `main`, matches the
     `Cargo.toml` version, and has a `CHANGELOG.md` section. It then builds
     the `render` target for `linux/amd64` and `linux/arm64` on native
     runners, runs the smoke test with the baked databases and a Trivy scan
     on each, refuses to overwrite an existing `:vX.Y.Z`, and pushes
     `:vX.Y.Z`, `:latest`, and `:YYYYMM` with provenance, an SBOM, and a
     signed GitHub attestation.
   - The same run builds static `x86_64`/`aarch64` musl binaries, attests
     them, and creates the GitHub release with the changelog notes,
     the binaries, and `SHA256SUMS`. The image is pushed only after both
     binaries built, and a failing Render deploy hook only leaves a warning.
   - If a release run fails after the image was pushed (the `release` job,
     for example), use **Re-run failed jobs**, never **Re-run all jobs**: a
     full re-run stops at "Refuse to overwrite a published version", since
     `:vX.Y.Z` already exists.

   Scheduled runs and manual runs (`workflow_dispatch`, from `main` only)
   rebuild the latest signed release on `main` (not `main`'s HEAD) with fresh
   databases and update only `:latest` and `:YYYYMM`. Forks build their own
   `main` instead, because their tags are not signed with this key. Such a
   rebuild keeps the release's base image and dependencies, so when the
   monthly Trivy scan starts failing on a fixed base-image or dependency
   issue, cut a patch release with Dependabot's bumps. Its GitHub attestation
   names the workflow run on `main`; the image's
   `org.opencontainers.image.revision` label names the release commit built.

4. **Verify the release** (anyone can do this)

   ```sh
   printf 'proxpulse-release namespaces="git" %s\n' \
     "$(cut -d' ' -f1,2 docs/proxpulse-release.pub)" > /tmp/allowed_signers
   git -c gpg.ssh.allowedSignersFile=/tmp/allowed_signers tag -v vX.Y.Z
   gh attestation verify oci://ghcr.io/nechel12/proxpulse-judge:vX.Y.Z --owner nechel12
   gh release download vX.Y.Z -R nechel12/proxpulse-judge
   sha256sum -c SHA256SUMS
   gh attestation verify proxpulse-judge-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz --owner nechel12
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
     `CF-Connecting-IP`. nginx: use `nginx.conf.example`; if it adds
     `X-Real-IP`/`Via`, list them in `EDGE_HEADERS`.
   - Public instances: set `METRICS_TOKEN` (or block `/metrics` at the edge).
     `SIGNING_KEY` is optional: ProxPulse picks up a new key by itself from 0.6.1
     on. In older versions a restart marks checks in progress as modified.
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
