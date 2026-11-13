# One Dockerfile, two targets (the last stage is the default target):
#   runtime — VPS: databases in the mounted /app/geo (docker-compose.yml);
#             if no .mmdb is present, the entrypoint downloads DB-IP Lite;
#   render  — free hosting (Render and similar): DB-IP Lite baked into the image,
#             no disk needed, the container is stateless, no curl inside.
#             Example: docker build --target render .
# DB-IP Lite is distributed under CC BY 4.0 — attribution is required:
# "IP Geolocation by DB-IP" with a link to https://db-ip.com
# (see also GET / — the service serves the licenses itself).
# MaxMind GeoLite2 must NOT be baked into the image (the EULA forbids public
# redistribution) — for MaxMind use the runtime target + a volume.
# Base images are pinned by digest; Dependabot updates them. Debian's security
# fixes are applied at build time (apt-get upgrade in base), so a fixed package
# does not wait for the next base image.
# TRUST_PROXY/TRUST_CF are deliberately unset: the image keeps the safe default 0,
# the environment defines the topology (.env, render.yaml). An image with TRUST_CF=1
# run directly would let anyone spoof the IP with a CF-Connecting-IP header.

FROM rust:1.99-trixie@sha256:09027f873d45b8ecd1dc86f1fa13b7a62b875c961f017a0e331267b350430137 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
# prefetch dependencies for layer caching
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --locked && rm -rf src target/release/.fingerprint/proxpulse-judge* target/release/proxpulse-judge*
COPY src ./src
RUN cargo build --release --locked

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS base
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --no-create-home --uid 10001 judge \
    && mkdir -p /app/geo /app/scripts \
    && chown -R judge:judge /app
COPY --from=build /build/target/release/proxpulse-judge /app/proxpulse-judge
COPY scripts/docker-entrypoint.sh /app/scripts/
ENV GEO_DIR=/app/geo \
    RUST_LOG=info
EXPOSE 8000
# The entrypoint may download databases for up to 10 minutes first.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10m \
  CMD ["/app/proxpulse-judge", "--healthcheck"]
ENTRYPOINT ["bash", "/app/scripts/docker-entrypoint.sh"]
LABEL org.opencontainers.image.title="proxpulse-judge" \
      org.opencontainers.image.source="https://github.com/nechel12/proxpulse-judge" \
      org.opencontainers.image.licenses="Apache-2.0"

# DB-IP Lite download tools: in runtime for the entrypoint fallback,
# in render only at build time.
FROM base AS fetcher
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gzip \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/download-dbip.sh /app/scripts/

# Fresh databases (slow stage: city ~130 MB); the script validates them with the
# same binary (--check-geo) before putting them in place.
FROM fetcher AS dbip
RUN GEO_DIR=/app/geo bash /app/scripts/download-dbip.sh

FROM base AS render
COPY --from=dbip --chown=judge:judge /app/geo /app/geo
USER judge
LABEL org.opencontainers.image.description="Self-hosted proxy-check backend with embedded DB-IP Lite geo DBs (CC BY 4.0, IP Geolocation by DB-IP https://db-ip.com)"

FROM fetcher AS runtime
USER judge
VOLUME ["/app/geo"]
LABEL org.opencontainers.image.description="Self-hosted proxy-check backend; mount .mmdb geo databases at /app/geo"
