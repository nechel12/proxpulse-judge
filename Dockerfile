# Rust multi-stage: static-ish glibc binary, tiny runtime
FROM rust:bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
# prefetch deps for layer caching
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release && rm -rf src target/release/.fingerprint/proxpulse-judge* target/release/proxpulse-judge*
COPY src ./src
RUN cargo build --release && (strip target/release/proxpulse-judge || true)

FROM debian:bookworm-slim
# curl/unzip нужны entrypoint-фолбэку (авто-скачивание DB-IP Lite,
# если в /app/geo нет .mmdb); в остальном рантайм без изменений.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 judge \
    && mkdir -p /app/geo /app/scripts \
    && chown -R judge:judge /app
COPY --from=build /build/target/release/proxpulse-judge /app/proxpulse-judge
COPY scripts/download-dbip.sh scripts/docker-entrypoint.sh /app/scripts/
USER judge

ENV GEO_DIR=/app/geo \
    TRUST_PROXY=1 \
    RUST_LOG=info

EXPOSE 8000
VOLUME ["/app/geo"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/app/proxpulse-judge", "--healthcheck"]

ENTRYPOINT ["bash", "/app/scripts/docker-entrypoint.sh"]
