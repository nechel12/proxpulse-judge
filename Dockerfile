# Rust multi-stage: static-ish glibc binary, tiny runtime
FROM rust:bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
# prefetch deps for layer caching
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release && rm -rf src target/release/.fingerprint/proxpulse-judge* target/release/proxpulse-judge*
COPY src ./src
RUN cargo build --release && strip target/release/proxpulse-judge

FROM debian:bookworm-slim
RUN useradd -m -u 10001 judge \
    && mkdir -p /app/geo \
    && chown -R judge:judge /app
COPY --from=build /build/target/release/proxpulse-judge /app/proxpulse-judge
USER judge

ENV GEO_DIR=/app/geo \
    TRUST_PROXY=1 \
    RUST_LOG=info

EXPOSE 8000
VOLUME ["/app/geo"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/app/proxpulse-judge", "--healthcheck"]

ENTRYPOINT ["/app/proxpulse-judge"]
