# Один Dockerfile, две цели (последняя стадия — цель по умолчанию):
#   runtime — VPS: базы в смонтированном /app/geo (docker-compose.yml);
#             если .mmdb нет, entrypoint сам скачает DB-IP Lite;
#   render  — free-hosting (Render и т.п.): DB-IP Lite вшиты в образ,
#             диск не нужен, контейнер stateless, curl внутри нет.
#             Пример: docker build --target render .
# DB-IP Lite распространяется под CC BY 4.0 — атрибуция обязательна:
# "IP Geolocation by DB-IP" со ссылкой https://db-ip.com
# (см. также GET / — лицензии отдаются самим сервисом).
# MaxMind GeoLite2 в образ класть НЕЛЬЗЯ (EULA запрещает публичную
# редистрибуцию) — для MaxMind используй цель runtime + volume.
# Базовые образы закреплены по digest; их обновляет Dependabot.
# TRUST_PROXY/TRUST_CF намеренно не задаются: в образе безопасный дефолт 0,
# топологию задаёт окружение (.env, render.yaml). Образ с TRUST_CF=1,
# запущенный напрямую, позволил бы подделать IP заголовком CF-Connecting-IP.

FROM rust:1.99-trixie@sha256:09027f873d45b8ecd1dc86f1fa13b7a62b875c961f017a0e331267b350430137 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
# предварительно скачать зависимости для кэширования слоя
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --locked && rm -rf src target/release/.fingerprint/proxpulse-judge* target/release/proxpulse-judge*
COPY src ./src
RUN cargo build --release --locked

FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS base
RUN apt-get update && apt-get install -y --no-install-recommends \
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
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/app/proxpulse-judge", "--healthcheck"]
ENTRYPOINT ["bash", "/app/scripts/docker-entrypoint.sh"]
LABEL org.opencontainers.image.title="proxpulse-judge" \
      org.opencontainers.image.source="https://github.com/nechel12/proxpulse-judge" \
      org.opencontainers.image.licenses="Apache-2.0"

# Инструменты скачивания DB-IP Lite: в runtime — для фолбэка entrypoint,
# в render — только на этапе сборки.
FROM base AS fetcher
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gzip \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/download-dbip.sh /app/scripts/

# Свежие базы (долгая стадия: city ~130 МБ); скрипт проверяет их тем же
# бинарником (--check-geo) до того, как положить на место.
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
