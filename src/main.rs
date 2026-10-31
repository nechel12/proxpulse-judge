//! proxpulse-judge: самостоятельно размещаемый бэкенд для проверки прокси.
//!
//! Один GET /judge заменяет несколько сторонних вызовов (ip-api, httpbin):
//! он видит выходной IP прокси, определяет геоданные по ЛОКАЛЬНЫМ файлам .mmdb,
//! возвращает заголовки для анализа анонимности и отдаёт фиксированный контент
//! для проверки на подмену.
mod app;
mod config;
mod geo;
mod logic;
mod metrics;
mod ratelimit;
mod server;

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use app::{AppState, REQUEST_TIMEOUT, VERSION};
use config::Config;
use geo::GeoPool;

/// Заголовки запроса должны поступить за это время (защита от slowloris).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Одновременно открытых соединений, включая простаивающие keep-alive.
const MAX_CONNECTIONS: usize = 4096;

fn healthcheck(addr: SocketAddr) -> bool {
    use std::io::{Read, Write};
    // Две секунды на подключение и две на чтение укладываются в таймаут
    // healthcheck Docker (5 с), а не могут занять до 8 с.
    let mut s = match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    if s.write_all(b"GET /healthz HTTP/1.0\r\nHost: x\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut resp = Vec::new();
    let mut buf = [0u8; 256];
    while resp.len() < 1024 {
        let n = s.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
        if resp.windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }
    // Проверяется строка статуса, а не произвольное «200» где-то в заголовках.
    let text = String::from_utf8_lossy(&resp);
    text.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        == Some("200")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    // Docker отправляет SIGTERM при `stop` — без этой ветки контейнер
    // завершался бы посреди запроса вместо плавного дренажа.
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            // нет источника SIGTERM: никогда не разрешать
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if std::env::args().any(|a| a == "--healthcheck") {
        let healthy = config::probe_addr().is_some_and(healthcheck);
        std::process::exit(i32::from(!healthy));
    }

    let geo_dir = std::env::var("GEO_DIR").unwrap_or_else(|_| "/app/geo".to_string());
    if std::env::args().any(|a| a == "--check-geo") {
        match GeoPool::open(Path::new(&geo_dir)).verify() {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("geo validation failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!("invalid configuration: {e}");
            std::process::exit(1);
        }
    };
    let state = Arc::new(AppState::new(GeoPool::open(Path::new(&cfg.geo_dir)), &cfg));
    let app = app::build_app(state);

    let addr = SocketAddr::new(cfg.bind, cfg.port);
    tracing::info!(
        "proxpulse-judge v{VERSION} on {addr} (trust_proxy={}, trust_cf={}, rate_per_minute={}, edge_headers={:?}, metrics_token={})",
        cfg.trust_proxy,
        cfg.trust_cf,
        cfg.rate_per_minute,
        cfg.edge_headers,
        cfg.metrics_token.is_some(),
    );
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    let limits = server::Limits {
        header_read_timeout: HEADER_READ_TIMEOUT,
        max_connections: MAX_CONNECTIONS,
        shutdown_grace: REQUEST_TIMEOUT + Duration::from_secs(5),
    };
    server::serve(listener, app, limits, shutdown_signal()).await;
}
