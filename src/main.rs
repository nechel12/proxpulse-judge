//! proxpulse-judge: self-hosted proxy-check backend.
//!
//! One GET /judge replaces several third-party calls (ip-api, httpbin):
//! it sees the proxy exit IP, resolves geo from LOCAL .mmdb files,
//! echoes headers for anonymity analysis and serves fixed content
//! for tamper checks.
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

/// Request headers must arrive within this time (slowloris guard).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Open connections at once, idle keep-alive ones included.
const MAX_CONNECTIONS: usize = 4096;

fn healthcheck(addr: SocketAddr) -> bool {
    use std::io::{Read, Write};
    // Two seconds for connect and two for read stays below the Docker
    // healthcheck timeout (5s) instead of potentially taking 8s.
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
    // Check the status line, not an arbitrary "200" elsewhere in headers.
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
    // Docker sends SIGTERM on `stop` — without this arm the container
    // would die mid-request instead of draining gracefully.
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            // no SIGTERM source: never resolve
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
