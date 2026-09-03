//! proxpulse-judge: self-hosted proxy-check backend.
//!
//! One GET /judge replaces several third-party calls (ip-api, httpbin):
//! it sees the proxy exit IP, resolves geo from LOCAL .mmdb files,
//! echoes headers for anonymity analysis and serves fixed content
//! for tamper checks.
mod geo;
mod logic;

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use moka::sync::Cache;
use serde::Deserialize;
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use geo::{GeoInfo, GeoPool};
use logic::{anonymity_level, classify_ip, client_ip, forwarded_chain};

const VERSION: &str = "0.2.0";

#[derive(Clone)]
struct AppState {
    geo: Arc<GeoPool>,
    geo_cache: Cache<String, GeoInfo>,
    trust_proxy: bool,
    rdns_timeout: Duration,
}

#[derive(Deserialize)]
struct JudgeParams {
    direct_ip: Option<String>,
    rdns: Option<u8>,
}

#[derive(Deserialize)]
struct RdnsParam {
    rdns: Option<u8>,
}

fn headers_lower(headers: &HeaderMap) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (k, v) in headers.iter() {
        m.insert(
            k.as_str().to_ascii_lowercase(),
            v.to_str().unwrap_or("").to_string(),
        );
    }
    m
}

fn self_ip(headers: &HeaderMap, conn: Option<ConnectInfo<SocketAddr>>, trust: bool) -> String {
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let sock = conn.map(|c| c.0.ip().to_string());
    let sock_ref = sock.as_deref().unwrap_or("127.0.0.1");
    client_ip(xff, sock_ref, trust)
}

fn geo_cached(state: &AppState, ip: &str) -> GeoInfo {
    let key = ip.to_string();
    if let Some(hit) = state.geo_cache.get(&key) {
        return hit;
    }
    let info = state.geo.lookup(ip);
    state.geo_cache.insert(key, info.clone());
    info
}

async fn rdns_lookup(ip: &str, timeout: Duration) -> Option<String> {
    let addr: std::net::IpAddr = ip.parse().ok()?;
    let fut = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&addr).ok());
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => v,
        _ => None,
    }
}

async fn index(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "proxpulse-judge",
        "version": VERSION,
        "trust_proxy": s.trust_proxy,
        "geo_sources": s.geo.sources(),
        "endpoints": [
            "GET /generate_204",
            "GET /ip",
            "GET /headers",
            "GET /geo",
            "GET /type",
            "GET /content",
            "GET /judge",
            "GET /healthz",
        ],
    }))
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({"ok": true}))
}

async fn generate_204() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

async fn ip(
    State(s): State<Arc<AppState>>,
    conn: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    Json(serde_json::json!({ "ip": self_ip(&headers, conn, s.trust_proxy) }))
}

async fn headers_echo(
    State(s): State<Arc<AppState>>,
    conn: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let me = self_ip(&headers, conn, s.trust_proxy);
    let raw = headers_lower(&headers);
    let chain = forwarded_chain(
        raw.get("x-forwarded-for").map(|x| x.as_str()),
        &me,
        s.trust_proxy,
    );
    let mut visible = raw;
    if s.trust_proxy && visible.contains_key("x-forwarded-for") {
        visible.insert(
            "x-forwarded-for".to_string(),
            if chain.is_empty() {
                "(stripped)".to_string()
            } else {
                chain.join(", ")
            },
        );
    }
    Json(serde_json::json!({ "ip": me, "headers": visible, "xff_chain": chain }))
}

async fn geo_ep(
    State(s): State<Arc<AppState>>,
    conn: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let me = self_ip(&headers, conn, s.trust_proxy);
    let data = geo_cached(&s, &me);
    Json(serde_json::json!({ "ip": me, "geo": data, "source": sources_or_null(&s) }))
}

fn sources_or_null(s: &AppState) -> serde_json::Value {
    let m = s.geo.sources();
    if m.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::json!(m)
    }
}

async fn ip_type(
    State(s): State<Arc<AppState>>,
    conn: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(p): Query<RdnsParam>,
) -> impl IntoResponse {
    let me = self_ip(&headers, conn, s.trust_proxy);
    let data = geo_cached(&s, &me);
    let ptr = if p.rdns.unwrap_or(0) != 0 {
        rdns_lookup(&me, s.rdns_timeout).await
    } else {
        None
    };
    let (t, signals) = classify_ip(data.aso.as_deref(), None, ptr.as_deref());
    Json(serde_json::json!({ "ip": me, "ip_type": t, "signals": signals }))
}

async fn content() -> impl IntoResponse {
    Response::builder()
        .header("content-type", "application/json")
        .body(axum::body::Body::from(logic::FIXED_CONTENT))
        .unwrap()
}

async fn judge(
    State(s): State<Arc<AppState>>,
    conn: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(p): Query<JudgeParams>,
) -> impl IntoResponse {
    let me = self_ip(&headers, conn, s.trust_proxy);
    let raw = headers_lower(&headers);
    let chain = forwarded_chain(
        raw.get("x-forwarded-for").map(|x| x.as_str()),
        &me,
        s.trust_proxy,
    );

    let mut for_analysis = raw.clone();
    if s.trust_proxy && for_analysis.contains_key("x-forwarded-for") {
        // our reverse proxy appended `me` last — remove it, the rest
        // (if any) was forwarded by the checked proxy
        for_analysis.insert("x-forwarded-for".to_string(), chain.join(", "));
    }
    let level = anonymity_level(&for_analysis, p.direct_ip.as_deref());

    let g = geo_cached(&s, &me);
    let ptr = if p.rdns.unwrap_or(0) != 0 {
        rdns_lookup(&me, s.rdns_timeout).await
    } else {
        None
    };
    let (t, signals) = classify_ip(g.aso.as_deref(), None, ptr.as_deref());

    Json(serde_json::json!({
        "ip": me,
        "headers": raw,
        "xff_chain": chain,
        "anonymity": level,
        "geo": g,
        "geo_source": sources_or_null(&s),
        "ip_type": t,
        "type_signals": signals,
        "content_version": logic::CONTENT_VERSION,
        "content_sha256": logic::content_sha256(),
    }))
}

fn healthcheck(port: u16) -> bool {
    use std::io::{Read, Write};
    let addr: SocketAddr = match format!("127.0.0.1:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let mut s = match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(4)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    s.set_read_timeout(Some(Duration::from_secs(4))).ok();
    if s
        .write_all(b"GET /healthz HTTP/1.0\r\nHost: x\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).contains("200")
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8000);
    if std::env::args().any(|a| a == "--healthcheck") {
        std::process::exit(i32::from(!healthcheck(port)));
    }

    let geo_dir = env::var("GEO_DIR").unwrap_or_else(|_| "/app/geo".to_string());
    let trust_proxy = env::var("TRUST_PROXY").unwrap_or_else(|_| "1".to_string()) == "1";
    let rdns_timeout = Duration::from_secs_f64(
        env::var("RDNS_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1.5),
    );

    let state = Arc::new(AppState {
        geo: Arc::new(GeoPool::open(std::path::Path::new(&geo_dir))),
        geo_cache: Cache::builder().max_capacity(65_536).build(),
        trust_proxy,
        rdns_timeout,
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/generate_204", get(generate_204))
        .route("/ip", get(ip))
        .route("/headers", get(headers_echo))
        .route("/geo", get(geo_ep))
        .route("/type", get(ip_type))
        .route("/content", get(content))
        .route("/judge", get(judge))
        .with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
    tracing::info!("proxpulse-judge v{VERSION} on {addr} (trust_proxy={trust_proxy})");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use axum::{
        body::Body,
        http::Request,
    };
    use tower::ServiceExt;

    fn test_app() -> Router {
        let state = Arc::new(AppState {
            geo: Arc::new(GeoPool::open(std::path::Path::new("/nonexistent-dir-xyz"))),
            geo_cache: Cache::builder().max_capacity(1024).build(),
            trust_proxy: true,
            rdns_timeout: Duration::from_millis(100),
        });
        Router::new()
            .route("/", get(index))
            .route("/healthz", get(healthz))
            .route("/generate_204", get(generate_204))
            .route("/ip", get(ip))
            .route("/judge", get(judge))
            .route("/content", get(content))
            .with_state(state)
    }

    #[tokio::test]
    async fn healthz_ok() {
        let res = test_app()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn generate_204_empty() {
        let res = test_app()
            .oneshot(Request::get("/generate_204").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn judge_transparent() {
        let res = test_app()
            .oneshot(
                Request::get("/judge?direct_ip=1.1.1.1")
                    .header("x-forwarded-for", "1.1.1.1, 5.6.7.8")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ip"], "5.6.7.8");
        assert_eq!(v["anonymity"], "transparent");
        assert_eq!(v["content_sha256"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn judge_elite_no_leak() {
        let res = test_app()
            .oneshot(
                Request::get("/judge?direct_ip=1.1.1.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["anonymity"], "elite");
    }

    #[tokio::test]
    async fn content_stable() {
        let a = test_app()
            .oneshot(Request::get("/content").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let b = test_app()
            .oneshot(Request::get("/content").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let ba = axum::body::to_bytes(a.into_body(), 65536).await.unwrap();
        let bb = axum::body::to_bytes(b.into_body(), 65536).await.unwrap();
        assert_eq!(ba, bb);
        assert!(ba.len() > 32);
    }
}
