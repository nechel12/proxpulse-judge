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
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use moka::sync::Cache;
use serde::Deserialize;
use std::{
    collections::{HashMap, VecDeque},
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use geo::{GeoInfo, GeoPool};
use logic::{anonymity_level, classify_ip, client_ip, forwarded_chain};

const VERSION: &str = "0.5.1";

/// Fixed-window-ish per-IP limiter: at most `per_minute` requests
/// in any rolling 60s window. 0 disables. Pure function for testability:
/// returns Some(retry_after_secs) when over the limit.
fn check_limit(
    hits: &mut HashMap<String, VecDeque<Instant>>,
    key: &str,
    now: Instant,
    limit: u32,
) -> Option<u64> {
    // occasional full sweep so spoofed keys can't grow the map forever
    if hits.len() > 200_000 {
        hits.retain(|_, q| {
            while q.front().map(|t| now.duration_since(*t).as_secs() >= 60).unwrap_or(false) {
                q.pop_front();
            }
            !q.is_empty()
        });
        if hits.len() > 200_000 {
            return Some(60);
        }
    }
    let q = hits.entry(key.to_string()).or_default();
    while q.front().map(|t| now.duration_since(*t).as_secs() >= 60).unwrap_or(false) {
        q.pop_front();
    }
    if q.len() as u32 >= limit {
        let oldest = *q.front().unwrap();
        return Some((60 - now.duration_since(oldest).as_secs() + 1).max(1));
    }
    q.push_back(now);
    None
}

struct RateLimit {
    per_minute: u32,
    hits: Mutex<HashMap<String, VecDeque<Instant>>>,
}

async fn rate_limit_mw(
    State(s): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    let path = req.uri().path().to_string();
    if s.rate_limit.per_minute > 0 && path != "/healthz" && path != "/" {
        let conn = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .cloned();
        let key = self_ip(req.headers(), conn, s.trust_proxy, s.trust_cf);
        let retry = {
            let mut hits = s.rate_limit.hits.lock().unwrap();
            check_limit(&mut hits, &key, Instant::now(), s.rate_limit.per_minute)
        };
        if let Some(secs) = retry {
            let mut h = HeaderMap::new();
            h.insert(
                "retry-after",
                HeaderValue::from_str(&secs.to_string()).unwrap(),
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                h,
                Json(serde_json::json!({ "error": "rate limited" })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

#[derive(Clone)]
struct AppState {
    geo: Arc<GeoPool>,
    geo_cache: Cache<String, GeoInfo>,
    ptr_cache: Cache<String, Option<String>>,
    rdns_sem: Arc<tokio::sync::Semaphore>,
    rate_limit: Arc<RateLimit>,
    trust_proxy: bool,
    trust_cf: bool,
    rdns_timeout: Duration,
}

#[derive(Deserialize)]
struct JudgeParams {
    direct_ip: Option<String>,
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

fn self_ip(
    headers: &HeaderMap,
    conn: Option<ConnectInfo<SocketAddr>>,
    trust_proxy: bool,
    trust_cf: bool,
) -> String {
    let cf = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok());
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let sock = conn.map(|c| c.0.ip().to_string());
    let sock_ref = sock.as_deref().unwrap_or("127.0.0.1");
    client_ip(cf, xff, sock_ref, trust_proxy, trust_cf)
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

/// Server-side rDNS policy: resolve only when the ASN org is missing
/// (otherwise PTR adds nothing worth a DNS round-trip), at most
/// RDNS_MAX_CONCURRENT resolutions at once, results cached for an hour.
/// The client cannot request rDNS — there is no such parameter.
async fn maybe_rdns(state: &AppState, ip: &str, aso: Option<&str>) -> Option<String> {
    if aso.map(|o| !o.trim().is_empty()).unwrap_or(false) {
        return None;
    }
    let key = ip.to_string();
    if let Some(hit) = state.ptr_cache.get(&key) {
        return hit;
    }
    let _permit = state.rdns_sem.try_acquire().ok()?;
    let res = rdns_lookup(ip, state.rdns_timeout).await;
    state.ptr_cache.insert(key, res.clone());
    res
}

async fn index(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "proxpulse-judge",
        "version": VERSION,
        "trust_proxy": s.trust_proxy,
        "trust_cf": s.trust_cf,
        "geo_sources": s.geo.sources(),
        "licenses": {
            "dbip_lite": {
                "license": "CC BY 4.0",
                "url": "https://db-ip.com/db/lite.php",
                "attribution": "IP Geolocation by DB-IP (https://db-ip.com)",
            },
            "geolite2": {
                "license": "GeoLite EULA (CC BY-SA 4.0 aspects)",
                "url": "https://www.maxmind.com/en/geolite/eula",
                "attribution": "This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com",
            },
        },
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
    Json(serde_json::json!({ "ip": self_ip(&headers, conn, s.trust_proxy, s.trust_cf) }))
}

async fn headers_echo(
    State(s): State<Arc<AppState>>,
    conn: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let me = self_ip(&headers, conn, s.trust_proxy, s.trust_cf);
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
    let me = self_ip(&headers, conn, s.trust_proxy, s.trust_cf);
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
) -> impl IntoResponse {
    let me = self_ip(&headers, conn, s.trust_proxy, s.trust_cf);
    let data = geo_cached(&s, &me);
    let ptr = maybe_rdns(&s, &me, data.aso.as_deref()).await;
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
    let me = self_ip(&headers, conn, s.trust_proxy, s.trust_cf);
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
    let level = {
        // garbage direct_ip is ignored instead of compared (a header value
        // could otherwise "match" it and fake a transparent verdict)
        let direct = p
            .direct_ip
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty() && d.parse::<std::net::IpAddr>().is_ok());
        anonymity_level(&for_analysis, direct)
    };

    let g = geo_cached(&s, &me);
    let ptr = maybe_rdns(&s, &me, g.aso.as_deref()).await;
    let (t, signals) = classify_ip(g.aso.as_deref(), None, ptr.as_deref());

    no_store_json(serde_json::json!({
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

fn no_store_json(v: serde_json::Value) -> impl IntoResponse {
    let mut h = HeaderMap::new();
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    (h, Json(v))
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
    let trust_cf = env::var("TRUST_CF").unwrap_or_else(|_| "1".to_string()) == "1";
    let rdns_timeout = Duration::from_secs_f64(
        env::var("RDNS_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1.5),
    );
    // requests per IP per rolling minute, 0 = off
    let rate_per_minute: u32 = env::var("RATE_LIMIT_PER_MINUTE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6000);

    let state = Arc::new(AppState {
        geo: Arc::new(GeoPool::open(std::path::Path::new(&geo_dir))),
        geo_cache: Cache::builder().max_capacity(65_536).build(),
        ptr_cache: Cache::builder()
            .max_capacity(65_536)
            .time_to_live(Duration::from_secs(3600))
            .build(),
        rdns_sem: Arc::new(tokio::sync::Semaphore::new(16)),
        rate_limit: Arc::new(RateLimit {
            per_minute: rate_per_minute,
            hits: Mutex::new(HashMap::new()),
        }),
        trust_proxy,
        trust_cf,
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
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit_mw,
        ))
        .with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
    tracing::info!("proxpulse-judge v{VERSION} on {addr} (trust_proxy={trust_proxy}, trust_cf={trust_cf}, rate_per_minute={rate_per_minute})");
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
        test_app_with_limit(1_000_000)
    }

    fn test_app_with_limit(per_minute: u32) -> Router {
        let state = Arc::new(AppState {
            geo: Arc::new(GeoPool::open(std::path::Path::new("/nonexistent-dir-xyz"))),
            geo_cache: Cache::builder().max_capacity(1024).build(),
            ptr_cache: Cache::builder().max_capacity(1024).build(),
            rdns_sem: Arc::new(tokio::sync::Semaphore::new(16)),
            rate_limit: Arc::new(RateLimit {
                per_minute,
                hits: Mutex::new(HashMap::new()),
            }),
            trust_proxy: true,
            trust_cf: true,
            rdns_timeout: Duration::from_millis(100),
        });
        Router::new()
            .route("/", get(index))
            .route("/healthz", get(healthz))
            .route("/generate_204", get(generate_204))
            .route("/ip", get(ip))
            .route("/judge", get(judge))
            .route("/content", get(content))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                rate_limit_mw,
            ))
            .with_state(state)
    }

    #[test]
    fn limit_window_allows_then_blocks() {
        let mut hits = HashMap::new();
        let now = Instant::now();
        assert_eq!(check_limit(&mut hits, "1.2.3.4", now, 2), None);
        assert_eq!(check_limit(&mut hits, "1.2.3.4", now, 2), None);
        let retry = check_limit(&mut hits, "1.2.3.4", now, 2);
        assert!(retry.is_some() && retry.unwrap() >= 1 && retry.unwrap() <= 61);
        // another IP has its own budget
        assert_eq!(check_limit(&mut hits, "5.6.7.8", now, 2), None);
    }

    #[tokio::test]
    async fn rate_limit_blocks_and_healthz_exempt() {
        let app = test_app_with_limit(2);
        let get_ip = || {
            Request::get("/ip")
                .header("x-forwarded-for", "9.9.9.9")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            app.clone().oneshot(get_ip()).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone().oneshot(get_ip()).await.unwrap().status(),
            StatusCode::OK
        );
        let limited = app.clone().oneshot(get_ip()).await.unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key("retry-after"));
        // healthz never counts
        for _ in 0..5 {
            assert_eq!(
                app.clone()
                    .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
    }

    #[tokio::test]
    async fn garbage_direct_ip_is_ignored() {
        // user-agent "matches" the garbage direct_ip — must NOT fake transparent
        let res = test_app()
            .oneshot(
                Request::get("/judge?direct_ip=not-an-ip")
                    .header("user-agent", "not-an-ip")
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
    async fn judge_sends_no_store() {
        let res = test_app()
            .oneshot(Request::get("/judge").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            res.headers().get("cache-control").and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }

    #[tokio::test]
    async fn index_has_licenses() {
        let res = test_app()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["service"], "proxpulse-judge");
        assert_eq!(v["licenses"]["dbip_lite"]["license"], "CC BY 4.0");
        assert!(v["licenses"]["geolite2"]["url"]
            .as_str()
            .unwrap_or("")
            .contains("maxmind.com"));
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
    async fn judge_via_cf_tunnel_transparent() {
        // CF edge: exit 5.6.7.8, proxy leaked 1.1.1.1 into XFF
        let res = test_app()
            .oneshot(
                Request::get("/judge?direct_ip=1.1.1.1")
                    .header("cf-connecting-ip", "5.6.7.8")
                    .header("x-forwarded-for", "1.1.1.1, 5.6.7.8")
                    .header("cf-ray", "abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ip"], "5.6.7.8");
        assert_eq!(v["anonymity"], "transparent");
    }

    #[tokio::test]
    async fn judge_via_cf_tunnel_direct_is_elite() {
        // direct check through the tunnel: CF-Connecting-IP == direct IP
        // must NOT count as a leak
        let res = test_app()
            .oneshot(
                Request::get("/judge?direct_ip=1.1.1.1")
                    .header("cf-connecting-ip", "1.1.1.1")
                    .header("x-forwarded-for", "1.1.1.1")
                    .header("cf-ray", "abc123")
                    .header("cf-ipcountry", "DE")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ip"], "1.1.1.1");
        assert_eq!(v["anonymity"], "elite");
    }

    #[tokio::test]
    async fn rdns_skipped_when_asn_known() {
        // ASN org present → no DNS round-trip at all (fast, offline-safe)
        let state = Arc::new(AppState {
            geo: Arc::new(GeoPool::open(std::path::Path::new("/nonexistent-dir-xyz"))),
            geo_cache: Cache::builder().max_capacity(16).build(),
            ptr_cache: Cache::builder().max_capacity(16).build(),
            rdns_sem: Arc::new(tokio::sync::Semaphore::new(16)),
            rate_limit: Arc::new(RateLimit {
                per_minute: 1_000_000,
                hits: Mutex::new(HashMap::new()),
            }),
            trust_proxy: true,
            trust_cf: true,
            rdns_timeout: Duration::from_millis(50),
        });
        let t0 = std::time::Instant::now();
        let res = maybe_rdns(&state, "8.8.8.8", Some("Google LLC")).await;
        assert!(res.is_none());
        assert!(t0.elapsed() < Duration::from_secs(5));
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
