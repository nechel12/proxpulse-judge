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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use geo::{GeoInfo, GeoPool};
use logic::{
    anonymity_level, classify_ip, client_ip, forwarded_chain, normalize_host, pre_edge_xff,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPOSITORY: &str = "https://github.com/nechel12/proxpulse-judge";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CONCURRENCY: usize = 512;

/// Rolling 60s window for one key. 0 disables the limiter before this is
/// called. Pure function for testability: returns Some(retry_after_secs)
/// when over the limit.
fn check_limit(q: &mut VecDeque<Instant>, now: Instant, limit: u32) -> Option<u64> {
    if limit == 0 {
        return None;
    }
    while q
        .front()
        .map(|t| now.duration_since(*t).as_secs() >= 60)
        .unwrap_or(false)
    {
        q.pop_front();
    }
    if q.len() as u32 >= limit {
        if let Some(oldest) = q.front().copied() {
            return Some((60 - now.duration_since(oldest).as_secs() + 1).max(1));
        }
    }
    q.push_back(now);
    None
}

struct RateLimit {
    per_minute: u32,
    /// Bounded per-key deques: moka evicts whole keys, so memory cannot
    /// grow without limit and there is no global sweep under one lock.
    hits: Cache<String, Arc<Mutex<VecDeque<Instant>>>>,
}

fn new_hits_cache() -> Cache<String, Arc<Mutex<VecDeque<Instant>>>> {
    Cache::builder()
        .max_capacity(100_000)
        .time_to_idle(Duration::from_secs(120))
        .build()
}

/// Process-local counters exported on `/metrics`; no external metrics
/// dependency is needed.
#[derive(Default)]
struct Metrics {
    requests: AtomicU64,
    responses_4xx: AtomicU64,
    responses_5xx: AtomicU64,
    rate_limited: AtomicU64,
    rdns_lookups: AtomicU64,
    rdns_timeouts: AtomicU64,
    rdns_skipped: AtomicU64,
}

async fn rate_limit_mw(
    State(s): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    let path = req.uri().path().to_string();
    if s.rate_limit.per_minute > 0 && path != "/healthz" && path != "/readyz" && path != "/metrics"
    {
        let conn = req.extensions().get::<ConnectInfo<SocketAddr>>().cloned();
        let key = self_ip(req.headers(), conn.map(|c| c.0), s.trust_proxy, s.trust_cf);
        let retry = {
            let entry = s
                .rate_limit
                .hits
                .get_with(key, || Arc::new(Mutex::new(VecDeque::new())));
            let mut q = entry.lock().unwrap_or_else(|p| p.into_inner());
            check_limit(&mut q, Instant::now(), s.rate_limit.per_minute)
        };
        if let Some(secs) = retry {
            s.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
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

async fn metrics_mw(
    State(s): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let res = next.run(req).await;
    s.metrics.requests.fetch_add(1, Ordering::Relaxed);
    let status = res.status();
    if status.is_client_error() {
        s.metrics.responses_4xx.fetch_add(1, Ordering::Relaxed);
    }
    if status.is_server_error() {
        s.metrics.responses_5xx.fetch_add(1, Ordering::Relaxed);
    }
    res
}

async fn concurrency_mw(
    State(s): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path();
    if matches!(path, "/healthz" | "/readyz" | "/metrics") {
        return next.run(req).await;
    }
    let permit = match tokio::time::timeout(
        Duration::from_secs(5),
        s.concurrency.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "busy" })),
            )
                .into_response()
        }
    };
    let res = next.run(req).await;
    drop(permit);
    res
}

async fn timeout_mw(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(res) => res,
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(serde_json::json!({ "error": "request timeout" })),
        )
            .into_response(),
    }
}

#[derive(Clone)]
struct AppState {
    geo: Arc<GeoPool>,
    geo_cache: Cache<String, GeoInfo>,
    ptr_cache: Cache<String, Option<String>>,
    rdns_sem: Arc<tokio::sync::Semaphore>,
    rate_limit: Arc<RateLimit>,
    metrics: Arc<Metrics>,
    concurrency: Arc<tokio::sync::Semaphore>,
    trust_proxy: bool,
    trust_cf: bool,
    rdns_timeout: Duration,
}

#[derive(Deserialize)]
struct JudgeParams {
    direct_ip: Option<String>,
}

/// Join all values of a header with ", " so duplicate header lines are
/// handled the same way everywhere. `HeaderMap::get` only returns the
/// first value, while `iter()` yields the last one per name — that
/// mismatch used to produce an inconsistent `ip`/`xff_chain` pair.
fn joined_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    let mut out = String::from_utf8_lossy(first.as_bytes()).into_owned();
    for v in values {
        out.push_str(", ");
        out.push_str(&String::from_utf8_lossy(v.as_bytes()));
    }
    Some(out)
}

fn headers_lower(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .keys()
        .filter_map(|name| {
            joined_header(headers, name.as_str()).map(|v| (name.as_str().to_ascii_lowercase(), v))
        })
        .collect()
}

fn self_ip(
    headers: &HeaderMap,
    conn: Option<SocketAddr>,
    trust_proxy: bool,
    trust_cf: bool,
) -> String {
    let cf = joined_header(headers, "cf-connecting-ip");
    let xff = joined_header(headers, "x-forwarded-for");
    let sock = conn.map(|addr| addr.ip().to_string());
    let sock_ref = sock.as_deref().unwrap_or("127.0.0.1");
    client_ip(
        cf.as_deref(),
        xff.as_deref(),
        sock_ref,
        trust_proxy,
        trust_cf,
    )
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

/// parse `RDNS_TIMEOUT` without panicking on negative/NaN/overflowing
/// values (Duration::from_secs_f64 panics for those).
fn parse_rdns_timeout(raw: Option<&str>) -> Duration {
    raw.and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(|v| Duration::from_secs_f64(v.min(60.0)))
        .unwrap_or(Duration::from_secs_f64(1.5))
}

fn is_public_ip(addr: std::net::IpAddr) -> bool {
    match addr.to_canonical() {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            let is_cgnat = octets[0] == 100 && (octets[1] & 0b1100_0000) == 64;
            let is_benchmark = octets[0] == 198 && (octets[1] == 18 || octets[1] == 19);
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || is_cgnat
                || is_benchmark)
        }
        std::net::IpAddr::V6(v6) => {
            let segs = v6.segments();
            let is_doc = segs[0] == 0x2001 && segs[1] == 0x0db8;
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || is_doc)
        }
    }
}

/// Server-side rDNS policy: resolve only when the ASN org is missing
/// (otherwise PTR adds nothing worth a DNS round-trip), only for public
/// unicast IPs, at most RDNS_MAX_CONCURRENT resolutions at once, results
/// cached for an hour. The client cannot request rDNS — there is no such
/// parameter.
async fn maybe_rdns(state: &AppState, ip: &str, aso: Option<&str>) -> Option<String> {
    if state.rdns_timeout.is_zero() || aso.map(|o| !o.trim().is_empty()).unwrap_or(false) {
        return None;
    }
    let addr = ip.parse::<std::net::IpAddr>().ok()?.to_canonical();
    if !is_public_ip(addr) {
        return None;
    }
    let key = addr.to_string();
    if let Some(hit) = state.ptr_cache.get(&key) {
        return hit;
    }
    // Keep the permit inside the blocking task: wrapping the JoinHandle
    // in a timeout only stops waiting, not the resolver call. This bounds
    // the number of real blocking lookups (and their threads) to the
    // semaphore, even when callers give up early.
    let permit = match tokio::time::timeout(
        Duration::from_millis(100),
        state.rdns_sem.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        _ => {
            state.metrics.rdns_skipped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    if let Some(hit) = state.ptr_cache.get(&key) {
        return hit;
    }
    state.metrics.rdns_lookups.fetch_add(1, Ordering::Relaxed);
    let cache = state.ptr_cache.clone();
    let key_for_task = key.clone();
    let fut = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let res = dns_lookup::lookup_addr(&addr).ok();
        // Cache the eventual answer even if the request timed out: the
        // next request should not repeat a slow/absent lookup.
        cache.insert(key_for_task, res.clone());
        res
    });
    match tokio::time::timeout(state.rdns_timeout, fut).await {
        Ok(Ok(v)) => v,
        _ => {
            state.metrics.rdns_timeouts.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

async fn index(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "proxpulse-judge",
        "version": VERSION,
        "repository": REPOSITORY,
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
            "GET /readyz",
            "GET /metrics",
        ],
    }))
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({"ok": true}))
}

async fn readyz(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let sources = s.geo.sources();
    Json(serde_json::json!({
        "ok": true,
        "geo_ready": !sources.is_empty(),
        "geo_sources": sources,
    }))
}

async fn metrics_ep(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let m = &s.metrics;
    let geo_ready = if s.geo.sources().is_empty() { 0 } else { 1 };
    let body = format!(
        "# HELP proxpulse_requests_total Total HTTP requests handled.\n\
         # TYPE proxpulse_requests_total counter\n\
         proxpulse_requests_total {}\n\
         # HELP proxpulse_responses_4xx_total Responses with 4xx status.\n\
         # TYPE proxpulse_responses_4xx_total counter\n\
         proxpulse_responses_4xx_total {}\n\
         # HELP proxpulse_responses_5xx_total Responses with 5xx status.\n\
         # TYPE proxpulse_responses_5xx_total counter\n\
         proxpulse_responses_5xx_total {}\n\
         # HELP proxpulse_rate_limited_total Requests rejected by the rate limiter.\n\
         # TYPE proxpulse_rate_limited_total counter\n\
         proxpulse_rate_limited_total {}\n\
         # HELP proxpulse_rdns_lookups_total Blocking rDNS lookups spawned.\n\
         # TYPE proxpulse_rdns_lookups_total counter\n\
         proxpulse_rdns_lookups_total {}\n\
         # HELP proxpulse_rdns_timeouts_total rDNS lookups that exceeded the request timeout.\n\
         # TYPE proxpulse_rdns_timeouts_total counter\n\
         proxpulse_rdns_timeouts_total {}\n\
         # HELP proxpulse_rdns_skipped_total Requests skipped because no rDNS permit was available.\n\
         # TYPE proxpulse_rdns_skipped_total counter\n\
         proxpulse_rdns_skipped_total {}\n\
         # HELP proxpulse_geo_ready 1 when at least one geo database is loaded.\n\
         # TYPE proxpulse_geo_ready gauge\n\
         proxpulse_geo_ready {}\n\
         # HELP proxpulse_build_info Build version information.\n\
         # TYPE proxpulse_build_info gauge\n\
         proxpulse_build_info{{version=\"{}\"}} 1\n",
        m.requests.load(Ordering::Relaxed),
        m.responses_4xx.load(Ordering::Relaxed),
        m.responses_5xx.load(Ordering::Relaxed),
        m.rate_limited.load(Ordering::Relaxed),
        m.rdns_lookups.load(Ordering::Relaxed),
        m.rdns_timeouts.load(Ordering::Relaxed),
        m.rdns_skipped.load(Ordering::Relaxed),
        geo_ready,
        VERSION,
    );
    let mut h = HeaderMap::new();
    h.insert(
        "content-type",
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    (h, body)
}

async fn generate_204() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

async fn ip(
    State(s): State<Arc<AppState>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    Json(serde_json::json!({ "ip": self_ip(&headers, Some(conn.0), s.trust_proxy, s.trust_cf) }))
}

async fn headers_echo(
    State(s): State<Arc<AppState>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let me = self_ip(&headers, Some(conn.0), s.trust_proxy, s.trust_cf);
    let raw = headers_lower(&headers);
    let chain = forwarded_chain(
        raw.get("x-forwarded-for").map(|x| x.as_str()),
        &me,
        s.trust_proxy,
        s.trust_cf,
        raw.get("cf-connecting-ip").map(|x| x.as_str()),
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
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let me = self_ip(&headers, Some(conn.0), s.trust_proxy, s.trust_cf);
    let data = geo_cached(&s, &me);
    Json(serde_json::json!({
        "ip": me,
        "geo": data,
        "source": sources_or_null(&s),
        "attribution": attribution(&s),
    }))
}

fn sources_or_null(s: &AppState) -> serde_json::Value {
    let m = s.geo.sources();
    if m.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::json!(m)
    }
}

/// Required attribution for the DB actually loaded (DB-IP CC BY 4.0 /
/// MaxMind GeoLite2 EULA), so API consumers can show it with geo results.
fn attribution(s: &AppState) -> Vec<&'static str> {
    s.geo.attributions()
}

async fn ip_type(
    State(s): State<Arc<AppState>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let me = self_ip(&headers, Some(conn.0), s.trust_proxy, s.trust_cf);
    let data = geo_cached(&s, &me);
    let ptr = maybe_rdns(&s, &me, data.aso.as_deref()).await;
    let (t, signals) = classify_ip(data.aso.as_deref(), ptr.as_deref());
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
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(p): Query<JudgeParams>,
) -> impl IntoResponse {
    let me = self_ip(&headers, Some(conn.0), s.trust_proxy, s.trust_cf);
    let raw = headers_lower(&headers);
    let chain = forwarded_chain(
        raw.get("x-forwarded-for").map(|x| x.as_str()),
        &me,
        s.trust_proxy,
        s.trust_cf,
        raw.get("cf-connecting-ip").map(|x| x.as_str()),
    );

    let mut for_analysis = raw.clone();
    if s.trust_proxy && for_analysis.contains_key("x-forwarded-for") {
        // strip our edge's own additions (see forwarded_chain): the rest
        // (if any) was forwarded by the checked proxy
        let raw_pre_edge = pre_edge_xff(
            raw.get("x-forwarded-for").map(|x| x.as_str()),
            &me,
            s.trust_proxy,
            s.trust_cf,
            raw.get("cf-connecting-ip").map(|x| x.as_str()),
        );
        let stripped = if !chain.is_empty() {
            chain.join(", ")
        } else if !raw_pre_edge.is_empty() {
            "unknown".to_string()
        } else {
            String::new()
        };
        for_analysis.insert("x-forwarded-for".to_string(), stripped);
    }
    let level = {
        // garbage direct_ip is ignored instead of compared (a header value
        // could otherwise "match" it and fake a transparent verdict)
        let direct = p.direct_ip.as_deref().and_then(normalize_host);
        anonymity_level(&for_analysis, direct.as_deref(), s.trust_cf)
    };

    let g = geo_cached(&s, &me);
    let ptr = maybe_rdns(&s, &me, g.aso.as_deref()).await;
    let (t, signals) = classify_ip(g.aso.as_deref(), ptr.as_deref());

    no_store_json(serde_json::json!({
        "ip": me,
        "headers": raw,
        "xff_chain": chain,
        "anonymity": level,
        "geo": g,
        "geo_source": sources_or_null(&s),
        "attribution": attribution(&s),
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

/// Add `Cache-Control: no-store` to every per-request response. Only the
/// fixed-content endpoint is safe to cache.
async fn no_store_mw(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_string();
    let mut res = next.run(req).await;
    if path != "/content" || res.status() != StatusCode::OK {
        res.headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
    }
    res
}

/// Lightweight access logging at debug level; default `RUST_LOG=info`
/// keeps normal request handling quiet.
async fn access_log_mw(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let started = Instant::now();
    let res = next.run(req).await;
    tracing::debug!(
        method = %method,
        path = %path,
        status = res.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis(),
        "request"
    );
    res
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
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
    // Docker sends SIGTERM on `stop` — without this arm the container
    // would die mid-request instead of draining gracefully.
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_ep))
        .route("/generate_204", get(generate_204))
        .route("/ip", get(ip))
        .route("/headers", get(headers_echo))
        .route("/geo", get(geo_ep))
        .route("/type", get(ip_type))
        .route("/content", get(content))
        .route("/judge", get(judge))
        .layer(axum::middleware::from_fn(timeout_mw))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            concurrency_mw,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit_mw,
        ))
        .layer(axum::middleware::from_fn(no_store_mw))
        .layer(axum::middleware::from_fn(access_log_mw))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            metrics_mw,
        ))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8000);
    if std::env::args().any(|a| a == "--healthcheck") {
        std::process::exit(i32::from(!healthcheck(port)));
    }

    let geo_dir = env::var("GEO_DIR").unwrap_or_else(|_| "/app/geo".to_string());
    if std::env::args().any(|a| a == "--check-geo") {
        let pool = GeoPool::open(std::path::Path::new(&geo_dir));
        match pool.verify() {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("geo validation failed: {e}");
                std::process::exit(1);
            }
        }
    }
    let trust_proxy = env::var("TRUST_PROXY").unwrap_or_else(|_| "1".to_string()) == "1";
    // CF headers are proxy headers too: without TRUST_PROXY the service
    // must resolve the IP from the socket, never from client headers.
    let trust_cf = trust_proxy && env::var("TRUST_CF").unwrap_or_else(|_| "0".to_string()) == "1";
    let rdns_timeout = parse_rdns_timeout(env::var("RDNS_TIMEOUT").ok().as_deref());
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
            hits: new_hits_cache(),
        }),
        metrics: Arc::new(Metrics::default()),
        concurrency: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENCY)),
        trust_proxy,
        trust_cf,
        rdns_timeout,
    });

    let app = build_app(state);

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
    tracing::info!("proxpulse-judge v{VERSION} on {addr} (trust_proxy={trust_proxy}, trust_cf={trust_cf}, rate_per_minute={rate_per_minute})");
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    async fn add_connect_info(
        mut req: axum::http::Request<axum::body::Body>,
        next: axum::middleware::Next,
    ) -> Response {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))));
        next.run(req).await
    }

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
                hits: new_hits_cache(),
            }),
            metrics: Arc::new(Metrics::default()),
            concurrency: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENCY)),
            trust_proxy: true,
            trust_cf: true,
            rdns_timeout: Duration::ZERO,
        });
        build_app(state).layer(axum::middleware::from_fn(add_connect_info))
    }

    #[test]
    fn rdns_timeout_parsing_is_panic_free() {
        let default = Duration::from_secs_f64(1.5);
        assert_eq!(parse_rdns_timeout(None), default);
        assert_eq!(parse_rdns_timeout(Some("")), default);
        assert_eq!(parse_rdns_timeout(Some("-1")), default);
        assert_eq!(parse_rdns_timeout(Some("nan")), default);
        assert_eq!(parse_rdns_timeout(Some("inf")), default);
        assert_eq!(
            parse_rdns_timeout(Some("2.5")),
            Duration::from_secs_f64(2.5)
        );
        assert_eq!(parse_rdns_timeout(Some("0")), Duration::ZERO);
        assert_eq!(parse_rdns_timeout(Some("1e9")), Duration::from_secs(60));
    }

    #[test]
    fn limit_window_allows_then_blocks() {
        let mut q = VecDeque::new();
        let now = Instant::now();
        assert_eq!(check_limit(&mut q, now, 2), None);
        assert_eq!(check_limit(&mut q, now, 2), None);
        let retry = check_limit(&mut q, now, 2);
        assert!(retry.is_some() && retry.unwrap() >= 1 && retry.unwrap() <= 61);
        // another key has its own queue/budget
        let mut other = VecDeque::new();
        assert_eq!(check_limit(&mut other, now, 2), None);
        // limit = 0 is a no-op even on an empty queue
        assert_eq!(check_limit(&mut VecDeque::new(), now, 0), None);
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
            res.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }

    #[tokio::test]
    async fn dynamic_endpoints_are_no_store() {
        for path in [
            "/ip", "/headers", "/geo", "/type", "/healthz", "/readyz", "/metrics",
        ] {
            let res = test_app()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            assert_eq!(
                res.headers()
                    .get("cache-control")
                    .and_then(|v| v.to_str().ok()),
                Some("no-store"),
                "{path}"
            );
        }
        // /content is the fixed integrity reference and may be cached.
        let res = test_app()
            .oneshot(Request::get("/content").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(res.headers().get("cache-control").is_none());
    }

    #[tokio::test]
    async fn metrics_and_readyz() {
        let app = test_app();
        let ready = app
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);
        let body = axum::body::to_bytes(ready.into_body(), 65536)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["geo_ready"], false);

        let metrics = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(metrics.status(), StatusCode::OK);
        let body = axum::body::to_bytes(metrics.into_body(), 65536)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("proxpulse_requests_total"));
        assert!(text.contains("proxpulse_build_info"));
        assert!(text.contains("proxpulse_geo_ready 0"));
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
        assert_eq!(v["repository"], REPOSITORY);
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
    async fn duplicate_xff_is_joined_consistently() {
        let res = test_app()
            .oneshot(
                Request::get("/judge?direct_ip=1.1.1.1")
                    .header("x-forwarded-for", "1.1.1.1")
                    .header("x-forwarded-for", "9.9.9.9")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ip"], "9.9.9.9");
        assert_eq!(v["xff_chain"], serde_json::json!(["1.1.1.1"]));
        assert_eq!(v["headers"]["x-forwarded-for"], "1.1.1.1, 9.9.9.9");
        assert_eq!(v["anonymity"], "transparent");
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
                hits: new_hits_cache(),
            }),
            metrics: Arc::new(Metrics::default()),
            concurrency: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENCY)),
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
    async fn rdns_skipped_for_private_and_loopback_ips() {
        let state = Arc::new(AppState {
            geo: Arc::new(GeoPool::open(std::path::Path::new("/nonexistent-dir-xyz"))),
            geo_cache: Cache::builder().max_capacity(16).build(),
            ptr_cache: Cache::builder().max_capacity(16).build(),
            rdns_sem: Arc::new(tokio::sync::Semaphore::new(16)),
            rate_limit: Arc::new(RateLimit {
                per_minute: 1_000_000,
                hits: new_hits_cache(),
            }),
            metrics: Arc::new(Metrics::default()),
            concurrency: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENCY)),
            trust_proxy: true,
            trust_cf: true,
            rdns_timeout: Duration::from_secs(2),
        });
        for ip in [
            "127.0.0.1",
            "::1",
            "10.0.0.1",
            "172.17.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.1.1",
            "203.0.113.7",
            "2001:db8::1",
            "fe80::1",
            "fc00::1",
        ] {
            assert!(maybe_rdns(&state, ip, None).await.is_none(), "{ip}");
        }
        assert_eq!(state.metrics.rdns_lookups.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn judge_unknown_xff_behind_proxy_is_anonymous() {
        let res = test_app()
            .oneshot(
                Request::get("/judge?direct_ip=1.2.3.4")
                    .header("x-forwarded-for", "unknown, 5.6.7.8")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ip"], "5.6.7.8");
        assert_eq!(v["xff_chain"], serde_json::json!([]));
        assert_eq!(v["anonymity"], "anonymous");
    }

    #[tokio::test]
    async fn judge_non_ascii_header_still_detects_ip_leak() {
        let mut req = Request::get("/judge?direct_ip=1.2.3.4")
            .header("x-forwarded-for", "5.6.7.8")
            .body(Body::empty())
            .unwrap();
        req.headers_mut().insert(
            "x-client-info",
            HeaderValue::from_bytes(b"proxy \xc3\xa9 1.2.3.4").unwrap(),
        );
        let res = test_app().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["anonymity"], "transparent");
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
