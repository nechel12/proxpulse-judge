//! HTTP API: shared state, middleware and handlers.
use axum::{
    Json, Router,
    extract::{ConnectInfo, Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{
            AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS,
        },
    },
    response::{IntoResponse, Response},
    routing::get,
};
use moka::sync::Cache;
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

use crate::config::Config;
use crate::geo::{GeoInfo, GeoPool};
use crate::logic::{
    self, anonymity_level, classify_ip, client_ip, normalize_chain, normalize_host, pre_edge_xff,
};
use crate::metrics::{Metrics, inc};
use crate::ratelimit::RateLimit;
use crate::sign::{Signer, valid_nonce};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const REPOSITORY: &str = "https://github.com/nechel12/proxpulse-judge";
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CONCURRENCY: usize = 512;
const RDNS_MAX_CONCURRENT: usize = 16;

pub struct AppState {
    pub geo: GeoPool,
    pub geo_cache: Cache<String, GeoInfo>,
    pub ptr_cache: Cache<String, Option<String>>,
    pub rdns_sem: Arc<Semaphore>,
    pub rate_limit: RateLimit,
    pub metrics: Metrics,
    pub concurrency: Arc<Semaphore>,
    pub trust_proxy: bool,
    pub trust_cf: bool,
    pub rdns_timeout: Duration,
    pub edge_headers: Vec<String>,
    pub metrics_token: Option<String>,
    pub signer: Signer,
}

impl AppState {
    pub fn new(geo: GeoPool, cfg: &Config) -> Self {
        Self {
            geo,
            geo_cache: Cache::builder().max_capacity(65_536).build(),
            ptr_cache: Cache::builder()
                .max_capacity(65_536)
                .time_to_live(Duration::from_secs(3600))
                .build(),
            rdns_sem: Arc::new(Semaphore::new(RDNS_MAX_CONCURRENT)),
            rate_limit: RateLimit::new(cfg.rate_per_minute),
            metrics: Metrics::default(),
            concurrency: Arc::new(Semaphore::new(MAX_CONCURRENCY)),
            trust_proxy: cfg.trust_proxy,
            trust_cf: cfg.trust_cf,
            rdns_timeout: cfg.rdns_timeout,
            edge_headers: cfg.edge_headers.clone(),
            metrics_token: cfg.metrics_token.clone(),
            signer: cfg.signer.clone(),
        }
    }
}

/// Monitoring endpoints bypass the rate and concurrency limits so probes
/// keep working under load.
fn is_monitoring(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz" | "/metrics")
}

async fn rate_limit_mw(
    State(s): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !is_monitoring(req.uri().path()) {
        let conn = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0);
        let client = self_ip(&s, req.headers(), conn);
        if let Some(secs) = s.rate_limit.check(&client) {
            inc(&s.metrics.rate_limited);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", secs.to_string())],
                Json(serde_json::json!({ "error": "rate limited" })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

async fn metrics_mw(
    State(s): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let res = next.run(req).await;
    inc(&s.metrics.requests);
    let status = res.status();
    if status.is_client_error() {
        inc(&s.metrics.responses_4xx);
    }
    if status.is_server_error() {
        inc(&s.metrics.responses_5xx);
    }
    res
}

async fn concurrency_mw(
    State(s): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if is_monitoring(req.uri().path()) {
        return next.run(req).await;
    }
    let permit = tokio::time::timeout(
        Duration::from_secs(5),
        s.concurrency.clone().acquire_owned(),
    )
    .await;
    let Ok(Ok(_permit)) = permit else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "busy" })),
        )
            .into_response();
    };
    next.run(req).await
}

async fn timeout_mw(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(res) => res,
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(serde_json::json!({ "error": "request timeout" })),
        )
            .into_response(),
    }
}

/// `Cache-Control: no-store` on every per-request response (only the fixed
/// `/content` reference may be cached) and `nosniff` everywhere, since
/// several endpoints echo client-controlled header values.
async fn response_headers_mw(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let cacheable = req.uri().path() == "/content";
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if !cacheable || res.status() != StatusCode::OK {
        res.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

/// Lightweight access logging at debug level; default `RUST_LOG=info`
/// keeps normal request handling quiet.
async fn access_log_mw(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
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

#[derive(Deserialize)]
struct JudgeParams {
    direct_ip: Option<String>,
    /// Random value from the checker, bound into the signature.
    nonce: Option<String>,
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

fn self_ip(s: &AppState, headers: &HeaderMap, conn: Option<SocketAddr>) -> String {
    let cf = joined_header(headers, "cf-connecting-ip");
    let xff = joined_header(headers, "x-forwarded-for");
    let sock = conn.map(|addr| addr.ip().to_string());
    client_ip(
        cf.as_deref(),
        xff.as_deref(),
        sock.as_deref().unwrap_or("127.0.0.1"),
        s.trust_proxy,
        s.trust_cf,
    )
}

/// Request headers as the client side sent them: X-Forwarded-For keeps
/// only the entries added before our reverse proxy (dropped when there are
/// none), and `EDGE_HEADERS` are removed. This view is both echoed and
/// analysed. Also returns the normalized forwarded chain.
fn proxy_view(
    s: &AppState,
    headers: &HeaderMap,
    me: &str,
) -> (HashMap<String, String>, Vec<String>) {
    let mut view = headers_lower(headers);
    let pre_edge = pre_edge_xff(
        view.get("x-forwarded-for").map(String::as_str),
        me,
        s.trust_proxy,
        s.trust_cf,
        view.get("cf-connecting-ip").map(String::as_str),
    );
    let chain = normalize_chain(&pre_edge);
    if s.trust_proxy {
        view.retain(|name, _| !s.edge_headers.contains(name));
        if pre_edge.is_empty() {
            view.remove("x-forwarded-for");
        } else {
            view.insert("x-forwarded-for".to_string(), pre_edge.join(", "));
        }
    }
    (view, chain)
}

fn geo_cached(state: &AppState, ip: &str) -> GeoInfo {
    state
        .geo_cache
        .get_with(ip.to_string(), || state.geo.lookup(ip))
}

fn is_public_ip(addr: IpAddr) -> bool {
    match addr.to_canonical() {
        IpAddr::V4(v4) => {
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
        IpAddr::V6(v6) => {
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
    if state.rdns_timeout.is_zero() || aso.is_some_and(|o| !o.trim().is_empty()) {
        return None;
    }
    let addr = ip.parse::<IpAddr>().ok()?.to_canonical();
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
    let Ok(Ok(permit)) = tokio::time::timeout(
        Duration::from_millis(100),
        state.rdns_sem.clone().acquire_owned(),
    )
    .await
    else {
        inc(&state.metrics.rdns_skipped);
        return None;
    };
    if let Some(hit) = state.ptr_cache.get(&key) {
        return hit;
    }
    inc(&state.metrics.rdns_lookups);
    let cache = state.ptr_cache.clone();
    let fut = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let res = dns_lookup::lookup_addr(&addr).ok();
        // Cache the eventual answer even if the request timed out: the
        // next request should not repeat a slow/absent lookup.
        cache.insert(key, res.clone());
        res
    });
    match tokio::time::timeout(state.rdns_timeout, fut).await {
        Ok(Ok(v)) => v,
        _ => {
            inc(&state.metrics.rdns_timeouts);
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
            "GET /key",
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

/// Compare without an early exit on the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn metrics_ep(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = &s.metrics_token {
        let presented = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if !presented.is_some_and(|p| constant_time_eq(p.as_bytes(), token.as_bytes())) {
            return (
                StatusCode::UNAUTHORIZED,
                [(WWW_AUTHENTICATE, "Bearer")],
                Json(serde_json::json!({ "error": "unauthorized" })),
            )
                .into_response();
        }
    }
    let body = s.metrics.render(!s.geo.sources().is_empty(), VERSION);
    ([(CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

async fn generate_204() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

async fn ip(
    State(s): State<Arc<AppState>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    Json(serde_json::json!({ "ip": self_ip(&s, &headers, Some(conn.0)) }))
}

async fn headers_echo(
    State(s): State<Arc<AppState>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let me = self_ip(&s, &headers, Some(conn.0));
    let (view, chain) = proxy_view(&s, &headers, &me);
    Json(serde_json::json!({ "ip": me, "headers": view, "xff_chain": chain }))
}

async fn geo_ep(
    State(s): State<Arc<AppState>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let me = self_ip(&s, &headers, Some(conn.0));
    let data = geo_cached(&s, &me);
    Json(serde_json::json!({
        "ip": me,
        "geo": data,
        "source": sources_or_null(&s),
        "attribution": s.geo.attributions(),
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

async fn ip_type(
    State(s): State<Arc<AppState>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let me = self_ip(&s, &headers, Some(conn.0));
    let data = geo_cached(&s, &me);
    let ptr = maybe_rdns(&s, &me, data.aso.as_deref()).await;
    let (t, signals) = classify_ip(data.aso.as_deref(), ptr.as_deref());
    Json(serde_json::json!({ "ip": me, "ip_type": t, "signals": signals }))
}

async fn content() -> impl IntoResponse {
    ([(CONTENT_TYPE, "application/json")], logic::FIXED_CONTENT)
}

/// Public key for /judge signatures.
async fn key(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "alg": "ed25519",
        "key_id": s.signer.key_id,
        "public_key": s.signer.public_key,
    }))
}

async fn judge(
    State(s): State<Arc<AppState>>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(p): Query<JudgeParams>,
) -> Response {
    let me = self_ip(&s, &headers, Some(conn.0));
    let (view, chain) = proxy_view(&s, &headers, &me);
    // A line feed would move bytes between the signed fields (sign::message),
    // so such a value counts as absent for the verdict and the signature alike.
    let direct_raw = p.direct_ip.as_deref().filter(|d| !d.contains('\n'));
    // garbage direct_ip is ignored instead of compared (a header value
    // could otherwise "match" it and fake a transparent verdict)
    let direct = direct_raw.and_then(normalize_host);
    let level = anonymity_level(&view, direct.as_deref(), s.trust_cf);

    let g = geo_cached(&s, &me);
    let ptr = maybe_rdns(&s, &me, g.aso.as_deref()).await;
    let (t, signals) = classify_ip(g.aso.as_deref(), ptr.as_deref());

    let body = serde_json::json!({
        "ip": me,
        "headers": view,
        "xff_chain": chain,
        "anonymity": level,
        "geo": g,
        "geo_source": sources_or_null(&s),
        "attribution": s.geo.attributions(),
        "ip_type": t,
        "type_signals": signals,
        "content_version": logic::CONTENT_VERSION,
        "content_sha256": logic::content_sha256(),
    })
    .to_string()
    .into_bytes();
    let challenge = p.nonce.as_deref().filter(|n| valid_nonce(n)).unwrap_or("");
    let sig = s.signer.sign(challenge, direct_raw.unwrap_or(""), &body);
    let mut res = ([(CONTENT_TYPE, "application/json")], body).into_response();
    let h = res.headers_mut();
    if let (Ok(sig), Ok(id)) = (
        HeaderValue::from_str(&sig),
        HeaderValue::from_str(&s.signer.key_id),
    ) {
        h.insert("x-judge-signature", sig);
        h.insert("x-judge-key-id", id);
    }
    res
}

pub fn build_app(state: Arc<AppState>) -> Router {
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
        .route("/key", get(key))
        .layer(axum::middleware::from_fn(timeout_mw))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            concurrency_mw,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit_mw,
        ))
        .layer(axum::middleware::from_fn(response_headers_mw))
        .layer(axum::middleware::from_fn(access_log_mw))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            metrics_mw,
        ))
        .with_state(state)
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use crate::geo::test_mmdb::{self, TempDir};
    use axum::{body::Body, http::Request};
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;

    const NO_GEO_DIR: &str = "/nonexistent-dir-xyz";

    async fn add_connect_info(
        mut req: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> Response {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))));
        next.run(req).await
    }

    fn test_config(per_minute: u32, rdns_timeout: Duration) -> Config {
        Config {
            port: 8000,
            bind: IpAddr::from([127, 0, 0, 1]),
            geo_dir: NO_GEO_DIR.to_string(),
            trust_proxy: true,
            trust_cf: true,
            rdns_timeout,
            rate_per_minute: per_minute,
            edge_headers: vec![],
            metrics_token: None,
            signer: crate::sign::Signer::generate().unwrap(),
        }
    }

    fn test_state(geo_dir: &Path, cfg: &Config) -> Arc<AppState> {
        Arc::new(AppState::new(GeoPool::open(geo_dir), cfg))
    }

    fn test_app_with(cfg: &Config) -> Router {
        test_app_with_state(test_state(Path::new(NO_GEO_DIR), cfg))
    }

    fn test_app_with_state(state: Arc<AppState>) -> Router {
        build_app(state).layer(axum::middleware::from_fn(add_connect_info))
    }

    fn test_app() -> Router {
        test_app_with(&test_config(1_000_000, Duration::ZERO))
    }

    fn get_with(path: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut req = Request::get(path);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.body(Body::empty()).unwrap()
    }

    async fn json(app: Router, req: Request<Body>) -> serde_json::Value {
        let res = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn rate_limit_blocks_and_healthz_exempt() {
        let app = test_app_with(&test_config(2, Duration::ZERO));
        let get_ip = || get_with("/ip", &[("x-forwarded-for", "9.9.9.9")]);
        for _ in 0..2 {
            assert_eq!(
                app.clone().oneshot(get_ip()).await.unwrap().status(),
                StatusCode::OK
            );
        }
        let limited = app.clone().oneshot(get_ip()).await.unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            limited
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("30")
        );
        assert_eq!(
            limited
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        // healthz never counts
        for _ in 0..5 {
            assert_eq!(
                app.clone()
                    .oneshot(get_with("/healthz", &[]))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
    }

    #[tokio::test]
    async fn rate_limit_is_not_bypassed_by_rotating_ipv6_in_a_64() {
        let app = test_app_with(&test_config(2, Duration::ZERO));
        let get_from = |ip: &str| get_with("/ip", &[("x-forwarded-for", ip)]);
        for ip in ["2001:db8:1:2::1", "2001:db8:1:2::2"] {
            assert_eq!(
                app.clone().oneshot(get_from(ip)).await.unwrap().status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            app.clone()
                .oneshot(get_from("2001:db8:1:2:ffff::3"))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // another /64 has its own budget
        assert_eq!(
            app.oneshot(get_from("2001:db8:1:3::1"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn garbage_direct_ip_is_ignored() {
        // user-agent "matches" the garbage direct_ip — must NOT fake transparent
        let v = json(
            test_app(),
            get_with("/judge?direct_ip=not-an-ip", &[("user-agent", "not-an-ip")]),
        )
        .await;
        assert_eq!(v["anonymity"], "elite");
    }

    #[tokio::test]
    async fn dynamic_endpoints_are_no_store_and_nosniff() {
        for path in [
            "/ip", "/headers", "/geo", "/type", "/judge", "/key", "/healthz", "/readyz", "/metrics",
        ] {
            let res = test_app().oneshot(get_with(path, &[])).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            assert_eq!(
                res.headers()
                    .get(CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-store"),
                "{path}"
            );
            assert_eq!(
                res.headers()
                    .get(X_CONTENT_TYPE_OPTIONS)
                    .and_then(|v| v.to_str().ok()),
                Some("nosniff"),
                "{path}"
            );
        }
        // /content is the fixed integrity reference and may be cached.
        let res = test_app().oneshot(get_with("/content", &[])).await.unwrap();
        assert!(res.headers().get(CACHE_CONTROL).is_none());
        assert!(res.headers().get(X_CONTENT_TYPE_OPTIONS).is_some());
    }

    #[tokio::test]
    async fn metrics_and_readyz() {
        let app = test_app();
        let v = json(app.clone(), get_with("/readyz", &[])).await;
        assert_eq!(v["ok"], true);
        assert_eq!(v["geo_ready"], false);

        let metrics = app.oneshot(get_with("/metrics", &[])).await.unwrap();
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
    async fn metrics_token_is_enforced_when_set() {
        let mut cfg = test_config(1_000_000, Duration::ZERO);
        cfg.metrics_token = Some("s3cret".to_string());
        let app = test_app_with(&cfg);
        for auth in [None, Some("Bearer wrong"), Some("s3cret")] {
            let headers: Vec<(&str, &str)> =
                auth.map(|a| ("authorization", a)).into_iter().collect();
            let res = app
                .clone()
                .oneshot(get_with("/metrics", &headers))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{auth:?}");
        }
        let res = app
            .oneshot(get_with("/metrics", &[("authorization", "Bearer s3cret")]))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn index_has_licenses() {
        let v = json(test_app(), get_with("/", &[])).await;
        assert_eq!(v["service"], "proxpulse-judge");
        assert_eq!(v["repository"], REPOSITORY);
        assert_eq!(v["licenses"]["dbip_lite"]["license"], "CC BY 4.0");
        assert!(
            v["licenses"]["geolite2"]["url"]
                .as_str()
                .unwrap_or("")
                .contains("maxmind.com")
        );
    }

    #[tokio::test]
    async fn generate_204_empty() {
        let res = test_app()
            .oneshot(get_with("/generate_204", &[]))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn judge_transparent() {
        let v = json(
            test_app(),
            get_with(
                "/judge?direct_ip=1.1.1.1",
                &[("x-forwarded-for", "1.1.1.1, 5.6.7.8")],
            ),
        )
        .await;
        assert_eq!(v["ip"], "5.6.7.8");
        assert_eq!(v["anonymity"], "transparent");
        assert_eq!(v["content_sha256"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn duplicate_xff_is_joined_consistently() {
        let v = json(
            test_app(),
            get_with(
                "/judge?direct_ip=1.1.1.1",
                &[
                    ("x-forwarded-for", "1.1.1.1"),
                    ("x-forwarded-for", "9.9.9.9"),
                ],
            ),
        )
        .await;
        assert_eq!(v["ip"], "9.9.9.9");
        assert_eq!(v["xff_chain"], serde_json::json!(["1.1.1.1"]));
        // the echoed XFF is what came from before our edge
        assert_eq!(v["headers"]["x-forwarded-for"], "1.1.1.1");
        assert_eq!(v["anonymity"], "transparent");
    }

    #[tokio::test]
    async fn edge_only_xff_is_not_echoed() {
        for path in ["/judge", "/headers"] {
            let v = json(
                test_app(),
                get_with(path, &[("x-forwarded-for", "5.6.7.8")]),
            )
            .await;
            assert_eq!(v["ip"], "5.6.7.8", "{path}");
            assert!(v["headers"].get("x-forwarded-for").is_none(), "{path}");
            assert_eq!(v["xff_chain"], serde_json::json!([]), "{path}");
        }
    }

    #[tokio::test]
    async fn judge_answers_are_signed_with_the_published_key() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Without SIGNING_KEY (a generated key) and with one: both sign.
        let generated = test_config(1_000_000, Duration::ZERO);
        let mut configured = test_config(1_000_000, Duration::ZERO);
        configured.signer =
            crate::sign::Signer::from_seed_b64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
                .unwrap();
        for cfg in [generated, configured] {
            let key = json(test_app_with(&cfg), get_with("/key", &[])).await;
            assert_eq!(key["alg"], "ed25519");
            let public: [u8; 32] = STANDARD
                .decode(key["public_key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let vk = VerifyingKey::from_bytes(&public).unwrap();

            let res = test_app_with(&cfg)
                .oneshot(get_with("/judge?direct_ip=1.1.1.1&nonce=abcdefgh12", &[]))
                .await
                .unwrap();
            assert_eq!(
                res.headers()["x-judge-key-id"],
                key["key_id"].as_str().unwrap()
            );
            let sig = STANDARD
                .decode(res.headers()["x-judge-signature"].as_bytes())
                .unwrap();
            let sig = Signature::from_slice(&sig).unwrap();
            let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
            let ok = crate::sign::message("abcdefgh12", "1.1.1.1", &body);
            assert!(vk.verify(&ok, &sig).is_ok());
            // Another nonce or direct_ip does not verify: no replay, no rewrite.
            let replay = crate::sign::message("otherNonce1", "1.1.1.1", &body);
            assert!(vk.verify(&replay, &sig).is_err());
            let moved = crate::sign::message("abcdefgh12", "2.2.2.2", &body);
            assert!(vk.verify(&moved, &sig).is_err());
        }
    }

    /// The key from `cfg`, and the signature and body of the answer at `path`.
    async fn signed_answer(
        cfg: &Config,
        path: &str,
    ) -> (
        ed25519_dalek::VerifyingKey,
        ed25519_dalek::Signature,
        Vec<u8>,
    ) {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let public: [u8; 32] = STANDARD
            .decode(&cfg.signer.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let res = test_app_with(cfg)
            .oneshot(get_with(path, &[]))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{path}");
        let sig = STANDARD
            .decode(res.headers()["x-judge-signature"].as_bytes())
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), 65536).await.unwrap();
        (
            ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap(),
            ed25519_dalek::Signature::from_slice(&sig).unwrap(),
            body.to_vec(),
        )
    }

    #[tokio::test]
    async fn line_feed_in_direct_ip_cannot_move_bytes_into_the_body() {
        use crate::sign::message;
        use ed25519_dalek::Verifier;

        let cfg = test_config(1_000_000, Duration::ZERO);
        let (vk, sig, body) =
            signed_answer(&cfg, "/judge?direct_ip=1.1.1.1%0Aforged&nonce=abcdefgh12").await;

        // What a proxy would present: its prefix as part of the body, checked
        // against the direct_ip the client really sent.
        let forged = [b"forged\n".as_slice(), &body].concat();
        assert!(
            vk.verify(&message("abcdefgh12", "1.1.1.1", &forged), &sig)
                .is_err()
        );
        assert!(
            vk.verify(&message("abcdefgh12", "1.1.1.1", &body), &sig)
                .is_err()
        );
        // The value counted as absent.
        assert!(vk.verify(&message("abcdefgh12", "", &body), &sig).is_ok());
    }

    #[tokio::test]
    async fn line_feed_in_direct_ip_counts_as_absent_for_the_verdict() {
        let leak = [
            ("x-forwarded-for", "1.1.1.1"),
            ("x-forwarded-for", "9.9.9.9"),
        ];
        let verdict = |path: &'static str| json(test_app(), get_with(path, &leak));
        assert_eq!(
            verdict("/judge?direct_ip=1.1.1.1").await["anonymity"],
            "transparent"
        );
        // Otherwise a proxy could inject a direct_ip the client never sent and
        // change the verdict while the signature still verifies.
        assert_eq!(
            verdict("/judge?direct_ip=1.1.1.1%0A").await["anonymity"],
            verdict("/judge").await["anonymity"]
        );
    }

    #[tokio::test]
    async fn absent_values_and_invalid_nonce_sign_as_empty() {
        use crate::sign::message;
        use ed25519_dalek::Verifier;

        let cfg = test_config(1_000_000, Duration::ZERO);
        for path in ["/judge", "/judge?nonce=short"] {
            let (vk, sig, body) = signed_answer(&cfg, path).await;
            assert!(vk.verify(&message("", "", &body), &sig).is_ok(), "{path}");
        }
    }

    #[tokio::test]
    async fn other_direct_ip_forms_stay_bound_to_the_signature() {
        use crate::sign::message;
        use ed25519_dalek::Verifier;

        let cfg = test_config(1_000_000, Duration::ZERO);
        // Only a line feed counts as absent: a carriage return is signed as
        // received, so it fails for a client that sent the clean value.
        let (vk, sig, body) =
            signed_answer(&cfg, "/judge?direct_ip=1.1.1.1%0D&nonce=abcdefgh12").await;
        assert!(
            vk.verify(&message("abcdefgh12", "1.1.1.1", &body), &sig)
                .is_err()
        );
        assert!(
            vk.verify(&message("abcdefgh12", "1.1.1.1\r", &body), &sig)
                .is_ok()
        );

        // A duplicate is rejected before anything is signed.
        let res = test_app_with(&cfg)
            .oneshot(get_with(
                "/judge?direct_ip=1.1.1.1&direct_ip=2.2.2.2&nonce=abcdefgh12",
                &[],
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(res.headers().get("x-judge-signature").is_none());
    }

    #[tokio::test]
    async fn judge_elite_no_leak() {
        let v = json(test_app(), get_with("/judge?direct_ip=1.1.1.1", &[])).await;
        assert_eq!(v["anonymity"], "elite");
    }

    #[tokio::test]
    async fn edge_headers_are_not_attributed_to_the_proxy() {
        // nginx in front adds X-Real-IP = the connecting proxy's exit IP
        let req = || {
            get_with(
                "/judge?direct_ip=1.1.1.1",
                &[("x-real-ip", "5.6.7.8"), ("x-forwarded-for", "5.6.7.8")],
            )
        };
        let v = json(test_app(), req()).await;
        assert_eq!(v["anonymity"], "anonymous");

        let mut cfg = test_config(1_000_000, Duration::ZERO);
        cfg.edge_headers = vec!["x-real-ip".to_string()];
        let v = json(test_app_with(&cfg), req()).await;
        assert_eq!(v["anonymity"], "elite");
        assert!(v["headers"].get("x-real-ip").is_none());
    }

    #[tokio::test]
    async fn judge_via_cf_tunnel_transparent() {
        // CF edge: exit 5.6.7.8, proxy leaked 1.1.1.1 into XFF
        let v = json(
            test_app(),
            get_with(
                "/judge?direct_ip=1.1.1.1",
                &[
                    ("cf-connecting-ip", "5.6.7.8"),
                    ("x-forwarded-for", "1.1.1.1, 5.6.7.8"),
                    ("cf-ray", "abc123"),
                ],
            ),
        )
        .await;
        assert_eq!(v["ip"], "5.6.7.8");
        assert_eq!(v["anonymity"], "transparent");
    }

    #[tokio::test]
    async fn judge_via_cf_tunnel_direct_is_elite() {
        // direct check through the tunnel: CF-Connecting-IP == direct IP
        // must NOT count as a leak
        let v = json(
            test_app(),
            get_with(
                "/judge?direct_ip=1.1.1.1",
                &[
                    ("cf-connecting-ip", "1.1.1.1"),
                    ("x-forwarded-for", "1.1.1.1"),
                    ("cf-ray", "abc123"),
                    ("cf-ipcountry", "DE"),
                ],
            ),
        )
        .await;
        assert_eq!(v["ip"], "1.1.1.1");
        assert_eq!(v["anonymity"], "elite");
    }

    #[tokio::test]
    async fn judge_reads_real_geo_databases() {
        let dir = TempDir::new("api-judge-geo");
        test_mmdb::write_city_and_asn(dir.path());
        let state = test_state(dir.path(), &test_config(1_000_000, Duration::ZERO));
        let v = json(
            test_app_with_state(state),
            get_with("/judge", &[("x-forwarded-for", "203.0.113.7")]),
        )
        .await;
        assert_eq!(v["ip"], "203.0.113.7");
        assert_eq!(v["geo"]["country_code"], "DE");
        assert_eq!(v["geo"]["asn"], 64500);
        assert_eq!(v["geo_source"]["city"], "GeoLite2-City.mmdb");
        assert_eq!(v["ip_type"], "datacenter");
        assert!(
            v["attribution"][0]
                .as_str()
                .unwrap_or("")
                .contains("MaxMind")
        );
    }

    #[tokio::test]
    async fn rdns_skipped_when_asn_known() {
        // ASN org present → no DNS round-trip at all (fast, offline-safe)
        let state = test_state(
            Path::new(NO_GEO_DIR),
            &test_config(1_000_000, Duration::from_millis(50)),
        );
        let t0 = Instant::now();
        let res = maybe_rdns(&state, "8.8.8.8", Some("Google LLC")).await;
        assert!(res.is_none());
        assert!(t0.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn rdns_skipped_for_private_and_loopback_ips() {
        let state = test_state(
            Path::new(NO_GEO_DIR),
            &test_config(1_000_000, Duration::from_secs(2)),
        );
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
        let v = json(
            test_app(),
            get_with(
                "/judge?direct_ip=1.2.3.4",
                &[("x-forwarded-for", "unknown, 5.6.7.8")],
            ),
        )
        .await;
        assert_eq!(v["ip"], "5.6.7.8");
        assert_eq!(v["xff_chain"], serde_json::json!([]));
        assert_eq!(v["headers"]["x-forwarded-for"], "unknown");
        assert_eq!(v["anonymity"], "anonymous");
    }

    #[tokio::test]
    async fn judge_non_ascii_header_still_detects_ip_leak() {
        let mut req = get_with(
            "/judge?direct_ip=1.2.3.4",
            &[("x-forwarded-for", "5.6.7.8")],
        );
        req.headers_mut().insert(
            "x-client-info",
            HeaderValue::from_bytes(b"proxy \xc3\xa9 1.2.3.4").unwrap(),
        );
        let v = json(test_app(), req).await;
        assert_eq!(v["anonymity"], "transparent");
    }

    #[tokio::test]
    async fn content_stable() {
        let a = test_app().oneshot(get_with("/content", &[])).await.unwrap();
        let b = test_app().oneshot(get_with("/content", &[])).await.unwrap();
        let ba = axum::body::to_bytes(a.into_body(), 65536).await.unwrap();
        let bb = axum::body::to_bytes(b.into_body(), 65536).await.unwrap();
        assert_eq!(ba, bb);
        assert!(ba.len() > 32);
    }
}
