//! Runtime configuration from environment variables.
use std::{
    env,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

pub struct Config {
    pub port: u16,
    pub bind: IpAddr,
    pub geo_dir: String,
    /// Behind a reverse proxy: client IP from the end of X-Forwarded-For.
    pub trust_proxy: bool,
    /// Behind Cloudflare: client IP from CF-Connecting-IP (needs trust_proxy).
    pub trust_cf: bool,
    pub rdns_timeout: Duration,
    /// Burst and sustained requests per client per minute; 0 disables.
    pub rate_per_minute: u32,
    /// Lowercased names of headers our own reverse proxy adds; they are
    /// not attributed to the checked proxy.
    pub edge_headers: Vec<String>,
    /// Bearer token required by `/metrics`; open when unset.
    pub metrics_token: Option<String>,
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok()
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let trust_proxy = parse_flag("TRUST_PROXY", var("TRUST_PROXY").as_deref())?;
        // CF headers are proxy headers too: without TRUST_PROXY the service
        // must resolve the IP from the socket, never from client headers.
        let trust_cf = trust_proxy && parse_flag("TRUST_CF", var("TRUST_CF").as_deref())?;
        let mut edge_headers = parse_edge_headers(var("EDGE_HEADERS").as_deref())?;
        if !trust_proxy && !edge_headers.is_empty() {
            tracing::warn!(
                "EDGE_HEADERS is ignored without TRUST_PROXY=1 (no reverse proxy in front)"
            );
            edge_headers.clear();
        }
        Ok(Self {
            port: port(),
            bind: parse_bind(var("BIND_ADDR").as_deref())?,
            geo_dir: var("GEO_DIR").unwrap_or_else(|| "/app/geo".to_string()),
            trust_proxy,
            trust_cf,
            rdns_timeout: parse_rdns_timeout(var("RDNS_TIMEOUT").as_deref()),
            rate_per_minute: var("RATE_LIMIT_PER_MINUTE")
                .and_then(|v| v.parse().ok())
                .unwrap_or(6000),
            edge_headers,
            metrics_token: var("METRICS_TOKEN").filter(|t| !t.trim().is_empty()),
        })
    }
}

fn port() -> u16 {
    var("PORT").and_then(|v| v.parse().ok()).unwrap_or(8000)
}

/// Where `--healthcheck` connects: loopback for a wildcard bind, otherwise
/// the bound address itself.
pub fn probe_addr() -> Option<SocketAddr> {
    let ip = match parse_bind(var("BIND_ADDR").as_deref()).ok()? {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    Some(SocketAddr::new(ip, port()))
}

/// `1/true/yes/on` or `0/false/no/off` (any case); unset or empty is off.
/// Anything else is an error: these flags decide which client headers are
/// trusted, so a typo must not silently change that.
pub fn parse_flag(name: &str, raw: Option<&str>) -> Result<bool, String> {
    match raw.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("" | "0" | "false" | "no" | "off") => Ok(false),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some(other) => Err(format!("{name}: expected 1/0 or true/false, got {other:?}")),
    }
}

/// `BIND_ADDR`: listen address, `0.0.0.0` by default; `::` (or `[::]`)
/// listens on IPv6 as well where the host allows dual-stack sockets.
pub fn parse_bind(raw: Option<&str>) -> Result<IpAddr, String> {
    match raw.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        Some(v) => v
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|_| format!("BIND_ADDR: not an IP address: {v:?}")),
    }
}

/// `EDGE_HEADERS`: comma-separated header names that our reverse proxy adds
/// itself (e.g. nginx `X-Real-IP`). X-Forwarded-For is not accepted here:
/// its edge hops are already stripped via TRUST_PROXY, and ignoring it
/// entirely would hide leaks.
pub fn parse_edge_headers(raw: Option<&str>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for name in raw.unwrap_or("").split(',').map(str::trim) {
        if name.is_empty() {
            continue;
        }
        let name = name.to_ascii_lowercase();
        if axum::http::HeaderName::from_bytes(name.as_bytes()).is_err() {
            return Err(format!("EDGE_HEADERS: invalid header name {name:?}"));
        }
        if name == "x-forwarded-for" {
            return Err("EDGE_HEADERS must not contain x-forwarded-for".to_string());
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out)
}

/// Parse `RDNS_TIMEOUT` without panicking on negative/NaN/overflowing
/// values (Duration::from_secs_f64 panics for those).
pub fn parse_rdns_timeout(raw: Option<&str>) -> Duration {
    raw.and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(|v| Duration::from_secs_f64(v.min(60.0)))
        .unwrap_or(Duration::from_secs_f64(1.5))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn flags_accept_common_spellings_and_reject_typos() {
        for on in ["1", "true", "TRUE", "yes", "On", " 1 "] {
            assert_eq!(parse_flag("X", Some(on)), Ok(true), "{on}");
        }
        for off in ["0", "false", "No", "off", ""] {
            assert_eq!(parse_flag("X", Some(off)), Ok(false), "{off}");
        }
        assert_eq!(parse_flag("X", None), Ok(false));
        assert!(parse_flag("X", Some("ture")).is_err());
        assert!(parse_flag("X", Some("2")).is_err());
    }

    #[test]
    fn bind_addr_parsing() {
        assert_eq!(parse_bind(None), Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert_eq!(
            parse_bind(Some("  ")),
            Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            parse_bind(Some("::")),
            Ok(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        );
        assert_eq!(
            parse_bind(Some("[::]")),
            Ok(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        );
        assert_eq!(
            parse_bind(Some("127.0.0.1")),
            Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert!(parse_bind(Some("localhost")).is_err());
    }

    #[test]
    fn edge_headers_are_normalized_and_validated() {
        assert_eq!(parse_edge_headers(None), Ok(vec![]));
        assert_eq!(
            parse_edge_headers(Some(" X-Real-IP, via,,x-real-ip ")),
            Ok(vec!["x-real-ip".to_string(), "via".to_string()])
        );
        assert!(parse_edge_headers(Some("X-Forwarded-For")).is_err());
        assert!(parse_edge_headers(Some("bad header")).is_err());
    }
}
