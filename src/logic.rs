//! Pure logic of proxpulse-judge: no I/O, fully unit-testable.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Fixed tamper-check content. Never change bytes without bumping
/// [`CONTENT_VERSION`], otherwise checkers comparing against an old
/// baseline will see "modified".
pub const CONTENT_VERSION: u8 = 1;
pub const FIXED_CONTENT: &[u8] =
    b"{\"proxpulse\":\"judge\",\"v\":1,\"payload\":\"0123456789abcdef0123456789abcdef0123456789abcdef\"}";

pub fn content_sha256() -> String {
    let mut h = Sha256::new();
    h.update(FIXED_CONTENT);
    format!("{:x}", h.finalize())
}

/// Headers a reverse proxy (Caddy/nginx) adds itself. They must NOT be
/// treated as proxy telltales, otherwise every check behind a reverse
/// proxy would look "anonymous".
const INFRA_HEADERS: &[&str] = &[
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-ssl",
    "x-real-port",
];

pub fn split_xff(value: Option<&str>) -> Vec<String> {
    match value {
        Some(v) => v
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        None => vec![],
    }
}

/// Resolve the real client IP (= proxy exit IP when checked via proxy).
///
/// Caddy appends the client address to the END of X-Forwarded-For,
/// so with trust_proxy the last entry is authoritative.
pub fn client_ip(xff: Option<&str>, socket_ip: &str, trust_proxy: bool) -> String {
    if trust_proxy {
        let chain = split_xff(xff);
        if let Some(last) = chain.last() {
            return last.clone();
        }
    }
    socket_ip.to_string()
}

/// XFF entries added BEFORE our reverse proxy (i.e. by the checked proxy).
pub fn forwarded_chain(xff: Option<&str>, client: &str, trust_proxy: bool) -> Vec<String> {
    if !trust_proxy {
        return split_xff(xff);
    }
    let mut chain = split_xff(xff);
    if chain.last().map(|s| s.as_str()) == Some(client) {
        chain.pop();
    }
    chain
}

fn is_telltale(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if INFRA_HEADERS.contains(&n.as_str()) {
        return false;
    }
    matches!(
        n.as_str(),
        "via"
            | "forwarded"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "proxy-agent"
            | "x-proxy-id"
            | "x-real-ip"
    ) || n.starts_with("proxy-")
        || n.starts_with("x-proxy")
}

/// elite | anonymous | transparent.
///
/// `headers` — lowercased request headers as seen by judge, with the
/// reverse-proxy-added last XFF entry already removed (see
/// [`forwarded_chain`]). `direct_ip` — checker's own IP learned via a
/// direct /ip call; without it leak detection is limited to
/// multi-hop XFF chains.
pub fn anonymity_level(headers: &HashMap<String, String>, direct_ip: Option<&str>) -> &'static str {
    let chain = split_xff(headers.get("x-forwarded-for").map(|s| s.as_str()));

    if let Some(d) = direct_ip {
        if !d.is_empty() {
            if chain.iter().any(|c| c == d || c.contains(d)) {
                return "transparent";
            }
            if headers
                .iter()
                .any(|(k, v)| k != "x-forwarded-for" && v.contains(d))
            {
                return "transparent";
            }
        }
    }
    if chain.len() > 1 {
        // multi-hop chain without a known direct IP: something leaks hops
        return "transparent";
    }
    if !chain.is_empty() {
        return "anonymous";
    }
    if headers.keys().any(|k| is_telltale(k)) {
        return "anonymous";
    }
    "elite"
}

const HOSTING_KW: &[&str] = &[
    "hosting",
    "host",
    "cloud",
    "vps",
    "dedicat",
    "datacenter",
    "data center",
    "colocation",
    "servers",
    "cdn",
    "compute",
    "bare metal",
    "virtual",
    "hypervisor",
];
/// Well-known hosters/clouds whose org names carry no generic keyword.
const HOSTING_VENDORS: &[&str] = &[
    "hetzner",
    "ovh",
    "digitalocean",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "cloudflare",
    "contabo",
    "aeza",
    "scaleway",
    "vultr",
    "linode",
    "leaseweb",
    "selectel",
    "timeweb",
    "beget",
    "alibaba",
    "tencent",
    "oracle cloud",
    "ibm cloud",
    "yandex cloud",
];
const MOBILE_KW: &[&str] = &[
    "mobile", "cellular", "wireless", "mobility", "gsm", " lte", "5g ",
];
const RESIDENTIAL_KW: &[&str] = &[
    "dynamic",
    "residential",
    "broadband",
    "dsl",
    "cable",
    "fiber",
    "ftth",
    " fttb",
    "pool",
    "retail",
    "subscriber",
];
const BUSINESS_KW: &[&str] = &[
    "ltd",
    "llc",
    "inc",
    "gmbh",
    "corp",
    "bank",
    "university",
    "government",
    "enterprise",
    "airline",
    "hotel",
];

fn hits(text: &str, keywords: &[&str]) -> Vec<String> {
    let t = format!(" {} ", text.to_ascii_lowercase());
    keywords
        .iter()
        .filter(|k| t.contains(**k))
        .map(|k| k.trim().to_string())
        .collect()
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TypeSignals {
    pub org: Option<String>,
    pub asn_org: Option<String>,
    pub rdns: Option<String>,
    pub hosting_kw: Vec<String>,
    pub hosting_vendor: Vec<String>,
    pub mobile_kw: Vec<String>,
    pub residential_kw: Vec<String>,
    pub business_kw: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Heuristic IP type. Local data can't prove residential-vs-business
/// the way paid ASN DBs do — `TypeSignals` exposes WHY, so callers
/// (and humans) can judge.
pub fn classify_ip(
    org: Option<&str>,
    asn_org: Option<&str>,
    rdns: Option<&str>,
) -> (String, TypeSignals) {
    let hay_org = format!("{} {}", org.unwrap_or(""), asn_org.unwrap_or(""));
    let hay_all = format!("{} {}", hay_org, rdns.unwrap_or(""));
    let hosting_kw = hits(&hay_org, HOSTING_KW);
    let low = hay_org.to_ascii_lowercase();
    let hosting_vendor: Vec<String> = HOSTING_VENDORS
        .iter()
        .filter(|v| low.contains(**v))
        .map(|v| v.to_string())
        .collect();
    let mut signals = TypeSignals {
        org: org.map(str::to_string),
        asn_org: asn_org.map(str::to_string),
        rdns: rdns.map(str::to_string),
        hosting_kw,
        hosting_vendor,
        mobile_kw: hits(&hay_all, MOBILE_KW),
        residential_kw: hits(&hay_all, RESIDENTIAL_KW),
        business_kw: hits(&hay_org, BUSINESS_KW),
        note: None,
    };
    if !signals.mobile_kw.is_empty() {
        return ("mobile".to_string(), signals);
    }
    if !signals.hosting_kw.is_empty() || !signals.hosting_vendor.is_empty() {
        return ("datacenter".to_string(), signals);
    }
    if !signals.business_kw.is_empty() {
        return ("business".to_string(), signals);
    }
    if !signals.residential_kw.is_empty() {
        return ("residential".to_string(), signals);
    }
    if !hay_org.trim().is_empty() {
        signals.note = Some("default: ordinary ISP".to_string());
        return ("residential".to_string(), signals);
    }
    ("unknown".to_string(), signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn content_hash_stable() {
        assert_eq!(content_sha256().len(), 64);
        assert_eq!(content_sha256(), content_sha256());
        assert!(FIXED_CONTENT.len() > 32);
    }

    #[test]
    fn client_ip_resolution() {
        assert_eq!(client_ip(None, "9.9.9.9", false), "9.9.9.9");
        assert_eq!(client_ip(None, "9.9.9.9", true), "9.9.9.9");
        // proxy forwarded 1.2.3.4, Caddy appended exit 5.6.7.8
        assert_eq!(
            client_ip(Some("1.2.3.4, 5.6.7.8"), "10.0.0.1", true),
            "5.6.7.8"
        );
    }

    #[test]
    fn chain_strips_caddy_entry() {
        assert_eq!(
            forwarded_chain(Some("1.2.3.4, 5.6.7.8"), "5.6.7.8", true),
            vec!["1.2.3.4"]
        );
        assert!(forwarded_chain(Some("5.6.7.8"), "5.6.7.8", true).is_empty());
        assert_eq!(
            forwarded_chain(Some("1.2.3.4"), "9.9.9.9", false),
            vec!["1.2.3.4"]
        );
    }

    #[test]
    fn elite_direct_behind_caddy() {
        assert_eq!(
            anonymity_level(&map(&[("x-forwarded-for", "")]), Some("1.1.1.1")),
            "elite"
        );
        assert_eq!(anonymity_level(&map(&[("user-agent", "x")]), None), "elite");
    }

    #[test]
    fn transparent_leak() {
        let h = map(&[("x-forwarded-for", "1.1.1.1"), ("user-agent", "x")]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1")), "transparent");
    }

    #[test]
    fn anonymous_forwarded_no_leak() {
        let h = map(&[("x-forwarded-for", "9.9.9.9"), ("user-agent", "x")]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1")), "anonymous");
    }

    #[test]
    fn anonymous_via() {
        assert_eq!(
            anonymity_level(&map(&[("via", "1.0 proxy")]), Some("1.1.1.1")),
            "anonymous"
        );
    }

    #[test]
    fn infra_headers_ignored() {
        let h = map(&[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "check.x"),
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1")), "elite");
    }

    #[test]
    fn classify_datacenter() {
        let (t, s) = classify_ip(Some("Hetzner Online GmbH"), None, None);
        assert_eq!(t, "datacenter");
        assert!(!s.hosting_kw.is_empty() || !s.hosting_vendor.is_empty());
    }

    #[test]
    fn classify_mobile() {
        let (t, _) = classify_ip(Some("Mobile TeleSystems PJSC"), None, None);
        assert_eq!(t, "mobile");
    }

    #[test]
    fn classify_residential_default() {
        let (t, _) = classify_ip(Some("Rostelecom"), None, None);
        assert_eq!(t, "residential");
    }

    #[test]
    fn classify_unknown() {
        let (t, _) = classify_ip(None, None, None);
        assert_eq!(t, "unknown");
    }
}
