//! Pure logic of proxpulse-judge: no I/O, fully unit-testable.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;

/// Fixed tamper-check content. Never change bytes without bumping
/// [`CONTENT_VERSION`], otherwise checkers comparing against an old
/// baseline will see "modified".
pub const CONTENT_VERSION: u8 = 1;
pub const FIXED_CONTENT: &[u8] =
    b"{\"proxpulse\":\"judge\",\"v\":1,\"payload\":\"0123456789abcdef0123456789abcdef0123456789abcdef\"}";

pub fn content_sha256() -> String {
    let mut h = Sha256::new();
    h.update(FIXED_CONTENT);
    hex_lower(h.finalize().as_ref())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
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
const CF_INFRA_HEADERS: &[&str] = &[
    "cdn-loop",
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "true-client-ip",
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

/// Normalize one XFF/CF address entry: trim, unwrap "[v6]:port",
/// strip a ":port" suffix from bare IPv4 ("1.2.3.4:5678" — some
/// proxies append it, but it is not part of the address).
pub fn clean_host(s: &str) -> String {
    let t = s.trim();
    if let Some(stripped) = t.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
        return t.to_string();
    }
    if let Some((ip, port)) = t.rsplit_once(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
        && ip.split('.').count() == 4
        && ip.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return ip.to_string();
    }
    t.to_string()
}

/// Canonical textual form of an address taken from a header:
/// trims, unwraps `[v6]:port` / `v4:port`, validates, canonicalizes
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d` → `a.b.c.d`), and re-prints it.
pub fn normalize_host(s: &str) -> Option<String> {
    clean_host(s)
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical().to_string())
}

fn is_ipv4_char(c: char) -> bool {
    c.is_ascii_digit() || c == '.'
}

fn is_ipv6_char(c: char) -> bool {
    c.is_ascii_hexdigit() || c == ':' || c == '.'
}

/// True when `ip` occurs in `text` on character boundaries (so
/// `1.2.3.4` does not match inside `1.2.3.40`, and `::1` does not
/// match inside `::10`), including non-canonical IPv6 or IPv4-mapped forms.
fn ip_in_text(text: &str, ip: &std::net::IpAddr) -> bool {
    let ip = ip.to_canonical();
    let needle = ip.to_string().to_ascii_lowercase();
    let haystack = text.to_ascii_lowercase();
    let boundary: fn(char) -> bool = match ip {
        std::net::IpAddr::V4(_) => is_ipv4_char,
        std::net::IpAddr::V6(_) => is_ipv6_char,
    };
    if haystack.match_indices(&needle).any(|(idx, _)| {
        let before = haystack[..idx].chars().next_back();
        let after = haystack[idx + needle.len()..].chars().next();
        !before.map(boundary).unwrap_or(false) && !after.map(boundary).unwrap_or(false)
    }) {
        return true;
    }
    haystack
        .split(|c: char| !is_ipv6_char(c))
        .filter(|tok| !tok.is_empty())
        .filter_map(normalize_host)
        .any(|cand| cand == needle)
}

/// Resolve the real client IP (= proxy exit IP when checked via proxy).
///
/// Priority: `CF-Connecting-IP` (set by Cloudflare edge, single IP,
/// only when trust_cf) → last X-Forwarded-For entry (appended by our
/// own reverse proxy, only when trust_proxy) → socket address.
pub fn client_ip(
    cf_ip: Option<&str>,
    xff: Option<&str>,
    socket_ip: &str,
    trust_proxy: bool,
    trust_cf: bool,
) -> String {
    if trust_cf && let Some(cf) = cf_ip.and_then(normalize_host) {
        return cf;
    }
    if trust_proxy {
        let chain = split_xff(xff);
        if let Some(last) = chain.last()
            && let Some(ip) = normalize_host(last)
        {
            return ip;
        }
    }
    normalize_host(socket_ip).unwrap_or_else(|| socket_ip.to_string())
}

/// XFF entries added BEFORE our reverse proxy (i.e. by the checked proxy).
///
/// How our edge appends determines the cleanup:
/// - direct edge (Caddy/nginx): appends the client itself, which is also
///   what [`client_ip`] resolves — pop that single trailing entry;
/// - CDN in front of the edge (Cloudflare in front of Render, or in front
///   of Caddy): the CDN writes the client and the hops below it append
///   their own addresses after it (live Render shape:
///   `[client, CF-egress, inner-LB]`), so everything from the first client
///   entry onward is our infrastructure — truncate there. The CDN branch
///   only fires when the client was actually resolved from a valid
///   `CF-Connecting-IP`, otherwise the legacy single pop applies and the
///   Caddy/VPS behaviour is unchanged.
///
/// Raw XFF tokens added BEFORE our reverse proxy (including non-IP placeholders
/// such as Squid's `unknown`).
pub fn pre_edge_xff(
    xff: Option<&str>,
    client: &str,
    trust_proxy: bool,
    trust_cf: bool,
    cf_ip: Option<&str>,
) -> Vec<String> {
    let mut raw = split_xff(xff);
    if !trust_proxy {
        return raw;
    }
    let client = normalize_host(client).unwrap_or_else(|| client.to_string());
    // CDN branch: same condition as the CF priority in [`client_ip`]; the
    // equality guard keeps this fail-closed if a caller ever passes an
    // inconsistent client.
    let cdn_client = if trust_cf {
        cf_ip.and_then(normalize_host)
    } else {
        None
    };
    if cdn_client.as_deref() == Some(client.as_str()) {
        // The CDN appends the client address to the proxy-supplied chain,
        // so the *last* occurrence marks where our infrastructure begins.
        // The first occurrence may be a value the checked proxy prepended
        // itself, and truncating there would hide leaks after it.
        if let Some(pos) = raw
            .iter()
            .rposition(|e| normalize_host(e).as_deref() == Some(client.as_str()))
        {
            raw.truncate(pos);
        }
        // Drop any remaining copies of the edge/client address (an elite
        // proxy may have put its own exit into XFF as well).
        raw.retain(|e| normalize_host(e).as_deref() != Some(client.as_str()));
        return raw;
    }
    if raw.last().and_then(|s| normalize_host(s)).as_deref() == Some(client.as_str()) {
        raw.pop();
    }
    raw
}

/// Normalized IPs of pre-edge XFF entries; non-IP placeholders are dropped.
pub fn normalize_chain(entries: &[String]) -> Vec<String> {
    entries.iter().filter_map(|e| normalize_host(e)).collect()
}

#[cfg(test)]
fn forwarded_chain(
    xff: Option<&str>,
    client: &str,
    trust_proxy: bool,
    trust_cf: bool,
    cf_ip: Option<&str>,
) -> Vec<String> {
    normalize_chain(&pre_edge_xff(xff, client, trust_proxy, trust_cf, cf_ip))
}

fn is_infra(name: &str, trust_cf: bool) -> bool {
    let n = name.to_ascii_lowercase();
    // Only headers controlled by Cloudflare are infrastructure. Arbitrary
    // cf-* names can pass through the edge and must still be checked for leaks.
    INFRA_HEADERS.contains(&n.as_str()) || (trust_cf && CF_INFRA_HEADERS.contains(&n.as_str()))
}

fn is_telltale(name: &str, trust_cf: bool) -> bool {
    let n = name.to_ascii_lowercase();
    if is_infra(&n, trust_cf) {
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
/// reverse-proxy-added XFF entries already removed (see
/// [`pre_edge_xff`]). `direct_ip` — checker's own IP learned via a
/// direct /ip call; without it only proxy presence can be determined.
pub fn anonymity_level(
    headers: &HashMap<String, String>,
    direct_ip: Option<&str>,
    trust_cf: bool,
) -> &'static str {
    let raw_xff = split_xff(headers.get("x-forwarded-for").map(|s| s.as_str()));
    let chain: Vec<String> = raw_xff.iter().filter_map(|e| normalize_host(e)).collect();
    let direct: Option<std::net::IpAddr> = direct_ip
        .and_then(normalize_host)
        .and_then(|d| d.parse().ok());

    if let Some(d) = direct {
        let d_str = d.to_string();
        if chain.iter().any(|c| c == &d_str) {
            return "transparent";
        }
        if headers
            .iter()
            .any(|(k, v)| k != "x-forwarded-for" && !is_infra(k, trust_cf) && ip_in_text(v, &d))
        {
            return "transparent";
        }
    }
    if !chain.is_empty() || !raw_xff.is_empty() {
        return "anonymous";
    }
    if headers.keys().any(|k| is_telltale(k, trust_cf)) {
        return "anonymous";
    }
    "elite"
}

const HOSTING_KW: &[&str] = &[
    "hosting",
    "host",
    "cloud",
    "vps",
    "dedicated",
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
    "mobile", "cellular", "wireless", "mobility", "gsm", "lte", "5g",
];
const RESIDENTIAL_KW: &[&str] = &[
    "dynamic",
    "residential",
    "broadband",
    "dsl",
    "adsl",
    "vdsl",
    "cable",
    "fiber",
    "ftth",
    "fttb",
    "pool",
    "retail",
    "subscriber",
];
const BUSINESS_KW: &[&str] = &[
    "bank",
    "university",
    "government",
    "enterprise",
    "airline",
    "hotel",
];

/// Whole-word match: "inc" must not match "Zinc", "host" must not match
/// "ghost". Multi-word keywords are matched as phrases with the same
/// boundary rule.
fn contains_word(text: &str, needle: &str) -> bool {
    let needle = needle.trim();
    if needle.is_empty() {
        return false;
    }
    text.match_indices(needle).any(|(idx, _)| {
        let before = text[..idx].chars().next_back();
        let after = text[idx + needle.len()..].chars().next();
        !before.map(|c| c.is_alphanumeric()).unwrap_or(false)
            && !after.map(|c| c.is_alphanumeric()).unwrap_or(false)
    })
}

fn hits(text: &str, keywords: &[&str]) -> Vec<String> {
    let t = text.to_ascii_lowercase();
    keywords
        .iter()
        .filter(|k| contains_word(&t, k))
        .map(|k| k.trim().to_string())
        .collect()
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TypeSignals {
    pub org: Option<String>,
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
pub fn classify_ip(org: Option<&str>, rdns: Option<&str>) -> (String, TypeSignals) {
    let hay_org = org.unwrap_or("").to_string();
    let hay_all = format!("{} {}", hay_org, rdns.unwrap_or(""));
    let hosting_kw = hits(&hay_org, HOSTING_KW);
    let low = hay_org.to_ascii_lowercase();
    // single-word vendors match whole tokens only: substring matching
    // would flag e.g. "Shaw Communications" via "aws". Multi-word
    // vendors ("oracle cloud") are long enough for substring matching.
    let tokens: Vec<&str> = low
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    // Google's residential Fiber ISP shares the cloud vendor token.
    let google_fiber = contains_word(&low, "google fiber");
    let hosting_vendor: Vec<String> = HOSTING_VENDORS
        .iter()
        .filter(|v| {
            let v: &str = v;
            if v == "google" && google_fiber {
                return false;
            }
            if v.contains(' ') {
                contains_word(&low, v)
            } else {
                tokens.contains(&v)
            }
        })
        .map(|v| (*v).to_string())
        .collect();
    let mut signals = TypeSignals {
        org: org.map(str::to_string),
        rdns: rdns.map(str::to_string),
        hosting_kw,
        hosting_vendor,
        mobile_kw: hits(&hay_all, MOBILE_KW),
        residential_kw: hits(&hay_all, RESIDENTIAL_KW),
        business_kw: hits(&hay_org, BUSINESS_KW),
        note: None,
    };
    if google_fiber {
        signals.note = Some("google fiber: residential ISP".to_string());
        return ("residential".to_string(), signals);
    }
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
        assert_eq!(client_ip(None, None, "9.9.9.9", false, true), "9.9.9.9");
        assert_eq!(client_ip(None, None, "9.9.9.9", true, true), "9.9.9.9");
        // proxy forwarded 1.2.3.4, Caddy appended exit 5.6.7.8
        assert_eq!(
            client_ip(None, Some("1.2.3.4, 5.6.7.8"), "10.0.0.1", true, true),
            "5.6.7.8"
        );
    }

    #[test]
    fn client_ip_prefers_cf_header() {
        // Cloudflare edge: real exit in CF-Connecting-IP, socket is the tunnel
        assert_eq!(
            client_ip(
                Some("5.6.7.8"),
                Some("9.9.9.9, 5.6.7.8"),
                "172.21.0.1",
                true,
                true
            ),
            "5.6.7.8"
        );
        // garbage CF value is ignored, XFF fallback still works
        assert_eq!(
            client_ip(
                Some("not-an-ip"),
                Some("9.9.9.9, 5.6.7.8"),
                "172.21.0.1",
                true,
                true
            ),
            "5.6.7.8"
        );
        // trust_cf off → CF header ignored
        assert_eq!(
            client_ip(Some("5.6.7.8"), None, "172.21.0.1", false, false),
            "172.21.0.1"
        );
    }

    #[test]
    fn chain_strips_caddy_entry() {
        assert_eq!(
            forwarded_chain(Some("1.2.3.4, 5.6.7.8"), "5.6.7.8", true, false, None),
            vec!["1.2.3.4"]
        );
        assert!(forwarded_chain(Some("5.6.7.8"), "5.6.7.8", true, false, None).is_empty());
        assert_eq!(
            forwarded_chain(Some("1.2.3.4"), "9.9.9.9", false, false, None),
            vec!["1.2.3.4"]
        );
    }

    #[test]
    fn chain_strips_cdn_infra_hops() {
        // Live Render shape: CF wrote the client, then CF-egress and the
        // inner LB appended their hops. All infra must go, whatever leaked
        // before it must stay.
        // Direct check.
        assert!(
            forwarded_chain(
                Some("1.2.3.4, 172.71.146.141, 10.29.121.232"),
                "1.2.3.4",
                true,
                true,
                Some("1.2.3.4"),
            )
            .is_empty()
        );
        // Elite proxy: only its exit IP precedes the infra hops.
        assert!(
            forwarded_chain(
                Some("9.9.9.9, 172.71.146.141, 10.29.121.232"),
                "9.9.9.9",
                true,
                true,
                Some("9.9.9.9"),
            )
            .is_empty()
        );
        // Transparent proxy: the leaked IP survives, infra does not.
        assert_eq!(
            forwarded_chain(
                Some("1.2.3.4, 9.9.9.9, 172.71.146.141, 10.29.121.232"),
                "9.9.9.9",
                true,
                true,
                Some("9.9.9.9"),
            ),
            vec!["1.2.3.4"]
        );
        // Single-hop CDN shape strips as well.
        assert!(
            forwarded_chain(
                Some("9.9.9.9, 5.6.7.8"),
                "9.9.9.9",
                true,
                true,
                Some("9.9.9.9"),
            )
            .is_empty()
        );
        // Inconsistent caller input (client not from CF header):
        // fail closed, legacy single pop applies.
        assert_eq!(
            forwarded_chain(Some("9.9.9.9"), "1.1.1.1", true, true, Some("9.9.9.9")),
            vec!["9.9.9.9"]
        );
    }

    #[test]
    fn render_direct_check_is_elite_not_transparent() {
        // Full live Render-shaped request: CF-Connecting-IP is the client,
        // XFF carries [client, CF-egress, inner-LB]. Must be elite,
        // not transparent — with the real direct_ip and without it.
        let h = map(&[
            ("cf-connecting-ip", "1.1.1.1"),
            ("cf-ray", "abc123"),
            ("x-forwarded-for", "1.1.1.1, 172.71.146.141, 10.29.121.232"),
        ]);
        let chain = forwarded_chain(
            h.get("x-forwarded-for").map(|s| s.as_str()),
            "1.1.1.1",
            true,
            true,
            h.get("cf-connecting-ip").map(|s| s.as_str()),
        );
        assert!(chain.is_empty());
        let mut for_analysis = h.clone();
        for_analysis.insert("x-forwarded-for".to_string(), chain.join(", "));
        assert_eq!(
            anonymity_level(&for_analysis, Some("1.1.1.1"), true),
            "elite"
        );
        assert_eq!(anonymity_level(&for_analysis, None, true), "elite");
    }

    #[test]
    fn render_true_client_ip_is_not_a_leak() {
        // Live Render headers: True-Client-IP duplicates the exit IP on
        // every request. In a direct check direct_ip == exit IP, so without
        // the exclusion this misdetects as transparent.
        let h = map(&[
            ("cf-connecting-ip", "1.1.1.1"),
            ("true-client-ip", "1.1.1.1"),
            ("cf-ray", "abc123"),
            ("x-forwarded-for", ""),
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true), "elite");
    }

    #[test]
    fn elite_direct_behind_caddy() {
        assert_eq!(
            anonymity_level(&map(&[("x-forwarded-for", "")]), Some("1.1.1.1"), true),
            "elite"
        );
        assert_eq!(
            anonymity_level(&map(&[("user-agent", "x")]), None, true),
            "elite"
        );
    }

    #[test]
    fn transparent_leak() {
        let h = map(&[("x-forwarded-for", "1.1.1.1"), ("user-agent", "x")]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true), "transparent");
    }

    #[test]
    fn multiple_non_direct_hops_are_anonymous() {
        let h = map(&[("x-forwarded-for", "9.9.9.9, 8.8.8.8")]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true), "anonymous");
        assert_eq!(anonymity_level(&h, None, true), "anonymous");
    }

    #[test]
    fn anonymous_forwarded_no_leak() {
        let h = map(&[("x-forwarded-for", "9.9.9.9"), ("user-agent", "x")]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true), "anonymous");
    }

    #[test]
    fn anonymous_via() {
        assert_eq!(
            anonymity_level(&map(&[("via", "1.0 proxy")]), Some("1.1.1.1"), true),
            "anonymous"
        );
    }

    #[test]
    fn infra_headers_ignored() {
        let h = map(&[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "check.x"),
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true), "elite");
    }

    #[test]
    fn cf_direct_check_is_elite_not_transparent() {
        // direct check through CF tunnel: CF-Connecting-IP always equals
        // the exit IP by construction — must not count as a leak
        let h = map(&[
            ("cf-connecting-ip", "1.1.1.1"),
            ("cf-ray", "abc123"),
            ("cf-ipcountry", "DE"),
            ("cdn-loop", "cloudflare"),
            ("x-forwarded-for", ""),
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true), "elite");
    }

    #[test]
    fn cf_transparent_still_detected() {
        // proxy leaked 1.1.1.1 into XFF, CF appended exit 5.6.7.8
        let h = map(&[
            ("cf-connecting-ip", "5.6.7.8"),
            ("x-forwarded-for", "1.1.1.1"),
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true), "transparent");
    }

    #[test]
    fn true_client_ip_is_a_leak_without_trust_cf() {
        let h = map(&[("true-client-ip", "1.1.1.1"), ("x-forwarded-for", "")]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), false), "transparent");
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true), "elite");
    }

    #[test]
    fn cf_header_is_a_leak_without_trust_cf() {
        let h = map(&[("cf-connecting-ip", "1.1.1.1"), ("x-forwarded-for", "")]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), false), "transparent");
    }

    #[test]
    fn unknown_cf_header_is_checked_for_leaks() {
        let h = map(&[
            ("cf-connecting-ip", "5.6.7.8"),
            ("cf-custom", "1.1.1.1"),
            ("x-forwarded-for", ""),
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true), "transparent");
    }

    #[test]
    fn classify_datacenter() {
        let (t, s) = classify_ip(Some("Hetzner Online GmbH"), None);
        assert_eq!(t, "datacenter");
        assert!(!s.hosting_kw.is_empty() || !s.hosting_vendor.is_empty());
    }

    #[test]
    fn classify_mobile() {
        let (t, _) = classify_ip(Some("Mobile TeleSystems PJSC"), None);
        assert_eq!(t, "mobile");
    }

    #[test]
    fn vendor_substring_no_false_positive() {
        // "Shaw" contains "aws" — must NOT match the vendor list
        let (t, s) = classify_ip(Some("Shaw Communications"), None);
        assert!(s.hosting_vendor.is_empty());
        assert_eq!(t, "residential");
    }

    #[test]
    fn classify_keywords_respect_word_boundaries() {
        // "Ghost" contains "host".
        let (t, _) = classify_ip(Some("Ghost Productions"), None);
        assert_eq!(t, "residential");
        let (t, _) = classify_ip(Some("Acme Bank"), None);
        assert_eq!(t, "business");
        let (t, _) = classify_ip(Some("Ghost Hosting"), None);
        assert_eq!(t, "datacenter");
    }

    #[test]
    fn legal_suffix_does_not_make_residential_ip_business() {
        let (t, s) = classify_ip(Some("Comcast Cable Communications LLC"), None);
        assert_eq!(t, "residential");
        assert!(s.business_kw.is_empty());
        assert!(!s.residential_kw.is_empty());
    }

    #[test]
    fn classify_google_fiber_is_residential() {
        let (t, _) = classify_ip(Some("Google Fiber Inc."), None);
        assert_eq!(t, "residential");
    }

    #[test]
    fn classify_residential_default() {
        let (t, _) = classify_ip(Some("Rostelecom"), None);
        assert_eq!(t, "residential");
    }

    #[test]
    fn classify_unknown() {
        let (t, _) = classify_ip(None, None);
        assert_eq!(t, "unknown");
    }

    #[test]
    fn host_port_tolerance() {
        assert_eq!(clean_host("1.2.3.4:5678"), "1.2.3.4");
        assert_eq!(clean_host("  1.2.3.4  "), "1.2.3.4");
        assert_eq!(clean_host("[::1]:8080"), "::1");
        assert_eq!(clean_host("2001:db8::1"), "2001:db8::1");
        // sloppy proxy appends source port: exit still resolves, chain strips
        assert_eq!(
            client_ip(None, Some("9.9.9.9:40000, 5.6.7.8"), "x", true, true),
            "5.6.7.8"
        );
        assert_eq!(
            forwarded_chain(Some("1.2.3.4:40000, 5.6.7.8"), "5.6.7.8", true, false, None),
            vec!["1.2.3.4".to_string()]
        );
    }

    #[test]
    fn client_ip_rejects_garbage_xff() {
        assert_eq!(
            client_ip(None, Some("not-an-ip"), "9.9.9.9", true, true),
            "9.9.9.9"
        );
        assert_eq!(
            client_ip(None, Some("1.2.3.4:80, garbage"), "9.9.9.9", true, true),
            "9.9.9.9"
        );
        // a valid address with a source port still resolves
        assert_eq!(
            client_ip(None, Some("1.2.3.4:80"), "9.9.9.9", true, true),
            "1.2.3.4"
        );
    }

    #[test]
    fn prefix_is_not_a_leak() {
        let h = map(&[("x-forwarded-for", "1.2.3.40")]);
        assert_eq!(anonymity_level(&h, Some("1.2.3.4"), true), "anonymous");
        let h = map(&[("user-agent", "Mozilla 1.2.3.40")]);
        assert_eq!(anonymity_level(&h, Some("1.2.3.4"), true), "elite");
    }

    #[test]
    fn header_value_exact_ip_is_a_leak() {
        let h = map(&[("referer", "https://x/?ip=1.2.3.4&y=1")]);
        assert_eq!(anonymity_level(&h, Some("1.2.3.4"), true), "transparent");
    }

    #[test]
    fn ipv6_forms_are_normalized() {
        let h = map(&[("x-forwarded-for", "2001:0db8:0:0:0:0:0:1")]);
        assert_eq!(
            anonymity_level(&h, Some("2001:db8::1"), true),
            "transparent"
        );
        let h = map(&[("x-forwarded-for", "2001:db8::10")]);
        assert_eq!(anonymity_level(&h, Some("2001:db8::1"), true), "anonymous");
        // Non-canonical IPv6 in non-XFF headers must also be detected as a leak
        let h = map(&[("x-real-ip", "2001:0db8:0:0:0:0:0:1")]);
        assert_eq!(
            anonymity_level(&h, Some("2001:db8::1"), true),
            "transparent"
        );
        let h = map(&[(
            "forwarded",
            "for=\"[2001:0db8:0:0:0:0:0:1]:8080\";proto=http",
        )]);
        assert_eq!(
            anonymity_level(&h, Some("2001:db8::1"), true),
            "transparent"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_is_canonicalized() {
        assert_eq!(
            normalize_host("::ffff:1.2.3.4"),
            Some("1.2.3.4".to_string())
        );
        assert_eq!(
            normalize_host("[::ffff:1.2.3.4]:8080"),
            Some("1.2.3.4".to_string())
        );
        let h = map(&[("x-forwarded-for", "::ffff:1.2.3.4")]);
        assert_eq!(anonymity_level(&h, Some("1.2.3.4"), true), "transparent");
        let h = map(&[("x-forwarded-for", "1.2.3.4")]);
        assert_eq!(
            anonymity_level(&h, Some("::ffff:1.2.3.4"), true),
            "transparent"
        );
        let h = map(&[("x-client-ip", "::ffff:0102:0304")]);
        assert_eq!(anonymity_level(&h, Some("1.2.3.4"), true), "transparent");
    }

    #[test]
    fn unknown_xff_is_anonymous_not_elite() {
        let h = map(&[("x-forwarded-for", "unknown")]);
        assert_eq!(anonymity_level(&h, Some("1.2.3.4"), true), "anonymous");
        assert_eq!(anonymity_level(&h, None, true), "anonymous");
    }

    #[test]
    fn trailing_garbage_xff_does_not_pop_earlier_client_hop() {
        assert_eq!(
            forwarded_chain(Some("9.9.9.9, garbage"), "9.9.9.9", true, false, None),
            vec!["9.9.9.9".to_string()]
        );
    }

    #[test]
    fn cdn_chain_uses_last_client_occurrence() {
        // Realistic CF append: the proxy prepended its own exit (same as
        // CF-Connecting-IP) before the leaked real IP; CF appended the
        // client again, then infra hops followed.
        assert_eq!(
            forwarded_chain(
                Some("9.9.9.9, 1.2.3.4, 9.9.9.9, 172.71.146.141, 10.29.121.232"),
                "9.9.9.9",
                true,
                true,
                Some("9.9.9.9"),
            ),
            vec!["1.2.3.4"]
        );
        // Elite proxy: exit only, CF appended it again -> nothing leaks.
        assert!(
            forwarded_chain(
                Some("9.9.9.9, 9.9.9.9, 172.71.146.141, 10.29.121.232"),
                "9.9.9.9",
                true,
                true,
                Some("9.9.9.9"),
            )
            .is_empty()
        );
    }
}
