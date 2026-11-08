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

/// Headers our own reverse proxy (Caddy/nginx) adds. Behind one
/// (`TRUST_PROXY=1`) their presence is not blamed on the checked proxy,
/// otherwise every check would look "anonymous". Without one nothing in
/// front of the judge adds them, so they mark a proxy like any other
/// `X-Forwarded-*`.
const INFRA_HEADERS: &[&str] = &[
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-ssl",
    "x-real-port",
];
/// Headers Cloudflare adds (`TRUST_CF=1`). Their values are the client's own
/// address, so behind Cloudflare they are neither telltales nor leaks.
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

/// True when `ip` occurs in `text` as an address of its own: `1.2.3.4` does
/// not match inside `1.2.3.40`, nor `::1` inside `::10`. Punctuation after it
/// (`from 1.2.3.4.`) or a label before it (`ip:2001:db8::1`) does not hide it,
/// and neither do non-canonical, IPv4-mapped or percent-encoded forms.
fn ip_in_text(text: &str, ip: &std::net::IpAddr) -> bool {
    let ip = ip.to_canonical();
    ip_in_plain_text(text, &ip) || percent_decoded(text).is_some_and(|d| ip_in_plain_text(&d, &ip))
}

fn ip_in_plain_text(text: &str, ip: &std::net::IpAddr) -> bool {
    let needle = ip.to_string().to_ascii_lowercase();
    let haystack = text.to_ascii_lowercase();
    let part: fn(char) -> bool = match ip {
        std::net::IpAddr::V4(_) => is_ipv4_char,
        std::net::IpAddr::V6(_) => is_ipv6_char,
    };
    let v6 = matches!(ip, std::net::IpAddr::V6(_));
    if haystack.match_indices(&needle).any(|(idx, _)| {
        let before = &haystack[..idx];
        (ends_address(before.chars().rev(), part) || (v6 && after_word_label(before)))
            && ends_address(haystack[idx + needle.len()..].chars(), part)
    }) {
        return true;
    }
    haystack
        .split(|c: char| !is_ipv6_char(c))
        .filter(|tok| !tok.is_empty())
        .flat_map(|tok| [tok, tok.trim_matches(|c| c == '.' || c == ':')])
        .filter_map(normalize_host)
        .any(|cand| cand == needle)
}

/// Whether the characters next to a match, walking away from it, end the
/// address: no address character, or a lone `.` or `:` that no address
/// character follows (sentence punctuation, a `key:` label).
fn ends_address(mut next: impl Iterator<Item = char>, part: fn(char) -> bool) -> bool {
    match next.next() {
        None => true,
        Some(c) if !part(c) => true,
        Some('.' | ':') => !next.next().is_some_and(part),
        Some(_) => false,
    }
}

/// Whether `before` ends in a word label and its colon (`src:`, `id:`): hex
/// letters that a letter past `f` precedes are part of a word, not of an
/// IPv6 address. `cafe:` alone may be an address and does not count.
fn after_word_label(before: &str) -> bool {
    let Some(label) = before.strip_suffix(':') else {
        return false;
    };
    label
        .trim_end_matches(|c: char| c.is_ascii_hexdigit())
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphabetic())
}

/// `text` with its `%XX` escapes decoded, when it has any.
fn percent_decoded(text: &str) -> Option<String> {
    if !text.contains('%') {
        return None;
    }
    let hex = |b: Option<&u8>| b.and_then(|&b| (b as char).to_digit(16));
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(high), Some(low)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2)))
        {
            out.push((high * 16 + low) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Resolve the real client IP (= proxy exit IP when checked via proxy).
///
/// Priority: `CF-Connecting-IP` (set by Cloudflare edge, single IP,
/// only with both trust_proxy and trust_cf) → last X-Forwarded-For entry
/// (appended by our own reverse proxy, only when trust_proxy) → socket
/// address.
pub fn client_ip(
    cf_ip: Option<&str>,
    xff: Option<&str>,
    socket_ip: &str,
    trust_proxy: bool,
    trust_cf: bool,
) -> String {
    // Config already clears trust_cf without trust_proxy; checked here too,
    // since a CF header without a reverse proxy in front is the client's own.
    if trust_proxy
        && trust_cf
        && let Some(cf) = cf_ip.and_then(normalize_host)
    {
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
///   `CF-Connecting-IP`, otherwise the single pop applies.
///
/// Either way only the copy our side added goes: a proxy that wrote its own
/// exit address into XFF still reveals itself, behind Caddy and Cloudflare
/// alike. The result keeps non-IP placeholders such as Squid's `unknown`.
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

/// A (lowercased) header our own side adds: not blamed on the checked proxy.
/// Only Cloudflare's own names count as Cloudflare's: arbitrary `cf-*` names
/// pass through its edge.
fn is_infra(name: &str, trust_proxy: bool, trust_cf: bool) -> bool {
    trust_proxy && (INFRA_HEADERS.contains(&name) || (trust_cf && CF_INFRA_HEADERS.contains(&name)))
}

/// Whether a (lowercased) header's value is searched for the client's own
/// address. Not `Host`, which names the judge, nor our reverse proxy's copy
/// of it in `X-Forwarded-Host`. Behind Cloudflare, not `CF-Connecting-IP`,
/// which is the client address by design, nor a `True-Client-IP` that only
/// repeats it; Cloudflare's other headers never hold the client address, so
/// a value the proxy put there is still searched.
fn scanned_for_leaks(
    name: &str,
    value: &str,
    headers: &HashMap<String, String>,
    trust_proxy: bool,
    trust_cf: bool,
) -> bool {
    let same_as = |other: &str| {
        headers
            .get(other)
            .is_some_and(|o| o.trim().eq_ignore_ascii_case(value.trim()))
    };
    match name {
        "host" => false,
        "x-forwarded-host" => !(trust_proxy && same_as("host")),
        "cf-connecting-ip" => !(trust_proxy && trust_cf),
        "true-client-ip" => !(trust_proxy && trust_cf && same_as("cf-connecting-ip")),
        _ => true,
    }
}

/// Header names that only a proxy on the way adds: their presence alone means
/// "not elite", whatever their value. So do every `Proxy-*` and `X-Proxy*`
/// name and, with nothing in front of the judge, every `X-Forwarded-*` (see
/// [`is_telltale`]). Cloudflare's own headers are not here: a judge behind
/// Cloudflare with `TRUST_CF=0` would then call every proxy anonymous; their
/// values are still scanned for the client's address.
const TELLTALE_HEADERS: &[&str] = &[
    "via",
    "forwarded",
    "forwarded-for",
    "forwarded-for-ip",
    "x-forwarded",
    "x-forwarded-for",
    "x-real-ip",
    "client-ip",
    "x-client-ip",
    "x-originating-ip",
    "x-cluster-client-ip",
    "x-remote-ip",
    "x-remote-addr",
    "coming-from",
    "x-coming-from",
    "xroxy-connection",
];

fn is_telltale(name: &str, trust_proxy: bool, trust_cf: bool) -> bool {
    if is_infra(name, trust_proxy, trust_cf) {
        return false;
    }
    // Behind a reverse proxy, edges add X-Forwarded-* names of their own
    // (Traefik's -Server, ingress-nginx's -Scheme, Envoy's -Client-Cert), so
    // only the listed ones count there.
    TELLTALE_HEADERS.contains(&name)
        || ["proxy-", "x-proxy"].iter().any(|p| name.starts_with(p))
        || (!trust_proxy && (name.starts_with("x-forwarded") || INFRA_HEADERS.contains(&name)))
}

/// levels: elite | anonymous | transparent.
///
/// `headers` — request headers as seen by judge, with the
/// reverse-proxy-added XFF entries already removed and `X-Forwarded-For`
/// dropped when none are left (see [`pre_edge_xff`]). Any `X-Forwarded-For`
/// left, even an empty one, came from the proxy side. `direct_ip` —
/// checker's own IP learned via a direct /ip call; without it only proxy
/// presence can be determined.
pub fn anonymity_level(
    headers: &HashMap<String, String>,
    direct_ip: Option<&str>,
    trust_proxy: bool,
    trust_cf: bool,
) -> &'static str {
    let lower = |k: &String| k.to_ascii_lowercase();
    if let Some(d) = direct_ip
        .and_then(normalize_host)
        .and_then(|d| d.parse::<std::net::IpAddr>().ok())
        && headers.iter().any(|(k, v)| {
            scanned_for_leaks(&lower(k), v, headers, trust_proxy, trust_cf) && ip_in_text(v, &d)
        })
    {
        return "transparent";
    }
    if headers
        .keys()
        .any(|k| is_telltale(&lower(k), trust_proxy, trust_cf))
    {
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
        // Checkers compare against this hash: changing FIXED_CONTENT fails
        // here until CONTENT_VERSION is bumped along with the new hash.
        assert_eq!(
            (CONTENT_VERSION, content_sha256().as_str()),
            (
                1,
                "1a0525d8797ca470e7b4a7c47622a89b011760f9db2d587ce7a5e06e99c1bcb9"
            )
        );
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
        // As proxy_view does: no entries left, no X-Forwarded-For.
        let mut for_analysis = h.clone();
        for_analysis.remove("x-forwarded-for");
        assert_eq!(
            anonymity_level(&for_analysis, Some("1.1.1.1"), true, true),
            "elite"
        );
        assert_eq!(anonymity_level(&for_analysis, None, true, true), "elite");
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
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true, true), "elite");
    }

    #[test]
    fn elite_direct_behind_caddy() {
        assert_eq!(
            anonymity_level(&map(&[]), Some("1.1.1.1"), true, true),
            "elite"
        );
        assert_eq!(
            anonymity_level(&map(&[("user-agent", "x")]), None, true, true),
            "elite"
        );
    }

    #[test]
    fn transparent_leak() {
        let h = map(&[("x-forwarded-for", "1.1.1.1"), ("user-agent", "x")]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, true),
            "transparent"
        );
    }

    #[test]
    fn multiple_non_direct_hops_are_anonymous() {
        let h = map(&[("x-forwarded-for", "9.9.9.9, 8.8.8.8")]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, true),
            "anonymous"
        );
        assert_eq!(anonymity_level(&h, None, true, true), "anonymous");
    }

    #[test]
    fn anonymous_forwarded_no_leak() {
        let h = map(&[("x-forwarded-for", "9.9.9.9"), ("user-agent", "x")]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, true),
            "anonymous"
        );
    }

    #[test]
    fn anonymous_via() {
        assert_eq!(
            anonymity_level(&map(&[("via", "1.0 proxy")]), Some("1.1.1.1"), true, true),
            "anonymous"
        );
    }

    #[test]
    fn proxy_headers_are_never_elite() {
        // Each of these only appears when a proxy is on the way; with a value
        // that is not the client's address the verdict is still not elite.
        for name in [
            "Via",
            "Forwarded",
            "Forwarded-For",
            "Forwarded-For-IP",
            "X-Forwarded",
            "X-Real-IP",
            "Client-IP",
            "X-Client-IP",
            "X-Originating-IP",
            "X-Cluster-Client-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "Coming-From",
            "X-Coming-From",
            "Xroxy-Connection",
            "Proxy-Connection",
            "X-ProxyUser-Ip",
        ] {
            for trust_cf in [false, true] {
                for direct in [Some("1.1.1.1"), None] {
                    let h = map(&[(&name.to_ascii_lowercase(), "9.9.9.9")]);
                    assert_eq!(
                        anonymity_level(&h, direct, true, trust_cf),
                        "anonymous",
                        "{name} trust_cf={trust_cf} direct={direct:?}"
                    );
                }
            }
        }
        // The same headers carrying the client's own address leak it.
        let h = map(&[("x-client-ip", "1.1.1.1")]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, false),
            "transparent"
        );
        // Cloudflare's headers alone do not mark a proxy (see TELLTALE_HEADERS).
        let h = map(&[("cf-connecting-ip", "9.9.9.9"), ("cf-ray", "x")]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true, false), "elite");
    }

    #[test]
    fn infra_headers_ignored() {
        let h = map(&[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "check.x"),
            ("host", "check.x"),
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true, true), "elite");
    }

    #[test]
    fn without_a_reverse_proxy_its_headers_mark_the_proxy() {
        // TRUST_PROXY=0: nothing in front of the judge adds these, so the
        // checked proxy did.
        for (name, value) in [
            ("x-forwarded-proto", "http"),
            ("x-forwarded-port", "3128"),
            ("x-forwarded-host", "example.com"),
            ("x-forwarded-ssl", "off"),
            ("x-forwarded-server", "squid"),
            ("x-real-port", "40000"),
        ] {
            let h = map(&[(name, value)]);
            assert_eq!(
                anonymity_level(&h, Some("1.1.1.1"), false, false),
                "anonymous",
                "{name}"
            );
            assert_eq!(anonymity_level(&h, None, false, false), "anonymous");
        }
        let h = map(&[("x-forwarded-host", "1.1.1.1")]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), false, false),
            "transparent"
        );
        // Behind a reverse proxy the value is still searched for a leak.
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, false),
            "transparent"
        );
        // An empty X-Forwarded-For is still a proxy's header.
        let h = map(&[("x-forwarded-for", "")]);
        assert_eq!(anonymity_level(&h, None, false, false), "anonymous");
    }

    #[test]
    fn cf_headers_count_as_cloudflare_only_behind_a_reverse_proxy() {
        let h = map(&[("cf-connecting-ip", "1.1.1.1"), ("cf-ray", "x")]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true, true), "elite");
        // Without TRUST_PROXY there is no Cloudflare in front, whatever
        // trust_cf says: the value is the client's own.
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), false, true),
            "transparent"
        );
        assert_eq!(
            client_ip(Some("1.1.1.1"), None, "9.9.9.9", false, true),
            "9.9.9.9"
        );
    }

    #[test]
    fn leaks_in_loose_notations_are_found() {
        for (name, value) in [
            ("x-forwarded-for", "for=1.1.1.1, 5.6.7.8"),
            ("x-forwarded-for", "\"1.1.1.1\", 5.6.7.8"),
            ("x-note", "from 1.1.1.1."),
            ("x-note", "client: 1.1.1.1:"),
            ("x-note", "seen at host.1.1.1.1"),
            ("x-note", "1%2E1%2E1%2E1"),
        ] {
            let h = map(&[(name, value)]);
            assert_eq!(
                anonymity_level(&h, Some("1.1.1.1"), true, true),
                "transparent",
                "{name}: {value}"
            );
        }
        for value in [
            "ip:2001:db8::1",
            "src:2001:db8::1",
            "id:2001:db8::1",
            "2001:db8::1.",
            "2001%3Adb8%3A%3A1",
            "[2001%3adb8%3a%3a1]%3a443",
        ] {
            let h = map(&[("x-note", value)]);
            assert_eq!(
                anonymity_level(&h, Some("2001:db8::1"), true, true),
                "transparent",
                "{value}"
            );
        }
        // Still on boundaries: a longer address is not this one.
        for value in ["1.1.1.10", "11.1.1.1", "1.1.1.1.5", "21.1.1.1."] {
            let h = map(&[("x-note", value)]);
            assert_eq!(
                anonymity_level(&h, Some("1.1.1.1"), true, true),
                "elite",
                "{value}"
            );
        }
        let h = map(&[
            ("x-note", "2001:db8::10"),
            ("x-other", "a2001:db8::1"),
            ("x-third", "cafe:2001:db8::1"),
        ]);
        assert_eq!(
            anonymity_level(&h, Some("2001:db8::1"), true, true),
            "elite"
        );
        // Host names the judge, never the client.
        let h = map(&[("host", "1.1.1.1:8000")]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), false, false), "elite");
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
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true, true), "elite");
    }

    #[test]
    fn cf_transparent_still_detected() {
        // proxy leaked 1.1.1.1 into XFF, CF appended exit 5.6.7.8
        let h = map(&[
            ("cf-connecting-ip", "5.6.7.8"),
            ("x-forwarded-for", "1.1.1.1"),
        ]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, true),
            "transparent"
        );
    }

    #[test]
    fn true_client_ip_is_a_leak_without_trust_cf() {
        let h = map(&[("true-client-ip", "1.1.1.1")]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, false),
            "transparent"
        );
        // Behind Cloudflare it only repeats CF-Connecting-IP; on its own it
        // is the proxy's.
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, true),
            "transparent"
        );
        let h = map(&[
            ("true-client-ip", "1.1.1.1"),
            ("cf-connecting-ip", "1.1.1.1"),
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true, true), "elite");
    }

    #[test]
    fn cloudflare_headers_that_never_hold_the_client_are_searched() {
        // CDN-Loop is appended to, never replaced: a proxy's value survives.
        let h = map(&[
            ("cf-connecting-ip", "9.9.9.9"),
            ("cdn-loop", "1.1.1.1, cloudflare; loops=1"),
        ]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, true),
            "transparent"
        );
        let h = map(&[
            ("cf-connecting-ip", "9.9.9.9"),
            ("true-client-ip", "1.1.1.1"),
        ]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, true),
            "transparent"
        );
    }

    #[test]
    fn edge_forwarded_names_do_not_mark_a_proxy_behind_a_reverse_proxy() {
        // Traefik, ingress-nginx and Envoy add X-Forwarded-* names of their
        // own: behind a reverse proxy only the listed ones count.
        for name in [
            "x-forwarded-server",
            "x-forwarded-scheme",
            "x-forwarded-prefix",
        ] {
            let h = map(&[(name, "edge-1")]);
            assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true, false), "elite");
            assert_eq!(
                anonymity_level(&h, Some("1.1.1.1"), false, false),
                "anonymous"
            );
        }
        // Our Caddy copies Host into X-Forwarded-Host: not a leak.
        let h = map(&[
            ("host", "1.1.1.1:8000"),
            ("x-forwarded-host", "1.1.1.1:8000"),
        ]);
        assert_eq!(anonymity_level(&h, Some("1.1.1.1"), true, false), "elite");
        let h = map(&[("host", "judge.x"), ("x-forwarded-host", "1.1.1.1")]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, false),
            "transparent"
        );
    }

    #[test]
    fn cf_header_is_a_leak_without_trust_cf() {
        let h = map(&[("cf-connecting-ip", "1.1.1.1")]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, false),
            "transparent"
        );
    }

    #[test]
    fn unknown_cf_header_is_checked_for_leaks() {
        let h = map(&[("cf-connecting-ip", "5.6.7.8"), ("cf-custom", "1.1.1.1")]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, true),
            "transparent"
        );
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
        assert_eq!(
            anonymity_level(&h, Some("1.2.3.4"), true, true),
            "anonymous"
        );
        let h = map(&[("user-agent", "Mozilla 1.2.3.40")]);
        assert_eq!(anonymity_level(&h, Some("1.2.3.4"), true, true), "elite");
    }

    #[test]
    fn header_value_exact_ip_is_a_leak() {
        let h = map(&[("referer", "https://x/?ip=1.2.3.4&y=1")]);
        assert_eq!(
            anonymity_level(&h, Some("1.2.3.4"), true, true),
            "transparent"
        );
    }

    #[test]
    fn ipv6_forms_are_normalized() {
        let h = map(&[("x-forwarded-for", "2001:0db8:0:0:0:0:0:1")]);
        assert_eq!(
            anonymity_level(&h, Some("2001:db8::1"), true, true),
            "transparent"
        );
        let h = map(&[("x-forwarded-for", "2001:db8::10")]);
        assert_eq!(
            anonymity_level(&h, Some("2001:db8::1"), true, true),
            "anonymous"
        );
        // Non-canonical IPv6 in non-XFF headers must also be detected as a leak
        let h = map(&[("x-real-ip", "2001:0db8:0:0:0:0:0:1")]);
        assert_eq!(
            anonymity_level(&h, Some("2001:db8::1"), true, true),
            "transparent"
        );
        let h = map(&[(
            "forwarded",
            "for=\"[2001:0db8:0:0:0:0:0:1]:8080\";proto=http",
        )]);
        assert_eq!(
            anonymity_level(&h, Some("2001:db8::1"), true, true),
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
        assert_eq!(
            anonymity_level(&h, Some("1.2.3.4"), true, true),
            "transparent"
        );
        let h = map(&[("x-forwarded-for", "1.2.3.4")]);
        assert_eq!(
            anonymity_level(&h, Some("::ffff:1.2.3.4"), true, true),
            "transparent"
        );
        let h = map(&[("x-client-ip", "::ffff:0102:0304")]);
        assert_eq!(
            anonymity_level(&h, Some("1.2.3.4"), true, true),
            "transparent"
        );
    }

    #[test]
    fn unknown_xff_is_anonymous_not_elite() {
        let h = map(&[("x-forwarded-for", "unknown")]);
        assert_eq!(
            anonymity_level(&h, Some("1.2.3.4"), true, true),
            "anonymous"
        );
        assert_eq!(anonymity_level(&h, None, true, true), "anonymous");
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
            vec!["9.9.9.9", "1.2.3.4"]
        );
        // A proxy that wrote its own exit into XFF: only CF's copy goes, so
        // the proxy still shows, as it does behind Caddy.
        let behind_cf = forwarded_chain(
            Some("9.9.9.9, 9.9.9.9, 172.71.146.141, 10.29.121.232"),
            "9.9.9.9",
            true,
            true,
            Some("9.9.9.9"),
        );
        let behind_caddy = forwarded_chain(Some("9.9.9.9, 9.9.9.9"), "9.9.9.9", true, false, None);
        assert_eq!(behind_cf, vec!["9.9.9.9"]);
        assert_eq!(behind_caddy, behind_cf);
        let h = map(&[("x-forwarded-for", "9.9.9.9")]);
        assert_eq!(
            anonymity_level(&h, Some("1.1.1.1"), true, true),
            "anonymous"
        );
    }
}
