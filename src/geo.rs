//! Local .mmdb pool: GeoLite2 / DB-IP Lite, read fully into RAM.
//! Records are decoded flexibly (multiple key spellings) so both
//! MaxMind and DB-IP files work.
use maxminddb::Reader;
use serde::Serialize;
use serde_json::Value;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

const CITY_CANDIDATES: &[&str] = &["GeoLite2-City.mmdb", "dbip-city-lite.mmdb"];
const COUNTRY_CANDIDATES: &[&str] = &["GeoLite2-Country.mmdb", "dbip-country-lite.mmdb"];
const ASN_CANDIDATES: &[&str] = &["GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb"];

#[derive(Debug, Clone, Default, Serialize)]
pub struct GeoInfo {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aso: Option<String>,
}

impl GeoInfo {
    fn has_any_field(&self) -> bool {
        self.country.is_some()
            || self.country_code.is_some()
            || self.city.is_some()
            || self.latitude.is_some()
            || self.longitude.is_some()
            || self.asn.is_some()
            || self.aso.is_some()
    }
}

pub struct GeoPool {
    city: Option<Reader<Vec<u8>>>,
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
    sources: std::collections::HashMap<String, String>,
}

fn try_open(path: &Path) -> Option<Reader<Vec<u8>>> {
    match Reader::open_readfile(path) {
        Ok(r) => Some(r),
        Err(e) => {
            warn!("cannot open {}: {}", path.display(), e);
            None
        }
    }
}

fn open_first(dir: &Path, names: &[&str]) -> (Option<Reader<Vec<u8>>>, Option<String>) {
    let mut candidates: Vec<PathBuf> = names
        .iter()
        .map(|n| dir.join(n))
        .filter(|p| p.exists())
        .collect();
    // glob fallback: any matching file
    let pattern = if names[0].contains("City") || names[0].contains("city") {
        "city"
    } else if names[0].contains("ASN") || names[0].contains("asn") {
        "asn"
    } else {
        "country"
    };
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut hits: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|x| x.path()))
            .filter(|p| {
                p.extension().map(|x| x == "mmdb").unwrap_or(false)
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.to_ascii_lowercase().contains(pattern))
                        .unwrap_or(false)
                    && !candidates.contains(p)
            })
            .collect();
        hits.sort();
        candidates.extend(hits);
    }
    for path in &candidates {
        if let Some(r) = try_open(path) {
            let kind = r.metadata().database_type.to_ascii_lowercase();
            if !kind.contains(pattern) {
                warn!(
                    "ignoring {}: database_type {:?} does not look like {}",
                    path.display(),
                    r.metadata().database_type,
                    pattern
                );
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string();
            return (Some(r), Some(name));
        }
    }
    (None, None)
}

impl GeoPool {
    pub fn open(dir: &Path) -> Self {
        let (city, city_src) = open_first(dir, CITY_CANDIDATES);
        let (country, country_src) = open_first(dir, COUNTRY_CANDIDATES);
        let (asn, asn_src) = open_first(dir, ASN_CANDIDATES);
        let mut sources = std::collections::HashMap::new();
        if let Some(s) = city_src {
            sources.insert("city".to_string(), s);
        }
        if let Some(s) = country_src {
            sources.insert("country".to_string(), s);
        }
        if let Some(s) = asn_src {
            sources.insert("asn".to_string(), s);
        }
        let pool = Self {
            city,
            country,
            asn,
            sources,
        };
        info!("geo sources: {:?} (dir={})", pool.sources(), dir.display());
        pool
    }

    pub fn sources(&self) -> &std::collections::HashMap<String, String> {
        &self.sources
    }

    /// Required attribution notices for the loaded databases (inspects both
    /// filenames and MMDB `database_type` metadata).
    pub fn attributions(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut labels: Vec<String> = self
            .sources
            .values()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        for reader in [&self.city, &self.country, &self.asn].into_iter().flatten() {
            labels.push(reader.metadata().database_type.to_ascii_lowercase());
        }
        for name in labels {
            if name.contains("maxmind") || name.contains("geolite") || name.contains("geoip") {
                out.push("This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com");
            } else if name.contains("dbip") || name.contains("db-ip") {
                out.push("IP Geolocation by DB-IP (https://db-ip.com)");
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    pub fn lookup(&self, ip: &str) -> GeoInfo {
        let addr: IpAddr = match ip.parse::<IpAddr>() {
            Ok(a) => a.to_canonical(),
            Err(_) => {
                return GeoInfo {
                    ip: ip.to_string(),
                    error: Some("invalid ip".to_string()),
                    ..Default::default()
                }
            }
        };
        let mut out = GeoInfo {
            ip: ip.to_string(),
            ..Default::default()
        };
        if let Some(reader) = &self.city {
            match lookup_value(reader, addr) {
                Ok(Some(v)) if !is_empty_record(&v) => {
                    apply_city(&v, &mut out);
                }
                Ok(_) => {}
                Err(e) => out.error = Some(format!("city: {}", short_err(&e.to_string()))),
            }
        }
        if out.country.is_none() && out.country_code.is_none() {
            if let Some(reader) = &self.country {
                match lookup_value(reader, addr) {
                    Ok(Some(v)) if !is_empty_record(&v) => {
                        apply_city(&v, &mut out);
                    }
                    Ok(_) => {}
                    Err(e) => out.error = Some(format!("country: {}", short_err(&e.to_string()))),
                }
            }
        }
        if let Some(reader) = &self.asn {
            match lookup_value(reader, addr) {
                Ok(Some(v)) if !is_empty_record(&v) => {
                    apply_asn(&v, &mut out);
                }
                Ok(_) => {}
                Err(e) => out.error = Some(format!("asn: {}", short_err(&e.to_string()))),
            }
        }
        let found = out.has_any_field();
        if found {
            // A failed city/country reader must not poison a response that
            // was successfully filled from another source.
            out.error = None;
        }
        if !found && out.error.is_none() {
            out.error = Some(if self.sources().is_empty() {
                "no db".to_string()
            } else {
                "not found".to_string()
            });
        }
        out
    }

    /// Full structural validation of every loaded database. Expensive:
    /// intended for `--check-geo` after downloads, not per request.
    pub fn verify(&self) -> Result<(), String> {
        let mut any = false;
        for (kind, reader) in [
            ("city", self.city.as_ref()),
            ("country", self.country.as_ref()),
            ("asn", self.asn.as_ref()),
        ] {
            if let Some(reader) = reader {
                any = true;
                reader
                    .verify()
                    .map_err(|e| format!("{kind}: {}", short_err(&e.to_string())))?;
            }
        }
        if any {
            Ok(())
        } else {
            Err("no geo databases loaded".to_string())
        }
    }
}

fn lookup_value(
    reader: &Reader<Vec<u8>>,
    addr: IpAddr,
) -> Result<Option<Value>, maxminddb::MaxMindDbError> {
    let result = reader.lookup(addr)?;
    if !result.has_data() {
        return Ok(None);
    }
    result.decode::<Value>()
}

fn short_err(e: &str) -> String {
    e.chars().take(80).collect()
}

fn is_empty_record(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Object(m) => m.is_empty(),
        _ => false,
    }
}

fn get_str(v: &Value, paths: &[&[&str]]) -> Option<String> {
    // Try every shape, not just the first path that resolves: e.g. a
    // `country` object without `names.en` should still fall through to a
    // flat `country` string or `registered_country`.
    paths.iter().find_map(|path| {
        let mut cur = v;
        for key in *path {
            cur = cur.get(*key)?;
        }
        cur.as_str()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    })
}

fn get_f64(v: &Value, paths: &[&[&str]]) -> Option<f64> {
    paths.iter().find_map(|path| {
        let mut cur = v;
        for key in *path {
            cur = cur.get(*key)?;
        }
        cur.as_f64().or_else(|| cur.as_i64().map(|n| n as f64))
    })
}

fn get_u32(v: &Value, paths: &[&[&str]]) -> Option<u32> {
    paths.iter().find_map(|path| {
        let mut cur = v;
        for key in *path {
            cur = cur.get(*key)?;
        }
        if let Some(n) = cur.as_u64() {
            if n <= u32::MAX as u64 {
                return Some(n as u32);
            }
        }
        if let Some(n) = cur.as_i64() {
            if (0..=u32::MAX as i64).contains(&n) {
                return Some(n as u32);
            }
        }
        None
    })
}

fn apply_city(v: &Value, out: &mut GeoInfo) {
    if out.country.is_none() {
        out.country = get_str(
            v,
            &[
                &["country", "names", "en"],
                &["registered_country", "names", "en"],
                &["country"],
            ],
        );
    }
    if out.country_code.is_none() {
        out.country_code = get_str(
            v,
            &[
                &["country", "iso_code"],
                &["registered_country", "iso_code"],
                &["country_code"],
                &["countryCode"],
            ],
        );
    }
    if out.city.is_none() {
        out.city = get_str(v, &[&["city", "names", "en"], &["city"]]);
    }
    if out.latitude.is_none() {
        out.latitude = get_f64(v, &[&["location", "latitude"], &["latitude"], &["lat"]]);
    }
    if out.longitude.is_none() {
        out.longitude = get_f64(
            v,
            &[
                &["location", "longitude"],
                &["longitude"],
                &["lon"],
                &["lng"],
            ],
        );
    }
    // some ASN-combined DBs also carry org fields
    if out.aso.is_none() {
        out.aso = get_str(
            v,
            &[
                &["autonomous_system_organization"],
                &["aso"],
                &["organization"],
                &["org"],
            ],
        );
    }
    if out.asn.is_none() {
        out.asn = get_u32(v, &[&["autonomous_system_number"], &["asn"]]);
    }
}

fn apply_asn(v: &Value, out: &mut GeoInfo) {
    if out.asn.is_none() {
        out.asn = get_u32(v, &[&["autonomous_system_number"], &["asn"]]);
    }
    if out.aso.is_none() {
        out.aso = get_str(
            v,
            &[
                &["autonomous_system_organization"],
                &["aso"],
                &["organization"],
                &["org"],
            ],
        );
    }
}

/// Minimal MaxMind DB writer for tests: an IPv4-only search tree with a
/// single /24 network and one data record, written as a real `.mmdb` file.
/// Tests then go through `maxminddb::Reader` (open, metadata, lookup,
/// decode, verify) instead of feeding hand-built JSON to the field mappers.
#[cfg(test)]
pub(crate) mod test_mmdb {
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};

    const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
    const PREFIX_LEN: u32 = 24;

    /// Control byte (plus extended type and size bytes) of one data field.
    fn control(out: &mut Vec<u8>, kind: u8, size: usize) {
        // Sizes up to 28 fit in the control byte; the one-byte extension
        // (29 + next byte) is enough for test records.
        assert!(size < 285, "value too large for the test writer");
        let type_bits = if kind > 7 { 0 } else { kind };
        out.push((type_bits << 5) | size.min(29) as u8);
        if kind > 7 {
            out.push(kind - 7);
        }
        if size >= 29 {
            out.push((size - 29) as u8);
        }
    }

    /// JSON to MMDB types: string → utf8_string, float → double,
    /// non-negative integer → uint32, object → map, array → array.
    /// Records are decoded leniently into JSON; metadata is decoded into
    /// typed fields and is written by [`write`] with exact integer types.
    fn encode(out: &mut Vec<u8>, v: &Value) {
        match v {
            Value::String(s) => {
                control(out, 2, s.len());
                out.extend_from_slice(s.as_bytes());
            }
            Value::Number(n) if n.is_f64() => {
                control(out, 3, 8);
                out.extend_from_slice(&n.as_f64().unwrap().to_be_bytes());
            }
            Value::Number(n) => {
                let int = n.as_u64().and_then(|n| u32::try_from(n).ok());
                control(out, 6, 4);
                out.extend_from_slice(&int.expect("u32 integer").to_be_bytes());
            }
            Value::Object(m) => {
                control(out, 7, m.len());
                for (k, v) in m {
                    encode(out, &Value::String(k.clone()));
                    encode(out, v);
                }
            }
            Value::Array(a) => {
                control(out, 11, a.len());
                for v in a {
                    encode(out, v);
                }
            }
            Value::Bool(_) | Value::Null => unimplemented!("not used by tests"),
        }
    }

    /// Write a database whose only network is `network`/24.
    pub(crate) fn write(path: &Path, database_type: &str, network: [u8; 4], record: &Value) {
        // One node per prefix bit: the matching branch descends, the other
        // one is the "no data" record (== node_count). The last matching
        // branch points at offset 0 of the data section.
        let node_count = PREFIX_LEN;
        let empty = node_count;
        let data = node_count + 16;
        let bits = u32::from_be_bytes(network);
        let mut out = Vec::new();
        for depth in 0..PREFIX_LEN {
            let next = if depth + 1 == PREFIX_LEN {
                data
            } else {
                depth + 1
            };
            let records = if (bits >> (31 - depth)) & 1 == 0 {
                [next, empty]
            } else {
                [empty, next]
            };
            for r in records {
                // 24-bit records
                out.extend_from_slice(&r.to_be_bytes()[1..]);
            }
        }
        out.extend_from_slice(&[0; 16]);
        encode(&mut out, record);
        out.extend_from_slice(METADATA_MARKER);
        // metadata map: 6 typed integers + 3 JSON-shaped entries
        control(&mut out, 7, 9);
        let integers: [(&str, u8, Vec<u8>); 6] = [
            (
                "binary_format_major_version",
                5,
                2u16.to_be_bytes().to_vec(),
            ),
            (
                "binary_format_minor_version",
                5,
                0u16.to_be_bytes().to_vec(),
            ),
            ("ip_version", 5, 4u16.to_be_bytes().to_vec()),
            ("record_size", 5, 24u16.to_be_bytes().to_vec()),
            ("node_count", 6, node_count.to_be_bytes().to_vec()),
            ("build_epoch", 9, 1_700_000_000u64.to_be_bytes().to_vec()),
        ];
        for (key, kind, bytes) in integers {
            encode(&mut out, &json!(key));
            control(&mut out, kind, bytes.len());
            out.extend_from_slice(&bytes);
        }
        for (key, value) in [
            ("database_type", json!(database_type)),
            ("description", json!({"en": "proxpulse-judge test"})),
            ("languages", json!(["en"])),
        ] {
            encode(&mut out, &json!(key));
            encode(&mut out, &value);
        }
        std::fs::write(path, out).expect("write test mmdb");
    }

    /// MaxMind-shaped City and ASN databases covering 203.0.113.0/24.
    pub(crate) fn write_city_and_asn(dir: &Path) {
        write(
            &dir.join("GeoLite2-City.mmdb"),
            "GeoLite2-City",
            [203, 0, 113, 0],
            &json!({
                "city": {"names": {"en": "Frankfurt"}},
                "country": {"iso_code": "DE", "names": {"en": "Germany"}},
                "location": {"latitude": 50.1, "longitude": 8.6},
            }),
        );
        write(
            &dir.join("GeoLite2-ASN.mmdb"),
            "GeoLite2-ASN",
            [203, 0, 113, 0],
            &json!({
                "autonomous_system_number": 64500,
                "autonomous_system_organization": "Example Hosting GmbH",
            }),
        );
    }

    /// Per-test directory under the system temp dir, removed on drop.
    pub(crate) struct TempDir(PathBuf);

    impl TempDir {
        pub(crate) fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("proxpulse-judge-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create test dir");
            Self(dir)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_mmdb::{self, TempDir};
    use super::*;
    use serde_json::json;

    const MAXMIND_ATTRIBUTION: &str =
        "This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com";

    #[test]
    fn real_mmdb_files_are_read_and_verified() {
        let dir = TempDir::new("geo-real-mmdb");
        test_mmdb::write_city_and_asn(dir.path());
        let pool = GeoPool::open(dir.path());
        assert_eq!(
            pool.sources().get("city").map(String::as_str),
            Some("GeoLite2-City.mmdb")
        );
        assert_eq!(
            pool.sources().get("asn").map(String::as_str),
            Some("GeoLite2-ASN.mmdb")
        );
        pool.verify()
            .expect("test databases are structurally valid");
        assert_eq!(pool.attributions(), vec![MAXMIND_ATTRIBUTION]);

        let info = pool.lookup("203.0.113.7");
        assert_eq!(info.error, None);
        assert_eq!(info.country.as_deref(), Some("Germany"));
        assert_eq!(info.country_code.as_deref(), Some("DE"));
        assert_eq!(info.city.as_deref(), Some("Frankfurt"));
        assert_eq!(info.latitude, Some(50.1));
        assert_eq!(info.longitude, Some(8.6));
        assert_eq!(info.asn, Some(64500));
        assert_eq!(info.aso.as_deref(), Some("Example Hosting GmbH"));

        // IPv4-mapped IPv6 resolves through the IPv4 tree
        let mapped = pool.lookup("::ffff:203.0.113.7");
        assert_eq!(mapped.country_code.as_deref(), Some("DE"));
        // databases are loaded, the address is simply not covered
        assert_eq!(
            pool.lookup("198.51.100.1").error.as_deref(),
            Some("not found")
        );
        // IPv6 in IPv4-only databases is a reported error, not a panic
        assert!(pool.lookup("2001:db8::1").error.is_some());
    }

    #[test]
    fn mismatched_database_type_is_ignored() {
        // Named like a City database but carrying ASN data: must not be
        // used for city lookups (and is not picked up as ASN either).
        let dir = TempDir::new("geo-type-mismatch");
        test_mmdb::write(
            &dir.path().join("GeoLite2-City.mmdb"),
            "GeoLite2-ASN",
            [203, 0, 113, 0],
            &json!({"autonomous_system_number": 64500}),
        );
        let pool = GeoPool::open(dir.path());
        assert!(pool.sources().is_empty());
        assert_eq!(pool.lookup("203.0.113.7").error.as_deref(), Some("no db"));
    }

    #[test]
    fn dbip_files_get_dbip_attribution() {
        let dir = TempDir::new("geo-dbip");
        test_mmdb::write(
            &dir.path().join("dbip-city-lite.mmdb"),
            "DBIP-City-Lite",
            [203, 0, 113, 0],
            &json!({"country": {"iso_code": "DE"}}),
        );
        let pool = GeoPool::open(dir.path());
        assert_eq!(
            pool.attributions(),
            vec!["IP Geolocation by DB-IP (https://db-ip.com)"]
        );
        assert_eq!(
            pool.lookup("203.0.113.7").country_code.as_deref(),
            Some("DE")
        );
    }

    #[test]
    fn maxmind_shaped_record() {
        let v = json!({
            "city": {"names": {"en": "Frankfurt"}},
            "country": {"iso_code": "DE", "names": {"en": "Germany"}},
            "location": {"latitude": 50.1, "longitude": 8.6},
        });
        let mut out = GeoInfo::default();
        apply_city(&v, &mut out);
        assert_eq!(out.city.as_deref(), Some("Frankfurt"));
        assert_eq!(out.country_code.as_deref(), Some("DE"));
        assert_eq!(out.country.as_deref(), Some("Germany"));
        assert_eq!(out.latitude, Some(50.1));
    }

    #[test]
    fn flat_shaped_record() {
        let v = json!({
            "city": "Paris", "country": "France", "country_code": "FR",
            "latitude": 48.8, "longitude": 2.3,
        });
        let mut out = GeoInfo::default();
        apply_city(&v, &mut out);
        assert_eq!(out.city.as_deref(), Some("Paris"));
        assert_eq!(out.country_code.as_deref(), Some("FR"));
    }

    #[test]
    fn asn_record_variants() {
        let v =
            json!({"autonomous_system_number": 9009, "autonomous_system_organization": "M-net"});
        let mut out = GeoInfo::default();
        apply_asn(&v, &mut out);
        assert_eq!(out.asn, Some(9009));
        assert_eq!(out.aso.as_deref(), Some("M-net"));
        let v2 = json!({"asn": 123, "org": "Example"});
        let mut out2 = GeoInfo::default();
        apply_asn(&v2, &mut out2);
        assert_eq!(out2.asn, Some(123));
    }

    #[test]
    fn invalid_ip_without_db() {
        let pool = GeoPool::open(Path::new("/nonexistent-dir-xyz"));
        let info = pool.lookup("not-an-ip");
        assert_eq!(info.error.as_deref(), Some("invalid ip"));
        let info2 = pool.lookup("8.8.8.8");
        assert_eq!(info2.error.as_deref(), Some("no db"));
        assert!(pool.verify().is_err());
    }
}
