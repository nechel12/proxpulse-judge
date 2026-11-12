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

/// Notices the database licences require wherever their data is shown.
pub const MAXMIND_ATTRIBUTION: &str = "This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com";
pub const DBIP_ATTRIBUTION: &str = "IP Geolocation by DB-IP (https://db-ip.com)";

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
    /// Database files that were found but could not be used (unreadable, or
    /// not the kind their name says); `verify` fails on them.
    skipped: Vec<String>,
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

/// The first usable database of one `kind` ("city", "country", "asn"), its
/// file name, and the names of the candidates before it that could not be
/// used. After the known `names`, any `.mmdb` whose name contains `kind`.
fn open_first(
    dir: &Path,
    names: &[&str],
    kind: &str,
) -> (Option<Reader<Vec<u8>>>, Option<String>, Vec<String>) {
    let mut candidates: Vec<PathBuf> = names
        .iter()
        .map(|n| dir.join(n))
        .filter(|p| p.exists())
        .collect();
    let pattern = kind;
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
        // Newest first: dated names (`dbip-city-lite-2026-11.mmdb`) sort by date.
        hits.sort_by(|a, b| b.cmp(a));
        candidates.extend(hits);
    }
    let mut skipped = Vec::new();
    for path in &candidates {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        let Some(r) = try_open(path) else {
            skipped.push(name);
            continue;
        };
        let kind = r.metadata().database_type.to_ascii_lowercase();
        if !kind.contains(pattern) {
            warn!(
                "ignoring {}: database_type {:?} does not look like {}",
                path.display(),
                r.metadata().database_type,
                pattern
            );
            skipped.push(name);
            continue;
        }
        return (Some(r), Some(name), skipped);
    }
    (None, None, skipped)
}

impl GeoPool {
    pub fn open(dir: &Path) -> Self {
        let (city, city_src, mut skipped) = open_first(dir, CITY_CANDIDATES, "city");
        let (country, country_src, more) = open_first(dir, COUNTRY_CANDIDATES, "country");
        skipped.extend(more);
        let (asn, asn_src, more) = open_first(dir, ASN_CANDIDATES, "asn");
        skipped.extend(more);
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
            skipped,
        };
        info!("geo sources: {:?} (dir={})", pool.sources(), dir.display());
        pool
    }

    pub fn sources(&self) -> &std::collections::HashMap<String, String> {
        &self.sources
    }

    /// Required attribution notices for the loaded databases. Each database's
    /// own `database_type` says whose it is; its file name is asked only when
    /// the type names no vendor.
    pub fn attributions(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (kind, reader) in [
            ("city", &self.city),
            ("country", &self.country),
            ("asn", &self.asn),
        ] {
            let Some(reader) = reader else { continue };
            let file = self.sources.get(kind).map(String::as_str).unwrap_or("");
            if let Some(notice) =
                vendor_notice(&reader.metadata().database_type).or_else(|| vendor_notice(file))
            {
                out.push(notice);
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    pub fn lookup(&self, addr: IpAddr) -> GeoInfo {
        let addr = addr.to_canonical();
        let mut out = GeoInfo {
            ip: addr.to_string(),
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
        if out.country.is_none()
            && out.country_code.is_none()
            && let Some(reader) = &self.country
        {
            match lookup_value(reader, addr) {
                Ok(Some(v)) if !is_empty_record(&v) => {
                    apply_city(&v, &mut out);
                }
                Ok(_) => {}
                Err(e) => out.error = Some(format!("country: {}", short_err(&e.to_string()))),
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

    /// Full structural validation of every loaded database, and an error for
    /// any database file that could not be loaded at all. Expensive: intended
    /// for `--check-geo` after downloads, not per request.
    pub fn verify(&self) -> Result<(), String> {
        if !self.skipped.is_empty() {
            return Err(format!("cannot use {}", self.skipped.join(", ")));
        }
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

/// The notice of the vendor a database type or file name mentions. DB-IP is
/// asked first: the type of its ASN database is
/// `DBIP-ASN-Lite (compat=GeoLite2-ASN)`, which names MaxMind's too.
fn vendor_notice(label: &str) -> Option<&'static str> {
    let label = label.to_ascii_lowercase();
    if label.contains("dbip") || label.contains("db-ip") {
        Some(DBIP_ATTRIBUTION)
    } else if ["maxmind", "geolite", "geoip"]
        .iter()
        .any(|v| label.contains(v))
    {
        Some(MAXMIND_ATTRIBUTION)
    } else {
        None
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

/// The value at `path` in a record, as `record["a"]["b"]` would reach it.
fn at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(v, |cur, key| cur.get(*key))
}

// Each getter tries every shape, not just the first path that resolves:
// e.g. a `country` object without `names.en` still falls through to a flat
// `country` string or `registered_country`.

fn get_str(v: &Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        at(v, path)?
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    })
}

fn get_f64(v: &Value, paths: &[&[&str]]) -> Option<f64> {
    // as_f64 reads integers too.
    paths.iter().find_map(|path| at(v, path)?.as_f64())
}

fn get_u32(v: &Value, paths: &[&[&str]]) -> Option<u32> {
    paths
        .iter()
        .find_map(|path| u32::try_from(at(v, path)?.as_u64()?).ok())
}

// The record shape is MaxMind's, which DB-IP Lite follows key for key
// (checked against its City and ASN files); no other shape is read.

fn apply_city(v: &Value, out: &mut GeoInfo) {
    if out.country.is_none() {
        out.country = get_str(
            v,
            &[
                &["country", "names", "en"],
                &["registered_country", "names", "en"],
            ],
        );
    }
    if out.country_code.is_none() {
        out.country_code = get_str(
            v,
            &[
                &["country", "iso_code"],
                &["registered_country", "iso_code"],
            ],
        );
    }
    if out.city.is_none() {
        out.city = get_str(v, &[&["city", "names", "en"]]);
    }
    if out.latitude.is_none() {
        out.latitude = get_f64(v, &[&["location", "latitude"]]);
    }
    if out.longitude.is_none() {
        out.longitude = get_f64(v, &[&["location", "longitude"]]);
    }
    // Some combined databases carry the ASN fields as well.
    apply_asn(v, out);
}

fn apply_asn(v: &Value, out: &mut GeoInfo) {
    if out.asn.is_none() {
        out.asn = get_u32(v, &[&["autonomous_system_number"]]);
    }
    if out.aso.is_none() {
        out.aso = get_str(v, &[&["autonomous_system_organization"]]);
    }
}

/// Minimal MaxMind DB writer for tests: an IPv4-only search tree with a
/// single /24 network and one data record, written as a real `.mmdb` file.
/// Tests then go through `maxminddb::Reader` (open, metadata, lookup,
/// decode, verify) instead of feeding hand-built JSON to the field mappers.
#[cfg(test)]
pub(crate) mod test_mmdb {
    use serde_json::{Value, json};
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

    /// The only network of every test database: 203.0.113.0/24.
    const NETWORK: [u8; 4] = [203, 0, 113, 0];

    /// Write a database whose only network is [`NETWORK`].
    pub(crate) fn write(path: &Path, database_type: &str, record: &Value) {
        // One node per prefix bit: the matching branch descends, the other
        // one is the "no data" record (== node_count). The last matching
        // branch points at offset 0 of the data section.
        let node_count = PREFIX_LEN;
        let empty = node_count;
        let data = node_count + 16;
        let bits = u32::from_be_bytes(NETWORK);
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
            &json!({
                "city": {"names": {"en": "Frankfurt"}},
                "country": {"iso_code": "DE", "names": {"en": "Germany"}},
                "location": {"latitude": 50.1, "longitude": 8.6},
            }),
        );
        write(
            &dir.join("GeoLite2-ASN.mmdb"),
            "GeoLite2-ASN",
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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

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

        let info = pool.lookup(ip("203.0.113.7"));
        assert_eq!(info.error, None);
        assert_eq!(info.country.as_deref(), Some("Germany"));
        assert_eq!(info.country_code.as_deref(), Some("DE"));
        assert_eq!(info.city.as_deref(), Some("Frankfurt"));
        assert_eq!(info.latitude, Some(50.1));
        assert_eq!(info.longitude, Some(8.6));
        assert_eq!(info.asn, Some(64500));
        assert_eq!(info.aso.as_deref(), Some("Example Hosting GmbH"));

        // IPv4-mapped IPv6 resolves through the IPv4 tree
        let mapped = pool.lookup(ip("::ffff:203.0.113.7"));
        assert_eq!(mapped.country_code.as_deref(), Some("DE"));
        // databases are loaded, the address is simply not covered
        assert_eq!(
            pool.lookup(ip("198.51.100.1")).error.as_deref(),
            Some("not found")
        );
        // IPv6 in IPv4-only databases is a reported error, not a panic
        assert!(pool.lookup(ip("2001:db8::1")).error.is_some());
    }

    #[test]
    fn mismatched_database_type_is_ignored() {
        // Named like a City database but carrying ASN data: must not be
        // used for city lookups (and is not picked up as ASN either).
        let dir = TempDir::new("geo-type-mismatch");
        test_mmdb::write(
            &dir.path().join("GeoLite2-City.mmdb"),
            "GeoLite2-ASN",
            &json!({"autonomous_system_number": 64500}),
        );
        let pool = GeoPool::open(dir.path());
        assert!(pool.sources().is_empty());
        assert_eq!(
            pool.lookup(ip("203.0.113.7")).error.as_deref(),
            Some("no db")
        );
        assert!(pool.verify().is_err());
    }

    #[test]
    fn one_broken_database_fails_the_check() {
        // A valid City next to a broken ASN must not pass --check-geo: the
        // download scripts would replace a working ASN database with it.
        let dir = TempDir::new("geo-one-broken");
        test_mmdb::write_city_and_asn(dir.path());
        std::fs::write(dir.path().join("GeoLite2-ASN.mmdb"), b"not a database").unwrap();
        let pool = GeoPool::open(dir.path());
        assert!(pool.sources().contains_key("city"));
        let err = pool.verify().unwrap_err();
        assert!(err.contains("GeoLite2-ASN.mmdb"), "{err}");
    }

    #[test]
    fn the_newest_dated_database_wins() {
        let dir = TempDir::new("geo-dated");
        for (month, code) in [("2026-01", "DE"), ("2026-11", "FR"), ("2026-02", "PL")] {
            test_mmdb::write(
                &dir.path().join(format!("dbip-city-lite-{month}.mmdb")),
                "DBIP-City-Lite",
                &json!({"country": {"iso_code": code}}),
            );
        }
        let pool = GeoPool::open(dir.path());
        assert_eq!(
            pool.sources().get("city").map(String::as_str),
            Some("dbip-city-lite-2026-11.mmdb")
        );
        assert_eq!(
            pool.lookup(ip("203.0.113.7")).country_code.as_deref(),
            Some("FR")
        );
    }

    #[test]
    fn dbip_files_get_dbip_attribution() {
        let dir = TempDir::new("geo-dbip");
        test_mmdb::write(
            &dir.path().join("dbip-city-lite.mmdb"),
            "DBIP-City-Lite",
            &json!({"country": {"iso_code": "DE"}}),
        );
        // The type DB-IP really gives its ASN database names GeoLite2 too.
        test_mmdb::write(
            &dir.path().join("dbip-asn-lite.mmdb"),
            "DBIP-ASN-Lite (compat=GeoLite2-ASN)",
            &json!({"autonomous_system_number": 64500}),
        );
        let pool = GeoPool::open(dir.path());
        assert_eq!(pool.sources().len(), 2);
        assert_eq!(pool.attributions(), vec![DBIP_ATTRIBUTION]);
        assert_eq!(
            pool.lookup(ip("203.0.113.7")).country_code.as_deref(),
            Some("DE")
        );
    }

    #[test]
    fn the_database_type_decides_the_attribution_over_the_file_name() {
        // A DB-IP file kept under the name a deployment already mounts.
        let dir = TempDir::new("geo-renamed");
        test_mmdb::write(
            &dir.path().join("GeoLite2-City.mmdb"),
            "DBIP-City-Lite",
            &json!({"country": {"iso_code": "DE"}}),
        );
        assert_eq!(
            GeoPool::open(dir.path()).attributions(),
            vec![DBIP_ATTRIBUTION]
        );
    }

    #[test]
    fn a_country_without_its_name_falls_back_to_the_registered_one() {
        // The shape of a real DB-IP City record, with the country's name
        // missing: the registered country still names it.
        let v = json!({
            "city": {"names": {"en": "Falkenstein"}},
            "country": {"iso_code": "DE"},
            "registered_country": {"iso_code": "DE", "names": {"en": "Germany"}},
            "location": {"latitude": 50.4754, "longitude": 12},
        });
        let mut out = GeoInfo::default();
        apply_city(&v, &mut out);
        assert_eq!(out.country.as_deref(), Some("Germany"));
        assert_eq!(out.country_code.as_deref(), Some("DE"));
        assert_eq!(out.city.as_deref(), Some("Falkenstein"));
        // An integer coordinate is a number like any other.
        assert_eq!((out.latitude, out.longitude), (Some(50.4754), Some(12.0)));
    }

    #[test]
    fn asn_record() {
        let v =
            json!({"autonomous_system_number": 9009, "autonomous_system_organization": "M-net"});
        let mut out = GeoInfo::default();
        apply_asn(&v, &mut out);
        assert_eq!(out.asn, Some(9009));
        assert_eq!(out.aso.as_deref(), Some("M-net"));
        // A number that is no ASN is not taken.
        let mut out = GeoInfo::default();
        apply_asn(&json!({"autonomous_system_number": -1}), &mut out);
        assert_eq!(out.asn, None);
    }

    #[test]
    fn lookup_without_db() {
        let pool = GeoPool::open(Path::new("/nonexistent-dir-xyz"));
        let info2 = pool.lookup(ip("8.8.8.8"));
        assert_eq!(info2.error.as_deref(), Some("no db"));
        assert!(pool.verify().is_err());
    }
}
