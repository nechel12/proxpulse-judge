//! Local .mmdb pool: GeoLite2 / DB-IP Lite, read fully into RAM,
//! LRU-cached lookups. Records are decoded flexibly (multiple key
//! spellings) so both MaxMind and DB-IP files work.
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
            let kind = r.metadata.database_type.to_ascii_lowercase();
            if !kind.contains(pattern) {
                warn!(
                    "ignoring {}: database_type {:?} does not look like {}",
                    path.display(),
                    r.metadata.database_type,
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

    pub fn lookup(&self, ip: &str) -> GeoInfo {
        let addr: IpAddr = match ip.parse() {
            Ok(a) => a,
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
        let mut found = false;
        if let Some(reader) = &self.city {
            match lookup_value(reader, addr) {
                Ok(Some(v)) if !is_empty_record(&v) => {
                    apply_city(&v, &mut out);
                    found = true;
                }
                Ok(_) => {}
                Err(e) => out.error = Some(format!("city: {}", short_err(&e.to_string()))),
            }
        }
        if !found {
            if let Some(reader) = &self.country {
                match lookup_value(reader, addr) {
                    Ok(Some(v)) if !is_empty_record(&v) => {
                        apply_city(&v, &mut out);
                        found = true;
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
                    found = true;
                }
                Ok(_) => {}
                Err(e) => out.error = Some(format!("asn: {}", short_err(&e.to_string()))),
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
