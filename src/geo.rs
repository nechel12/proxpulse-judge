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
    city_src: Option<String>,
    country: Option<Reader<Vec<u8>>>,
    country_src: Option<String>,
    asn: Option<Reader<Vec<u8>>>,
    asn_src: Option<String>,
}

fn open_first(dir: &Path, names: &[&str]) -> (Option<Reader<Vec<u8>>>, Option<String>) {
    for name in names {
        let path = dir.join(name);
        if path.exists() {
            match Reader::open_readfile(&path) {
                Ok(r) => return (Some(r), Some(name.to_string())),
                Err(e) => warn!("cannot open {}: {}", path.display(), e),
            }
        }
    }
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
            })
            .collect();
        hits.sort();
        for path in hits {
            match Reader::open_readfile(&path) {
                Ok(r) => {
                    return (
                        Some(r),
                        Some(
                            path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("?")
                                .to_string(),
                        ),
                    )
                }
                Err(e) => warn!("cannot open {}: {}", path.display(), e),
            }
        }
    }
    (None, None)
}

impl GeoPool {
    pub fn open(dir: &Path) -> Self {
        let (city, city_src) = open_first(dir, CITY_CANDIDATES);
        let (country, country_src) = open_first(dir, COUNTRY_CANDIDATES);
        let (asn, asn_src) = open_first(dir, ASN_CANDIDATES);
        let pool = Self {
            city,
            city_src,
            country,
            country_src,
            asn,
            asn_src,
        };
        info!("geo sources: {:?} (dir={})", pool.sources(), dir.display());
        pool
    }

    pub fn sources(&self) -> std::collections::HashMap<String, String> {
        let mut m = std::collections::HashMap::new();
        if let Some(s) = &self.city_src {
            m.insert("city".to_string(), s.clone());
        }
        if let Some(s) = &self.country_src {
            m.insert("country".to_string(), s.clone());
        }
        if let Some(s) = &self.asn_src {
            m.insert("asn".to_string(), s.clone());
        }
        m
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
            match reader.lookup::<Value>(addr) {
                Ok(v) => {
                    if !is_empty_record(&v) {
                        apply_city(&v, &mut out);
                        found = true;
                    }
                }
                Err(maxminddb::MaxMindDBError::AddressNotFoundError(_)) => {}
                Err(e) => out.error = Some(format!("city: {}", short_err(&e.to_string()))),
            }
        }
        if !found {
            if let Some(reader) = &self.country {
                match reader.lookup::<Value>(addr) {
                    Ok(v) => {
                        if !is_empty_record(&v) {
                            apply_city(&v, &mut out);
                            found = true;
                        }
                    }
                    Err(maxminddb::MaxMindDBError::AddressNotFoundError(_)) => {}
                    Err(e) => out.error = Some(format!("country: {}", short_err(&e.to_string()))),
                }
            }
        }
        if let Some(reader) = &self.asn {
            match reader.lookup::<Value>(addr) {
                Ok(v) => {
                    if !is_empty_record(&v) {
                        apply_asn(&v, &mut out);
                        found = true;
                    }
                }
                Err(maxminddb::MaxMindDBError::AddressNotFoundError(_)) => {}
                Err(e) => out.error = Some(format!("asn: {}", short_err(&e.to_string()))),
            }
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
    for path in paths {
        let mut cur = v;
        let mut ok = true;
        for key in *path {
            match cur.get(*key) {
                Some(next) => cur = next,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            if let Some(s) = cur.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

fn get_f64(v: &Value, paths: &[&[&str]]) -> Option<f64> {
    for path in paths {
        let mut cur = v;
        let mut ok = true;
        for key in *path {
            match cur.get(*key) {
                Some(next) => cur = next,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            if let Some(n) = cur.as_f64() {
                return Some(n);
            }
            if let Some(n) = cur.as_i64() {
                return Some(n as f64);
            }
        }
    }
    None
}

fn get_u32(v: &Value, paths: &[&[&str]]) -> Option<u32> {
    for path in paths {
        let mut cur = v;
        let mut ok = true;
        for key in *path {
            match cur.get(*key) {
                Some(next) => cur = next,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
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
        }
    }
    None
}

fn apply_city(v: &Value, out: &mut GeoInfo) {
    if out.country.is_none() {
        out.country = get_str(
            v,
            &[&["country", "names", "en"], &["country"]],
        );
    }
    if out.country_code.is_none() {
        out.country_code = get_str(
            v,
            &[&["country", "iso_code"], &["country_code"], &["countryCode"]],
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
            &[&["location", "longitude"], &["longitude"], &["lon"], &["lng"]],
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
        let v = json!({"autonomous_system_number": 9009, "autonomous_system_organization": "M-net"});
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
    }
}
