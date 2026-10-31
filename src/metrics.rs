//! Process-local counters exported on `/metrics` in the Prometheus text
//! format; no external metrics dependency is needed.
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub requests: AtomicU64,
    pub responses_4xx: AtomicU64,
    pub responses_5xx: AtomicU64,
    pub rate_limited: AtomicU64,
    pub rdns_lookups: AtomicU64,
    pub rdns_timeouts: AtomicU64,
    pub rdns_skipped: AtomicU64,
}

/// Increment a counter; ordering does not matter for these statistics.
pub fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

impl Metrics {
    /// Text exposition format 0.0.4.
    pub fn render(&self, geo_ready: bool, version: &str) -> String {
        let counters = [
            (
                "proxpulse_requests_total",
                "Total HTTP requests handled.",
                &self.requests,
            ),
            (
                "proxpulse_responses_4xx_total",
                "Responses with 4xx status.",
                &self.responses_4xx,
            ),
            (
                "proxpulse_responses_5xx_total",
                "Responses with 5xx status.",
                &self.responses_5xx,
            ),
            (
                "proxpulse_rate_limited_total",
                "Requests rejected by the rate limiter.",
                &self.rate_limited,
            ),
            (
                "proxpulse_rdns_lookups_total",
                "Blocking rDNS lookups spawned.",
                &self.rdns_lookups,
            ),
            (
                "proxpulse_rdns_timeouts_total",
                "rDNS lookups that exceeded the request timeout.",
                &self.rdns_timeouts,
            ),
            (
                "proxpulse_rdns_skipped_total",
                "Requests skipped because no rDNS permit was available.",
                &self.rdns_skipped,
            ),
        ];
        let mut out = String::new();
        for (name, help, value) in counters {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}\n",
                value.load(Ordering::Relaxed)
            ));
        }
        out.push_str(&format!(
            "# HELP proxpulse_geo_ready 1 when at least one geo database is loaded.\n\
             # TYPE proxpulse_geo_ready gauge\n\
             proxpulse_geo_ready {}\n\
             # HELP proxpulse_build_info Build version information.\n\
             # TYPE proxpulse_build_info gauge\n\
             proxpulse_build_info{{version=\"{version}\"}} 1\n",
            u8::from(geo_ready)
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_exposes_counters_and_gauges() {
        let m = Metrics::default();
        inc(&m.requests);
        inc(&m.requests);
        let text = m.render(true, "1.2.3");
        assert!(
            text.contains("# TYPE proxpulse_requests_total counter\nproxpulse_requests_total 2\n")
        );
        assert!(text.contains("proxpulse_rate_limited_total 0\n"));
        assert!(text.contains("proxpulse_geo_ready 1\n"));
        assert!(text.contains("proxpulse_build_info{version=\"1.2.3\"} 1\n"));
    }
}
