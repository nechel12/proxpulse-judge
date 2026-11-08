//! Per-client token-bucket rate limiting.
use moka::sync::Cache;
use std::{
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct TokenBucket {
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    fn new(limit: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(limit),
            updated: now,
        }
    }
}

/// Burst up to `limit`, then refill at `limit` tokens per minute. Pure
/// function for testability: returns Some(retry_after_secs) when empty.
/// `limit` is above zero: [`RateLimit::check`], the only caller, never asks
/// with 0.
fn check_limit(bucket: &mut TokenBucket, now: Instant, limit: u32) -> Option<u64> {
    debug_assert!(limit > 0);
    let refill_rate = f64::from(limit) / 60.0;
    let elapsed = now.duration_since(bucket.updated).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * refill_rate).min(f64::from(limit));
    bucket.updated = now;
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        return None;
    }
    Some(((1.0 - bucket.tokens) / refill_rate).ceil().max(1.0) as u64)
}

/// Bucket key for a resolved client IP. An IPv6 client usually controls a
/// whole /64, so per-address buckets would let it rotate source addresses
/// and bypass the limit; IPv6 clients share one bucket per /64, keyed by
/// the network's first address.
pub fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        v4 => v4,
    }
}

pub struct RateLimit {
    per_minute: u32,
    /// Constant-size per-key buckets; moka bounds the number of keys.
    hits: Cache<IpAddr, Arc<Mutex<TokenBucket>>>,
}

impl RateLimit {
    /// `per_minute` is both the burst and the sustained rate; 0 disables.
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            hits: Cache::builder()
                .max_capacity(100_000)
                .time_to_idle(Duration::from_secs(120))
                .build(),
        }
    }

    /// Take one token for `client_ip`; Some(retry_after_secs) when empty.
    pub fn check(&self, client_ip: IpAddr) -> Option<u64> {
        if self.per_minute == 0 {
            return None;
        }
        let entry = self.hits.get_with(bucket_key(client_ip), || {
            Arc::new(Mutex::new(TokenBucket::new(
                self.per_minute,
                Instant::now(),
            )))
        });
        let mut bucket = entry.lock().unwrap_or_else(|p| p.into_inner());
        check_limit(&mut bucket, Instant::now(), self.per_minute)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_bucket_allows_then_blocks() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(2, now);
        assert_eq!(check_limit(&mut bucket, now, 2), None);
        assert_eq!(check_limit(&mut bucket, now, 2), None);
        assert_eq!(check_limit(&mut bucket, now, 2), Some(30));
        // another key has its own budget
        let mut other = TokenBucket::new(2, now);
        assert_eq!(check_limit(&mut other, now, 2), None);
    }

    #[test]
    fn limit_bucket_refills_and_reports_exact_delay() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(1, now);
        assert_eq!(check_limit(&mut bucket, now, 1), None);
        assert_eq!(check_limit(&mut bucket, now, 1), Some(60));
        assert_eq!(
            check_limit(&mut bucket, now + Duration::from_secs(30), 1),
            Some(30)
        );
        assert_eq!(
            check_limit(&mut bucket, now + Duration::from_secs(60), 1),
            None
        );
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn bucket_key_groups_ipv6_by_64() {
        assert_eq!(bucket_key(ip("9.9.9.9")), ip("9.9.9.9"));
        assert_eq!(bucket_key(ip("2001:db8:1:2::1")), ip("2001:db8:1:2::"));
        assert_eq!(
            bucket_key(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")),
            ip("2001:db8:1:2::")
        );
        assert_eq!(bucket_key(ip("2001:db8:1:3::1")), ip("2001:db8:1:3::"));
        // an IPv4-mapped address is the IPv4 client, not an IPv6 network
        assert_eq!(bucket_key(ip("::ffff:9.9.9.9")), ip("9.9.9.9"));
    }

    #[test]
    fn one_ipv6_network_shares_a_bucket() {
        let limit = RateLimit::new(2);
        assert_eq!(limit.check(ip("2001:db8:1:2::1")), None);
        assert_eq!(limit.check(ip("2001:db8:1:2::2")), None);
        assert!(limit.check(ip("2001:db8:1:2::3")).is_some());
        assert_eq!(limit.check(ip("2001:db8:1:3::1")), None);
    }

    #[test]
    fn disabled_limit_never_blocks() {
        let limit = RateLimit::new(0);
        for _ in 0..10 {
            assert_eq!(limit.check(ip("9.9.9.9")), None);
        }
    }
}
