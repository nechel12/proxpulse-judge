//! Ограничение частоты запросов на клиента через token bucket.
use moka::sync::Cache;
use std::{
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub struct TokenBucket {
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    pub fn new(limit: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(limit),
            updated: now,
        }
    }
}

/// Всплеск до `limit`, затем пополнение со скоростью `limit` токенов в минуту. Чистая
/// функция для тестируемости: возвращает Some(retry_after_secs), когда токенов нет.
pub fn check_limit(bucket: &mut TokenBucket, now: Instant, limit: u32) -> Option<u64> {
    if limit == 0 {
        return None;
    }
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

/// Ключ корзины для определённого IP клиента. Клиент IPv6 обычно контролирует
/// целый /64, поэтому корзины на каждый адрес позволили бы ему менять исходные адреса
/// и обходить лимит; клиенты IPv6 делят одну корзину на /64.
pub fn bucket_key(ip: &str) -> String {
    match ip.parse::<IpAddr>().map(|a| a.to_canonical()) {
        Ok(IpAddr::V6(v6)) => {
            let network = Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64));
            format!("{network}/64")
        }
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Err(_) => ip.to_string(),
    }
}

pub struct RateLimit {
    per_minute: u32,
    /// Корзины постоянного размера на каждый ключ; moka ограничивает число ключей.
    hits: Cache<String, Arc<Mutex<TokenBucket>>>,
}

impl RateLimit {
    /// `per_minute` задаёт и всплеск, и установившуюся скорость; 0 отключает лимит.
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            hits: Cache::builder()
                .max_capacity(100_000)
                .time_to_idle(Duration::from_secs(120))
                .build(),
        }
    }

    /// Взять один токен для `client_ip`; Some(retry_after_secs), когда токенов нет.
    pub fn check(&self, client_ip: &str) -> Option<u64> {
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
        // у другого ключа свой бюджет
        let mut other = TokenBucket::new(2, now);
        assert_eq!(check_limit(&mut other, now, 2), None);
        // limit = 0 ничего не делает даже при пустой корзине
        assert_eq!(check_limit(&mut TokenBucket::new(0, now), now, 0), None);
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

    #[test]
    fn bucket_key_groups_ipv6_by_64() {
        assert_eq!(bucket_key("9.9.9.9"), "9.9.9.9");
        assert_eq!(bucket_key("2001:db8:1:2::1"), "2001:db8:1:2::/64");
        assert_eq!(
            bucket_key("2001:db8:1:2:ffff:ffff:ffff:ffff"),
            "2001:db8:1:2::/64"
        );
        assert_eq!(bucket_key("2001:db8:1:3::1"), "2001:db8:1:3::/64");
        // адрес, отображённый из IPv4, — это IPv4-клиент, а не сеть IPv6
        assert_eq!(bucket_key("::ffff:9.9.9.9"), "9.9.9.9");
    }

    #[test]
    fn disabled_limit_never_blocks() {
        let limit = RateLimit::new(0);
        for _ in 0..10 {
            assert_eq!(limit.check("9.9.9.9"), None);
        }
    }
}
