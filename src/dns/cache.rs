use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::dns::worker::WorkerPool;

const CACHE_TTL: Duration = Duration::from_secs(300);
const NEGATIVE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsState {
    Resolving,
    Resolved(String),
    Negative,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    state: DnsState,
    inserted: Instant,
}

/// Thread-safe reverse DNS cache with deduplicated pending request tracking and negative caching.
#[derive(Debug)]
pub struct DnsCache {
    inner: Mutex<HashMap<IpAddr, CacheEntry>>,
    pending: Mutex<HashSet<IpAddr>>,
    pool: WorkerPool,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashSet::new()),
            pool: WorkerPool::new(4, 512),
        }
    }

    /// Return a cached name if resolved and not expired.
    pub fn get(&self, ip: &IpAddr) -> Option<String> {
        let guard = self.inner.lock();
        guard.get(ip).and_then(|e| match &e.state {
            DnsState::Resolved(name) if e.inserted.elapsed() < CACHE_TTL => Some(name.clone()),
            _ => None,
        })
    }

    /// Return current DNS lookup state if valid.
    pub fn state(&self, ip: &IpAddr) -> Option<DnsState> {
        let guard = self.inner.lock();
        guard.get(ip).and_then(|e| match &e.state {
            DnsState::Resolved(_) if e.inserted.elapsed() < CACHE_TTL => Some(e.state.clone()),
            DnsState::Negative if e.inserted.elapsed() < NEGATIVE_TTL => Some(DnsState::Negative),
            DnsState::Resolving if e.inserted.elapsed() < Duration::from_secs(10) => {
                Some(DnsState::Resolving)
            }
            _ => None,
        })
    }

    /// Insert or refresh an entry.
    pub fn insert(&self, ip: IpAddr, name: Option<String>) {
        let mut guard = self.inner.lock();
        let state = match name.and_then(|n| sanitize_hostname(&n)) {
            Some(n) => DnsState::Resolved(n),
            None => DnsState::Negative,
        };
        guard.insert(
            ip,
            CacheEntry {
                state,
                inserted: Instant::now(),
            },
        );
        self.pending.lock().remove(&ip);
    }

    /// Resolve asynchronously via bounded worker queue if not cached or pending.
    pub fn resolve_async(self: &Arc<Self>, ip: IpAddr) {
        if self.state(&ip).is_some() {
            return;
        }
        {
            let mut pending = self.pending.lock();
            if !pending.insert(ip) {
                return;
            }
        }
        let cache = Arc::clone(self);
        if self.pool.send((ip, cache)).is_err() {
            self.pending.lock().remove(&ip);
        }
    }

    /// Format an address using the cache when available.
    pub fn display(&self, ip: &IpAddr, enable_dns: bool) -> String {
        if enable_dns {
            if let Some(name) = self.get(ip) {
                return name;
            }
        }
        ip.to_string()
    }
}

/// Sanitize untrusted hostnames from DNS resolution:
/// 1. Strip control characters (including newlines, tabs, and null bytes).
/// 2. Truncate to RFC 1035 max hostname length limit (253 bytes) at UTF-8 boundaries.
/// 3. Return None if the resulting string is empty or contains only whitespace.
pub fn sanitize_hostname(raw: &str) -> Option<String> {
    let filtered: String = raw.chars().filter(|c| !c.is_control()).collect();
    let trimmed = filtered.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut boundary = trimmed.len().min(253);
    while boundary > 0 && !trimmed.is_char_boundary(boundary) {
        boundary -= 1;
    }

    let result = &trimmed[..boundary];
    if result.is_empty() {
        None
    } else {
        Some(result.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_valid_hostname() {
        assert_eq!(
            sanitize_hostname("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            sanitize_hostname("  sub.domain.co.uk  "),
            Some("sub.domain.co.uk".to_string())
        );
    }

    #[test]
    fn test_sanitize_control_characters() {
        assert_eq!(
            sanitize_hostname("example\x00.com\n\r\t"),
            Some("example.com".to_string())
        );
        assert_eq!(
            sanitize_hostname("host\x1b[31mname\x1b[0m.com"),
            Some("host[31mname[0m.com".to_string())
        );
    }

    #[test]
    fn test_sanitize_empty_or_whitespace() {
        assert_eq!(sanitize_hostname(""), None);
        assert_eq!(sanitize_hostname("   \n\t   "), None);
        assert_eq!(sanitize_hostname("\x00\x01\x02"), None);
    }

    #[test]
    fn test_sanitize_length_truncation() {
        let long_name = "a".repeat(300) + ".com";
        let sanitized = sanitize_hostname(&long_name).unwrap();
        assert_eq!(sanitized.len(), 253);
        assert_eq!(sanitized, "a".repeat(253));

        let unicode_long = "🦀".repeat(100); // Each crab is 4 bytes
        let sanitized_u = sanitize_hostname(&unicode_long).unwrap();
        assert!(sanitized_u.len() <= 253);
        assert_eq!(sanitized_u.len(), 252); // 63 crabs * 4 bytes = 252 bytes
    }

    #[test]
    fn test_dns_cache_sanitization_integration() {
        let cache = DnsCache::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        cache.insert(ip, Some("bad\nhost\x00name.com".to_string()));
        assert_eq!(cache.get(&ip), Some("badhostname.com".to_string()));

        cache.insert(ip, Some("\t\n  ".to_string()));
        assert_eq!(cache.get(&ip), None);
        assert_eq!(cache.state(&ip), Some(DnsState::Negative));
    }
}
