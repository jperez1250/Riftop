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

    /// Insert or refresh an entry, sanitizing the resolved hostname.
    pub fn insert(&self, ip: IpAddr, name: Option<String>) {
        let mut guard = self.inner.lock();
        let sanitized_name = name.and_then(|n| sanitize_hostname(&n));
        let state = match sanitized_name {
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

/// Sanitize hostname from DNS lookup by stripping control characters and bounding length to 253 bytes (RFC 1035).
#[must_use]
pub fn sanitize_hostname(name: &str) -> Option<String> {
    let sanitized: String = name.chars().filter(|c| !c.is_control()).collect();
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() <= 253 {
        Some(trimmed.to_string())
    } else {
        let mut end = 253;
        while !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        Some(trimmed[..end].to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_sanitize_hostname_valid() {
        assert_eq!(
            sanitize_hostname("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            sanitize_hostname("  sub.example.com  "),
            Some("sub.example.com".to_string())
        );
    }

    #[test]
    fn test_sanitize_hostname_control_characters() {
        assert_eq!(
            sanitize_hostname("\x1b[31m malicious.com \x1b[0m"),
            Some("[31m malicious.com [0m".to_string())
        );
        assert_eq!(
            sanitize_hostname("host\r\nname\0.com"),
            Some("hostname.com".to_string())
        );
        assert_eq!(sanitize_hostname("\t\r\n"), None);
    }

    #[test]
    fn test_sanitize_hostname_max_length() {
        let long_name = "a".repeat(300);
        let sanitized = sanitize_hostname(&long_name).unwrap();
        assert_eq!(sanitized.len(), 253);

        // UTF-8 boundary test
        let unicode_long = "🦀".repeat(100); // 4 bytes each, 400 bytes total
        let sanitized_unicode = sanitize_hostname(&unicode_long).unwrap();
        assert!(sanitized_unicode.len() <= 253);
        assert!(std::str::from_utf8(sanitized_unicode.as_bytes()).is_ok());
    }

    #[test]
    fn test_dns_cache_insert_sanitizes() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        cache.insert(ip, Some("\x1b[2Jmalicious.local\n".to_string()));
        assert_eq!(cache.get(&ip), Some("[2Jmalicious.local".to_string()));
    }
}
