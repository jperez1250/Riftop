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

/// Sanitize DNS name by stripping control characters and bounding length to 253 chars (RFC 1035).
#[must_use]
pub fn sanitize_dns_name(name: &str) -> Option<String> {
    let sanitized: String = name.chars().filter(|c| !c.is_control()).take(253).collect();
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
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

    /// Insert or refresh an entry, sanitizing untrusted DNS names.
    pub fn insert(&self, ip: IpAddr, name: Option<String>) {
        let mut guard = self.inner.lock();
        let sanitized = name.and_then(|n| sanitize_dns_name(&n));
        let state = match sanitized {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_sanitize_dns_name_valid() {
        assert_eq!(
            sanitize_dns_name("example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_sanitize_dns_name_strips_control_chars() {
        assert_eq!(
            sanitize_dns_name("example.com\x1b[2J\r\n"),
            Some("example.com[2J".to_string())
        );
    }

    #[test]
    fn test_sanitize_dns_name_bounds_length() {
        let long_name = "a".repeat(300);
        if let Some(sanitized) = sanitize_dns_name(&long_name) {
            assert_eq!(sanitized.len(), 253);
        } else {
            panic!("should produce sanitized name");
        }
    }

    #[test]
    fn test_sanitize_dns_name_empty_or_control_only() {
        assert_eq!(sanitize_dns_name("   "), None);
        assert_eq!(sanitize_dns_name("\x00\x01\x1b"), None);
    }

    #[test]
    fn test_cache_insert_sanitizes() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.insert(ip, Some("evil.com\x1b[2J".to_string()));
        assert_eq!(cache.get(&ip), Some("evil.com[2J".to_string()));

        cache.insert(ip, Some("\x1b\x00\r\n".to_string()));
        assert_eq!(cache.get(&ip), None);
        assert_eq!(cache.state(&ip), Some(DnsState::Negative));
    }
}
