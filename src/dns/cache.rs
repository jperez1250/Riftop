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

/// Sanitize hostname by stripping control characters and bounding length to RFC 1035 max (253 chars).
fn sanitize_hostname(s: &str) -> Option<String> {
    let cleaned: String = s.chars().filter(|c| !c.is_control()).take(253).collect();
    if cleaned.trim().is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_sanitize_hostname_control_chars() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let cache = DnsCache::new();
        cache.insert(ip, Some("host\x1b[31m.example.com\n\r".to_string()));
        assert_eq!(cache.get(&ip), Some("host[31m.example.com".to_string()));
    }

    #[test]
    fn test_sanitize_hostname_bounded_length() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));
        let cache = DnsCache::new();
        let long_name = "a".repeat(300);
        cache.insert(ip, Some(long_name));
        let resolved = cache.get(&ip);
        assert!(resolved.is_some());
        if let Some(r) = resolved {
            assert_eq!(r.len(), 253);
        }
    }

    #[test]
    fn test_sanitize_hostname_only_control_chars() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12));
        let cache = DnsCache::new();
        cache.insert(ip, Some("\x1b\x07\n\r  ".to_string()));
        assert_eq!(cache.get(&ip), None);
        assert_eq!(cache.state(&ip), Some(DnsState::Negative));
    }
}
