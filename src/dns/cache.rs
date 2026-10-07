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

/// Sanitize hostnames by stripping control characters and truncating to max 253 chars (RFC 1035).
pub fn sanitize_hostname(name: &str) -> String {
    name.chars().filter(|c| !c.is_control()).take(253).collect()
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
        let state = match name {
            Some(n) => {
                let sanitized = sanitize_hostname(&n);
                if sanitized.is_empty() {
                    DnsState::Negative
                } else {
                    DnsState::Resolved(sanitized)
                }
            }
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

    #[test]
    fn test_sanitize_hostname_normal() {
        assert_eq!(sanitize_hostname("example.com"), "example.com");
        assert_eq!(sanitize_hostname("sub.domain.org"), "sub.domain.org");
    }

    #[test]
    fn test_sanitize_hostname_control_chars() {
        assert_eq!(sanitize_hostname("host\x1b[31m.com"), "host[31m.com");
        assert_eq!(sanitize_hostname("host\n\r\t\0.com"), "host.com");
    }

    #[test]
    fn test_sanitize_hostname_length_limit() {
        let long_name = "a".repeat(300);
        let sanitized = sanitize_hostname(&long_name);
        assert_eq!(sanitized.len(), 253);
        assert_eq!(sanitized, "a".repeat(253));
    }

    #[test]
    fn test_dns_cache_insert_sanitization() {
        use std::net::Ipv4Addr;

        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        // Standard insertion
        cache.insert(ip, Some("valid.host.com".to_string()));
        assert_eq!(cache.get(&ip), Some("valid.host.com".to_string()));

        // Insertion with control characters
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        cache.insert(ip2, Some("bad\x1b[2J.host.com".to_string()));
        assert_eq!(cache.get(&ip2), Some("bad[2J.host.com".to_string()));

        // Insertion with only control characters -> Negative state
        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        cache.insert(ip3, Some("\x1b\x07\n\r".to_string()));
        assert_eq!(cache.get(&ip3), None);
        assert_eq!(cache.state(&ip3), Some(DnsState::Negative));
        assert_eq!(cache.display(&ip3, true), "192.0.2.3");
    }
}
