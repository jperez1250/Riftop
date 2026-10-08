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
        let sanitized = name.and_then(|n| sanitize_hostname(&n));
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

/// Sanitize a hostname string by stripping control characters and enforcing RFC 1035 max length (253 chars).
/// Returns `None` if the resulting sanitized hostname is empty.
#[must_use]
pub fn sanitize_hostname(s: &str) -> Option<String> {
    let clean: String = s.chars().filter(|c| !c.is_control()).take(253).collect();
    let trimmed = clean.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
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
            sanitize_hostname("  host.local  "),
            Some("host.local".to_string())
        );
    }

    #[test]
    fn test_sanitize_hostname_control_chars() {
        assert_eq!(
            sanitize_hostname("host\x1b[31m.com\n\r\t\0"),
            Some("host[31m.com".to_string())
        );
        assert_eq!(sanitize_hostname("\n\r\t\0"), None);
    }

    #[test]
    fn test_sanitize_hostname_length_limit() {
        let long_name = "a".repeat(300);
        let sanitized = sanitize_hostname(&long_name).unwrap_or_default();
        assert_eq!(sanitized.len(), 253);
    }

    #[test]
    fn test_dns_cache_insert_sanitization() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        // Malicious PTR record with ANSI escape and control chars
        cache.insert(ip, Some("bad\x1b[2Jserver\n.com".to_string()));
        assert_eq!(cache.get(&ip), Some("bad[2Jserver.com".to_string()));

        // Pure control chars should become Negative state (None from get)
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));
        cache.insert(ip2, Some("\x00\x07\n\r".to_string()));
        assert_eq!(cache.get(&ip2), None);
        assert_eq!(cache.state(&ip2), Some(DnsState::Negative));
    }
}
