use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::dns::worker::WorkerPool;

const CACHE_TTL: Duration = Duration::from_secs(300);
const NEGATIVE_TTL: Duration = Duration::from_secs(60);

/// Sanitize a domain hostname by stripping control characters, limiting length to 253 (RFC 1035),
/// trimming whitespace, and returning `None` if the sanitized result is empty.
#[must_use]
pub fn sanitize_hostname(name: &str) -> Option<String> {
    let clean: String = name.chars().filter(|c| !c.is_control()).take(253).collect();
    let trimmed = clean.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

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

    /// Insert or refresh an entry, sanitizing the hostname.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_sanitize_hostname() {
        assert_eq!(sanitize_hostname("example.com"), Some("example.com".into()));
        assert_eq!(
            sanitize_hostname("  example.com  \n"),
            Some("example.com".into())
        );
        assert_eq!(
            sanitize_hostname("host\x1b[31m.local\x00"),
            Some("host[31m.local".into())
        );
        assert_eq!(sanitize_hostname("\n\r\t\0"), None);

        let overlong = "a".repeat(300);
        assert_eq!(sanitize_hostname(&overlong), Some("a".repeat(253)));
    }

    #[test]
    fn test_cache_insert_sanitization() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        // Unsafe control char hostname gets sanitized upon insertion
        cache.insert(ip, Some("bad\nhost.com\x00".into()));
        assert_eq!(cache.get(&ip), Some("badhost.com".into()));

        // Control-only hostname results in negative caching
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        cache.insert(ip2, Some("\x00\n\r".into()));
        assert_eq!(cache.get(&ip2), None);
        assert_eq!(cache.state(&ip2), Some(DnsState::Negative));
    }
}
