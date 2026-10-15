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
        let state = match name {
            Some(n) => DnsState::Resolved(sanitize_hostname(&n)),
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

/// Sanitize a reverse DNS hostname string by stripping control characters and bounding length to 253 bytes (RFC 1035).
pub fn sanitize_hostname(name: &str) -> String {
    let mut clean = String::with_capacity(name.len().min(253));
    for c in name.chars() {
        if c.is_control() {
            continue;
        }
        if clean.len() + c.len_utf8() > 253 {
            break;
        }
        clean.push(c);
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_insert_sanitizes_control_characters() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        cache.insert(ip, Some("evil\x1b[31mhost\r\n.com".to_string()));
        assert_eq!(cache.get(&ip).unwrap(), "evil[31mhost.com");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_insert_truncates_long_hostname() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));
        let long_name = "a".repeat(300);
        cache.insert(ip, Some(long_name));
        let resolved = cache.get(&ip).unwrap();
        assert_eq!(resolved.len(), 253);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_insert_truncates_utf8_safely() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12));
        // 252 ASCII 'a's + 2-byte UTF-8 char 'é' (254 bytes total if pushed)
        let name = format!("{}é", "a".repeat(252));
        cache.insert(ip, Some(name));
        let resolved = cache.get(&ip).unwrap();
        assert_eq!(resolved.len(), 252);
        assert_eq!(resolved, "a".repeat(252));
    }
}
