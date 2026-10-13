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
        let state = match name.as_deref().and_then(sanitize_hostname) {
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

/// Sanitize hostname by stripping control characters and bounding to 253 bytes (RFC 1035).
#[must_use]
pub fn sanitize_hostname(raw: &str) -> Option<String> {
    let filtered: String = raw.chars().filter(|c| !c.is_control()).collect();
    if filtered.is_empty() {
        return None;
    }
    if filtered.len() <= 253 {
        Some(filtered)
    } else {
        let mut end = 253;
        while !filtered.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            None
        } else {
            Some(filtered[..end].to_string())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_sanitize_hostname_normal() {
        assert_eq!(
            sanitize_hostname("example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_sanitize_hostname_strips_control_characters() {
        assert_eq!(
            sanitize_hostname("example\x1b[2J.com\r\n\0"),
            Some("example[2J.com".to_string())
        );
    }

    #[test]
    fn test_sanitize_hostname_empty_after_stripping() {
        assert_eq!(sanitize_hostname("\x1b\r\n\0\x08"), None);
    }

    #[test]
    fn test_sanitize_hostname_bounds_length() {
        let long_name = "a".repeat(300);
        let sanitized = sanitize_hostname(&long_name).unwrap();
        assert_eq!(sanitized.len(), 253);
    }

    #[test]
    fn test_sanitize_hostname_utf8_boundary() {
        // '🦀' is 4 bytes in UTF-8
        let prefix = "a".repeat(251);
        let name = format!("{prefix}🦀🦀🦀");
        let sanitized = sanitize_hostname(&name).unwrap();
        assert!(sanitized.len() <= 253);
        assert!(sanitized.is_char_boundary(sanitized.len()));
    }

    #[test]
    fn test_dns_cache_insert_sanitization() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.insert(ip, Some("host\x1b[31m.com".to_string()));
        assert_eq!(cache.get(&ip), Some("host[31m.com".to_string()));

        let ip_empty = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5));
        cache.insert(ip_empty, Some("\r\n".to_string()));
        assert_eq!(cache.get(&ip_empty), None);
        assert_eq!(cache.state(&ip_empty), Some(DnsState::Negative));
    }
}
