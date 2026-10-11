use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::dns::worker::WorkerPool;

const CACHE_TTL: Duration = Duration::from_secs(300);
const NEGATIVE_TTL: Duration = Duration::from_secs(60);

/// Sanitize a hostname by stripping control characters and truncating to at most 253 bytes
/// at UTF-8 character boundaries (RFC 1035).
#[must_use]
pub fn sanitize_hostname(name: &str) -> String {
    let filtered: String = name.chars().filter(|c| !c.is_control()).collect();
    if filtered.len() <= 253 {
        filtered
    } else {
        let mut end = 253;
        while end > 0 && !filtered.is_char_boundary(end) {
            end -= 1;
        }
        filtered[..end].to_string()
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_hostname_removes_control_chars() {
        let input = "example\x07.com\r\n\x1b[31m";
        let sanitized = sanitize_hostname(input);
        assert_eq!(sanitized, "example.com[31m");
    }

    #[test]
    fn test_sanitize_hostname_truncates_long_names() {
        let long_name = "a".repeat(300);
        let sanitized = sanitize_hostname(&long_name);
        assert_eq!(sanitized.len(), 253);
    }

    #[test]
    fn test_sanitize_hostname_utf8_boundary() {
        // 252 ASCII 'a's followed by 3-byte UTF-8 character '€' (total length 255 bytes)
        let name = format!("{0}€", "a".repeat(252));
        let sanitized = sanitize_hostname(&name);
        assert_eq!(sanitized.len(), 252);
        assert_eq!(sanitized, "a".repeat(252));
    }

    #[test]
    fn test_dns_cache_sanitizes_inserted_hostname() {
        let cache = DnsCache::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        cache.insert(ip, Some("bad\nhost\x00name.com".to_string()));
        assert_eq!(cache.get(&ip), Some("badhostname.com".to_string()));
    }
}
