use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::dns::worker::WorkerPool;

const CACHE_TTL: Duration = Duration::from_secs(300);
const NEGATIVE_TTL: Duration = Duration::from_secs(60);

/// Sanitize DNS hostname by removing control characters and bounding length to 253 bytes.
#[must_use]
pub fn sanitize_hostname(s: &str) -> String {
    let sanitized: String = s.chars().filter(|c| !c.is_control()).collect();
    if sanitized.len() > 253 {
        let mut end = 253;
        while !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        sanitized[..end].to_string()
    } else {
        sanitized
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
            Some(n) => {
                let clean = sanitize_hostname(&n);
                if clean.is_empty() {
                    DnsState::Negative
                } else {
                    DnsState::Resolved(clean)
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_sanitize_hostname_control_chars() {
        let input = "host\x1b\x07\r\n.example.com";
        let cleaned = sanitize_hostname(input);
        assert_eq!(cleaned, "host.example.com");
    }

    #[test]
    fn test_sanitize_hostname_length_bound() {
        let long_host = "a".repeat(300);
        let cleaned = sanitize_hostname(&long_host);
        assert_eq!(cleaned.len(), 253);
    }

    #[test]
    fn test_sanitize_hostname_multibyte_utf8_bound() {
        let multi_byte = "🦀".repeat(100);
        let cleaned = sanitize_hostname(&multi_byte);
        assert!(cleaned.len() <= 253);
        assert!(std::str::from_utf8(cleaned.as_bytes()).is_ok());
    }

    #[test]
    fn test_insert_control_only_hostname_becomes_negative() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        cache.insert(ip, Some("\x1b\r\n".to_string()));
        assert_eq!(cache.state(&ip), Some(DnsState::Negative));
        assert_eq!(cache.get(&ip), None);
    }
}
