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
        let state = match name
            .map(|n| sanitize_hostname(&n))
            .filter(|n| !n.is_empty())
        {
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

/// Sanitize a DNS hostname by removing control characters and truncating to 253 bytes.
fn sanitize_hostname(s: &str) -> String {
    let sanitized: String = s.chars().filter(|c| !c.is_control()).collect();
    if sanitized.len() <= 253 {
        sanitized
    } else {
        let mut end = 253;
        while end > 0 && !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        sanitized[..end].to_string()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_sanitize_hostname_control_chars() {
        let input = "example\n\r\t.com\x1b[31m";
        let output = sanitize_hostname(input);
        assert_eq!(output, "example.com[31m");
    }

    #[test]
    fn test_sanitize_hostname_length_and_utf8() {
        let long_ascii = "a".repeat(300);
        let output = sanitize_hostname(&long_ascii);
        assert_eq!(output.len(), 253);

        // Multi-byte character test across boundary
        let multi_byte = "a".repeat(252) + "🦀🦀";
        let output_mb = sanitize_hostname(&multi_byte);
        assert!(output_mb.len() <= 253);
        assert_eq!(output_mb, "a".repeat(252));
    }

    #[test]
    fn test_dns_cache_insert_sanitization() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Control characters stripped
        cache.insert(ip, Some("host\n\r.local".to_string()));
        assert_eq!(cache.get(&ip), Some("host.local".to_string()));

        // Empty string resulting from only control chars becomes Negative state
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        cache.insert(ip2, Some("\n\r\t".to_string()));
        assert_eq!(cache.get(&ip2), None);
        assert_eq!(cache.state(&ip2), Some(DnsState::Negative));
    }
}
