use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::dns::worker::WorkerPool;

const CACHE_TTL: Duration = Duration::from_secs(300);
const NEGATIVE_TTL: Duration = Duration::from_secs(60);

/// Sanitize untrusted DNS hostname by removing control characters and truncating to RFC 1035 limit (253 bytes).
fn sanitize_hostname(name: &str) -> Option<String> {
    let sanitized: String = name.chars().filter(|c| !c.is_control()).collect();
    if sanitized.is_empty() {
        return None;
    }
    if sanitized.len() > 253 {
        let mut end = 253;
        while end > 0 && !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            return None;
        }
        Some(sanitized[..end].to_string())
    } else {
        Some(sanitized)
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
    }

    #[test]
    fn test_sanitize_hostname_strips_control_chars() {
        let dirty = "\x1b[31mhost.example.com\x1b[0m\n\r\t";
        assert_eq!(
            sanitize_hostname(dirty),
            Some("[31mhost.example.com[0m".to_string())
        );
    }

    #[test]
    fn test_sanitize_hostname_all_control_chars_returns_none() {
        assert_eq!(sanitize_hostname("\n\r\t\x1b\x00"), None);
    }

    #[test]
    fn test_sanitize_hostname_truncates_at_253_bytes() {
        let long_name = "a".repeat(300);
        let sanitized = sanitize_hostname(&long_name);
        if let Some(res) = sanitized {
            assert_eq!(res.len(), 253);
            assert_eq!(res, "a".repeat(253));
        } else {
            panic!("expected sanitized hostname to be Some");
        }
    }

    #[test]
    fn test_dns_cache_sanitizes_inserted_names() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        cache.insert(ip, Some("evil.com\x1b[2J\n".to_string()));
        assert_eq!(cache.get(&ip), Some("evil.com[2J".to_string()));

        let ip_bad = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        cache.insert(ip_bad, Some("\n\r".to_string()));
        assert_eq!(cache.state(&ip_bad), Some(DnsState::Negative));
    }
}
