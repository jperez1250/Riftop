use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::dns::worker::WorkerPool;

const CACHE_TTL: Duration = Duration::from_secs(300);
const NEGATIVE_TTL: Duration = Duration::from_secs(60);
const MAX_DNS_NAME_LEN: usize = 253; // RFC 1035 max domain name length

pub(crate) fn sanitize_dns_name(name: &str) -> String {
    let filtered: String = name.chars().filter(|c| !c.is_ascii_control()).collect();
    if filtered.len() <= MAX_DNS_NAME_LEN {
        filtered
    } else {
        let mut idx = MAX_DNS_NAME_LEN;
        while idx > 0 && !filtered.is_char_boundary(idx) {
            idx -= 1;
        }
        filtered[..idx].to_string()
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
            Some(n) => DnsState::Resolved(sanitize_dns_name(&n)),
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
    fn test_sanitize_dns_name_control_chars() {
        let raw = "malicious\x1b[2J\x1b[H.example.com\r\n\t";
        let sanitized = sanitize_dns_name(raw);
        assert_eq!(sanitized, "malicious[2J[H.example.com");
    }

    #[test]
    fn test_sanitize_dns_name_max_length() {
        let long_name = "a".repeat(300);
        let sanitized = sanitize_dns_name(&long_name);
        assert_eq!(sanitized.len(), 253);
        assert_eq!(sanitized, "a".repeat(253));
    }

    #[test]
    fn test_sanitize_dns_name_utf8_boundary() {
        // Multi-byte character '🦀' is 4 bytes.
        // 250 'a's + '🦀' (4 bytes) = 254 bytes.
        // Bounding at 253 bytes must not slice inside the 4-byte char.
        let mut text = "a".repeat(250);
        text.push('🦀');
        let sanitized = sanitize_dns_name(&text);
        assert_eq!(sanitized.len(), 250);
        assert_eq!(sanitized, "a".repeat(250));
    }

    #[test]
    fn test_dns_cache_insert_sanitizes() {
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        cache.insert(ip, Some("evil\n\rhost.com".to_string()));
        assert_eq!(cache.get(&ip), Some("evilhost.com".to_string()));
    }
}
