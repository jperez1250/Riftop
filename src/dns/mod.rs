//! Reverse DNS lookup with a simple cache.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

const CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
struct CacheEntry {
    name: Option<String>,
    inserted: Instant,
}

/// Thread-safe reverse DNS cache with deduplicated pending request tracking.
#[derive(Debug, Default)]
pub struct DnsCache {
    inner: Mutex<HashMap<IpAddr, CacheEntry>>,
    pending: Mutex<HashSet<IpAddr>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashSet::new()),
        }
    }

    /// Return a cached name if present and not expired.
    pub fn get(&self, ip: &IpAddr) -> Option<String> {
        let guard = self.inner.lock();
        guard.get(ip).and_then(|e| {
            if e.inserted.elapsed() < CACHE_TTL {
                e.name.clone()
            } else {
                None
            }
        })
    }

    /// Insert or refresh an entry.
    pub fn insert(&self, ip: IpAddr, name: Option<String>) {
        let mut guard = self.inner.lock();
        guard.insert(
            ip,
            CacheEntry {
                name,
                inserted: Instant::now(),
            },
        );
        self.pending.lock().remove(&ip);
    }

    /// Resolve asynchronously in a background thread if not cached or pending.
    pub fn resolve_async(self: &Arc<Self>, ip: IpAddr) {
        if self.get(&ip).is_some() {
            return;
        }
        {
            let mut pending = self.pending.lock();
            if !pending.insert(ip) {
                return;
            }
        }
        let cache = Arc::clone(self);
        thread::spawn(move || {
            let name = dns_lookup::lookup_addr(&ip).ok();
            cache.insert(ip, name);
        });
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
