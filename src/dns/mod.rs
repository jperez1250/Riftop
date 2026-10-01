//! Reverse DNS lookup cache facade.

pub mod cache;
pub mod worker;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

use parking_lot::Mutex;

use cache::CacheStore;
pub use cache::DnsState;
use worker::spawn_worker_pool;

/// Thread-safe reverse DNS cache with deduplicated pending request tracking and negative caching.
#[derive(Debug)]
pub struct DnsCache {
    store: Mutex<CacheStore>,
    pending: Mutex<HashSet<IpAddr>>,
    tx: Mutex<SyncSender<(IpAddr, Arc<DnsCache>)>>,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        let tx = spawn_worker_pool(4);
        Self {
            store: Mutex::new(CacheStore::new()),
            pending: Mutex::new(HashSet::new()),
            tx: Mutex::new(tx),
        }
    }

    /// Return a cached name if resolved and not expired.
    pub fn get(&self, ip: &IpAddr) -> Option<String> {
        self.store.lock().get(ip)
    }

    /// Return current DNS lookup state if valid.
    pub fn state(&self, ip: &IpAddr) -> Option<DnsState> {
        self.store.lock().state(ip)
    }

    /// Insert or refresh an entry.
    pub fn insert(&self, ip: IpAddr, name: Option<String>) {
        self.store.lock().insert(ip, name);
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
        if self.tx.lock().try_send((ip, cache)).is_err() {
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
