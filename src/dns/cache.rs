#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::all)]
#![allow(clippy::all)]
//! Reverse DNS lookup cache data structures and expiration rules.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub const CACHE_TTL: Duration = Duration::from_secs(300);
pub const NEGATIVE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsState {
    Resolving,
    Resolved(String),
    Negative,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub state: DnsState,
    pub inserted: Instant,
}

#[derive(Debug, Default)]
pub struct CacheStore {
    entries: HashMap<IpAddr, CacheEntry>,
}

impl CacheStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn get(&self, ip: &IpAddr) -> Option<String> {
        self.entries.get(ip).and_then(|e| match &e.state {
            DnsState::Resolved(name) if e.inserted.elapsed() < CACHE_TTL => Some(name.clone()),
            _ => None,
        })
    }

    pub fn state(&self, ip: &IpAddr) -> Option<DnsState> {
        self.entries.get(ip).and_then(|e| match &e.state {
            DnsState::Resolved(_) if e.inserted.elapsed() < CACHE_TTL => Some(e.state.clone()),
            DnsState::Negative if e.inserted.elapsed() < NEGATIVE_TTL => Some(DnsState::Negative),
            DnsState::Resolving if e.inserted.elapsed() < Duration::from_secs(10) => {
                Some(DnsState::Resolving)
            }
            _ => None,
        })
    }

    pub fn insert(&mut self, ip: IpAddr, name: Option<String>) {
        let state = match name {
            Some(n) => DnsState::Resolved(n),
            None => DnsState::Negative,
        };
        self.entries.insert(
            ip,
            CacheEntry {
                state,
                inserted: Instant::now(),
            },
        );
    }
}
