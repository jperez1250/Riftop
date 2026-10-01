#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::all)]
#![allow(clippy::all)]
//! DNS resolution worker pool and thread spawning logic.

use std::net::IpAddr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use parking_lot::Mutex;

use crate::dns::DnsCache;

pub fn spawn_worker_pool(worker_count: usize) -> SyncSender<(IpAddr, Arc<DnsCache>)> {
    let (tx, rx) = sync_channel::<(IpAddr, Arc<DnsCache>)>(512);
    let rx = Arc::new(Mutex::new(rx));

    for _ in 0..worker_count {
        let rx = Arc::clone(&rx);
        thread::spawn(move || worker_loop(&rx));
    }

    tx
}

fn worker_loop(rx: &Arc<Mutex<Receiver<(IpAddr, Arc<DnsCache>)>>>) {
    loop {
        let (ip, cache) = {
            let guard = rx.lock();
            match guard.recv() {
                Ok(item) => item,
                Err(_) => break,
            }
        };
        let name = dns_lookup::lookup_addr(&ip).ok();
        cache.insert(ip, name);
    }
}
