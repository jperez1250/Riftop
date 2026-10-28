use std::net::IpAddr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use parking_lot::Mutex;

pub type WorkerMessage = (IpAddr, Arc<crate::dns::cache::DnsCache>);

#[derive(Debug)]
pub struct WorkerPool {
    pub tx: Mutex<SyncSender<WorkerMessage>>,
}

impl WorkerPool {
    #[must_use]
    pub fn new(worker_count: usize, queue_capacity: usize) -> Self {
        let (tx, rx) = sync_channel::<WorkerMessage>(queue_capacity);
        let rx = Arc::new(Mutex::new(rx));

        for _ in 0..worker_count {
            let rx_clone = Arc::clone(&rx);
            thread::spawn(move || worker_loop(&rx_clone));
        }

        Self { tx: Mutex::new(tx) }
    }

    pub fn send(
        &self,
        msg: WorkerMessage,
    ) -> Result<(), std::sync::mpsc::TrySendError<WorkerMessage>> {
        self.tx.lock().try_send(msg)
    }
}

fn worker_loop(rx: &Arc<Mutex<Receiver<WorkerMessage>>>) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_worker_pool_creation_and_send() {
        let pool = WorkerPool::new(1, 10);
        let cache = Arc::new(crate::dns::cache::DnsCache::new());
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let res = pool.send((ip, cache));
        assert!(res.is_ok(), "Failed to send message to worker pool");
    }
}
