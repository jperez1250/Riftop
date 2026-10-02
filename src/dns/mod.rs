//! Reverse DNS lookup with a simple cache.

pub mod cache;
pub mod worker;

pub use cache::{DnsCache, DnsState};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_dns_cache_insert_and_display() {
        let cache = DnsCache::new();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        // Unresolved initially
        assert_eq!(cache.get(&ip), None);
        assert_eq!(cache.state(&ip), None);
        assert_eq!(cache.display(&ip, true), "1.1.1.1");
        assert_eq!(cache.display(&ip, false), "1.1.1.1");

        // Insert resolved entry
        cache.insert(ip, Some("one.one.one.one".to_string()));
        assert_eq!(cache.get(&ip), Some("one.one.one.one".to_string()));
        assert_eq!(
            cache.state(&ip),
            Some(DnsState::Resolved("one.one.one.one".to_string()))
        );
        assert_eq!(cache.display(&ip, true), "one.one.one.one");
        assert_eq!(cache.display(&ip, false), "1.1.1.1");

        // Insert negative entry
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        cache.insert(ip2, None);
        assert_eq!(cache.get(&ip2), None);
        assert_eq!(cache.state(&ip2), Some(DnsState::Negative));
        assert_eq!(cache.display(&ip2, true), "192.0.2.1");
    }
}
