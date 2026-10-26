# Sentinel Security Journal

## 2025-05-20 - Reverse DNS Hostname Sanitization and IPv4 Link-Local Filtering
**Vulnerability:** Reverse DNS responses over network queries could contain control characters or unbounded lengths causing UI corruption or memory bloat; also IPv4 link-local packets (169.254.0.0/16) bypassed link-local filtering when `allow_link_local` was false.
**Learning:** Hostnames from DNS PTR records must be sanitized (ASCII control characters stripped, length bounded to 253 bytes per RFC 1035 on UTF-8 character boundaries) before storing in `DnsCache`. `PacketFilter::accept` must check both IPv4 (`is_link_local_v4`) and IPv6 (`is_link_local_v6`) link-local ranges.
**Prevention:** Always sanitize untrusted network strings before storing or rendering, and ensure packet filter rules handle both IP families uniformly.
