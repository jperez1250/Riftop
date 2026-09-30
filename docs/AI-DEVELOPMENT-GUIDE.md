# Riftop AI Development & Architectural Guide

## Overview

`Riftop` is a high-performance network bandwidth monitoring tool written in Rust, built as an `iftop` replacement.
It captures network frames in real-time or from PCAP recordings, decodes network protocols, computes exponential moving average and sliding window rates over 2s, 10s, and 40s intervals, and renders live TUI snapshots or structured exports (JSON, CSV, text).

---

## Architecture Overview

```text
Capture (pcap / live)
   │
   ▼
PacketDecoder (etherparse: Ethernet / SLL / SLL2 / RAW / IPv4 / IPv6 / TCP / UDP)
   │
   ▼
PacketEvent
   │
   ├─► BPF / Network Filters
   │
   ▼
FlowEngine (mpsc channel)
   │
   ▼
FlowTable (Capacity MAX_FLOWS = 100,000)
   │
   ├─► RateWindows (2s, 10s, 40s)
   ├─► Direction Accounting (Sent / Received / Unknown)
   └─► Global Counters (seen, accepted, total bytes, sent bytes, recv bytes)
   │
   ▼
Snapshot Engine
   │
   ├─► Top Hosts (`src/top.rs`)
   ├─► Top Ports (`src/top.rs`)
   ├─► Top Protocols (`src/top.rs`)
   │
   ▼
TUI (`src/ui/mod.rs`) & Export (`src/export.rs`)
```

---

## Core Domain Invariants & Guardrails

1. **Flow Identity (`FlowKey`) vs Presentation (`show_ports`)**
   - `FlowKey` defines semantic network flow identity (`(src, dst, sport, dport, protocol)`).
   - Presentation toggles like `--no-ports` MUST NOT mutate the underlying `FlowKey` or zero `protocol` in ways that collapse distinct protocols or corrupt Top Protocols aggregation.

2. **Endpoint Byte Attribution (`bytes_a_to_b`, `bytes_b_to_a`)**
   - Canonical ordering in `FlowKey::new` guarantees `a <= b`.
   - `record_endpoints` attributes bytes from source `s` to destination `d`:
     - Traffic from `a` to `b` increments `bytes_a_to_b`.
     - Traffic from `b` to `a` increments `bytes_b_to_a`.
   - Top Hosts and Top Ports MUST use `bytes_a_to_b` and `bytes_b_to_a` to attribute directional bytes without double-counting flow totals.

3. **Direction Classification (`Direction`)**
   - Live traffic classifies direction relative to local host interfaces (`Direction::Sent`, `Direction::Received`).
   - Offline PCAP traffic without local interface information classifies direction explicitly as `Direction::Unknown` rather than fabricating local host identity.

4. **Capacity Limits (`MAX_FLOWS = 100,000`)**
   - Flow entry creation is capped at 100,000 active flows.
   - Global counters MUST distinguish captured/seen traffic from traffic actually admitted and stored in `FlowTable`.

5. **Rate Calculations (`RateWindow`)**
   - Window rates over 2s, 10s, and 40s MUST compute `total_bytes / window_secs` over active sample buckets.

6. **DNS Concurrency & Caching**
   - DNS resolution uses a bounded worker pool to prevent thread explosion under high packet rates.
   - Lookup states (`Resolving`, `Resolved`, `Negative`) prevent redundant queries on lookup failures.
