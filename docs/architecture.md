# Architecture — Riftop (Rust)

## Module boundaries

```
capture/     → open device or PCAP file; emit raw frames + timestamps
protocols/   → decode Ethernet/IP/TCP/UDP; emit FlowEndpoints (no stats)
stats/       → FlowTable, rate windows, direction, totals
dns/         → optional reverse lookup cache (async, non-blocking)
tui/         → rendering only; reads snapshots from stats
app.rs       → wires modules; owns tick loop
main.rs      → CLI + privilege boundary
```

Capture never imports TUI. TUI never opens pcap.

## Data flow

```
[live NIC / PCAP fixture]
        │
        ▼
   capture::Source
        │  PacketMeta { ts, bytes }
        ▼
   protocols::decode
        │  Option<FlowEvent>
        ▼
   stats::FlowTable::record
        │
        ▼
   snapshot ──► tui::draw
```

## Privilege isolation

- Prefer `CAP_NET_RAW` / `CAP_NET_ADMIN` on the binary (setcap) over full root.
- Offline PCAP mode requires **no** elevated privileges (used by all regression tests).

## Tick model

- Capture thread (or iterator for offline) feeds events.
- UI / analysis tick every `interval_ms` (default 1000 ms, matching legacy RESOLUTION).
- Rate windows: 2s / 10s / 40s sample ages (legacy history_divs × RESOLUTION).

## Testing layers

| Layer | Location | Privileges |
|-------|----------|------------|
| Unit (keys, rates, decode) | `src/**` `#[cfg(test)]` | none |
| Integration | `tests/integration/` | none |
| Regression vs fixtures | `tests/regression_*.rs` | none (PCAP only) |
| Live capture smoke | manual / optional CI job | capabilities |
