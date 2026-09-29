# Riftop

Modern **iftop**-style real-time bandwidth monitor written in Rust.

Shows the top host pairs by bandwidth on a network interface, with 2s / 10s / 40s rate windows, optional reverse DNS, and a clean terminal UI.

## Features

- Live packet capture via **libpcap** (`pcap` crate)
- Packet parsing with **etherparse** (no unsafe)
- Flow accounting with sliding-window rates (2s / 10s / 40s)
- Terminal UI with **ratatui** + **crossterm**
- Optional reverse DNS (cached, non-blocking)
- BPF filter support
- Strict Clippy lints and idiomatic error handling (`thiserror` / `anyhow`)

## Requirements

- Rust 1.75+ (edition 2021)
- libpcap development headers
  - Debian/Ubuntu: `sudo apt install libpcap-dev`
  - Fedora: `sudo dnf install libpcap-devel`
  - macOS: included with Xcode CLT / brew
- Root privileges (or `CAP_NET_RAW`) to open the capture device

## Build

```bash
cargo build --release
```

## Usage

```bash
# Default interface, with DNS
sudo ./target/release/riftop

# Specific interface
sudo ./target/release/riftop -i eth0

# BPF filter (HTTPS only)
sudo ./target/release/riftop -f "tcp port 443"

# No DNS, show ports, 30 lines
sudo ./target/release/riftop -n -P -l 30
```

### Keybindings

| Key | Action            |
|-----|-------------------|
| `q` / Esc | Quit         |
| `n` | Toggle DNS        |
| `p` | Toggle ports      |

## Architecture

```
src/
├── main.rs          # CLI + orchestration
├── cli.rs           # clap arguments
├── error.rs         # thiserror types
├── capture/         # pcap + etherparse
├── flow/            # FlowKey, RateWindow, FlowTable
├── dns/             # reverse lookup cache
└── ui/              # ratatui TUI
```

Capture runs on a background thread and updates a shared `FlowTable` protected by `parking_lot::Mutex`. The UI thread reads snapshots and renders at the configured interval.

## License

GPL-2.0-or-later (same spirit as the original iftop).
