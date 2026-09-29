# Riftop

Modern **iftop**-style real-time bandwidth monitor written in Rust.

Branch: `refactorc_testing` — rewrite in progress. See [docs/PROJECT_RULES.md](docs/PROJECT_RULES.md).

## Status

| Layer | Status |
|-------|--------|
| Legacy analysis | [docs/legacy-analysis.md](docs/legacy-analysis.md) |
| Capture (live + offline PCAP) | In progress |
| Protocol decode | Minimal Ethernet/IP/TCP/UDP |
| Flow stats (2s/10s/40s) | MVP |
| PCAP regression tests | Skeleton |
| TUI (ratatui) | MVP (not the priority) |

## Development order

```
legacy analysis → capture/parser → statistics → PCAP tests → TUI
```

## Build

```bash
# Dependencies: libpcap-dev, Rust stable
cargo build --release

# Optional: non-root capture
sudo setcap cap_net_raw,cap_net_admin=eip target/release/riftop
```

## Test (no root)

```bash
./scripts/test-regression.sh
# or
cargo test --all-features
```

## Usage

```bash
sudo ./target/release/riftop -i eth0
sudo ./target/release/riftop -f "tcp port 443"
```

## Project layout

```
src/
  capture/     live + offline PCAP
  protocols/   decode only
  flow/        stats / rate windows
  dns/         reverse DNS cache
  ui/          ratatui (binary only)
docs/          architecture, compatibility, legacy analysis
fixtures/pcap/ deterministic captures
tests/regression_*.rs
scripts/
```

## License

GPL-2.0-or-later (same spirit as original iftop).
