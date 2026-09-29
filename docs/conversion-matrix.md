# Conversion matrix: legacy C → Rust

| Legacy module | Role | Rust status | Location |
|---------------|------|-------------|----------|
| `iftop.c` | main, capture loop, IP accounting | **Done** | `main.rs`, `capture/` |
| `ui.c` | curses UI, rates, hotkeys | **Done (MVP)** | `ui/` (ratatui) |
| `options.c/h` | CLI flags | **Done** | `cli.rs` |
| `cfgfile.c` | `~/.iftoprc` | Deferred | CLI-first |
| `resolver.c` | reverse DNS thread | **Done** | `dns/` |
| `addr_hash.c` + `hash.c` | flow hash table | **Done** | `flow/` |
| `sorted_list.c` | sorted display list | **Done** | `flow::top_sorted` |
| `serv_hash.c` | port → service | **Done** | `services.rs` |
| `screenfilter.c` | host name filter | Deferred | — |
| `edline.c` | interactive filter edit | Deferred | — |
| `addrs_ioctl.c` / `dlpi` | local MAC/IP | **Done** | `capture::local_addresses` |
| `ether.h` / `ip.h` / `tcp.h` | headers | **Done** | `etherparse` + `protocols/` |
| `sll.h` | Linux cooked | **Done** | `protocols::decode_linux_sll` |
| `llc.h` / `ppp.h` / tokenring | rare DLTs | Deferred | graceful ignore |
| autoconf / Makefile | build | **Done** | `Cargo.toml` |

## Feature parity

| Feature | Legacy | Rust |
|---------|--------|------|
| Live capture libpcap | ✓ | ✓ |
| Offline PCAP | — | ✓ `--pcap` |
| BPF filter | ✓ | ✓ |
| Rates 2s/10s/40s | ✓ | ✓ |
| Bidirectional host pairs | ✓ | ✓ |
| Direction by local IP | ✓ | ✓ |
| Reverse DNS | ✓ | ✓ |
| Port display + service names | ✓ | ✓ |
| Bits/bytes toggle | ✓ | ✓ |
| Promiscuous | ✓ | ✓ |
| Sort by column | ✓ | ✓ |
| Pause | ✓ | ✓ |
| Bar graph | ✓ | partial |
| Net filter -F/-G | ✓ | CLI only (TODO accounting) |
| Config file | ✓ | Deferred |

## Not converting

- Autoconf / `configure` / `Makefile.in`
- Solaris DLPI
- Token Ring / radiotap edge cases
- `cscope.*` index files
