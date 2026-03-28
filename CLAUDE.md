# Kagemusha — Tor Network Privacy Analyzer

Pure Rust workspace for Tor network analysis, relay monitoring, exit detection, and privacy auditing.

**Tests:** 42

## Architecture

```
kagemusha-core       — traits + types (ConsensusProvider, ExitDetector, RelayMonitor, PrivacyAuditor)
kagemusha-analyzer   — implementations (Onionoo client, exit list parser, consensus builder, audit engine)
kagemusha-cli        — CLI binary (clap subcommands: relays, exits, circuits, audit, status), execute() extracted for testability
```

### Key Types

| Type | Kind | Description |
|------|------|-------------|
| `RelayDetail` | Struct | Onionoo-style relay details (fingerprint, nickname, flags, bandwidth, country, etc.) |
| `BandwidthHistory` | Struct | Normalized bandwidth values over time (read/write history) |
| `AnalysisScope` | Enum | 6 variants (AllRelays, ExitNodes, GuardNodes, BridgeNodes, Country, Fingerprint) |
| `Error` | Struct | Clone + PartialEq + is_retryable() |

## Onionoo Integration

The analyzer crate talks to the [Onionoo API](https://metrics.torproject.org/onionoo.html)
for relay details, bandwidth history, and network statistics. Exit detection uses
the [Tor Bulk Exit List](https://check.torproject.org/torbulkexitlist).

## Privacy Audit Checks

- DNS leak detection (stub — planned: canary domain resolution)
- WebRTC leak detection (stub)
- IP exposure check (stub — planned: external IP comparison)
- Tor exit detection (checks bulk exit list)

## Build

```bash
cargo check                    # type-check workspace
cargo test                     # run all tests
cargo build --release          # optimized binary
nix build                      # Nix reproducible build (via substrate workspace builder)
```

## CLI Usage

```bash
kagemusha status               # network statistics
kagemusha relays               # list all relays
kagemusha relays <query>       # search relays by name/fingerprint/country
kagemusha exits                # list exit node IPs
kagemusha audit                # run privacy audit
kagemusha circuits             # circuit diversity analysis (stub)
```

## Conventions

- Edition 2024, Rust 1.89.0+, MIT license
- clippy pedantic, release profile (codegen-units=1, lto=true, opt-level=z)
- Pure Rust only (rustls, no C FFI)
- Config via shikumi (`~/.config/kagemusha/kagemusha.yaml`)
- async-trait, tokio, thiserror 2, tracing
