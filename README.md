# kagemusha

Tor network analyzer.

Monitors the live Tor network via the Onionoo API and Tor Bulk Exit List.
Queries relay details, tracks bandwidth history, detects exit nodes, and runs
privacy audits (DNS leak, WebRTC leak, IP exposure). Useful for network
operators, researchers, and security teams assessing Tor infrastructure health.

## Quick Start

```bash
cargo test                   # run all 42 tests
cargo build --release        # release binary
nix build                    # Nix hermetic build
```

## Crates

| Crate | Purpose |
|-------|---------|
| `kagemusha-core` | Traits: `ConsensusProvider`, `ExitDetector`, `RelayMonitor`, `PrivacyAuditor` |
| `kagemusha-analyzer` | Onionoo client, exit list parser, consensus builder, audit engine |
| `kagemusha-cli` | CLI binary with `relays`, `exits`, `circuits`, `audit`, and `status` subcommands |

## Privacy Audit Checks

- Exit node detection (Tor Bulk Exit List)
- DNS leak detection (canary domain resolution)
- WebRTC leak detection
- IP exposure check (external IP comparison)

## Usage

```bash
# Show Tor network statistics
kagemusha status

# List all relays
kagemusha relays

# Search relays by name, fingerprint, or country
kagemusha relays DE

# List current exit node IPs
kagemusha exits

# Run a privacy audit
kagemusha audit

# Circuit diversity analysis
kagemusha circuits
```

Configuration is managed via shikumi: `~/.config/kagemusha/kagemusha.yaml`.

## License

MIT
