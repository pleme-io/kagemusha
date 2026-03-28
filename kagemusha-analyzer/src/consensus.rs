use std::sync::Arc;

use chrono::Utc;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::debug;

use kagemusha_core::{
    ConsensusProvider, Error, NetworkConsensus, RelayEntry, RelayFlag, Result,
};

// ---------------------------------------------------------------------------
// Onionoo shapes (minimal, consensus-focused)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OnionooRelayResponse {
    #[serde(default)]
    relays: Vec<OnionooRelay>,
}

#[derive(Debug, Deserialize)]
struct OnionooRelay {
    fingerprint: Option<String>,
    nickname: Option<String>,
    #[serde(default)]
    or_addresses: Vec<String>,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    observed_bandwidth: Option<u64>,
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// Builds `NetworkConsensus` from Onionoo relay data.
pub struct OnionooConsensusProvider {
    base_url: String,
    http: reqwest::Client,
    cache: Arc<RwLock<Option<NetworkConsensus>>>,
}

impl OnionooConsensusProvider {
    /// Create a provider with the default Onionoo URL.
    #[must_use]
    pub fn new() -> Self {
        Self::with_base_url("https://onionoo.torproject.org")
    }

    /// Create a provider with a custom base URL.
    #[must_use]
    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(None)),
        }
    }
}

impl Default for OnionooConsensusProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ConsensusProvider for OnionooConsensusProvider {
    async fn fetch(&self) -> Result<NetworkConsensus> {
        let url = format!(
            "{}/details?type=relay&fields=fingerprint,nickname,or_addresses,flags,observed_bandwidth",
            self.base_url
        );
        debug!(%url, "fetching consensus from Onionoo");

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        let body: OnionooRelayResponse = resp
            .json()
            .await
            .map_err(|e| Error::Parse(e.to_string()))?;

        let now = Utc::now();
        let relays: Vec<RelayEntry> = body
            .relays
            .iter()
            .filter_map(|r| onionoo_to_relay_entry(r).ok())
            .collect();

        let consensus = NetworkConsensus {
            valid_after: now,
            valid_until: now + chrono::Duration::hours(1),
            relays,
        };

        // Update cache.
        {
            let mut cache = self.cache.write().await;
            *cache = Some(consensus.clone());
        }

        Ok(consensus)
    }

    async fn fetch_cached(&self) -> Option<NetworkConsensus> {
        let cache = self.cache.read().await;
        cache.clone()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_or_address(addr: &str) -> Option<(std::net::IpAddr, u16)> {
    if let Some(bracket_end) = addr.rfind(']') {
        let ip_str = addr.get(1..bracket_end)?;
        let port_str = addr.get(bracket_end + 2..)?;
        let ip: std::net::IpAddr = ip_str.parse().ok()?;
        let port: u16 = port_str.parse().ok()?;
        Some((ip, port))
    } else {
        let (ip_str, port_str) = addr.rsplit_once(':')?;
        let ip: std::net::IpAddr = ip_str.parse().ok()?;
        let port: u16 = port_str.parse().ok()?;
        Some((ip, port))
    }
}

fn parse_flag(s: &str) -> Option<RelayFlag> {
    match s {
        "Authority" => Some(RelayFlag::Authority),
        "BadExit" => Some(RelayFlag::BadExit),
        "Exit" => Some(RelayFlag::Exit),
        "Fast" => Some(RelayFlag::Fast),
        "Guard" => Some(RelayFlag::Guard),
        "HSDir" => Some(RelayFlag::HSDir),
        "Running" => Some(RelayFlag::Running),
        "Stable" => Some(RelayFlag::Stable),
        "StaleDesc" => Some(RelayFlag::StaleDesc),
        "V2Dir" => Some(RelayFlag::V2Dir),
        "Valid" => Some(RelayFlag::Valid),
        _ => None,
    }
}

fn onionoo_to_relay_entry(relay: &OnionooRelay) -> Result<RelayEntry> {
    let fingerprint = relay.fingerprint.clone().unwrap_or_default();
    let (address, or_port) = relay
        .or_addresses
        .first()
        .and_then(|a| parse_or_address(a))
        .ok_or_else(|| Error::Parse(format!("no valid address for {fingerprint}")))?;

    Ok(RelayEntry {
        fingerprint,
        nickname: relay.nickname.clone().unwrap_or_default(),
        address,
        or_port,
        dir_port: 0,
        flags: relay.flags.iter().filter_map(|f| parse_flag(f)).collect(),
        bandwidth: relay.observed_bandwidth.unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_relays() -> Vec<OnionooRelay> {
        vec![
            OnionooRelay {
                fingerprint: Some("AAA111".into()),
                nickname: Some("GuardRelay".into()),
                or_addresses: vec!["1.2.3.4:9001".into()],
                flags: vec!["Guard".into(), "Running".into(), "Valid".into()],
                observed_bandwidth: Some(100_000),
            },
            OnionooRelay {
                fingerprint: Some("BBB222".into()),
                nickname: Some("ExitRelay".into()),
                or_addresses: vec!["5.6.7.8:443".into()],
                flags: vec!["Exit".into(), "Running".into(), "Valid".into(), "Fast".into()],
                observed_bandwidth: Some(200_000),
            },
            OnionooRelay {
                fingerprint: Some("CCC333".into()),
                nickname: Some("MiddleRelay".into()),
                or_addresses: vec!["9.10.11.12:9001".into()],
                flags: vec!["Running".into(), "Stable".into()],
                observed_bandwidth: Some(50_000),
            },
        ]
    }

    #[test]
    fn constructs_consensus_from_mock_data() {
        let relays: Vec<RelayEntry> = mock_relays()
            .iter()
            .filter_map(|r| onionoo_to_relay_entry(r).ok())
            .collect();

        assert_eq!(relays.len(), 3);
        assert_eq!(relays[0].fingerprint, "AAA111");
        assert_eq!(relays[1].nickname, "ExitRelay");
        assert_eq!(relays[2].address, "9.10.11.12".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn counts_flags_correctly() {
        let relays: Vec<RelayEntry> = mock_relays()
            .iter()
            .filter_map(|r| onionoo_to_relay_entry(r).ok())
            .collect();

        let exit_count = relays
            .iter()
            .filter(|r| r.flags.contains(&RelayFlag::Exit))
            .count();
        let guard_count = relays
            .iter()
            .filter(|r| r.flags.contains(&RelayFlag::Guard))
            .count();

        assert_eq!(exit_count, 1);
        assert_eq!(guard_count, 1);
    }
}
