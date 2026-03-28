use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use tracing::debug;

use kagemusha_core::{
    Error, ExitNode, NetworkStats, RelayFlag, RelayInfo, Result,
};

// ---------------------------------------------------------------------------
// Onionoo JSON shapes
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
    country: Option<String>,
    first_seen: Option<String>,
    last_seen: Option<String>,
    #[serde(default)]
    exit_policy_summary: Option<OnionooExitPolicy>,
    #[serde(default)]
    dir_address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OnionooExitPolicy {
    #[serde(default)]
    accept: Option<Vec<String>>,
    #[serde(default)]
    reject: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct OninooBandwidthResponse {
    #[serde(default)]
    relays: Vec<OninooBandwidthRelay>,
}

#[derive(Debug, Deserialize)]
struct OninooBandwidthRelay {
    fingerprint: Option<String>,
    #[serde(default)]
    write_history: Option<serde_json::Value>,
    #[serde(default)]
    read_history: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client for the Onionoo Tor metrics API.
pub struct OnionooClient {
    base_url: String,
    http: reqwest::Client,
}

impl OnionooClient {
    /// Create a new client with the default Onionoo base URL.
    #[must_use]
    pub fn new() -> Self {
        Self::with_base_url("https://onionoo.torproject.org")
    }

    /// Create a new client with a custom base URL.
    #[must_use]
    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http: reqwest::Client::new(),
        }
    }

    /// Fetch relay details by fingerprint.
    pub async fn relay_details(&self, fingerprint: &str) -> Result<RelayInfo> {
        let url = format!(
            "{}/details?lookup={}",
            self.base_url, fingerprint
        );
        debug!(%url, "fetching relay details");

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

        let relay = body
            .relays
            .into_iter()
            .next()
            .ok_or_else(|| Error::RelayNotFound(fingerprint.to_owned()))?;

        onionoo_relay_to_info(&relay)
    }

    /// Search for relays matching a query string (nickname, fingerprint prefix, etc.).
    pub async fn relay_search(&self, query: &str) -> Result<Vec<RelayInfo>> {
        let url = format!(
            "{}/details?search={}",
            self.base_url, query
        );
        debug!(%url, "searching relays");

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

        body.relays
            .iter()
            .map(onionoo_relay_to_info)
            .collect()
    }

    /// Fetch bandwidth history for a relay.
    pub async fn bandwidth(&self, fingerprint: &str) -> Result<serde_json::Value> {
        let url = format!(
            "{}/bandwidth?lookup={}",
            self.base_url, fingerprint
        );
        debug!(%url, "fetching bandwidth");

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        let body: OninooBandwidthResponse = resp
            .json()
            .await
            .map_err(|e| Error::Parse(e.to_string()))?;

        let relay = body
            .relays
            .into_iter()
            .next()
            .ok_or_else(|| Error::RelayNotFound(fingerprint.to_owned()))?;

        Ok(serde_json::json!({
            "fingerprint": relay.fingerprint,
            "write_history": relay.write_history,
            "read_history": relay.read_history,
        }))
    }

    /// Fetch summary network statistics from Onionoo.
    pub async fn network_stats(&self) -> Result<NetworkStats> {
        let url = format!("{}/details?type=relay&fields=fingerprint,flags,observed_bandwidth,country", self.base_url);
        debug!(%url, "fetching network stats");

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

        let mut total_bandwidth: u64 = 0;
        let mut exit_relays: u32 = 0;
        let mut guard_relays: u32 = 0;
        let mut country_distribution = std::collections::HashMap::new();

        for relay in &body.relays {
            total_bandwidth += relay.observed_bandwidth.unwrap_or(0);

            if relay.flags.iter().any(|f| f == "Exit") {
                exit_relays += 1;
            }
            if relay.flags.iter().any(|f| f == "Guard") {
                guard_relays += 1;
            }

            if let Some(ref country) = relay.country {
                *country_distribution
                    .entry(country.clone())
                    .or_insert(0) += 1;
            }
        }

        let total_relays = u32::try_from(body.relays.len()).unwrap_or(u32::MAX);

        Ok(NetworkStats {
            total_relays,
            exit_relays,
            guard_relays,
            total_bandwidth,
            country_distribution,
        })
    }

    /// Fetch all exit nodes from Onionoo.
    pub async fn exit_nodes(&self) -> Result<Vec<ExitNode>> {
        let url = format!(
            "{}/details?type=relay&flag=Exit&fields=fingerprint,nickname,or_addresses,exit_policy_summary,country,observed_bandwidth",
            self.base_url
        );
        debug!(%url, "fetching exit nodes");

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

        body.relays
            .iter()
            .filter_map(|r| onionoo_relay_to_exit(r).ok())
            .collect::<Vec<_>>()
            .pipe_ok()
    }

    /// Return the base URL in use.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Default for OnionooClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extension trait to wrap a value in `Ok`.
trait PipeOk: Sized {
    fn pipe_ok(self) -> Result<Self> {
        Ok(self)
    }
}

impl<T> PipeOk for T {}

fn parse_or_address(addr: &str) -> Option<(IpAddr, u16)> {
    // Onionoo formats: "1.2.3.4:9001" or "[::1]:9001"
    if let Some(bracket_end) = addr.rfind(']') {
        // IPv6: "[addr]:port"
        let ip_str = addr.get(1..bracket_end)?;
        let port_str = addr.get(bracket_end + 2..)?;
        let ip: IpAddr = ip_str.parse().ok()?;
        let port: u16 = port_str.parse().ok()?;
        Some((ip, port))
    } else {
        // IPv4: "addr:port"
        let (ip_str, port_str) = addr.rsplit_once(':')?;
        let ip: IpAddr = ip_str.parse().ok()?;
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

fn onionoo_relay_to_info(relay: &OnionooRelay) -> Result<RelayInfo> {
    let fingerprint = relay
        .fingerprint
        .clone()
        .unwrap_or_default();

    let (address, or_port) = relay
        .or_addresses
        .first()
        .and_then(|a| parse_or_address(a))
        .ok_or_else(|| Error::Parse(format!("no valid address for relay {fingerprint}")))?;

    let dir_port = relay
        .dir_address
        .as_deref()
        .and_then(|a| parse_or_address(a))
        .map_or(0, |(_, p)| p);

    let flags: Vec<RelayFlag> = relay.flags.iter().filter_map(|f| parse_flag(f)).collect();
    let bandwidth = relay.observed_bandwidth.unwrap_or(0);

    let first_seen = relay
        .first_seen
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok().or_else(|| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|ndt| ndt.and_utc().fixed_offset())
        }))
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_default();

    let last_seen = relay
        .last_seen
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok().or_else(|| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|ndt| ndt.and_utc().fixed_offset())
        }))
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_default();

    let uptime_days = last_seen
        .signed_duration_since(first_seen)
        .num_days()
        .try_into()
        .unwrap_or(0);

    Ok(RelayInfo {
        fingerprint,
        nickname: relay.nickname.clone().unwrap_or_default(),
        address,
        or_port,
        dir_port,
        flags,
        bandwidth,
        country: relay.country.clone(),
        first_seen,
        last_seen,
        uptime_days,
    })
}

fn onionoo_relay_to_exit(relay: &OnionooRelay) -> Result<ExitNode> {
    let fingerprint = relay
        .fingerprint
        .clone()
        .unwrap_or_default();

    let (address, _) = relay
        .or_addresses
        .first()
        .and_then(|a| parse_or_address(a))
        .ok_or_else(|| Error::Parse(format!("no valid address for relay {fingerprint}")))?;

    let policy = relay
        .exit_policy_summary
        .as_ref()
        .map(|p| {
            if let Some(ref accept) = p.accept {
                format!("accept {}", accept.join(", "))
            } else if let Some(ref reject) = p.reject {
                format!("reject {}", reject.join(", "))
            } else {
                String::new()
            }
        })
        .unwrap_or_default();

    Ok(ExitNode {
        fingerprint,
        nickname: relay.nickname.clone().unwrap_or_default(),
        address,
        exit_policy_summary: policy,
        country: relay.country.clone(),
        bandwidth: relay.observed_bandwidth.unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_base_url() {
        let client = OnionooClient::new();
        assert_eq!(client.base_url(), "https://onionoo.torproject.org");
    }

    #[test]
    fn custom_base_url_strips_trailing_slash() {
        let client = OnionooClient::with_base_url("https://example.com/");
        assert_eq!(client.base_url(), "https://example.com");
    }

    #[test]
    fn parses_mock_relay_response() {
        let json = r#"{
            "relays": [{
                "fingerprint": "AAAA1234",
                "nickname": "TestRelay",
                "or_addresses": ["1.2.3.4:9001"],
                "flags": ["Exit", "Running", "Valid"],
                "observed_bandwidth": 50000,
                "country": "us",
                "first_seen": "2020-01-01 00:00:00",
                "last_seen": "2025-06-01 00:00:00"
            }]
        }"#;

        let body: OnionooRelayResponse = serde_json::from_str(json).unwrap();
        assert_eq!(body.relays.len(), 1);

        let info = onionoo_relay_to_info(&body.relays[0]).unwrap();
        assert_eq!(info.fingerprint, "AAAA1234");
        assert_eq!(info.nickname, "TestRelay");
        assert_eq!(info.address, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(info.or_port, 9001);
        assert_eq!(info.bandwidth, 50000);
        assert!(info.flags.contains(&RelayFlag::Exit));
        assert!(info.flags.contains(&RelayFlag::Running));
    }

    #[test]
    fn parses_ipv6_or_address() {
        let result = parse_or_address("[2001:db8::1]:443");
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_flag_known_and_unknown() {
        assert_eq!(parse_flag("Exit"), Some(RelayFlag::Exit));
        assert_eq!(parse_flag("Guard"), Some(RelayFlag::Guard));
        assert_eq!(parse_flag("Unknown"), None);
    }
}
