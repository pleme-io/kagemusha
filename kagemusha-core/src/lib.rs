//! Core types and traits for the kagemusha Tor network privacy analyzer.
//!
//! Provides the foundational abstractions for Tor network analysis:
//! consensus data, exit detection, relay monitoring, and privacy auditing.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced by kagemusha operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("network request failed: {0}")]
    Network(String),

    #[error("failed to parse response: {0}")]
    Parse(String),

    #[error("consensus unavailable: {0}")]
    ConsensusUnavailable(String),

    #[error("relay not found: {0}")]
    RelayNotFound(String),

    #[error("audit failed: {0}")]
    AuditFailed(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Whether this error is potentially retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Network(_) | Self::ConsensusUnavailable(_)
        )
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Provides Tor network consensus data.
#[async_trait::async_trait]
pub trait ConsensusProvider: Send + Sync {
    /// Fetch the current network consensus.
    async fn fetch(&self) -> Result<NetworkConsensus>;

    /// Return a cached consensus if available and still valid.
    async fn fetch_cached(&self) -> Option<NetworkConsensus>;
}

/// Detects whether an IP address belongs to a Tor exit node.
#[async_trait::async_trait]
pub trait ExitDetector: Send + Sync {
    /// Check if the given address is a known Tor exit.
    async fn is_exit(&self, addr: IpAddr) -> Result<bool>;

    /// List all known exit nodes.
    async fn list_exits(&self) -> Result<Vec<ExitNode>>;
}

/// Monitors individual relays and aggregate network statistics.
#[async_trait::async_trait]
pub trait RelayMonitor: Send + Sync {
    /// Fetch detailed information about a relay by fingerprint.
    async fn relay_info(&self, fingerprint: &str) -> Result<RelayInfo>;

    /// Fetch aggregate network statistics.
    async fn network_stats(&self) -> Result<NetworkStats>;
}

/// Runs privacy audits against the local connection.
#[async_trait::async_trait]
pub trait PrivacyAuditor: Send + Sync {
    /// Audit the current connection for privacy leaks.
    async fn audit_connection(&self) -> Result<PrivacyReport>;
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A snapshot of the Tor network consensus.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkConsensus {
    pub valid_after: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub relays: Vec<RelayEntry>,
}

/// A single relay in the consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEntry {
    pub fingerprint: String,
    pub nickname: String,
    pub address: IpAddr,
    pub or_port: u16,
    pub dir_port: u16,
    pub flags: Vec<RelayFlag>,
    pub bandwidth: u64,
}

/// Flags assigned to a relay by the directory authorities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelayFlag {
    Authority,
    BadExit,
    Exit,
    Fast,
    Guard,
    HSDir,
    Running,
    Stable,
    StaleDesc,
    V2Dir,
    Valid,
}

impl fmt::Display for RelayFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority => write!(f, "Authority"),
            Self::BadExit => write!(f, "BadExit"),
            Self::Exit => write!(f, "Exit"),
            Self::Fast => write!(f, "Fast"),
            Self::Guard => write!(f, "Guard"),
            Self::HSDir => write!(f, "HSDir"),
            Self::Running => write!(f, "Running"),
            Self::Stable => write!(f, "Stable"),
            Self::StaleDesc => write!(f, "StaleDesc"),
            Self::V2Dir => write!(f, "V2Dir"),
            Self::Valid => write!(f, "Valid"),
        }
    }
}

/// Detailed relay information in the Onionoo API style.
///
/// Extends the basic [`RelayEntry`] with geographic, routing probability,
/// and AS metadata fields from the Onionoo `/details` endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayDetail {
    /// Relay fingerprint (hex-encoded identity key hash).
    pub fingerprint: String,
    /// Human-readable relay nickname.
    pub nickname: String,
    /// OR addresses in `"IP:port"` or `"[IPv6]:port"` format.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub or_addresses: Vec<String>,
    /// Consensus flags assigned by directory authorities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<RelayFlag>,
    /// Consensus weight (bandwidth-based).
    pub consensus_weight: u64,
    /// ISO 3166-1 alpha-2 country code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Autonomous system number (e.g. `"AS13335"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_number: Option<String>,
    /// Relay platform/version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Guard probability (0.0-1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_probability: Option<f64>,
    /// Middle probability (0.0-1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_probability: Option<f64>,
    /// Exit probability (0.0-1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_probability: Option<f64>,
}

/// Bandwidth history in the Onionoo normalized-values format.
///
/// Values are normalized to 0-999 with a scale `factor` to recover
/// actual bytes. Intervals with no data are represented as `None`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BandwidthHistory {
    /// ISO 8601 timestamp of the first interval.
    pub first: String,
    /// ISO 8601 timestamp of the last interval.
    pub last: String,
    /// Duration of each interval in seconds.
    pub interval_secs: u64,
    /// Scale factor to recover actual bytes from normalized values.
    pub factor: f64,
    /// Normalized 0-999 values; `None` means no data for that interval.
    pub values: Vec<Option<u16>>,
}

/// The scope of a network analysis operation.
///
/// Inspired by nyx display modes, determines what level of the Tor
/// network the analysis operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisScope {
    /// Whole-network aggregate analysis.
    #[default]
    Network,
    /// Single relay analysis.
    Relay,
    /// Exit policy analysis.
    ExitPolicy,
    /// Relay family analysis.
    Family,
    /// Country-level analysis.
    Country,
    /// AS-level analysis.
    AutonomousSystem,
}

impl fmt::Display for AnalysisScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network => write!(f, "Network"),
            Self::Relay => write!(f, "Relay"),
            Self::ExitPolicy => write!(f, "ExitPolicy"),
            Self::Family => write!(f, "Family"),
            Self::Country => write!(f, "Country"),
            Self::AutonomousSystem => write!(f, "AutonomousSystem"),
        }
    }
}

/// A Tor exit node with policy information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitNode {
    pub fingerprint: String,
    pub nickname: String,
    pub address: IpAddr,
    pub exit_policy_summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    pub bandwidth: u64,
}

/// Detailed information about a single relay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayInfo {
    pub fingerprint: String,
    pub nickname: String,
    pub address: IpAddr,
    pub or_port: u16,
    pub dir_port: u16,
    pub flags: Vec<RelayFlag>,
    pub bandwidth: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub uptime_days: u32,
}

/// Aggregate network statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_relays: u32,
    pub exit_relays: u32,
    pub guard_relays: u32,
    pub total_bandwidth: u64,
    pub country_distribution: HashMap<String, u32>,
}

/// The result of a privacy audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyReport {
    pub dns_leak: bool,
    pub webrtc_leak: bool,
    pub ip_exposed: bool,
    pub tor_detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_fingerprint: Option<String>,
    pub recommendations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_flag_display() {
        assert_eq!(RelayFlag::Authority.to_string(), "Authority");
        assert_eq!(RelayFlag::Exit.to_string(), "Exit");
        assert_eq!(RelayFlag::Guard.to_string(), "Guard");
        assert_eq!(RelayFlag::Running.to_string(), "Running");
        assert_eq!(RelayFlag::Stable.to_string(), "Stable");
        assert_eq!(RelayFlag::HSDir.to_string(), "HSDir");
        assert_eq!(RelayFlag::V2Dir.to_string(), "V2Dir");
        assert_eq!(RelayFlag::Valid.to_string(), "Valid");
        assert_eq!(RelayFlag::BadExit.to_string(), "BadExit");
        assert_eq!(RelayFlag::StaleDesc.to_string(), "StaleDesc");
        assert_eq!(RelayFlag::Fast.to_string(), "Fast");
    }

    #[test]
    fn error_is_retryable() {
        assert!(Error::Network("timeout".into()).is_retryable());
        assert!(Error::ConsensusUnavailable("stale".into()).is_retryable());
        assert!(!Error::Parse("bad json".into()).is_retryable());
        assert!(!Error::RelayNotFound("ABCD".into()).is_retryable());
        assert!(!Error::AuditFailed("dns leak".into()).is_retryable());
        assert!(!Error::Other("misc".into()).is_retryable());
    }

    #[test]
    fn error_partial_eq() {
        assert_eq!(Error::Network("a".into()), Error::Network("a".into()));
        assert_ne!(Error::Network("a".into()), Error::Parse("a".into()));
    }

    #[test]
    fn relay_entry_serde_roundtrip() {
        let entry = RelayEntry {
            fingerprint: "AAAA1234".into(),
            nickname: "TestRelay".into(),
            address: "1.2.3.4".parse().unwrap(),
            or_port: 9001,
            dir_port: 0,
            flags: vec![RelayFlag::Exit, RelayFlag::Running],
            bandwidth: 50000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: RelayEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn exit_node_serde_roundtrip() {
        let node = ExitNode {
            fingerprint: "EXIT001".into(),
            nickname: "FastExit".into(),
            address: "5.6.7.8".parse().unwrap(),
            exit_policy_summary: "accept 80,443".into(),
            country: Some("de".into()),
            bandwidth: 500_000,
        };
        let json = serde_json::to_string(&node).unwrap();
        let back: ExitNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
    }

    #[test]
    fn exit_node_skip_none_country() {
        let node = ExitNode {
            fingerprint: "FP".into(),
            nickname: "N".into(),
            address: "1.2.3.4".parse().unwrap(),
            exit_policy_summary: String::new(),
            country: None,
            bandwidth: 0,
        };
        let json = serde_json::to_string(&node).unwrap();
        assert!(!json.contains("country"));
    }

    #[test]
    fn privacy_report_serde_roundtrip() {
        let report = PrivacyReport {
            dns_leak: false,
            webrtc_leak: false,
            ip_exposed: false,
            tor_detected: true,
            exit_fingerprint: Some("DEADBEEF".into()),
            recommendations: vec!["all good".into()],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: PrivacyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn network_stats_serde_roundtrip() {
        let stats = NetworkStats {
            total_relays: 7000,
            exit_relays: 1500,
            guard_relays: 2500,
            total_bandwidth: 1_000_000_000,
            country_distribution: HashMap::from([
                ("us".into(), 1000),
                ("de".into(), 800),
            ]),
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: NetworkStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, back);
    }

    // -----------------------------------------------------------------------
    // RelayDetail tests
    // -----------------------------------------------------------------------

    #[test]
    fn relay_detail_serde_roundtrip() {
        let detail = RelayDetail {
            fingerprint: "ABCDEF1234567890".into(),
            nickname: "FastRelay".into(),
            or_addresses: vec!["1.2.3.4:9001".into(), "[::1]:443".into()],
            flags: vec![RelayFlag::Guard, RelayFlag::Running, RelayFlag::Valid],
            consensus_weight: 150_000,
            country: Some("de".into()),
            as_number: Some("AS13335".into()),
            platform: Some("Tor 0.4.8.12".into()),
            guard_probability: Some(0.02),
            middle_probability: Some(0.01),
            exit_probability: None,
        };
        let json = serde_json::to_string(&detail).unwrap();
        let back: RelayDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(detail, back);
    }

    #[test]
    fn relay_detail_skip_empty_fields() {
        let detail = RelayDetail {
            fingerprint: "FP".into(),
            nickname: "N".into(),
            or_addresses: vec![],
            flags: vec![],
            consensus_weight: 0,
            country: None,
            as_number: None,
            platform: None,
            guard_probability: None,
            middle_probability: None,
            exit_probability: None,
        };
        let json = serde_json::to_string(&detail).unwrap();
        assert!(!json.contains("or_addresses"));
        assert!(!json.contains("flags"));
        assert!(!json.contains("country"));
        assert!(!json.contains("as_number"));
        assert!(!json.contains("platform"));
        assert!(!json.contains("guard_probability"));
    }

    #[test]
    fn relay_detail_with_probabilities() {
        let detail = RelayDetail {
            fingerprint: "FP".into(),
            nickname: "ExitRelay".into(),
            or_addresses: vec!["5.6.7.8:443".into()],
            flags: vec![RelayFlag::Exit],
            consensus_weight: 500_000,
            country: Some("us".into()),
            as_number: None,
            platform: None,
            guard_probability: Some(0.0),
            middle_probability: Some(0.0),
            exit_probability: Some(0.05),
        };
        assert!(detail.exit_probability.unwrap() > 0.0);
        assert_eq!(detail.guard_probability.unwrap(), 0.0);
    }

    // -----------------------------------------------------------------------
    // BandwidthHistory tests
    // -----------------------------------------------------------------------

    #[test]
    fn bandwidth_history_serde_roundtrip() {
        let history = BandwidthHistory {
            first: "2025-01-01T00:00:00Z".into(),
            last: "2025-01-02T00:00:00Z".into(),
            interval_secs: 900,
            factor: 1024.5,
            values: vec![Some(500), Some(750), None, Some(999), Some(0)],
        };
        let json = serde_json::to_string(&history).unwrap();
        let back: BandwidthHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(history, back);
    }

    #[test]
    fn bandwidth_history_empty_values() {
        let history = BandwidthHistory {
            first: "2025-01-01T00:00:00Z".into(),
            last: "2025-01-01T00:00:00Z".into(),
            interval_secs: 3600,
            factor: 1.0,
            values: vec![],
        };
        let json = serde_json::to_string(&history).unwrap();
        let back: BandwidthHistory = serde_json::from_str(&json).unwrap();
        assert!(back.values.is_empty());
    }

    #[test]
    fn bandwidth_history_all_none_values() {
        let history = BandwidthHistory {
            first: "2025-01-01T00:00:00Z".into(),
            last: "2025-01-01T06:00:00Z".into(),
            interval_secs: 3600,
            factor: 512.0,
            values: vec![None, None, None],
        };
        assert_eq!(history.values.len(), 3);
        assert!(history.values.iter().all(Option::is_none));
    }

    // -----------------------------------------------------------------------
    // AnalysisScope tests
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_scope_default_is_network() {
        assert_eq!(AnalysisScope::default(), AnalysisScope::Network);
    }

    #[test]
    fn analysis_scope_display() {
        assert_eq!(AnalysisScope::Network.to_string(), "Network");
        assert_eq!(AnalysisScope::Relay.to_string(), "Relay");
        assert_eq!(AnalysisScope::ExitPolicy.to_string(), "ExitPolicy");
        assert_eq!(AnalysisScope::Family.to_string(), "Family");
        assert_eq!(AnalysisScope::Country.to_string(), "Country");
        assert_eq!(AnalysisScope::AutonomousSystem.to_string(), "AutonomousSystem");
    }

    #[test]
    fn analysis_scope_serde_roundtrip() {
        let scopes = [
            AnalysisScope::Network,
            AnalysisScope::Relay,
            AnalysisScope::ExitPolicy,
            AnalysisScope::Family,
            AnalysisScope::Country,
            AnalysisScope::AutonomousSystem,
        ];
        for scope in scopes {
            let json = serde_json::to_string(&scope).unwrap();
            let back: AnalysisScope = serde_json::from_str(&json).unwrap();
            assert_eq!(scope, back);
        }
    }

    #[test]
    fn analysis_scope_equality() {
        assert_eq!(AnalysisScope::Network, AnalysisScope::Network);
        assert_ne!(AnalysisScope::Network, AnalysisScope::Relay);
    }
}
