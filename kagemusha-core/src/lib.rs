use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced by kagemusha operations.
#[derive(Debug, thiserror::Error)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConsensus {
    pub valid_after: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub relays: Vec<RelayEntry>,
}

/// A single relay in the consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// A Tor exit node with policy information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitNode {
    pub fingerprint: String,
    pub nickname: String,
    pub address: IpAddr,
    pub exit_policy_summary: String,
    pub country: Option<String>,
    pub bandwidth: u64,
}

/// Detailed information about a single relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub fingerprint: String,
    pub nickname: String,
    pub address: IpAddr,
    pub or_port: u16,
    pub dir_port: u16,
    pub flags: Vec<RelayFlag>,
    pub bandwidth: u64,
    pub country: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub uptime_days: u32,
}

/// Aggregate network statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_relays: u32,
    pub exit_relays: u32,
    pub guard_relays: u32,
    pub total_bandwidth: u64,
    pub country_distribution: HashMap<String, u32>,
}

/// The result of a privacy audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyReport {
    pub dns_leak: bool,
    pub webrtc_leak: bool,
    pub ip_exposed: bool,
    pub tor_detected: bool,
    pub exit_fingerprint: Option<String>,
    pub recommendations: Vec<String>,
}
