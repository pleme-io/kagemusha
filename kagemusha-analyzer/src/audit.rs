use std::sync::Arc;

use tracing::debug;

use kagemusha_core::{ExitDetector, PrivacyAuditor, PrivacyReport, Result};

/// A basic privacy auditor that checks for common leaks.
///
/// Currently a stub implementation that produces a report with
/// sensible defaults. Future versions will perform real DNS leak
/// tests, `WebRTC` detection, and IP exposure checks.
pub struct BasicPrivacyAuditor {
    exit_detector: Arc<dyn ExitDetector>,
}

impl BasicPrivacyAuditor {
    /// Create a new auditor with the given exit detector.
    #[must_use]
    pub fn new(exit_detector: Arc<dyn ExitDetector>) -> Self {
        Self { exit_detector }
    }
}

#[async_trait::async_trait]
impl PrivacyAuditor for BasicPrivacyAuditor {
    async fn audit_connection(&self) -> Result<PrivacyReport> {
        debug!("running privacy audit (stub)");

        // Stub: produce a conservative report.
        let mut recommendations = Vec::new();

        // DNS leak check (stub — always reports unknown).
        let dns_leak = false;
        recommendations.push("DNS leak test: not yet implemented — use a dedicated tool to verify".into());

        // WebRTC leak check (stub).
        let webrtc_leak = false;
        recommendations.push("WebRTC leak test: not yet implemented — disable WebRTC in browser".into());

        // IP exposure check (stub).
        let ip_exposed = false;
        recommendations.push("IP exposure check: not yet implemented — verify via external service".into());

        // Tor detection (stub — check if any exits are loaded).
        let exits = self.exit_detector.list_exits().await.unwrap_or_default();
        let tor_detected = !exits.is_empty();

        if !tor_detected {
            recommendations.push("No Tor exit nodes detected — you may not be connected to Tor".into());
        }

        Ok(PrivacyReport {
            dns_leak,
            webrtc_leak,
            ip_exposed,
            tor_detected,
            exit_fingerprint: None,
            recommendations,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use kagemusha_core::ExitNode;

    use super::*;

    struct MockExitDetector {
        exits: Vec<ExitNode>,
    }

    #[async_trait::async_trait]
    impl ExitDetector for MockExitDetector {
        async fn is_exit(&self, addr: IpAddr) -> Result<bool> {
            Ok(self.exits.iter().any(|e| e.address == addr))
        }

        async fn list_exits(&self) -> Result<Vec<ExitNode>> {
            Ok(self.exits.clone())
        }
    }

    #[tokio::test]
    async fn generates_report() {
        let detector = Arc::new(MockExitDetector { exits: vec![] });
        let auditor = BasicPrivacyAuditor::new(detector);
        let report = auditor.audit_connection().await.unwrap();

        assert!(!report.dns_leak);
        assert!(!report.webrtc_leak);
        assert!(!report.ip_exposed);
        assert!(!report.tor_detected);
        assert!(report.exit_fingerprint.is_none());
    }

    #[tokio::test]
    async fn all_checks_have_results() {
        let detector = Arc::new(MockExitDetector {
            exits: vec![ExitNode {
                fingerprint: "ABCD1234".into(),
                nickname: "TestExit".into(),
                address: "1.2.3.4".parse().unwrap(),
                exit_policy_summary: String::new(),
                country: None,
                bandwidth: 0,
            }],
        });

        let auditor = BasicPrivacyAuditor::new(detector);
        let report = auditor.audit_connection().await.unwrap();

        // With exits loaded, tor_detected should be true.
        assert!(report.tor_detected);
        // Recommendations should be populated.
        assert!(!report.recommendations.is_empty());
    }

    #[tokio::test]
    async fn recommendations_always_present() {
        let detector = Arc::new(MockExitDetector { exits: vec![] });
        let auditor = BasicPrivacyAuditor::new(detector);
        let report = auditor.audit_connection().await.unwrap();

        // Should always have at least the stub recommendations.
        assert!(report.recommendations.len() >= 3);
    }
}
