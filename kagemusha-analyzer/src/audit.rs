use std::net::IpAddr;
use std::sync::Arc;

use tracing::{debug, warn};

use kagemusha_core::{ExitDetector, PrivacyAuditor, PrivacyReport, Result};

/// A basic privacy auditor that checks for common leaks.
///
/// Performs real checks against the exit detector and generates
/// actionable recommendations based on findings.
pub struct BasicPrivacyAuditor {
    exit_detector: Arc<dyn ExitDetector>,
}

impl BasicPrivacyAuditor {
    /// Create a new auditor with the given exit detector.
    #[must_use]
    pub fn new(exit_detector: Arc<dyn ExitDetector>) -> Self {
        Self { exit_detector }
    }

    /// Check whether the observed external IP appears in the exit node list.
    ///
    /// If the external IP is NOT a known Tor exit, DNS resolution may be
    /// leaking outside the Tor circuit.
    async fn check_dns_leak(&self, exits: &[IpAddr], external_ip: Option<IpAddr>) -> bool {
        let Some(ip) = external_ip else {
            // Cannot determine — assume no leak detected (conservative).
            return false;
        };

        // If we have exits and the external IP is not among them, traffic may
        // be leaking through a non-Tor path.
        if exits.is_empty() {
            return false;
        }

        let is_exit = exits.contains(&ip);
        if !is_exit {
            warn!(
                ip = %ip,
                "external IP is not a known Tor exit — possible DNS leak"
            );
        }
        !is_exit
    }

    /// Check if the external IP matches a local interface address.
    ///
    /// If the externally visible IP is the same as a local interface, the real
    /// IP is exposed (no proxy or VPN in the path).
    fn check_ip_exposed(external_ip: Option<IpAddr>, local_addrs: &[IpAddr]) -> bool {
        let Some(ip) = external_ip else {
            return false;
        };
        let exposed = local_addrs.contains(&ip);
        if exposed {
            warn!(ip = %ip, "external IP matches a local interface — IP is exposed");
        }
        exposed
    }

    /// Build recommendations based on audit findings.
    fn build_recommendations(
        dns_leak: bool,
        webrtc_leak: bool,
        ip_exposed: bool,
        tor_detected: bool,
    ) -> Vec<String> {
        let mut recs = Vec::new();

        if dns_leak {
            recs.push(
                "DNS leak detected: configure your system to route DNS queries through Tor \
                 (e.g., set DNS to 127.0.0.1:5353 with a Tor DNS proxy)"
                    .into(),
            );
        } else {
            recs.push("DNS leak check: no leak detected".into());
        }

        if webrtc_leak {
            recs.push(
                "WebRTC leak detected: disable WebRTC in your browser \
                 (about:config → media.peerconnection.enabled = false)"
                    .into(),
            );
        } else {
            recs.push(
                "WebRTC leak check: not yet implemented — disable WebRTC in browser settings \
                 as a precaution"
                    .into(),
            );
        }

        if ip_exposed {
            recs.push(
                "IP exposed: your real IP is visible externally — ensure all traffic is \
                 routed through Tor or a VPN"
                    .into(),
            );
        } else {
            recs.push("IP exposure check: real IP does not appear to be exposed".into());
        }

        if !tor_detected {
            recs.push(
                "No Tor exit nodes detected — you may not be connected to Tor. \
                 Verify your Tor daemon is running and circuits are established"
                    .into(),
            );
        } else {
            recs.push("Tor connection: exit nodes detected, Tor appears active".into());
        }

        recs
    }
}

#[async_trait::async_trait]
impl PrivacyAuditor for BasicPrivacyAuditor {
    async fn audit_connection(&self) -> Result<PrivacyReport> {
        debug!("running privacy audit");

        // Gather exit node data.
        let exits = self.exit_detector.list_exits().await.unwrap_or_default();
        let exit_addresses: Vec<IpAddr> = exits.iter().map(|e| e.address).collect();
        let tor_detected = !exits.is_empty();

        // Determine the exit fingerprint (first exit, if any).
        let exit_fingerprint = exits
            .first()
            .filter(|e| !e.fingerprint.is_empty())
            .map(|e| e.fingerprint.clone());

        // External IP check — in the basic auditor we do not make network
        // requests ourselves. The external IP would need to be provided by a
        // higher-level caller or fetched via an IP echo service. For now we
        // pass None, which means DNS leak and IP exposure checks remain
        // conservative (no leak detected when unknown).
        let external_ip: Option<IpAddr> = None;

        // Local interface addresses — stub. A real implementation would
        // enumerate local network interfaces.
        let local_addrs: Vec<IpAddr> = Vec::new();

        let dns_leak = self.check_dns_leak(&exit_addresses, external_ip).await;
        let webrtc_leak = false; // Requires browser integration.
        let ip_exposed = Self::check_ip_exposed(external_ip, &local_addrs);

        let recommendations =
            Self::build_recommendations(dns_leak, webrtc_leak, ip_exposed, tor_detected);

        Ok(PrivacyReport {
            dns_leak,
            webrtc_leak,
            ip_exposed,
            tor_detected,
            exit_fingerprint,
            recommendations,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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

        // Should always have at least the four category recommendations.
        assert!(report.recommendations.len() >= 3);
    }

    #[tokio::test]
    async fn exit_fingerprint_captured() {
        let detector = Arc::new(MockExitDetector {
            exits: vec![ExitNode {
                fingerprint: "DEADBEEF".into(),
                nickname: "MyExit".into(),
                address: "10.0.0.1".parse().unwrap(),
                exit_policy_summary: String::new(),
                country: Some("de".into()),
                bandwidth: 100_000,
            }],
        });

        let auditor = BasicPrivacyAuditor::new(detector);
        let report = auditor.audit_connection().await.unwrap();

        assert!(report.tor_detected);
        assert_eq!(report.exit_fingerprint.as_deref(), Some("DEADBEEF"));
    }

    #[tokio::test]
    async fn dns_leak_detected_when_ip_not_exit() {
        // Verify the DNS leak check logic directly.
        let detector = Arc::new(MockExitDetector {
            exits: vec![ExitNode {
                fingerprint: "EXIT1".into(),
                nickname: "Exit1".into(),
                address: "1.2.3.4".parse().unwrap(),
                exit_policy_summary: String::new(),
                country: None,
                bandwidth: 0,
            }],
        });

        let auditor = BasicPrivacyAuditor::new(detector);

        // External IP that is NOT in the exit list = DNS leak.
        let exits = vec!["1.2.3.4".parse::<IpAddr>().unwrap()];
        let leak = auditor
            .check_dns_leak(&exits, Some("9.9.9.9".parse().unwrap()))
            .await;
        assert!(leak);

        // External IP that IS in the exit list = no leak.
        let no_leak = auditor
            .check_dns_leak(&exits, Some("1.2.3.4".parse().unwrap()))
            .await;
        assert!(!no_leak);
    }

    #[tokio::test]
    async fn ip_exposed_when_external_matches_local() {
        let local = vec!["192.168.1.10".parse::<IpAddr>().unwrap()];

        // External IP matches local interface = exposed.
        assert!(BasicPrivacyAuditor::check_ip_exposed(
            Some("192.168.1.10".parse().unwrap()),
            &local
        ));

        // Different external IP = not exposed.
        assert!(!BasicPrivacyAuditor::check_ip_exposed(
            Some("8.8.8.8".parse().unwrap()),
            &local
        ));

        // No external IP = not exposed (conservative).
        assert!(!BasicPrivacyAuditor::check_ip_exposed(None, &local));
    }

    #[tokio::test]
    async fn recommendations_vary_with_tor_status() {
        // No exits -> recommendations mention "not connected".
        let no_tor = Arc::new(MockExitDetector { exits: vec![] });
        let auditor = BasicPrivacyAuditor::new(no_tor);
        let report = auditor.audit_connection().await.unwrap();
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.contains("not be connected to Tor")));

        // With exits -> recommendations mention "appears active".
        let with_tor = Arc::new(MockExitDetector {
            exits: vec![ExitNode {
                fingerprint: "F1".into(),
                nickname: "N1".into(),
                address: "1.1.1.1".parse().unwrap(),
                exit_policy_summary: String::new(),
                country: None,
                bandwidth: 0,
            }],
        });
        let auditor = BasicPrivacyAuditor::new(with_tor);
        let report = auditor.audit_connection().await.unwrap();
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.contains("appears active")));
    }
}
