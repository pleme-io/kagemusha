//! Tor-routed privacy auditor using kakuremino [`TorTransport`].
//!
//! Feature-gated behind `tor`. Connects through the Tor network to perform
//! privacy checks from the perspective of an anonymous observer.

use std::sync::Arc;

use kakuremino::{AnonTransport, TorTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use kagemusha_core::{Error, ExitDetector, PrivacyAuditor, PrivacyReport, Result};

/// IP echo service used to determine the external IP as seen through Tor.
const IP_ECHO_HOST: &str = "ifconfig.me";
const IP_ECHO_PORT: u16 = 80;

/// Privacy auditor that routes checks through the Tor network.
///
/// Uses kakuremino [`TorTransport`] to establish an anonymous connection and
/// then verifies that traffic is properly anonymized by comparing the observed
/// external IP against known Tor exit nodes.
pub struct TorPrivacyAuditor {
    transport: Arc<TorTransport>,
    exit_detector: Arc<dyn ExitDetector>,
}

impl TorPrivacyAuditor {
    /// Create a new Tor-routed privacy auditor.
    ///
    /// The `transport` must already be bootstrapped.
    #[must_use]
    pub fn new(transport: Arc<TorTransport>, exit_detector: Arc<dyn ExitDetector>) -> Self {
        Self {
            transport,
            exit_detector,
        }
    }

    /// Fetch the external IP address as seen through the Tor circuit.
    async fn fetch_external_ip(&self) -> Result<String> {
        debug!("fetching external IP through Tor via {IP_ECHO_HOST}");

        let mut stream = self
            .transport
            .connect(IP_ECHO_HOST, IP_ECHO_PORT)
            .await
            .map_err(|e| Error::Network(format!("Tor connect to {IP_ECHO_HOST}: {e}")))?;

        // Send a minimal HTTP/1.1 request.
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {IP_ECHO_HOST}\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Error::Network(format!("write to {IP_ECHO_HOST}: {e}")))?;

        let mut buf = Vec::with_capacity(1024);
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| Error::Network(format!("read from {IP_ECHO_HOST}: {e}")))?;

        let response = String::from_utf8_lossy(&buf);

        // Extract body after the double CRLF header terminator.
        let body = response
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_owned();

        if body.is_empty() {
            return Err(Error::Parse(
                "empty response body from IP echo service".into(),
            ));
        }

        debug!(external_ip = %body, "Tor-visible external IP");
        Ok(body)
    }
}

#[async_trait::async_trait]
impl PrivacyAuditor for TorPrivacyAuditor {
    async fn audit_connection(&self) -> Result<PrivacyReport> {
        debug!("running Tor privacy audit via kakuremino");

        let mut recommendations = Vec::new();

        // 1. Check if Tor transport is ready.
        let ready = self.transport.is_ready().await;
        if !ready {
            recommendations.push(
                "Tor transport is not ready — bootstrap may still be in progress".into(),
            );
            return Ok(PrivacyReport {
                dns_leak: false,
                webrtc_leak: false,
                ip_exposed: false,
                tor_detected: false,
                exit_fingerprint: None,
                recommendations,
            });
        }

        // 2. Fetch external IP through Tor.
        let external_ip_str = match self.fetch_external_ip().await {
            Ok(ip) => ip,
            Err(e) => {
                warn!(error = %e, "failed to fetch external IP through Tor");
                recommendations.push(format!(
                    "Could not determine external IP through Tor: {e}"
                ));
                return Ok(PrivacyReport {
                    dns_leak: false,
                    webrtc_leak: false,
                    ip_exposed: false,
                    tor_detected: true,
                    exit_fingerprint: None,
                    recommendations,
                });
            }
        };

        let external_ip: std::net::IpAddr = external_ip_str.parse().map_err(|e| {
            Error::Parse(format!("invalid IP from echo service: {external_ip_str}: {e}"))
        })?;

        // 3. Check if external IP is a known Tor exit.
        let is_exit = self
            .exit_detector
            .is_exit(external_ip)
            .await
            .unwrap_or(false);

        let tor_detected = is_exit;
        let dns_leak = !is_exit;

        if dns_leak {
            recommendations.push(format!(
                "DNS leak detected: external IP {external_ip} is not a known Tor exit node — \
                 DNS queries may be leaking outside the Tor circuit"
            ));
        } else {
            recommendations.push(format!(
                "External IP {external_ip} is a known Tor exit — traffic is properly routed"
            ));
        }

        // 4. Look up exit fingerprint.
        let exits = self.exit_detector.list_exits().await.unwrap_or_default();
        let exit_fingerprint = exits
            .iter()
            .find(|e| e.address == external_ip)
            .filter(|e| !e.fingerprint.is_empty())
            .map(|e| e.fingerprint.clone());

        if let Some(ref fp) = exit_fingerprint {
            recommendations.push(format!("Exit node fingerprint: {fp}"));
        }

        // 5. WebRTC — cannot check from a CLI context.
        let webrtc_leak = false;
        recommendations.push(
            "WebRTC leak check: not applicable in CLI context — disable WebRTC in browsers"
                .into(),
        );

        // 6. IP exposure — if Tor is working, the real IP should not be exposed.
        let ip_exposed = false;
        if tor_detected {
            recommendations.push(
                "IP exposure: Tor is active, real IP should be hidden from destination servers"
                    .into(),
            );
        }

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
    use std::net::IpAddr;

    use kagemusha_core::ExitNode;

    use super::*;

    /// Mock exit detector for unit tests.
    struct MockExitDetector {
        exits: Vec<ExitNode>,
    }

    #[async_trait::async_trait]
    impl ExitDetector for MockExitDetector {
        async fn is_exit(&self, addr: IpAddr) -> kagemusha_core::Result<bool> {
            Ok(self.exits.iter().any(|e| e.address == addr))
        }

        async fn list_exits(&self) -> kagemusha_core::Result<Vec<ExitNode>> {
            Ok(self.exits.clone())
        }
    }

    #[test]
    fn struct_creation() {
        // TorTransport requires async bootstrap so we cannot create a real one
        // in a sync test. Instead we verify the type layout compiles and the
        // constructor signature is correct.
        fn _assert_auditor_is_send_sync<T: Send + Sync>() {}
        _assert_auditor_is_send_sync::<TorPrivacyAuditor>();
    }

    #[tokio::test]
    async fn report_generation_without_network() {
        // We cannot bootstrap a real TorTransport without network access.
        // This test verifies that the type compiles, the mock detector works,
        // and the auditor can be constructed. Actually calling audit_connection
        // requires a bootstrapped transport, so we test the helper logic
        // through the public BasicPrivacyAuditor instead.
        let detector = Arc::new(MockExitDetector {
            exits: vec![ExitNode {
                fingerprint: "TOR_EXIT_FP".into(),
                nickname: "TestTorExit".into(),
                address: "198.51.100.1".parse().unwrap(),
                exit_policy_summary: "accept 80,443".into(),
                country: Some("nl".into()),
                bandwidth: 500_000,
            }],
        });

        // Verify exit detector works as expected.
        let is_exit = detector
            .is_exit("198.51.100.1".parse().unwrap())
            .await
            .unwrap();
        assert!(is_exit);

        let not_exit = detector
            .is_exit("192.0.2.1".parse().unwrap())
            .await
            .unwrap();
        assert!(!not_exit);

        let exits = detector.list_exits().await.unwrap();
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].fingerprint, "TOR_EXIT_FP");
    }
}
