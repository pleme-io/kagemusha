use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::debug;

use kagemusha_core::{Error, ExitDetector, ExitNode, Result};

/// Default TTL for the exit list cache (1 hour).
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);

/// URL for the Tor bulk exit list.
const TOR_EXIT_LIST_URL: &str = "https://check.torproject.org/torbulkexitlist";

struct CachedExitList {
    addresses: Vec<IpAddr>,
    fetched_at: Instant,
}

/// Detects Tor exit nodes using the official bulk exit list.
pub struct TorExitDetector {
    http: reqwest::Client,
    exit_list_url: String,
    cache_ttl: Duration,
    cache: Arc<RwLock<Option<CachedExitList>>>,
}

impl TorExitDetector {
    /// Create a new detector with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            exit_list_url: TOR_EXIT_LIST_URL.to_owned(),
            cache_ttl: DEFAULT_CACHE_TTL,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a detector with a custom exit list URL and TTL.
    #[must_use]
    pub fn with_config(exit_list_url: &str, cache_ttl: Duration) -> Self {
        Self {
            http: reqwest::Client::new(),
            exit_list_url: exit_list_url.to_owned(),
            cache_ttl,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    async fn fetch_exit_list(&self) -> Result<Vec<IpAddr>> {
        debug!(url = %self.exit_list_url, "fetching Tor exit list");

        let resp = self
            .http
            .get(&self.exit_list_url)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;

        let body = resp
            .text()
            .await
            .map_err(|e| Error::Parse(e.to_string()))?;

        Ok(parse_exit_list(&body))
    }

    async fn get_or_refresh(&self) -> Result<Vec<IpAddr>> {
        // Check cache first.
        {
            let cache = self.cache.read().await;
            if let Some(ref cached) = *cache {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    debug!("using cached exit list");
                    return Ok(cached.addresses.clone());
                }
            }
        }

        // Refresh.
        let addresses = self.fetch_exit_list().await?;

        {
            let mut cache = self.cache.write().await;
            *cache = Some(CachedExitList {
                addresses: addresses.clone(),
                fetched_at: Instant::now(),
            });
        }

        Ok(addresses)
    }
}

impl Default for TorExitDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ExitDetector for TorExitDetector {
    async fn is_exit(&self, addr: IpAddr) -> Result<bool> {
        let exits = self.get_or_refresh().await?;
        Ok(exits.contains(&addr))
    }

    async fn list_exits(&self) -> Result<Vec<ExitNode>> {
        let exits = self.get_or_refresh().await?;
        Ok(exits
            .into_iter()
            .map(|addr| ExitNode {
                fingerprint: String::new(),
                nickname: String::new(),
                address: addr,
                exit_policy_summary: String::new(),
                country: None,
                bandwidth: 0,
            })
            .collect())
    }
}

/// Parse the Tor bulk exit list text format.
///
/// Each line is an IP address; lines starting with '#' or empty lines are skipped.
fn parse_exit_list(body: &str) -> Vec<IpAddr> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.parse::<IpAddr>().ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exit_list_format() {
        let body = "# comment\n1.2.3.4\n5.6.7.8\n\n# another comment\n9.10.11.12\n";
        let addrs = parse_exit_list(body);
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(addrs[1], "5.6.7.8".parse::<IpAddr>().unwrap());
        assert_eq!(addrs[2], "9.10.11.12".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn handles_empty_list() {
        let addrs = parse_exit_list("");
        assert!(addrs.is_empty());

        let addrs = parse_exit_list("# only comments\n# here\n");
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn caches_results() {
        let detector = TorExitDetector::with_config(
            "https://example.com/nonexistent",
            Duration::from_secs(3600),
        );

        // Pre-populate the cache.
        {
            let mut cache = detector.cache.write().await;
            *cache = Some(CachedExitList {
                addresses: vec!["1.2.3.4".parse().unwrap()],
                fetched_at: Instant::now(),
            });
        }

        // Should use cache without hitting the network.
        let result = detector.is_exit("1.2.3.4".parse().unwrap()).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = detector.is_exit("9.9.9.9".parse().unwrap()).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn skips_invalid_lines() {
        let body = "1.2.3.4\nnot_an_ip\n5.6.7.8\n";
        let addrs = parse_exit_list(body);
        assert_eq!(addrs.len(), 2);
    }
}
