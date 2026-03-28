use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;

use kagemusha_core::{ConsensusProvider, ExitDetector, PrivacyAuditor};
use kagemusha_analyzer::{
    BasicPrivacyAuditor, OnionooClient, OnionooConsensusProvider, TorExitDetector,
};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// Kagemusha — Tor network privacy analyzer.
#[derive(Parser)]
#[command(name = "kagemusha", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List or search Tor relays via Onionoo.
    Relays {
        /// Optional search query (nickname, fingerprint prefix, country code).
        query: Option<String>,
    },

    /// List known Tor exit nodes.
    Exits,

    /// Analyze circuit diversity (stub).
    Circuits,

    /// Run a privacy audit on the current connection.
    Audit,

    /// Show aggregate Tor network statistics.
    Status,
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

/// Execute the CLI with the given arguments.
///
/// Extracted for testability — `main` delegates here after initializing tracing.
async fn execute(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Relays { query } => cmd_relays(query).await?,
        Command::Exits => cmd_exits().await?,
        Command::Circuits => cmd_circuits().await?,
        Command::Audit => cmd_audit().await?,
        Command::Status => cmd_status().await?,
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    execute(cli).await
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

async fn cmd_relays(query: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let client = OnionooClient::new();

    let relays = if let Some(q) = query {
        info!(query = %q, "searching relays");
        client.relay_search(&q).await?
    } else {
        info!("fetching all relays (this may take a moment)");
        let provider = OnionooConsensusProvider::new();
        let consensus = provider.fetch().await?;
        // Convert relay entries to relay info via search.
        // For a full listing we just show the consensus count.
        println!("Total relays in consensus: {}", consensus.relays.len());
        return Ok(());
    };

    for relay in &relays {
        println!(
            "{:<20} {:<44} {:<16} {:>10} B/s  {}",
            relay.nickname,
            relay.fingerprint,
            relay.address,
            relay.bandwidth,
            relay.country.as_deref().unwrap_or("??"),
        );
    }
    println!("\n{} relay(s) found.", relays.len());

    Ok(())
}

async fn cmd_exits() -> Result<(), Box<dyn std::error::Error>> {
    let detector = TorExitDetector::new();
    let exits = detector.list_exits().await?;

    for exit in &exits {
        println!("{}", exit.address);
    }
    println!("\n{} exit node(s).", exits.len());

    Ok(())
}

async fn cmd_circuits() -> Result<(), Box<dyn std::error::Error>> {
    println!("Circuit diversity analysis is not yet implemented.");
    println!("This will analyze Tor circuit path selection for diversity issues.");
    Ok(())
}

async fn cmd_audit() -> Result<(), Box<dyn std::error::Error>> {
    let detector = Arc::new(TorExitDetector::new());
    let auditor = BasicPrivacyAuditor::new(detector);
    let report = auditor.audit_connection().await?;

    println!("Privacy Audit Report");
    println!("====================");
    println!("DNS leak:           {}", if report.dns_leak { "DETECTED" } else { "not detected" });
    println!("WebRTC leak:        {}", if report.webrtc_leak { "DETECTED" } else { "not detected" });
    println!("IP exposed:         {}", if report.ip_exposed { "DETECTED" } else { "not detected" });
    println!("Tor detected:       {}", if report.tor_detected { "yes" } else { "no" });
    if let Some(ref fp) = report.exit_fingerprint {
        println!("Exit fingerprint:   {fp}");
    }
    println!("\nRecommendations:");
    for rec in &report.recommendations {
        println!("  - {rec}");
    }

    Ok(())
}

async fn cmd_status() -> Result<(), Box<dyn std::error::Error>> {
    let client = OnionooClient::new();
    let stats = client.network_stats().await?;

    println!("Tor Network Status");
    println!("==================");
    println!("Total relays:       {}", stats.total_relays);
    println!("Exit relays:        {}", stats.exit_relays);
    println!("Guard relays:       {}", stats.guard_relays);
    println!("Total bandwidth:    {} B/s", stats.total_bandwidth);

    if !stats.country_distribution.is_empty() {
        println!("\nTop countries:");
        let mut countries: Vec<_> = stats.country_distribution.into_iter().collect();
        countries.sort_by(|a, b| b.1.cmp(&a.1));
        for (country, count) in countries.iter().take(10) {
            println!("  {country:<4} {count}");
        }
    }

    Ok(())
}
