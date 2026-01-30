//! FIPS daemon binary
//!
//! Loads configuration and creates the top-level node instance.

use fips::{Config, Node, TunState};
use tracing::{error, info, warn, Level};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Initialize logging
    let filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    info!("FIPS starting");

    // Load configuration
    info!("Loading configuration");
    let (config, loaded_paths) = match Config::load() {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    if loaded_paths.is_empty() {
        info!("No config files found, using defaults");
    } else {
        for path in &loaded_paths {
            info!(path = %path.display(), "Loaded config file");
        }
    }

    // Log identity status
    if config.has_identity() {
        info!("Using configured identity");
    } else {
        warn!("No identity configured, generating ephemeral keypair");
    }

    // Create node
    info!("Creating node");
    let mut node = match Node::new(config) {
        Ok(node) => node,
        Err(e) => {
            error!("Failed to create node: {}", e);
            std::process::exit(1);
        }
    };

    // Log node information
    info!(
        state = %node.state(),
        leaf_only = node.is_leaf_only(),
        "Node created"
    );
    info!("  npub: {}", node.npub());
    info!("  node_id: {}", hex::encode(node.node_id().as_bytes()));
    info!("  address: {}", node.identity().address());

    // Start the node (initializes TUN, spawns I/O threads)
    info!(
        tun_state = %node.tun_state(),
        "Starting node"
    );

    if let Err(e) = node.start().await {
        error!("Failed to start node: {}", e);
        std::process::exit(1);
    }

    // Show TUN interface details if active
    if node.tun_state() == TunState::Active {
        if let Some(tun_name) = node.config().tun.name.as_deref() {
            let output = std::process::Command::new("ip")
                .args(["link", "show", tun_name])
                .output();
            match output {
                Ok(out) => {
                    if out.status.success() {
                        info!(
                            "ip link show {}:\n{}",
                            tun_name,
                            String::from_utf8_lossy(&out.stdout)
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to run ip link: {}", e);
                }
            }
        }
    }

    info!("FIPS running, press Ctrl+C to exit");

    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("Shutdown signal received"),
        Err(e) => error!("Failed to listen for shutdown signal: {}", e),
    }

    info!("FIPS shutting down");

    // Stop the node (shuts down TUN, stops I/O threads)
    if let Err(e) = node.stop().await {
        warn!("Error during shutdown: {}", e);
    }

    info!("FIPS shutdown complete");
}
