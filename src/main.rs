use fips::Config;

fn main() {
    println!("FIPS Node Startup");
    println!("=================\n");

    // Load configuration from standard search paths
    println!("1. Loading configuration...");
    println!("   Search paths (in priority order, lowest to highest):");
    for path in Config::search_paths() {
        let exists = path.exists();
        let status = if exists { "[found]" } else { "[not found]" };
        println!("   {} {}", status, path.display());
    }
    println!();

    let (config, loaded_paths) = match Config::load() {
        Ok(result) => result,
        Err(e) => {
            eprintln!("   Error loading config: {}", e);
            std::process::exit(1);
        }
    };

    if loaded_paths.is_empty() {
        println!("   No config files found, using defaults.");
    } else {
        println!("   Loaded {} config file(s):", loaded_paths.len());
        for path in &loaded_paths {
            println!("   - {}", path.display());
        }
    }

    // Create identity from configuration
    println!("\n2. Initializing identity...");
    let identity = match config.create_identity() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("   Error creating identity: {}", e);
            std::process::exit(1);
        }
    };

    if config.has_identity() {
        println!("   Using configured identity.");
    } else {
        println!("   No identity configured, generated new keypair.");
    }

    println!();
    if let Some(nsec) = &config.identity.nsec {
        println!("   nsec:         {}", nsec);
    } else {
        println!("   nsec:         (generated)");
    }
    println!("   npub:         {}", identity.npub());
    println!("   node_id:      {}", identity.node_id());
    println!("   IPv6 address: {}", identity.address());

    println!("\nReady.");
}
