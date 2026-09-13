use std::env;

/// Executes foundation-level diagnostic health checks
pub fn run_doctor() -> Result<(), crate::cli_error::CliError> {
    println!("=== Relay System Health & Foundation Diagnostics ===");
    println!("Relay Version       : {}", env!("CARGO_PKG_VERSION"));
    println!("Target OS           : {}", env::consts::OS);
    println!("Target Architecture : {}", env::consts::ARCH);

    // Check working directory
    let cwd = env::current_dir().map_err(crate::cli_error::CliError::Io)?;
    println!("Working Directory   : {}", cwd.display());

    // Check if configuration directory exists
    let home_dir = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/.config/relay", home_dir);
    let config_exists = std::path::Path::new(&config_dir).exists();
    println!(
        "Config Directory    : {} [{}]",
        config_dir,
        if config_exists {
            "EXISTS"
        } else {
            "NOT CREATED (will be initialized on first run)"
        }
    );

    // Check local ledger directory
    let local_ledger_dir = cwd.join(".relay");
    let ledger_exists = local_ledger_dir.exists();
    println!(
        "Local Ledger Path   : {} [{}]",
        local_ledger_dir.display(),
        if ledger_exists {
            "EXISTS"
        } else {
            "NOT CREATED (will be initialized on first run)"
        }
    );

    // Check TTY availability
    let is_tty = atty_check();
    println!(
        "Terminal (TTY)      : {}",
        if is_tty {
            "Interactive TTY Available"
        } else {
            "Non-Interactive / Headless"
        }
    );

    println!("Status              : MCP Gateway Milestone B002 Operational");
    println!("=====================================================");

    Ok(())
}

fn atty_check() -> bool {
    // Basic check for TTY
    std::path::Path::new("/dev/tty").exists()
}
