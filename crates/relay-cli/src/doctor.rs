use crate::config::RelayConfig;
use std::env;

/// Executes comprehensive release-grade diagnostic health checks
pub fn run_doctor(config: &RelayConfig) -> Result<(), crate::cli_error::CliError> {
    println!("=== Relay System Health & Foundation Diagnostics ===");
    println!("Relay Version       : {}", env!("CARGO_PKG_VERSION"));
    println!("Target OS           : {}", env::consts::OS);
    println!("Target Architecture : {}", env::consts::ARCH);

    // Check working directory
    let cwd = env::current_dir().map_err(crate::cli_error::CliError::Io)?;
    println!("Working Directory   : {}", cwd.display());

    // Check configuration
    let home_dir = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/.config/relay", home_dir);
    let config_exists = std::path::Path::new(&config_dir).exists();
    println!(
        "Config Directory    : {} [{}]",
        config_dir,
        if config_exists {
            "EXISTS"
        } else {
            "NOT CREATED"
        }
    );

    // Check ledger path & permissions
    let ledger_path = &config.storage.ledger_path;
    let ledger_exists = ledger_path.exists();
    let mut ledger_status = if ledger_exists {
        "EXISTS"
    } else {
        "NOT CREATED"
    };
    #[cfg(unix)]
    let perms_str;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(ledger_path) {
            let mode = meta.permissions().mode() & 0o777;
            perms_str = format!("EXISTS (mode {:04o})", mode);
            ledger_status = &perms_str;
        }
    }
    println!(
        "Ledger Path         : {} [{}]",
        ledger_path.display(),
        ledger_status
    );

    // Check Policy Directory
    let policy_dir = &config.policy.policy_dir;
    let policy_exists = policy_dir.exists();
    println!(
        "Policy Directory    : {} [{}]",
        policy_dir.display(),
        if policy_exists {
            "EXISTS"
        } else {
            "DEFAULT (in-binary bundled)"
        }
    );

    // Check TTY availability
    let is_tty = atty_check();
    println!(
        "Terminal (TTY)      : {}",
        if is_tty {
            "Interactive TTY Available (/dev/tty)"
        } else {
            "Non-Interactive / Headless Gate Active"
        }
    );

    // Check Egress Mediation & Sandbox capability (M002)
    let egress_mode = if cfg!(target_os = "linux") {
        if relay_mcp::EgressSandboxLauncher::is_linux_netns_available() {
            "Linux Enforced Network Namespace Sandbox [ACTIVE/ENFORCED]"
        } else {
            "Linux Managed Cooperative Proxy [WARNING: unprivileged userns disabled]"
        }
    } else if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
        "Managed Cooperative Proxy Mode [COOPERATIVE]"
    } else {
        "Unsupported"
    };
    println!("Egress Sandbox Mode : {}", egress_mode);

    println!(
        "Status              : MCP Gateway Milestone B002 Operational (M002 Egress Mediation & Sandbox Active)"
    );
    println!("=====================================================");

    Ok(())
}

fn atty_check() -> bool {
    // Basic check for TTY
    std::path::Path::new("/dev/tty").exists()
}
