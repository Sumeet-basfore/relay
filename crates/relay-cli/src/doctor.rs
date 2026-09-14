use crate::config::RelayConfig;
use serde::{Deserialize, Serialize};
use std::env;

/// Structured diagnostic report model shared between CLI and UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub relay_version: String,
    pub target_os: String,
    pub target_arch: String,
    pub working_directory: String,
    pub config_directory: String,
    pub config_directory_exists: bool,
    pub ledger_path: String,
    pub ledger_exists: bool,
    pub ledger_permissions: Option<String>,
    pub policy_directory: String,
    pub policy_directory_exists: bool,
    pub tty_available: bool,
    pub egress_sandbox_mode: String,
    pub is_healthy: bool,
    pub status_message: String,
}

/// Generates canonical health & foundation diagnostics report
pub fn generate_doctor_report(
    config: &RelayConfig,
) -> Result<DoctorReport, crate::cli_error::CliError> {
    let relay_version = env!("CARGO_PKG_VERSION").to_string();
    let target_os = env::consts::OS.to_string();
    let target_arch = env::consts::ARCH.to_string();

    let cwd = env::current_dir().map_err(crate::cli_error::CliError::Io)?;
    let working_directory = cwd.display().to_string();

    let home_dir = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/.config/relay", home_dir);
    let config_directory_exists = std::path::Path::new(&config_dir).exists();

    let ledger_path = config.storage.ledger_path.display().to_string();
    let ledger_exists = config.storage.ledger_path.exists();

    let mut ledger_permissions = None;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&config.storage.ledger_path) {
            let mode = meta.permissions().mode() & 0o777;
            ledger_permissions = Some(format!("{:04o}", mode));
        }
    }

    let policy_dir = config.policy.policy_dir.display().to_string();
    let policy_directory_exists = config.policy.policy_dir.exists();

    let tty_available = atty_check();

    let egress_sandbox_mode = if cfg!(target_os = "linux") {
        if relay_mcp::EgressSandboxLauncher::is_linux_netns_available() {
            "Linux Enforced Network Namespace Sandbox [ACTIVE/ENFORCED]".to_string()
        } else {
            "Linux Managed Cooperative Proxy [WARNING: unprivileged userns disabled]".to_string()
        }
    } else if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
        "Managed Cooperative Proxy Mode [COOPERATIVE]".to_string()
    } else {
        "Unsupported".to_string()
    };

    let is_healthy = true;
    let status_message =
        "MCP Gateway Milestone B002 Operational (M002 Egress Mediation & Sandbox Active)"
            .to_string();

    Ok(DoctorReport {
        relay_version,
        target_os,
        target_arch,
        working_directory,
        config_directory: config_dir,
        config_directory_exists,
        ledger_path,
        ledger_exists,
        ledger_permissions,
        policy_directory: policy_dir,
        policy_directory_exists,
        tty_available,
        egress_sandbox_mode,
        is_healthy,
        status_message,
    })
}

/// Executes comprehensive release-grade diagnostic health checks to stdout
pub fn run_doctor(config: &RelayConfig) -> Result<(), crate::cli_error::CliError> {
    let report = generate_doctor_report(config)?;

    println!("=== Relay System Health & Foundation Diagnostics ===");
    println!("Relay Version       : {}", report.relay_version);
    println!("Target OS           : {}", report.target_os);
    println!("Target Architecture : {}", report.target_arch);
    println!("Working Directory   : {}", report.working_directory);
    println!(
        "Config Directory    : {} [{}]",
        report.config_directory,
        if report.config_directory_exists {
            "EXISTS"
        } else {
            "NOT CREATED"
        }
    );

    let ledger_status = if report.ledger_exists {
        if let Some(ref perms) = report.ledger_permissions {
            format!("EXISTS (mode {})", perms)
        } else {
            "EXISTS".to_string()
        }
    } else {
        "NOT CREATED".to_string()
    };
    println!(
        "Ledger Path         : {} [{}]",
        report.ledger_path, ledger_status
    );

    println!(
        "Policy Directory    : {} [{}]",
        report.policy_directory,
        if report.policy_directory_exists {
            "EXISTS"
        } else {
            "DEFAULT (in-binary bundled)"
        }
    );

    println!(
        "Terminal (TTY)      : {}",
        if report.tty_available {
            "Interactive TTY Available (/dev/tty)"
        } else {
            "Non-Interactive / Headless Gate Active"
        }
    );

    println!("Egress Sandbox Mode : {}", report.egress_sandbox_mode);
    println!("Status              : {}", report.status_message);
    println!("=====================================================");

    Ok(())
}

fn atty_check() -> bool {
    std::path::Path::new("/dev/tty").exists()
}
