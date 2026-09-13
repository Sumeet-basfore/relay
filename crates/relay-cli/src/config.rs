use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Root Relay configuration model
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayConfig {
    pub security: SecurityConfig,
    pub policy: PolicyConfig,
    pub storage: StorageConfig,
    pub proxy: ProxyConfig,
}

/// Security-critical configuration parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enforce strict default deny behavior
    pub default_deny: bool,
    /// Approval timeout in seconds
    pub approval_timeout_secs: u32,
    /// Maximum allowed JSON-RPC frame size (default 4MB)
    pub max_frame_size_bytes: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_deny: true,
            approval_timeout_secs: 30,
            max_frame_size_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Policy location configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Directory containing Cedar policy files (*.cedar)
    pub policy_dir: PathBuf,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policy_dir: PathBuf::from("policies"),
        }
    }
}

/// Persistence and storage configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageConfig {
    /// SQLite ledger database file path
    pub ledger_path: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            ledger_path: PathBuf::from(".relay/ledger.db"),
        }
    }
}

/// Loopback proxy configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Bind address for loopback HTTP egress proxy
    pub bind_host: String,
    /// Ephemeral port (0 = OS allocated)
    pub port: u16,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_host: "127.0.0.1".to_string(),
            port: 0,
        }
    }
}

impl RelayConfig {
    /// Load configuration from specified path or default locations
    pub fn load(path: Option<&Path>) -> Result<Self, crate::cli_error::CliError> {
        if let Some(p) = path {
            if p.exists() {
                let content = std::fs::read_to_string(p)
                    .map_err(|e| crate::cli_error::CliError::ConfigError(e.to_string()))?;
                let config: Self = toml::from_str(&content)
                    .map_err(|e| crate::cli_error::CliError::ConfigError(e.to_string()))?;
                return Ok(config);
            }
        }
        Ok(Self::default())
    }
}
