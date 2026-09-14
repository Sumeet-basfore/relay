//! Trusted PostgreSQL connection configuration.
//!
//! Enforces:
//! - Connection targets come from Relay configuration plus canonical resource identity
//! - No tool-argument override of host, port, TLS verification, or database name
//! - Loopback-only plaintext for hermetic integration tests

use std::time::Duration;

use super::error::PostgresError;

/// Default PostgreSQL port.
pub const DEFAULT_POSTGRES_PORT: u16 = 5432;
/// Maximum serialized query result size (2 MB).
pub const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;
/// Maximum rows returned for SELECT queries.
pub const MAX_RESULT_ROWS: usize = 10_000;
/// Maximum number of columns per result row.
pub const MAX_RESULT_COLUMNS: usize = 256;

/// Configuration for governed PostgreSQL client connections.
#[derive(Debug, Clone)]
pub struct PostgresClientConfig {
    pub connect_timeout: Duration,
    pub query_timeout: Duration,
    pub max_result_bytes: usize,
    pub max_result_rows: usize,
    pub max_result_columns: usize,
    pub allow_no_tls_loopback: bool,
    pub default_port: u16,
    pub fixed_search_path: String,
}

impl Default for PostgresClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            query_timeout: Duration::from_secs(30),
            max_result_bytes: MAX_RESULT_BYTES,
            max_result_rows: MAX_RESULT_ROWS,
            max_result_columns: MAX_RESULT_COLUMNS,
            allow_no_tls_loopback: false,
            default_port: DEFAULT_POSTGRES_PORT,
            fixed_search_path: "public".to_string(),
        }
    }
}

impl PostgresClientConfig {
    /// Test configuration permitting plaintext loopback connections.
    pub fn loopback_test() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            query_timeout: Duration::from_secs(10),
            max_result_bytes: MAX_RESULT_BYTES,
            max_result_rows: MAX_RESULT_ROWS,
            max_result_columns: MAX_RESULT_COLUMNS,
            allow_no_tls_loopback: true,
            default_port: DEFAULT_POSTGRES_PORT,
            fixed_search_path: "public".to_string(),
        }
    }

    /// Validates that a resolved host is permitted for connection.
    pub fn validate_host(&self, host: &str) -> Result<(), PostgresError> {
        if host.is_empty() {
            return Err(PostgresError::InvalidEndpoint(
                "PostgreSQL host cannot be empty".to_string(),
            ));
        }

        if host.contains('@')
            || host.contains('/')
            || host.contains('?')
            || host.contains('#')
            || host.contains(':')
            || host.contains(';')
            || host.contains(' ')
            || host.contains('\n')
            || host.contains('\r')
        {
            return Err(PostgresError::InvalidEndpoint(format!(
                "Host '{host}' contains forbidden connection-string metacharacters (SI-007)"
            )));
        }

        // Host must be a valid DNS hostname, IPv4, or IPv6 (without brackets)
        if !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(PostgresError::InvalidEndpoint(format!(
                "Host '{host}' contains invalid hostname characters"
            )));
        }

        Ok(())
    }

    /// Determines whether plaintext (NoTls) is permitted for the resolved host.
    pub fn allows_plaintext(&self, host: &str) -> bool {
        self.allow_no_tls_loopback && (host == "127.0.0.1" || host == "localhost")
    }
}
