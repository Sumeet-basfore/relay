//! Canonical PostgreSQL resource URI parsing and target binding.
//!
//! Canonical format (B003): `postgres://{host}/{database}/{table_list}`

use super::error::PostgresError;

/// Parsed canonical PostgreSQL resource identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresResource {
    pub host: String,
    pub database: String,
    pub tables: Vec<String>,
}

impl PostgresResource {
    /// Parses a canonical `postgres://` resource URI.
    pub fn parse(resource_uri: &str) -> Result<Self, PostgresError> {
        let trimmed = resource_uri.trim();
        let scheme_sep = "postgres://";
        if !trimmed.starts_with(scheme_sep) {
            return Err(PostgresError::ResourceMismatch {
                action_target: resource_uri.to_string(),
                op_target: "Expected postgres:// scheme".to_string(),
            });
        }

        let remainder = trimmed
            .strip_prefix(scheme_sep)
            .unwrap_or_default()
            .trim_matches('/');
        if remainder.is_empty() {
            return Err(PostgresError::InvalidArguments {
                operation: "postgres".to_string(),
                reason: "PostgreSQL resource URI missing host/database/table segments".to_string(),
            });
        }

        let parts: Vec<&str> = remainder.split('/').collect();
        if parts.len() < 2 {
            return Err(PostgresError::InvalidArguments {
                operation: "postgres".to_string(),
                reason: format!("Invalid postgres resource URI: {resource_uri}"),
            });
        }

        let host = parts[0].to_string();
        let database = parts[1].to_string();
        let tables = if parts.len() >= 3 && !parts[2].is_empty() {
            parts[2]
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty() && t != "all")
                .collect()
        } else {
            Vec::new()
        };

        if host.is_empty() || database.is_empty() {
            return Err(PostgresError::InvalidArguments {
                operation: "postgres".to_string(),
                reason: "PostgreSQL host and database must be non-empty".to_string(),
            });
        }

        Ok(Self {
            host,
            database,
            tables,
        })
    }

    /// Returns true when the resource authorizes any table in the database.
    pub fn allows_any_table(&self) -> bool {
        self.tables.is_empty()
    }
}

use std::fmt;
use zeroize::Zeroize;

/// Credential payload formats supported by the connector.
#[derive(Clone, PartialEq, Eq)]
pub struct PostgresCredentials {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for PostgresCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PostgresCredentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl PostgresCredentials {
    /// Parses credential material from a `SecretBuffer`.
    ///
    /// Supported formats:
    /// - JSON: `{"username":"relay","password":"secret"}`
    /// - Delimited: `username:password`
    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self, PostgresError> {
        let raw = std::str::from_utf8(secret).map_err(|_| {
            PostgresError::CredentialError(
                "PostgreSQL credential secret must be valid UTF-8".to_string(),
            )
        })?;

        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(raw) {
            let username = json_val
                .get("username")
                .or_else(|| json_val.get("user"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    PostgresError::CredentialError(
                        "PostgreSQL credential JSON missing 'username' field".to_string(),
                    )
                })?;
            let password = json_val
                .get("password")
                .or_else(|| json_val.get("pass"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    PostgresError::CredentialError(
                        "PostgreSQL credential JSON missing 'password' field".to_string(),
                    )
                })?;
            return Ok(Self {
                username: username.to_string(),
                password: password.to_string(),
            });
        }

        if let Some((username, password)) = raw.split_once(':') {
            if !username.is_empty() {
                return Ok(Self {
                    username: username.to_string(),
                    password: password.to_string(),
                });
            }
        }

        Err(PostgresError::CredentialError(
            "Unsupported PostgreSQL credential format; expected JSON or username:password"
                .to_string(),
        ))
    }
}
