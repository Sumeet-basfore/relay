//! Error taxonomy for Relay Native PostgreSQL Connector.
//!
//! Enforces:
//! - Distinction between Relay policy DENY and PostgreSQL permission denied
//! - Ambiguous mutation outcome tracking for timeouts on mutating statements
//! - Strong security redaction: secrets NEVER leak into error messages

use relay_domain::ExecutionError;
use thiserror::Error;

/// Specific error types for PostgreSQL operations and protocol execution.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PostgresError {
    #[error("Authentication failed: invalid PostgreSQL credentials")]
    AuthenticationFailed,

    #[error("PostgreSQL authorization failed: {0}")]
    AuthorizationFailed(String),

    #[error("PostgreSQL query error: {0}")]
    QueryError(String),

    #[error("PostgreSQL constraint violation: {0}")]
    ConstraintViolation(String),

    #[error("PostgreSQL serialization or deadlock: {0}")]
    SerializationConflict(String),

    #[error("Connection failure: {0}")]
    ConnectionFailure(String),

    #[error("TLS certificate or handshake failure: {0}")]
    TlsFailure(String),

    #[error("Query timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("Ambiguous mutation outcome: mutating statement timed out; remote state uncertain (operation: {operation})")]
    AmbiguousMutationOutcome { operation: String, reason: String },

    #[error("Result too large: {size} bytes exceeds limit of {limit} bytes")]
    ResultTooLarge { size: usize, limit: usize },

    #[error("Too many result rows: {rows} exceeds limit of {limit}")]
    ResultRowLimitExceeded { rows: usize, limit: usize },

    #[error("Invalid endpoint or host: {0}")]
    InvalidEndpoint(String),

    #[error("ActionHash mismatch: expected '{expected}', actual '{actual}'")]
    ActionHashMismatch { expected: String, actual: String },

    #[error("Resource mismatch: action target '{action_target}', operation target '{op_target}'")]
    ResourceMismatch {
        action_target: String,
        op_target: String,
    },

    #[error("Resource scope violation: {0}")]
    ResourceScopeViolation(String),

    #[error("Principal mismatch: lease principal '{lease_principal}', action principal '{action_principal}'")]
    PrincipalMismatch {
        lease_principal: String,
        action_principal: String,
    },

    #[error("Credential lease invalid or expired: {0}")]
    InvalidLease(String),

    #[error("Connector execution attempted without prior authorization")]
    UnauthorizedExecution,

    #[error("Unsupported SQL statement: {0}")]
    UnsupportedStatement(String),

    #[error("Search path ambiguity rejected: {0}")]
    SearchPathAmbiguity(String),

    #[error("Invalid arguments for operation '{operation}': {reason}")]
    InvalidArguments { operation: String, reason: String },

    #[error("Credential broker error: {0}")]
    CredentialError(String),

    #[error("Operation class mismatch: tool '{tool}' does not match SQL class '{sql_class}'")]
    OperationClassMismatch { tool: String, sql_class: String },
}

impl From<PostgresError> for ExecutionError {
    fn from(err: PostgresError) -> Self {
        match err {
            PostgresError::Timeout { timeout_ms } => ExecutionError::TimedOut { timeout_ms },
            PostgresError::AmbiguousMutationOutcome { operation, reason } => {
                ExecutionError::ConnectorFailed {
                    connector: "postgres".to_string(),
                    reason: format!(
                        "Ambiguous mutation outcome for operation '{operation}': {reason}"
                    ),
                }
            }
            PostgresError::QueryError(msg)
            | PostgresError::ConstraintViolation(msg)
            | PostgresError::SerializationConflict(msg) => ExecutionError::DatabaseError(msg),
            other => ExecutionError::ConnectorFailed {
                connector: "postgres".to_string(),
                reason: other.to_string(),
            },
        }
    }
}
