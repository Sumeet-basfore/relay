//! Error taxonomy for Relay Native GitHub Connector.
//!
//! Enforces:
//! - Upstream GitHub HTTP status code distinction (401, 403, 404, 409, 422, 429, 5xx)
//! - Network and TLS failure classification
//! - Ambiguous mutation outcome tracking for timeouts on mutating requests
//! - Strong security redaction: secrets NEVER leak into error messages

use relay_domain::ExecutionError;
use thiserror::Error;

/// Specific error types for GitHub operations and HTTP execution.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GitHubError {
    #[error("Authentication failed (HTTP 401): Bad credentials or expired token")]
    AuthenticationFailed,

    #[error("Authorization failed (HTTP 403): Insufficient repository permissions: {0}")]
    AuthorizationFailed(String),

    #[error("Rate limit exceeded: {message} (reset timestamp: {reset_at})")]
    RateLimited { message: String, reset_at: u64 },

    #[error("Resource not found (HTTP 404): {0}")]
    NotFound(String),

    #[error("Validation failed (HTTP 422): {0}")]
    ValidationError(String),

    #[error("Conflict (HTTP 409): {0}")]
    Conflict(String),

    #[error("GitHub server error (HTTP {status}): {message}")]
    ServerError { status: u16, message: String },

    #[error("Network failure: {0}")]
    NetworkFailure(String),

    #[error("TLS certificate or handshake failure: {0}")]
    TlsFailure(String),

    #[error("Request timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("Ambiguous mutation outcome: mutating request timed out; remote state uncertain (operation: {operation})")]
    AmbiguousMutationOutcome { operation: String, reason: String },

    #[error("Response body too large: {size} bytes exceeds limit of {limit} bytes")]
    ResponseTooLarge { size: usize, limit: usize },

    #[error("Invalid endpoint or host: {0}")]
    InvalidEndpoint(String),

    #[error("ActionHash mismatch: expected '{expected}', actual '{actual}'")]
    ActionHashMismatch { expected: String, actual: String },

    #[error("Resource mismatch: action target '{action_target}', operation target '{op_target}'")]
    ResourceMismatch {
        action_target: String,
        op_target: String,
    },

    #[error("Principal mismatch: lease principal '{lease_principal}', action principal '{action_principal}'")]
    PrincipalMismatch {
        lease_principal: String,
        action_principal: String,
    },

    #[error("Credential lease invalid or expired: {0}")]
    InvalidLease(String),

    #[error("Connector execution attempted without prior authorization")]
    UnauthorizedExecution,

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    #[error("Invalid arguments for operation '{operation}': {reason}")]
    InvalidArguments { operation: String, reason: String },

    #[error("Credential broker error: {0}")]
    CredentialError(String),
}

impl From<GitHubError> for ExecutionError {
    fn from(err: GitHubError) -> Self {
        match err {
            GitHubError::AuthenticationFailed => ExecutionError::HttpStatusError {
                status_code: 401,
                message: "Authentication failed: Bad credentials or expired token".to_string(),
            },
            GitHubError::AuthorizationFailed(msg) => ExecutionError::HttpStatusError {
                status_code: 403,
                message: format!("Authorization failed: {msg}"),
            },
            GitHubError::RateLimited { message, reset_at } => ExecutionError::HttpStatusError {
                status_code: 429,
                message: format!("Rate limit exceeded: {message} (resets at {reset_at})"),
            },
            GitHubError::NotFound(msg) => ExecutionError::HttpStatusError {
                status_code: 404,
                message: format!("Not found: {msg}"),
            },
            GitHubError::ValidationError(msg) => ExecutionError::HttpStatusError {
                status_code: 422,
                message: format!("Validation error: {msg}"),
            },
            GitHubError::Conflict(msg) => ExecutionError::HttpStatusError {
                status_code: 409,
                message: format!("Conflict: {msg}"),
            },
            GitHubError::ServerError { status, message } => ExecutionError::HttpStatusError {
                status_code: status,
                message,
            },
            GitHubError::Timeout { timeout_ms } => ExecutionError::TimedOut { timeout_ms },
            GitHubError::AmbiguousMutationOutcome { operation, reason } => {
                ExecutionError::ConnectorFailed {
                    connector: "github".to_string(),
                    reason: format!(
                        "Ambiguous mutation outcome for operation '{operation}': {reason}"
                    ),
                }
            }
            other => ExecutionError::ConnectorFailed {
                connector: "github".to_string(),
                reason: other.to_string(),
            },
        }
    }
}
