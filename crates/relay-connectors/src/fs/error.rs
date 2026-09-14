//! Error taxonomy for Relay Native Filesystem Connector (B010).
//!
//! Enforces:
//! - Clear distinction between Cedar policy DENY, sandbox/root violation, and OS permission errors
//! - Ambiguous mutation tracking for interrupted write/delete operations
//! - Safe redaction: raw path or content errors never leak outside security bounds

use relay_domain::ExecutionError;
use thiserror::Error;

/// Specific error types for Filesystem operations and boundaries.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FsError {
    #[error("ActionHash mismatch: expected '{expected}', actual '{actual}'")]
    ActionHashMismatch { expected: String, actual: String },

    #[error("Resource mismatch: action target '{action_target}', operation target '{op_target}'")]
    ResourceMismatch {
        action_target: String,
        op_target: String,
    },

    #[error("Unauthorized execution: Cedar policy decision is not ALLOW")]
    UnauthorizedExecution,

    #[error("Path traversal rejected: '{path}' escapes root jail '{root}' ({reason})")]
    PathTraversal {
        path: String,
        root: String,
        reason: String,
    },

    #[error("Symlink rejected: '{path}' ({reason})")]
    SymlinkError { path: String, reason: String },

    #[error("Special file rejected: '{path}' has unsupported file type '{file_type}'")]
    SpecialFileRejected { path: String, file_type: String },

    #[error("Prohibited system path rejected: '{0}'")]
    ProhibitedSystemPath(String),

    #[error("File not found: '{0}'")]
    NotFound(String),

    #[error("File already exists: '{0}'")]
    AlreadyExists(String),

    #[error("Permission denied by OS: '{path}' ({reason})")]
    PermissionDenied { path: String, reason: String },

    #[error("File size {size} bytes exceeds maximum limit of {limit} bytes")]
    FileTooLarge { size: u64, limit: u64 },

    #[error("Directory entry count {count} exceeds maximum limit of {limit}")]
    DirectoryEntryLimitExceeded { count: usize, limit: usize },

    #[error("Unsupported filesystem operation: '{0}'")]
    UnsupportedOperation(String),

    #[error("Invalid arguments for operation '{operation}': {reason}")]
    InvalidArguments { operation: String, reason: String },

    #[error("Filesystem I/O failure on '{path}': {reason}")]
    IoError { path: String, reason: String },

    #[error("Ambiguous mutation outcome: operation '{operation}' on '{path}' may have partially executed ({reason})")]
    AmbiguousMutationOutcome {
        operation: String,
        path: String,
        reason: String,
    },
}

impl From<FsError> for ExecutionError {
    fn from(err: FsError) -> Self {
        match err {
            FsError::IoError { path, reason } => {
                ExecutionError::FilesystemError(format!("{path}: {reason}"))
            }
            FsError::PermissionDenied { path, reason } => {
                ExecutionError::FilesystemError(format!("Permission denied: {path}: {reason}"))
            }
            FsError::NotFound(path) => {
                ExecutionError::FilesystemError(format!("Not found: {path}"))
            }
            FsError::AlreadyExists(path) => {
                ExecutionError::FilesystemError(format!("Already exists: {path}"))
            }
            FsError::FileTooLarge { size, limit } => ExecutionError::ConnectorFailed {
                connector: "fs".to_string(),
                reason: format!("File size {size} bytes exceeds limit {limit} bytes"),
            },
            FsError::DirectoryEntryLimitExceeded { count, limit } => {
                ExecutionError::ConnectorFailed {
                    connector: "fs".to_string(),
                    reason: format!("Directory entries {count} exceeds limit {limit}"),
                }
            }
            FsError::AmbiguousMutationOutcome {
                operation,
                path,
                reason,
            } => ExecutionError::ConnectorFailed {
                connector: "fs".to_string(),
                reason: format!("Ambiguous mutation for {operation} on {path}: {reason}"),
            },
            other => ExecutionError::ConnectorFailed {
                connector: "fs".to_string(),
                reason: other.to_string(),
            },
        }
    }
}
