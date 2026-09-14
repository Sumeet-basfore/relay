use relay_domain::ExitCode;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum CliError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Command execution error: {0}")]
    ExecutionError(String),

    #[error("Runtime error: {0}")]
    RuntimeError(String),

    #[error("Governed action denied by Cedar policy: {0}")]
    PolicyDenied(String),

    #[error("Operator rejected action on approval prompt: {0}")]
    ApprovalDenied(String),

    #[error("Approval required but Relay is in headless / non-interactive mode")]
    ApprovalRequired,

    #[error("Approval request timed out: {0}")]
    ApprovalExpired(String),

    #[error("Approval request was cancelled")]
    ApprovalCancelled,

    #[error("MCP JSON-RPC protocol error: {0}")]
    ProtocolError(String),

    #[error("Security or cryptographic failure: {0}")]
    SecurityFailure(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Feature not yet implemented (scheduled for future milestone): {0}")]
    NotImplemented(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl CliError {
    /// Maps CLI errors deterministically to standard Unix exit codes (A007, A010).
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::ConfigError(_) => ExitCode::ConfigError,
            Self::PolicyDenied(_) => ExitCode::PolicyDenied,
            Self::ApprovalDenied(_) => ExitCode::ApprovalDenied,
            Self::ApprovalRequired => ExitCode::ApprovalRequired,
            Self::ApprovalExpired(_) => ExitCode::ApprovalExpired,
            Self::ApprovalCancelled => ExitCode::ApprovalCancelled,
            Self::ProtocolError(_) => ExitCode::ProtocolError,
            Self::SecurityFailure(_) | Self::StorageError(_) => ExitCode::SecurityFailure,
            Self::ExecutionError(_)
            | Self::RuntimeError(_)
            | Self::NotImplemented(_)
            | Self::InternalError(_)
            | Self::Io(_) => ExitCode::RuntimeError,
        }
    }
}
