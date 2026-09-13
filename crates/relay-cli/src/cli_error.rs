use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum CliError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Command execution error: {0}")]
    ExecutionError(String),

    #[error("Feature not yet implemented (scheduled for future milestone): {0}")]
    NotImplemented(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
