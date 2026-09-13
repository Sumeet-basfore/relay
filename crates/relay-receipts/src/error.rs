//! Error definitions for Action Receipt generation, signing, and verification.

use thiserror::Error;

/// Errors produced during receipt construction, canonicalization, signing, and verification
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("ActionHash binding mismatch: expected '{expected}', actual '{actual}'")]
    ActionHashMismatch { expected: String, actual: String },

    #[error("Policy decision binding mismatch: expected Allow, found '{decision}'")]
    UnauthorizedExecution { decision: String },

    #[error("Binding mismatch on field '{field}': expected '{expected}', actual '{actual}'")]
    BindingMismatch {
        field: String,
        expected: String,
        actual: String,
    },

    #[error("Missing mandatory evidence: {0}")]
    MissingEvidence(String),

    #[error("Canonicalization failed: {0}")]
    CanonicalizationFailed(String),

    #[error("DSSE signing failed: {0}")]
    SigningFailed(String),

    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    #[error("Corrupted DSSE envelope: {0}")]
    CorruptedEnvelope(String),

    #[error("Unsupported schema or version: {0}")]
    UnsupportedSchema(String),

    #[error("Prohibited secret detected in receipt payload: {0}")]
    ProhibitedSecretDetected(String),

    #[error("Domain error: {0}")]
    Domain(String),

    #[error("Crypto error: {0}")]
    Crypto(String),
}

impl From<relay_domain::DomainError> for ReceiptError {
    fn from(err: relay_domain::DomainError) -> Self {
        ReceiptError::Domain(err.to_string())
    }
}

impl From<relay_domain::CryptoError> for ReceiptError {
    fn from(err: relay_domain::CryptoError) -> Self {
        ReceiptError::Crypto(err.to_string())
    }
}
