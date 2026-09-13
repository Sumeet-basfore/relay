//! in-toto Statement v1.0 and DSSE (RFC 9598) receipt signing engine for Relay.

pub mod builder;
pub mod canonical;
pub mod dsse;
pub mod error;
pub mod scrub;
pub mod signer;
pub mod verifier;

// Re-export core types
pub use builder::ActionReceiptBuilder;
pub use canonical::{canonicalize_statement, canonicalize_value};
pub use dsse::{base64_decode, base64_encode, compute_pae, create_envelope};
pub use error::ReceiptError;
pub use scrub::scrub_payload;
pub use signer::Ed25519ReceiptSigner;
pub use verifier::{ReceiptVerifier, VerificationResult};

// Backward-compatible alias
pub type DefaultReceiptSigner = Ed25519ReceiptSigner;
