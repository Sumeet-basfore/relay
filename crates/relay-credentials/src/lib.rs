//! Credential broker and secret isolation subsystem for Relay (Milestone B005).
//!
//! Provides Just-In-Time (JIT) credential leasing strictly bound to authorized actions,
//! OS keyring integration (Keychain / SecretService), memory locking (`mlock`),
//! and automatic zeroization on drop.

pub mod broker;
pub mod provider;

pub use broker::JitCredentialBroker;
pub use provider::{
    EncryptedFileCredentialProvider, InMemoryCredentialProvider, KeyringCredentialProvider,
};

/// Type alias maintaining backwards compatibility with foundation milestone B001
pub type DefaultCredentialBroker = JitCredentialBroker;
