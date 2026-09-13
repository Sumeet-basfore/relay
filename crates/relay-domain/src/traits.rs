use async_trait::async_trait;

use crate::approval::Approval;
use crate::authorization::{AuthorizationRequest, PolicyDecision};
use crate::credential::{CredentialLease, CredentialProviderType, CredentialRequest};
use crate::error::{
    ApprovalError, CanonicalizationError, CredentialError, CryptoError, ExecutionError,
    LedgerError, PolicyError,
};
use crate::execution::ExecutionResult;
use crate::id::{Digest, LeaseId, SequenceNumber};
use crate::ledger::LedgerEntry;
use crate::receipt::{ActionReceipt, DsseEnvelope, InTotoStatement};
use crate::resource::ResourceUri;
use crate::security::SecretBuffer;

/// Policy Decision Point (PDP) contract
#[async_trait]
pub trait PolicyEngine: Send + Sync {
    /// Evaluates an AuthorizationRequest against Cedar policies
    async fn evaluate(&self, request: &AuthorizationRequest)
        -> Result<PolicyDecision, PolicyError>;

    /// Returns the SHA-256 digest of the active policy set
    fn policy_digest(&self) -> Digest;
}

/// Credential Broker contract for leasing ephemeral JIT credentials
#[async_trait]
pub trait CredentialBroker: Send + Sync {
    /// Issues an ephemeral credential lease with memory-safe secret buffer
    /// validated against an authorizing policy decision.
    async fn acquire_lease(
        &self,
        request: &CredentialRequest,
        decision: &PolicyDecision,
    ) -> Result<(CredentialLease, SecretBuffer), CredentialError>;

    /// Validates an in-flight lease
    async fn validate_lease(&self, lease: &CredentialLease) -> Result<bool, CredentialError>;

    /// Consumes a lease after tool execution (SI-006 single-action bound)
    async fn consume_lease(&self, lease_id: &LeaseId) -> Result<(), CredentialError>;

    /// Explicitly revokes an active lease
    async fn revoke_lease(&self, lease_id: &LeaseId) -> Result<(), CredentialError>;
}

/// Keyring / Secret Provider contract
#[async_trait]
pub trait CredentialProvider: Send + Sync {
    /// Returns the provider type
    fn provider_type(&self) -> CredentialProviderType;

    /// Retrieves a secret from the underlying secure store
    async fn get_secret(&self, key_alias: &str) -> Result<SecretBuffer, CredentialError>;

    /// Sets a secret in the underlying secure store
    async fn set_secret(
        &self,
        key_alias: &str,
        secret: &SecretBuffer,
    ) -> Result<(), CredentialError>;

    /// Deletes a secret from the store
    async fn delete_secret(&self, key_alias: &str) -> Result<(), CredentialError>;

    /// Lists configured secret key aliases
    async fn list_secrets(&self) -> Result<Vec<String>, CredentialError>;
}

/// Native Connector contract for in-process tool execution
#[async_trait]
pub trait NativeConnector: Send + Sync {
    /// Returns the unique namespace for this connector (e.g. "github", "postgres", "fs")
    fn namespace(&self) -> &'static str;

    /// Executes the pre-authorized action with an optional secret buffer
    async fn execute(
        &self,
        tool_name: &str,
        canonical_args: &serde_json::Value,
        secret: Option<&SecretBuffer>,
    ) -> Result<ExecutionResult, ExecutionError>;
}

/// Execution Dispatcher contract for routing between native connectors and subprocess proxies
#[async_trait]
pub trait ExecutionDispatcher: Send + Sync {
    /// Dispatches an authorized action to the appropriate execution track
    async fn dispatch(
        &self,
        request: &AuthorizationRequest,
        lease: Option<&CredentialLease>,
        secret: Option<&SecretBuffer>,
    ) -> Result<ExecutionResult, ExecutionError>;
}

/// Interactive / Step-Up Approval Provider contract
#[async_trait]
pub trait ApprovalProvider: Send + Sync {
    /// Prompts human for interactive step-up approval
    async fn request_approval(&self, approval: &mut Approval) -> Result<(), ApprovalError>;
}

/// Cryptographic Action Receipt Signer contract
#[async_trait]
pub trait ReceiptSigner: Send + Sync {
    /// Signs an in-toto Statement producing a DSSE envelope
    async fn sign_statement(
        &self,
        statement: &InTotoStatement,
    ) -> Result<DsseEnvelope, CryptoError>;

    /// Returns the public key ID used for signing
    fn key_id(&self) -> String;

    /// Exports public key bytes (Ed25519)
    fn export_public_key(&self) -> Vec<u8>;
}

/// Append-Only SQLite Ledger Storage contract
#[async_trait]
pub trait Ledger: Send + Sync {
    /// Appends a signed ActionReceipt to the SQLite ledger
    async fn append(&self, receipt: &ActionReceipt) -> Result<LedgerEntry, LedgerError>;

    /// Retrieves an entry by sequence number
    async fn get_by_sequence(
        &self,
        seq: SequenceNumber,
    ) -> Result<Option<LedgerEntry>, LedgerError>;

    /// Verifies the cryptographic hash chain from genesis
    async fn verify_chain(&self) -> Result<bool, LedgerError>;

    /// Returns the latest entry's hash
    async fn get_latest_receipt_hash(&self) -> Result<Digest, LedgerError>;
}

/// RFC 8785 JSON Canonicalization and Domain AST Normalization contract
pub trait Canonicalizer: Send + Sync {
    /// Canonicalizes JSON arguments according to RFC 8785 (JCS)
    fn canonicalize_json(&self, raw: &serde_json::Value) -> Result<Vec<u8>, CanonicalizationError>;

    /// Normalizes path arguments preventing symlink and directory traversal escapes
    fn normalize_path(
        &self,
        raw_path: &str,
        base_dir: &str,
    ) -> Result<String, CanonicalizationError>;

    /// Normalizes SQL statements parsing to canonical AST
    fn normalize_sql(&self, raw_sql: &str) -> Result<String, CanonicalizationError>;
}

/// Resource URI Resolver contract
pub trait ResourceResolver: Send + Sync {
    /// Resolves target tool and parameters into a canonical ResourceUri
    fn resolve_resource(
        &self,
        tool_namespace: &str,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> Result<ResourceUri, CanonicalizationError>;
}
