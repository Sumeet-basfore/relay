use thiserror::Error;

/// Root error taxonomy for Relay
#[derive(Error, Debug)]
pub enum RelayError {
    #[error("Domain error: {0}")]
    Domain(#[from] DomainError),

    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Canonicalization error: {0}")]
    Canonicalization(#[from] CanonicalizationError),

    #[error("Policy error: {0}")]
    Policy(#[from] PolicyError),

    #[error("Approval error: {0}")]
    Approval(#[from] ApprovalError),

    #[error("Credential error: {0}")]
    Credential(#[from] CredentialError),

    #[error("Execution error: {0}")]
    Execution(#[from] ExecutionError),

    #[error("Ledger error: {0}")]
    Ledger(#[from] LedgerError),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Internal invariant violation: {0}")]
    InvariantViolation(#[from] InvariantViolationError),
}

/// Domain entity and state machine errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("Invalid identifier: {0}")]
    InvalidIdentifier(String),

    #[error("Invalid state transition from '{from}' to '{to}' on entity '{entity_id}': {reason}")]
    InvalidStateTransition {
        from: String,
        to: String,
        entity_id: String,
        reason: String,
    },

    #[error("Entity not found: {0}")]
    NotFound(String),

    #[error("Duplicate entity: {0}")]
    Duplicate(String),

    #[error("Resource parse error: {0}")]
    InvalidResource(String),

    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Policy or binding violation: {0}")]
    PolicyViolation(String),
}

/// JSON-RPC 2.0 and MCP transport errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Parse error (-32700): {0}")]
    ParseError(String),

    #[error("Invalid request (-32600): {0}")]
    InvalidRequest(String),

    #[error("Method not found (-32601): {0}")]
    MethodNotFound(String),

    #[error("Invalid params (-32602): {0}")]
    InvalidParams(String),

    #[error("Internal error (-32603): {0}")]
    InternalError(String),

    #[error("Frame too large: size {size_bytes} exceeds limit of {max_bytes} bytes")]
    FrameTooLarge { size_bytes: usize, max_bytes: usize },

    #[error("Stream disconnected / EOF")]
    Disconnected,
}

impl ProtocolError {
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::ParseError(_) => -32700,
            Self::InvalidRequest(_) => -32600,
            Self::MethodNotFound(_) => -32601,
            Self::InvalidParams(_) => -32602,
            Self::InternalError(_) => -32603,
            Self::FrameTooLarge { .. } => -32600,
            Self::Disconnected => -32000,
        }
    }
}

/// Payload and schema validation errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid field type for '{field}': expected '{expected}', got '{actual}'")]
    InvalidType {
        field: String,
        expected: String,
        actual: String,
    },

    #[error("Schema violation: {0}")]
    SchemaViolation(String),

    #[error("Schema digest mismatch: expected '{expected}', calculated '{calculated}'")]
    SchemaDigestMismatch {
        expected: String,
        calculated: String,
    },
}

/// RFC 8785 JSON Canonicalization and Domain AST Normalization errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CanonicalizationError {
    #[error("Duplicate JSON key '{0}' detected (forbidden by security policy)")]
    DuplicateKey(String),

    #[error("Malformed JSON input: {0}")]
    MalformedJson(String),

    #[error("Invalid tool identity '{0}': {1}")]
    InvalidToolIdentity(String, String),

    #[error("Resource normalization failed: {0}")]
    ResourceError(String),

    #[error("Invalid resource URI '{0}': {1}")]
    InvalidResource(String, String),

    #[error("Path normalization failed for '{path}': {reason}")]
    PathError { path: String, reason: String },

    #[error("Path traversal detected in '{path}': {reason}")]
    PathTraversal { path: String, reason: String },

    #[error("Dangling symlink detected at '{path}'")]
    DanglingSymlink { path: String },

    #[error("Symlink cycle detected at '{path}'")]
    SymlinkCycle { path: String },

    #[error("SQL AST normalization failed for '{sql}': {reason}")]
    SqlError { sql: String, reason: String },

    #[error("Unsupported SQL construct: {0}")]
    UnsupportedSql(String),

    #[error("Multi-statement SQL batching rejected ({count} statements detected; single statement required)")]
    MultiStatementSqlNotAllowed { count: usize },

    #[error("Oversized canonical representation ({size} bytes exceeds limit of {limit} bytes)")]
    OversizedCanonicalRepresentation { size: usize, limit: usize },

    #[error("Unsupported encoding: {0}")]
    UnsupportedEncoding(String),

    #[error("Schema digest mismatch: expected '{expected}', actual '{actual}'")]
    SchemaMismatch { expected: String, actual: String },

    #[error("JCS serialization failed: {0}")]
    JcsError(String),
}

impl CanonicalizationError {
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::MalformedJson(_) | Self::DuplicateKey(_) => -32700,
            Self::PathTraversal { .. } | Self::InvalidResource(..) => -32600,
            _ => -32602,
        }
    }
}

/// Policy evaluation and Cedar PDP errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    #[error("Policy initialization failed: {0}")]
    InitializationFailed(String),

    #[error("Policy evaluation failed: {0}")]
    EvaluationFailed(String),

    #[error("Action forbidden by policy: {reason}")]
    ActionForbidden { reason: String },

    #[error("Cedar schema validation error: {0}")]
    SchemaError(String),

    #[error("Policy set corrupted: {0}")]
    CorruptedPolicy(String),
}

/// Interactive TTY and Step-Up approval errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    #[error("Action denied by human approver: {0}")]
    DeniedByHuman(String),

    #[error("Approval request timed out after {timeout_secs}s")]
    TimedOut { timeout_secs: u64 },

    #[error("Non-interactive mode cannot fulfill approval request")]
    NonInteractiveMode,

    #[error("Approval cancelled: {0}")]
    Cancelled(String),

    #[error("Approval hash mismatch: approval bound to '{bound_hash}', action is '{action_hash}'")]
    HashMismatch {
        bound_hash: String,
        action_hash: String,
    },

    #[error("TTY unavailable: {0}")]
    TtyUnavailable(String),
}

/// Credential vaulting, leasing, and injection errors
/// NOTE: Must NEVER leak actual secret strings or tokens in error variants!
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    #[error("Secret not found in vault for provider '{provider}' and key '{key_alias}'")]
    NotFound { provider: String, key_alias: String },

    #[error("Keyring access denied or unavailable: {reason}")]
    KeyringUnavailable { reason: String },

    #[error("Credential lease expired: lease_id '{lease_id}'")]
    LeaseExpired { lease_id: String },

    #[error("Credential lease already consumed: lease_id '{lease_id}'")]
    LeaseAlreadyConsumed { lease_id: String },

    #[error("Credential lease revoked: lease_id '{lease_id}'")]
    LeaseRevoked { lease_id: String },

    #[error("Credential lease exhausted or invalid: {reason}")]
    LeaseExhausted { reason: String },

    #[error("Unauthorized credential acquisition: {reason}")]
    AccessDenied { reason: String },

    #[error("Human step-up approval required before credential acquisition: action_hash '{action_hash}'")]
    ApprovalRequired { action_hash: String },

    #[error(
        "Action hash mismatch: request action '{request_hash}', decision action '{decision_hash}'"
    )]
    ActionHashMismatch {
        request_hash: String,
        decision_hash: String,
    },

    #[error("Principal mismatch: request principal '{request_principal}', decision principal '{decision_principal}'")]
    PrincipalMismatch {
        request_principal: String,
        decision_principal: String,
    },

    #[error("Resource mismatch: request resource '{request_resource}', decision resource '{decision_resource}'")]
    ResourceMismatch {
        request_resource: String,
        decision_resource: String,
    },

    #[error("Provider error: {reason}")]
    ProviderError { reason: String },

    #[error("Memory locking (mlock) failed: {0}")]
    MemoryLockFailed(String),

    #[error("Invalid scope: {reason}")]
    InvalidScope { reason: String },
}

/// Tool execution, connector, and network dispatch errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    #[error("Connector '{connector}' execution failed: {reason}")]
    ConnectorFailed { connector: String, reason: String },

    #[error("Subprocess execution failed for '{command}': {reason}")]
    SubprocessFailed { command: String, reason: String },

    #[error("Execution timed out after {timeout_ms}ms")]
    TimedOut { timeout_ms: u64 },

    #[error("Target service returned HTTP error status {status_code}: {message}")]
    HttpStatusError { status_code: u16, message: String },

    #[error("Database query error: {0}")]
    DatabaseError(String),

    #[error("Filesystem I/O error: {0}")]
    FilesystemError(String),

    #[error("Egress proxy error: {0}")]
    EgressProxyError(String),

    #[error("Sandbox setup failed: {0}")]
    SandboxSetupFailed(String),

    #[error("Egress destination blocked: {0}")]
    EgressBlocked(String),
}

/// SQLite Ledger, WAL, and append-only hash chain errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    #[error("Database connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Database write error: {0}")]
    WriteError(String),

    #[error("Hash chain broken at sequence {sequence_number}: expected previous hash '{expected_prev}', got '{actual_prev}'")]
    HashChainBroken {
        sequence_number: u64,
        expected_prev: String,
        actual_prev: String,
    },

    #[error("Ledger query error: {0}")]
    QueryError(String),

    #[error("Database corruption detected: {0}")]
    Corruption(String),

    #[error("Sequence gap detected at sequence {actual}: expected {expected}")]
    SequenceGap { expected: u64, actual: u64 },

    #[error("Payload hash mismatch at sequence {sequence_number}: expected '{expected}', actual '{actual}'")]
    PayloadHashMismatch {
        sequence_number: u64,
        expected: String,
        actual: String,
    },

    #[error("Entry hash mismatch at sequence {sequence_number}: expected '{expected}', computed '{actual}'")]
    EntryHashMismatch {
        sequence_number: u64,
        expected: String,
        actual: String,
    },

    #[error("Invalid cryptographic signature on receipt '{receipt_id}' at sequence {sequence_number}: {reason}")]
    InvalidSignature {
        sequence_number: u64,
        receipt_id: String,
        reason: String,
    },

    #[error("Database schema migration failed: {0}")]
    MigrationFailed(String),

    #[error("Filesystem permission violation on ledger path: {0}")]
    PermissionError(String),

    #[error("Ledger serialization failed: {0}")]
    SerializationError(String),
}

/// Cryptographic signing and DSSE envelope verification errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Key loading failed: {0}")]
    KeyLoadingFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid DSSE envelope format: {0}")]
    InvalidEnvelope(String),

    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Security invariant violations (fatal software state assertion failures)
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum InvariantViolationError {
    #[error("Invariant SI-001 violation: Ambient target credential detected in agent context")]
    AmbientCredentialLeak,

    #[error(
        "Invariant SI-002 violation: Action execution attempted without prior authorization token"
    )]
    ExecutionWithoutAuthorization,

    #[error("Invariant SI-005 violation: Canonical representation divergence between policy and execution")]
    CanonicalDivergence,

    #[error("Invariant SI-009 violation: Ledger tampering or sequence gap detected")]
    LedgerTampering,

    #[error("Invariant SI-019 violation: External egress attempted without prior destination authorization")]
    ExternalEgressUnauthorized,

    #[error("Invariant SI-020 violation: Ephemeral proxy session expired, invalid, or unbound to action hash")]
    EphemeralProxySessionInvalid,

    #[error(
        "Invariant SI-021 violation: Real target credential exposed to subprocess environment"
    )]
    TargetCredentialLeak,

    #[error("Invariant SI-022 violation: Outbound request attempted to access blocked cloud metadata or private IP")]
    BlockedMetadataOrPrivateIp,

    #[error("Invariant SI-023 violation: Linux network namespace isolation compromised or bypass detected")]
    NetworkNamespaceIsolationFailed,

    #[error("Invariant SI-024 violation: Sandbox initialization failed to fail-closed")]
    SandboxFailClosedViolation,

    #[error("Invariant violation: {0}")]
    Custom(String),
}
