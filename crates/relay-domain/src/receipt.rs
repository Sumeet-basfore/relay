use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authorization::PolicyDecisionType;
use crate::error::DomainError;
use crate::execution::ExecutionRoute;
use crate::id::{
    ActionHash, ActionId, DecisionId, Digest, ExecutionId, OutputHash, PrincipalId, ReceiptId,
    SessionId,
};
use crate::resource::ResourceUri;

/// Cryptographic SHA-256 in-toto subject entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InTotoSubject {
    pub name: String,
    pub digest: std::collections::BTreeMap<String, String>,
}

impl InTotoSubject {
    pub fn new(name: impl Into<String>, sha256_hex: impl Into<String>) -> Self {
        let mut digest = std::collections::BTreeMap::new();
        digest.insert("sha256".to_string(), sha256_hex.into());
        Self {
            name: name.into(),
            digest,
        }
    }
}

/// Structured canonical proposal evidence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalEvidence {
    pub principal: PrincipalId,
    pub tool_namespace: String,
    pub tool_name: String,
    pub resource: ResourceUri,
    pub arguments: serde_json::Value,
    pub schema_digest: String,
    pub working_directory: String,
}

/// Structured Cedar policy decision evidence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvidence {
    pub decision_id: DecisionId,
    pub decision: PolicyDecisionType,
    pub policy_digest: Digest,
    pub determining_policies: Vec<String>,
    pub evaluated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Structured interactive operator approval evidence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalEvidence {
    pub approval_id: String,
    pub action_hash: ActionHash,
    pub decision: String,
    pub approver: String,
    pub approved_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub mechanism: String,
}

/// Structured JIT credential lease audit evidence (Zero Secret Material)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialLeaseEvidence {
    pub lease_id: String,
    pub provider: String,
    pub key_alias: String,
    pub scope: String,
    pub action_hash: ActionHash,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Structured execution dispatch evidence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEvidence {
    pub execution_id: ExecutionId,
    pub route: ExecutionRoute,
    pub connector: String,
    pub operation: String,
    pub target_resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Execution observation lifecycle status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionObservationStatus {
    Success,
    ExecutionError,
    TargetError,
    TransportError,
    Timeout,
    AmbiguousMutation,
    Cancelled,
}

/// Structured telemetry and outcome observation evidence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationEvidence {
    pub status: ExecutionObservationStatus,
    pub exit_code: i32,
    pub stdout_digest: OutputHash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_digest: Option<OutputHash>,
    pub output_byte_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status_code: Option<u16>,
    pub sanitized_preview: String,
    pub is_ambiguous_mutation: bool,
    pub retry_classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
}

/// Explicit epistemological fact segregation (SI-015)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpistemologyEvidence {
    pub asserted_by_relay: Vec<String>,
    pub observed_by_relay: Vec<String>,
    pub unverified_target_claims: Vec<String>,
}

impl Default for EpistemologyEvidence {
    fn default() -> Self {
        Self {
            asserted_by_relay: vec![
                "canonical_action_hash".to_string(),
                "policy_evaluation_decision".to_string(),
                "authorization_binding".to_string(),
                "jit_lease_governance".to_string(),
            ],
            observed_by_relay: vec![
                "transport_dispatch_timing".to_string(),
                "http_status_code".to_string(),
                "stdout_byte_length".to_string(),
                "raw_response_digest".to_string(),
            ],
            unverified_target_claims: vec![
                "remote_server_database_state_mutation".to_string(),
                "third_party_resource_final_persistence".to_string(),
            ],
        }
    }
}

/// The structured in-toto v1.0 Statement predicate for Relay Action Receipts
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionReceiptPredicate {
    pub receipt_id: ReceiptId,
    pub action_id: ActionId,
    pub session_id: SessionId,
    pub action_hash: ActionHash,
    pub timestamp: DateTime<Utc>,
    pub canonical_proposal: serde_json::Value,
    pub policy_decision: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_lease: Option<serde_json::Value>,
    pub execution: serde_json::Value,
    pub observation: serde_json::Value,
    pub epistemology: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_receipt_hash: Option<Digest>,
}

/// in-toto Statement v1.0 schema structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<InTotoSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: ActionReceiptPredicate,
}

impl InTotoStatement {
    pub const STATEMENT_TYPE: &'static str = "https://in-toto.io/Statement/v1";
    pub const PREDICATE_TYPE: &'static str = "https://relay.dev/ActionReceipt/v1";

    pub fn new(subject: Vec<InTotoSubject>, predicate: ActionReceiptPredicate) -> Self {
        Self {
            statement_type: Self::STATEMENT_TYPE.to_string(),
            subject,
            predicate_type: Self::PREDICATE_TYPE.to_string(),
            predicate,
        }
    }
}

/// Dead Simple Signing Envelope (DSSE - RFC 9598) signature block
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

/// DSSE Envelope (RFC 9598) wrapping the in-toto Statement
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String, // Base64-encoded canonical in-toto Statement JSON
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    pub const PAYLOAD_TYPE: &'static str = "application/vnd.in-toto+json";

    pub fn new(base64_payload: String, signatures: Vec<DsseSignature>) -> Self {
        Self {
            payload_type: Self::PAYLOAD_TYPE.to_string(),
            payload: base64_payload,
            signatures,
        }
    }
}

/// The pure pre-serialization domain-level ActionReceipt entity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainActionReceipt {
    pub receipt_id: ReceiptId,
    pub action_id: ActionId,
    pub session_id: SessionId,
    pub action_hash: ActionHash,
    pub parent_receipt_hash: Digest,
    pub proposal: ProposalEvidence,
    pub policy: PolicyEvidence,
    pub approval: Option<ApprovalEvidence>,
    pub credential_lease: Option<CredentialLeaseEvidence>,
    pub execution: ExecutionEvidence,
    pub observation: ObservationEvidence,
    pub epistemology: EpistemologyEvidence,
    pub created_at: DateTime<Utc>,
}

impl DomainActionReceipt {
    /// Transforms the domain action receipt into a canonical in-toto Statement v1.0
    pub fn to_in_toto_statement(&self) -> Result<InTotoStatement, DomainError> {
        let subject = vec![InTotoSubject::new(
            self.proposal.resource.as_str(),
            self.action_hash.to_hex(),
        )];

        let predicate = ActionReceiptPredicate {
            receipt_id: self.receipt_id,
            action_id: self.action_id,
            session_id: self.session_id,
            action_hash: self.action_hash,
            timestamp: self.created_at,
            canonical_proposal: serde_json::to_value(&self.proposal)
                .map_err(|e| DomainError::SerializationFailed(e.to_string()))?,
            policy_decision: serde_json::to_value(&self.policy)
                .map_err(|e| DomainError::SerializationFailed(e.to_string()))?,
            approval: self
                .approval
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|e| DomainError::SerializationFailed(e.to_string()))?,
            credential_lease: self
                .credential_lease
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|e| DomainError::SerializationFailed(e.to_string()))?,
            execution: serde_json::to_value(&self.execution)
                .map_err(|e| DomainError::SerializationFailed(e.to_string()))?,
            observation: serde_json::to_value(&self.observation)
                .map_err(|e| DomainError::SerializationFailed(e.to_string()))?,
            epistemology: serde_json::to_value(&self.epistemology)
                .map_err(|e| DomainError::SerializationFailed(e.to_string()))?,
            parent_receipt_hash: Some(self.parent_receipt_hash),
        };

        Ok(InTotoStatement::new(subject, predicate))
    }
}

/// The final signed ActionReceipt attestation artifact
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub receipt_id: ReceiptId,
    pub action_id: ActionId,
    pub session_id: SessionId,
    pub action_hash: ActionHash,
    pub receipt_hash: Digest,
    pub parent_receipt_hash: Digest,
    pub dsse_envelope: DsseEnvelope,
    pub created_at: DateTime<Utc>,
}

/// Type alias aligning with A003 naming for the signed DSSE receipt
pub type SignedActionReceipt = ActionReceipt;
