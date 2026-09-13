//! Action Receipt Builder constructing domain receipts and DSSE-signed in-toto envelopes.

use chrono::{DateTime, Utc};
use relay_canonical::CanonicalAction;
use relay_domain::{
    ActionReceipt, Approval, ApprovalEvidence, CredentialLease, CredentialLeaseEvidence, Digest,
    DomainActionReceipt, EpistemologyEvidence, ExecutionEvidence, ExecutionObservationStatus,
    ExecutionRoute, ObservationEvidence, OutputHash, PolicyDecision, PolicyDecisionType,
    PolicyEvidence, ProposalEvidence, ReceiptId,
};

use crate::canonical::canonicalize_statement;
use crate::error::ReceiptError;
use crate::scrub::scrub_payload;
use crate::signer::Ed25519ReceiptSigner;

/// Builder for constructing and cryptographically signing Relay Action Receipts.
pub struct ActionReceiptBuilder<'a> {
    action: &'a CanonicalAction,
    decision: &'a PolicyDecision,
    approval: Option<&'a Approval>,
    credential_lease: Option<&'a CredentialLease>,
    parent_receipt_hash: Digest,

    // Execution metadata
    execution_id: Option<relay_domain::ExecutionId>,
    route: ExecutionRoute,
    connector: String,
    operation: String,
    target_resource: String,
    http_method: Option<String>,
    endpoint: Option<String>,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    duration_ms: Option<u64>,

    // Observation metadata
    status: ExecutionObservationStatus,
    exit_code: i32,
    stdout_digest: OutputHash,
    stderr_digest: Option<OutputHash>,
    output_byte_count: usize,
    response_status_code: Option<u16>,
    sanitized_preview: String,
    is_ambiguous_mutation: bool,
    retry_classification: String,
    error_class: Option<String>,
}

impl<'a> ActionReceiptBuilder<'a> {
    /// Starts constructing a receipt bound to an authorized canonical action.
    pub fn new(action: &'a CanonicalAction, decision: &'a PolicyDecision) -> Self {
        Self {
            action,
            decision,
            approval: None,
            credential_lease: None,
            parent_receipt_hash: Digest::compute(b"RELAY_GENESIS_BLOCK"),

            execution_id: None,
            route: ExecutionRoute::Native,
            connector: action.tool.namespace.clone(),
            operation: action.tool.name.clone(),
            target_resource: action.resource.as_str().to_string(),
            http_method: None,
            endpoint: None,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            duration_ms: Some(0),

            status: ExecutionObservationStatus::Success,
            exit_code: 0,
            stdout_digest: OutputHash::compute(b""),
            stderr_digest: None,
            output_byte_count: 0,
            response_status_code: Some(200),
            sanitized_preview: String::new(),
            is_ambiguous_mutation: false,
            retry_classification: "IdempotentSafeToRetry".to_string(),
            error_class: None,
        }
    }

    pub fn with_approval(mut self, approval: Option<&'a Approval>) -> Self {
        self.approval = approval;
        self
    }

    pub fn with_credential_lease(mut self, lease: Option<&'a CredentialLease>) -> Self {
        self.credential_lease = lease;
        self
    }

    pub fn with_parent_receipt_hash(mut self, hash: Digest) -> Self {
        self.parent_receipt_hash = hash;
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_execution_metadata(
        mut self,
        execution_id: relay_domain::ExecutionId,
        route: ExecutionRoute,
        connector: impl Into<String>,
        operation: impl Into<String>,
        target_resource: impl Into<String>,
        http_method: Option<String>,
        endpoint: Option<String>,
        started_at: DateTime<Utc>,
        completed_at: Option<DateTime<Utc>>,
        duration_ms: Option<u64>,
    ) -> Self {
        self.execution_id = Some(execution_id);
        self.route = route;
        self.connector = connector.into();
        self.operation = operation.into();
        self.target_resource = target_resource.into();
        self.http_method = http_method;
        self.endpoint = endpoint;
        self.started_at = started_at;
        self.completed_at = completed_at;
        self.duration_ms = duration_ms;
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_observation(
        mut self,
        status: ExecutionObservationStatus,
        exit_code: i32,
        stdout_digest: OutputHash,
        stderr_digest: Option<OutputHash>,
        output_byte_count: usize,
        response_status_code: Option<u16>,
        sanitized_preview: impl Into<String>,
        is_ambiguous_mutation: bool,
        retry_classification: impl Into<String>,
        error_class: Option<String>,
    ) -> Self {
        self.status = status;
        self.exit_code = exit_code;
        self.stdout_digest = stdout_digest;
        self.stderr_digest = stderr_digest;
        self.output_byte_count = output_byte_count;
        self.response_status_code = response_status_code;
        self.sanitized_preview = sanitized_preview.into();
        self.is_ambiguous_mutation = is_ambiguous_mutation;
        self.retry_classification = retry_classification.into();
        self.error_class = error_class;
        self
    }

    /// Validates all cryptographic and domain bindings before assembling the domain receipt.
    pub fn build_domain(&self) -> Result<DomainActionReceipt, ReceiptError> {
        // 1. Invariant: Policy decision must be explicitly Allow
        if self.decision.decision != PolicyDecisionType::Allow {
            return Err(ReceiptError::UnauthorizedExecution {
                decision: format!("{:?}", self.decision.decision),
            });
        }

        // 2. Invariant: ActionHash in decision MUST match canonical action hash (SI-005)
        if self.decision.action_hash != self.action.action_hash {
            return Err(ReceiptError::ActionHashMismatch {
                expected: self.action.action_hash.to_hex(),
                actual: self.decision.action_hash.to_hex(),
            });
        }

        // 3. Invariant: If approval is present, it MUST bind to this exact ActionHash (SI-011)
        if let Some(approval) = self.approval {
            if approval.action_hash != self.action.action_hash {
                return Err(ReceiptError::BindingMismatch {
                    field: "approval.action_hash".to_string(),
                    expected: self.action.action_hash.to_hex(),
                    actual: approval.action_hash.to_hex(),
                });
            }
        }

        // 4. Invariant: If credential lease is present, it MUST bind to this exact ActionHash (SI-006)
        if let Some(lease) = self.credential_lease {
            if lease.action_hash != self.action.action_hash {
                return Err(ReceiptError::BindingMismatch {
                    field: "lease.action_hash".to_string(),
                    expected: self.action.action_hash.to_hex(),
                    actual: lease.action_hash.to_hex(),
                });
            }
        }

        let receipt_id = ReceiptId::new_v7();
        let action_id = self.action.action_id;
        let session_id = self.action.session_id;
        let action_hash = self.action.action_hash;

        let proposal = ProposalEvidence {
            principal: self.action.principal.clone(),
            tool_namespace: self.action.tool.namespace.clone(),
            tool_name: self.action.tool.name.clone(),
            resource: self.action.resource.clone(),
            arguments: self.action.canonical_arguments.clone(),
            schema_digest: self.action.schema_digest.to_hex(),
            working_directory: self.action.environment.cwd.clone(),
        };

        let policy = PolicyEvidence {
            decision_id: self.decision.decision_id,
            decision: self.decision.decision,
            policy_digest: self.decision.policy_digest,
            determining_policies: self.decision.determining_policies.clone(),
            evaluated_at: self.decision.evaluated_at,
            reason: self.decision.reason.clone(),
        };

        let approval_evidence = self.approval.map(|a| ApprovalEvidence {
            approval_id: a.approval_id.to_string(),
            action_hash: a.action_hash,
            decision: format!("{:?}", a.state),
            approver: a
                .approver
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "operator".to_string()),
            approved_at: a.resolved_at.unwrap_or_else(Utc::now),
            expires_at: Some(a.expires_at),
            mechanism: "local_interactive_tty".to_string(),
        });

        let credential_evidence = self.credential_lease.map(|l| CredentialLeaseEvidence {
            lease_id: l.lease_id.to_string(),
            provider: format!("{:?}", l.provider),
            key_alias: l.key_identifier.clone(),
            scope: l.scoped_resource.clone(),
            action_hash: l.action_hash,
            issued_at: l.issued_at,
            expires_at: l.expires_at,
        });

        let execution = ExecutionEvidence {
            execution_id: self
                .execution_id
                .unwrap_or_else(relay_domain::ExecutionId::new_v7),
            route: self.route,
            connector: self.connector.clone(),
            operation: self.operation.clone(),
            target_resource: self.target_resource.clone(),
            http_method: self.http_method.clone(),
            endpoint: self.endpoint.clone(),
            started_at: self.started_at,
            completed_at: self.completed_at,
            duration_ms: self.duration_ms,
        };

        // If marked ambiguous mutation, enforce status is AmbiguousMutation (SI-015)
        let effective_status = if self.is_ambiguous_mutation {
            ExecutionObservationStatus::AmbiguousMutation
        } else {
            self.status
        };

        let observation = ObservationEvidence {
            status: effective_status,
            exit_code: self.exit_code,
            stdout_digest: self.stdout_digest,
            stderr_digest: self.stderr_digest,
            output_byte_count: self.output_byte_count,
            response_status_code: self.response_status_code,
            sanitized_preview: self.sanitized_preview.clone(),
            is_ambiguous_mutation: self.is_ambiguous_mutation,
            retry_classification: self.retry_classification.clone(),
            error_class: self.error_class.clone(),
        };

        Ok(DomainActionReceipt {
            receipt_id,
            action_id,
            session_id,
            action_hash,
            parent_receipt_hash: self.parent_receipt_hash,
            proposal,
            policy,
            approval: approval_evidence,
            credential_lease: credential_evidence,
            execution,
            observation,
            epistemology: EpistemologyEvidence::default(),
            created_at: Utc::now(),
        })
    }

    /// Assembles the domain receipt, canonicalizes it to JCS bytes, scrubs secrets,
    /// and signs it using the provided Ed25519 signer producing the final `ActionReceipt`.
    pub fn build_and_sign(
        &self,
        signer: &Ed25519ReceiptSigner,
    ) -> Result<ActionReceipt, ReceiptError> {
        let domain_receipt = self.build_domain()?;
        let in_toto_statement = domain_receipt.to_in_toto_statement()?;

        // Canonicalize using RFC 8785 (JCS)
        let canonical_bytes = canonicalize_statement(&in_toto_statement)?;

        // Defensive secret scrubbing guard (SI-001, SI-008)
        scrub_payload(&canonical_bytes)?;

        // Compute ReceiptHash = SHA-256(canonical in-toto Statement bytes)
        let receipt_hash = Digest::compute(&canonical_bytes);

        // Sign canonical bytes producing DSSE envelope
        let dsse_envelope = signer
            .sign_payload_bytes_sync(relay_domain::DsseEnvelope::PAYLOAD_TYPE, &canonical_bytes)?;

        Ok(ActionReceipt {
            receipt_id: domain_receipt.receipt_id,
            action_id: domain_receipt.action_id,
            session_id: domain_receipt.session_id,
            action_hash: domain_receipt.action_hash,
            receipt_hash,
            parent_receipt_hash: domain_receipt.parent_receipt_hash,
            dsse_envelope,
            created_at: domain_receipt.created_at,
        })
    }
}
