use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{ApprovalError, DomainError};
use crate::id::{ActionHash, ApprovalId, DecisionId, Digest, PrincipalId};
use crate::traits::ApprovalProvider;
use async_trait::async_trait;

/// Lifecycle state for an interactive human approval
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

impl std::fmt::Display for ApprovalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "PENDING"),
            Self::Approved => write!(f, "APPROVED"),
            Self::Denied => write!(f, "DENIED"),
            Self::Expired => write!(f, "EXPIRED"),
            Self::Cancelled => write!(f, "CANCELLED"),
        }
    }
}

/// Mechanism through which approval was collected or evaluated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalMechanism {
    TtyInteractive,
    HeadlessGate,
    WebAuthn,
}

impl std::fmt::Display for ApprovalMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TtyInteractive => write!(f, "local_interactive_tty"),
            Self::HeadlessGate => write!(f, "headless_gate"),
            Self::WebAuthn => write!(f, "webauthn"),
        }
    }
}

/// Request context used to initiate an approval evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub action_hash: ActionHash,
    pub action_identity: String,
    pub principal: PrincipalId,
    pub resource: String,
    pub decision_id: DecisionId,
    pub policy_digest: Digest,
    pub summary: String,
    pub diff_digest: Option<Digest>,
    pub ttl_seconds: u32,
    pub terminal_device: Option<String>,
    pub risk_level: Option<String>,
    pub parameters_preview: Option<serde_json::Value>,
}

/// Interactive human confirmation for an approval-mandated action (A002, A003)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub approval_id: ApprovalId,
    pub action_hash: ActionHash,
    pub decision_id: DecisionId,
    pub terminal_device: Option<String>,
    pub summary: String,
    pub diff_digest: Option<Digest>,
    pub state: ApprovalState,
    pub approver: Option<PrincipalId>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub action_identity: Option<String>,
    pub principal: Option<PrincipalId>,
    pub resource: Option<String>,
    pub policy_digest: Option<Digest>,
    pub mechanism: Option<ApprovalMechanism>,
    pub denial_reason: Option<String>,
    pub parameters_preview: Option<serde_json::Value>,
}

impl Approval {
    /// Basic constructor maintaining backwards compatibility
    pub fn new(
        action_hash: ActionHash,
        decision_id: DecisionId,
        summary: impl Into<String>,
        terminal_device: Option<String>,
        ttl_seconds: u32,
    ) -> Self {
        let now = Utc::now();
        Self {
            approval_id: ApprovalId::new_v7(),
            action_hash,
            decision_id,
            terminal_device,
            summary: summary.into(),
            diff_digest: None,
            state: ApprovalState::Pending,
            approver: None,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_seconds as i64),
            resolved_at: None,
            action_identity: None,
            principal: None,
            resource: None,
            policy_digest: None,
            mechanism: None,
            denial_reason: None,
            parameters_preview: None,
        }
    }

    /// Full constructor binding all immutable action and policy attributes (A002, A003)
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_context(
        action_hash: ActionHash,
        decision_id: DecisionId,
        summary: impl Into<String>,
        terminal_device: Option<String>,
        ttl_seconds: u32,
        action_identity: impl Into<String>,
        principal: PrincipalId,
        resource: impl Into<String>,
        policy_digest: Digest,
        mechanism: ApprovalMechanism,
    ) -> Self {
        let now = Utc::now();
        Self {
            approval_id: ApprovalId::new_v7(),
            action_hash,
            decision_id,
            terminal_device,
            summary: summary.into(),
            diff_digest: None,
            state: ApprovalState::Pending,
            approver: None,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_seconds as i64),
            resolved_at: None,
            action_identity: Some(action_identity.into()),
            principal: Some(principal),
            resource: Some(resource.into()),
            policy_digest: Some(policy_digest),
            mechanism: Some(mechanism),
            denial_reason: None,
            parameters_preview: None,
        }
    }

    /// Create approval from a structured ApprovalRequest
    pub fn from_request(req: &ApprovalRequest, mechanism: ApprovalMechanism) -> Self {
        let now = Utc::now();
        Self {
            approval_id: ApprovalId::new_v7(),
            action_hash: req.action_hash,
            decision_id: req.decision_id,
            terminal_device: req.terminal_device.clone(),
            summary: req.summary.clone(),
            diff_digest: req.diff_digest,
            state: ApprovalState::Pending,
            approver: None,
            created_at: now,
            expires_at: now + Duration::seconds(req.ttl_seconds as i64),
            resolved_at: None,
            action_identity: Some(req.action_identity.clone()),
            principal: Some(req.principal.clone()),
            resource: Some(req.resource.clone()),
            policy_digest: Some(req.policy_digest),
            mechanism: Some(mechanism),
            denial_reason: None,
            parameters_preview: req.parameters_preview.clone(),
        }
    }

    /// Attach sanitized parameters preview
    pub fn with_parameters_preview(mut self, preview: serde_json::Value) -> Self {
        self.parameters_preview = Some(preview);
        self
    }

    /// Approve the action with the human approver identity (Pending -> Approved)
    pub fn approve(&mut self, approver: PrincipalId) -> Result<(), DomainError> {
        if self.is_expired() {
            self.state = ApprovalState::Expired;
            return Err(DomainError::InvalidStateTransition {
                from: "Expired".to_string(),
                to: "Approved".to_string(),
                entity_id: self.approval_id.to_string(),
                reason: "Cannot approve an expired approval request".to_string(),
            });
        }
        match self.state {
            ApprovalState::Pending => {
                self.state = ApprovalState::Approved;
                self.approver = Some(approver);
                self.resolved_at = Some(Utc::now());
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Approved".to_string(),
                entity_id: self.approval_id.to_string(),
                reason: "Approval can only be granted from Pending state".to_string(),
            }),
        }
    }

    /// Deny the action (Pending -> Denied)
    pub fn deny(
        &mut self,
        approver: Option<PrincipalId>,
        reason: Option<String>,
    ) -> Result<(), DomainError> {
        match self.state {
            ApprovalState::Pending => {
                self.state = ApprovalState::Denied;
                self.approver = approver;
                self.denial_reason = reason;
                self.resolved_at = Some(Utc::now());
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Denied".to_string(),
                entity_id: self.approval_id.to_string(),
                reason: "Approval can only be denied from Pending state".to_string(),
            }),
        }
    }

    /// Mark approval request as expired (Pending -> Expired)
    pub fn expire(&mut self) -> Result<(), DomainError> {
        match self.state {
            ApprovalState::Pending => {
                self.state = ApprovalState::Expired;
                self.resolved_at = Some(Utc::now());
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Expired".to_string(),
                entity_id: self.approval_id.to_string(),
                reason: "Only Pending approvals can transition to Expired".to_string(),
            }),
        }
    }

    /// Cancel the approval (Pending -> Cancelled)
    pub fn cancel(&mut self) -> Result<(), DomainError> {
        match self.state {
            ApprovalState::Pending => {
                self.state = ApprovalState::Cancelled;
                self.resolved_at = Some(Utc::now());
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Cancelled".to_string(),
                entity_id: self.approval_id.to_string(),
                reason: "Only Pending approvals can be cancelled".to_string(),
            }),
        }
    }

    /// Check if approval TTL has elapsed
    #[inline]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Validates whether this approval is valid and matches the given action parameters (SI-004)
    pub fn validate_binding(
        &self,
        action_hash: &ActionHash,
        principal: Option<&PrincipalId>,
        resource: Option<&str>,
        action_identity: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        if self.state != ApprovalState::Approved {
            return Err(DomainError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "Executing".to_string(),
                entity_id: self.approval_id.to_string(),
                reason: format!("Approval is in {:?} state, expected APPROVED", self.state),
            });
        }
        if now > self.expires_at {
            return Err(DomainError::InvalidStateTransition {
                from: "Expired".to_string(),
                to: "Executing".to_string(),
                entity_id: self.approval_id.to_string(),
                reason: "Approval has expired".to_string(),
            });
        }
        if &self.action_hash != action_hash {
            return Err(DomainError::PolicyViolation(format!(
                "Approval action_hash mismatch: expected {}, got {}",
                action_hash, self.action_hash
            )));
        }
        if let (Some(expected_principal), Some(bound_principal)) = (principal, &self.principal) {
            if expected_principal != bound_principal {
                return Err(DomainError::PolicyViolation(format!(
                    "Approval principal mismatch: expected {}, got {}",
                    expected_principal, bound_principal
                )));
            }
        }
        if let (Some(expected_resource), Some(bound_resource)) = (resource, &self.resource) {
            if expected_resource != bound_resource.as_str() {
                return Err(DomainError::PolicyViolation(format!(
                    "Approval resource mismatch: expected {}, got {}",
                    expected_resource, bound_resource
                )));
            }
        }
        if let (Some(expected_tool), Some(bound_tool)) = (action_identity, &self.action_identity) {
            if expected_tool != bound_tool.as_str() {
                return Err(DomainError::PolicyViolation(format!(
                    "Approval action_identity mismatch: expected {}, got {}",
                    expected_tool, bound_tool
                )));
            }
        }
        Ok(())
    }
}

/// Headless Approval Provider (fails closed with NonInteractiveMode)
#[derive(Debug, Default, Clone, Copy)]
pub struct HeadlessApprovalProvider;

#[async_trait]
impl ApprovalProvider for HeadlessApprovalProvider {
    async fn request_approval(&self, approval: &mut Approval) -> Result<(), ApprovalError> {
        let _ = approval.deny(
            None,
            Some("Headless mode: no human operator present".to_string()),
        );
        approval.mechanism = Some(ApprovalMechanism::HeadlessGate);
        Err(ApprovalError::NonInteractiveMode)
    }
}

/// Mock Approval Provider for deterministic testing
pub struct MockApprovalProvider {
    decision_queue: std::sync::Mutex<Vec<Result<PrincipalId, ApprovalError>>>,
}

impl MockApprovalProvider {
    pub fn new() -> Self {
        Self {
            decision_queue: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn with_outcomes(outcomes: Vec<Result<PrincipalId, ApprovalError>>) -> Self {
        Self {
            decision_queue: std::sync::Mutex::new(outcomes),
        }
    }

    pub fn push_outcome(&self, outcome: Result<PrincipalId, ApprovalError>) {
        let mut queue = self.decision_queue.lock().unwrap();
        queue.push(outcome);
    }
}

impl Default for MockApprovalProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalProvider for MockApprovalProvider {
    async fn request_approval(&self, approval: &mut Approval) -> Result<(), ApprovalError> {
        let mut queue = self.decision_queue.lock().unwrap();
        if queue.is_empty() {
            let _ = approval.deny(
                None,
                Some("MockApprovalProvider: queue exhausted".to_string()),
            );
            return Err(ApprovalError::DeniedByHuman(
                "No mock decisions in queue".to_string(),
            ));
        }
        let outcome = queue.remove(0);
        match outcome {
            Ok(approver) => {
                approval
                    .approve(approver)
                    .map_err(|e| ApprovalError::Cancelled(e.to_string()))?;
                Ok(())
            }
            Err(err) => {
                match &err {
                    ApprovalError::DeniedByHuman(reason) => {
                        let _ = approval.deny(None, Some(reason.clone()));
                    }
                    ApprovalError::TimedOut { .. } => {
                        let _ = approval.expire();
                    }
                    ApprovalError::Cancelled(reason) => {
                        let _ = approval.cancel();
                        approval.denial_reason = Some(reason.clone());
                    }
                    _ => {
                        let _ = approval.deny(None, Some(err.to_string()));
                    }
                }
                Err(err)
            }
        }
    }
}
