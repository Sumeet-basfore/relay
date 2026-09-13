use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::id::{ActionHash, ApprovalId, DecisionId, Digest, PrincipalId};

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

/// Interactive human confirmation for an approval-mandated action
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
}

impl Approval {
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
        }
    }

    /// Approve the action with the human approver identity
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

    /// Deny the action
    pub fn deny(&mut self, approver: Option<PrincipalId>) -> Result<(), DomainError> {
        match self.state {
            ApprovalState::Pending => {
                self.state = ApprovalState::Denied;
                self.approver = approver;
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

    /// Cancel the approval (e.g. agent disconnected or sent a new call)
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
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}
