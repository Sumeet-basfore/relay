use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::id::{ActionHash, DecisionId, Digest, PrincipalId, SessionId, ToolId};
use crate::resource::ResourceUri;

/// Policy decision outcomes produced by Cedar
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecisionType {
    Allow,
    Deny,
    ApprovalRequired,
}

/// The deterministic, canonical data structure evaluated by Cedar
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub principal: PrincipalId,
    pub action: String,
    pub resource: ResourceUri,
    pub session_id: SessionId,
    pub tool: ToolId,
    pub arguments: serde_json::Value,
    pub working_directory: String,
    pub timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_hash: Option<ActionHash>,
}

impl AuthorizationRequest {
    /// Computes the cryptographic ActionHash over the serialized representation
    pub fn compute_action_hash(&self) -> ActionHash {
        if let Some(hash) = self.action_hash {
            return hash;
        }
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        ActionHash::compute(&bytes)
    }
}

/// The immutable decision produced by Cedar
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision_id: DecisionId,
    pub action_hash: ActionHash,
    pub decision: PolicyDecisionType,
    pub evaluated_at: DateTime<Utc>,
    pub policy_digest: Digest,
    pub determining_policies: Vec<String>,
    pub diagnostics: Vec<String>,
    pub reason: Option<String>,
}

impl PolicyDecision {
    pub fn allow(
        action_hash: ActionHash,
        policy_digest: Digest,
        determining_policies: Vec<String>,
    ) -> Self {
        Self {
            decision_id: DecisionId::new_v7(),
            action_hash,
            decision: PolicyDecisionType::Allow,
            evaluated_at: Utc::now(),
            policy_digest,
            determining_policies,
            diagnostics: Vec::new(),
            reason: None,
        }
    }

    pub fn deny(
        action_hash: ActionHash,
        policy_digest: Digest,
        reason: impl Into<String>,
        determining_policies: Vec<String>,
    ) -> Self {
        Self {
            decision_id: DecisionId::new_v7(),
            action_hash,
            decision: PolicyDecisionType::Deny,
            evaluated_at: Utc::now(),
            policy_digest,
            determining_policies,
            diagnostics: Vec::new(),
            reason: Some(reason.into()),
        }
    }

    pub fn approval_required(
        action_hash: ActionHash,
        policy_digest: Digest,
        reason: impl Into<String>,
        determining_policies: Vec<String>,
    ) -> Self {
        Self {
            decision_id: DecisionId::new_v7(),
            action_hash,
            decision: PolicyDecisionType::ApprovalRequired,
            evaluated_at: Utc::now(),
            policy_digest,
            determining_policies,
            diagnostics: Vec::new(),
            reason: Some(reason.into()),
        }
    }

    pub fn is_allowed(&self) -> bool {
        self.decision == PolicyDecisionType::Allow
    }

    pub fn is_denied(&self) -> bool {
        self.decision == PolicyDecisionType::Deny
    }

    pub fn requires_approval(&self) -> bool {
        self.decision == PolicyDecisionType::ApprovalRequired
    }
}
