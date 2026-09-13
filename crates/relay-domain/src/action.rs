use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::id::{ActionHash, ActionId, ApprovalId, DecisionId, ExecutionId, SessionId, ToolId};

/// Lifecycle state for an Action aggregate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionState {
    Proposed,
    Authorized,
    AwaitingApproval,
    Approved,
    Rejected,
    Executing,
    Executed,
    ExecutionFailed,
    Settled,
}

/// Raw requested action received over MCP stdio transport
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedAction {
    pub method: String,
    pub tool_name: String,
    pub raw_arguments: serde_json::Value,
}

/// Execution environment captured at canonicalization time for security and policy context
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEnvironment {
    pub cwd: String,
    pub platform: String,
    pub is_interactive_tty: bool,
}

impl ExecutionEnvironment {
    pub fn new(
        cwd: impl Into<String>,
        platform: impl Into<String>,
        is_interactive_tty: bool,
    ) -> Self {
        Self {
            cwd: cwd.into(),
            platform: platform.into(),
            is_interactive_tty,
        }
    }

    pub fn current() -> Self {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| ".".to_string());
        Self {
            cwd,
            platform: std::env::consts::OS.to_string(),
            is_interactive_tty: false,
        }
    }
}

/// The root domain aggregate representing a single unit of governed work
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub action_id: ActionId,
    pub session_id: SessionId,
    pub tool_id: ToolId,
    pub requested_action: RequestedAction,
    pub state: ActionState,
    pub action_hash: Option<ActionHash>,
    pub decision_id: Option<DecisionId>,
    pub approval_id: Option<ApprovalId>,
    pub execution_id: Option<ExecutionId>,
    pub proposed_at: DateTime<Utc>,
    pub settled_at: Option<DateTime<Utc>>,
}

impl Action {
    pub fn new(session_id: SessionId, tool_id: ToolId, requested: RequestedAction) -> Self {
        Self {
            action_id: ActionId::new_v7(),
            session_id,
            tool_id,
            requested_action: requested,
            state: ActionState::Proposed,
            action_hash: None,
            decision_id: None,
            approval_id: None,
            execution_id: None,
            proposed_at: Utc::now(),
            settled_at: None,
        }
    }

    /// Mark action as authorized by Cedar policy
    pub fn mark_authorized(
        &mut self,
        action_hash: ActionHash,
        decision_id: DecisionId,
    ) -> Result<(), DomainError> {
        match self.state {
            ActionState::Proposed => {
                self.state = ActionState::Authorized;
                self.action_hash = Some(action_hash);
                self.decision_id = Some(decision_id);
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Authorized".to_string(),
                entity_id: self.action_id.to_string(),
                reason: "Action can only be Authorized from Proposed state".to_string(),
            }),
        }
    }

    /// Mark action as awaiting human approval
    pub fn mark_awaiting_approval(
        &mut self,
        action_hash: ActionHash,
        decision_id: DecisionId,
        approval_id: ApprovalId,
    ) -> Result<(), DomainError> {
        match self.state {
            ActionState::Proposed => {
                self.state = ActionState::AwaitingApproval;
                self.action_hash = Some(action_hash);
                self.decision_id = Some(decision_id);
                self.approval_id = Some(approval_id);
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "AwaitingApproval".to_string(),
                entity_id: self.action_id.to_string(),
                reason: "Action can only enter AwaitingApproval from Proposed state".to_string(),
            }),
        }
    }

    /// Mark action as approved by human
    pub fn mark_approved(&mut self) -> Result<(), DomainError> {
        match self.state {
            ActionState::AwaitingApproval => {
                self.state = ActionState::Approved;
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Approved".to_string(),
                entity_id: self.action_id.to_string(),
                reason: "Action must be in AwaitingApproval state to be Approved".to_string(),
            }),
        }
    }

    /// Mark action as rejected (by policy deny or human rejection)
    pub fn mark_rejected(&mut self) -> Result<(), DomainError> {
        match self.state {
            ActionState::Proposed | ActionState::AwaitingApproval => {
                self.state = ActionState::Rejected;
                self.settled_at = Some(Utc::now());
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Rejected".to_string(),
                entity_id: self.action_id.to_string(),
                reason: "Cannot reject action in current state".to_string(),
            }),
        }
    }

    /// Mark action as executing
    pub fn mark_executing(&mut self, execution_id: ExecutionId) -> Result<(), DomainError> {
        match self.state {
            ActionState::Authorized | ActionState::Approved => {
                self.state = ActionState::Executing;
                self.execution_id = Some(execution_id);
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Executing".to_string(),
                entity_id: self.action_id.to_string(),
                reason: "Action must be Authorized or Approved before Executing".to_string(),
            }),
        }
    }

    /// Mark action execution as completed successfully
    pub fn mark_executed(&mut self) -> Result<(), DomainError> {
        match self.state {
            ActionState::Executing => {
                self.state = ActionState::Executed;
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Executed".to_string(),
                entity_id: self.action_id.to_string(),
                reason: "Action must be Executing to complete".to_string(),
            }),
        }
    }

    /// Mark action execution as failed
    pub fn mark_execution_failed(&mut self) -> Result<(), DomainError> {
        match self.state {
            ActionState::Executing => {
                self.state = ActionState::ExecutionFailed;
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "ExecutionFailed".to_string(),
                entity_id: self.action_id.to_string(),
                reason: "Action must be Executing to fail".to_string(),
            }),
        }
    }

    /// Settle the action after writing the receipt to the ledger
    pub fn settle(&mut self) -> Result<(), DomainError> {
        match self.state {
            ActionState::Executed | ActionState::ExecutionFailed | ActionState::Rejected => {
                self.state = ActionState::Settled;
                self.settled_at = Some(Utc::now());
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Settled".to_string(),
                entity_id: self.action_id.to_string(),
                reason: "Action must be Executed, ExecutionFailed, or Rejected to Settle"
                    .to_string(),
            }),
        }
    }
}
