use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::id::{ActionHash, ActionId, ExecutionId, LeaseId, OutputHash};

/// Physical routing path for action execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionRoute {
    Native,
    SubprocessProxy,
}

/// Lifecycle state for physical action execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Indeterminate,
}

/// The physical execution attempt of an authorized action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Execution {
    pub execution_id: ExecutionId,
    pub action_id: ActionId,
    pub action_hash: ActionHash,
    pub route: ExecutionRoute,
    pub lease_id: Option<LeaseId>,
    pub state: ExecutionState,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
    pub result: Option<ExecutionResult>,
}

impl Execution {
    pub fn new(
        action_id: ActionId,
        action_hash: ActionHash,
        route: ExecutionRoute,
        lease_id: Option<LeaseId>,
    ) -> Self {
        Self {
            execution_id: ExecutionId::new_v7(),
            action_id,
            action_hash,
            route,
            lease_id,
            state: ExecutionState::Pending,
            started_at: Utc::now(),
            completed_at: None,
            duration_ms: None,
            result: None,
        }
    }

    /// Mark execution as running
    pub fn start(&mut self) -> Result<(), DomainError> {
        match self.state {
            ExecutionState::Pending => {
                self.state = ExecutionState::Running;
                self.started_at = Utc::now();
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Running".to_string(),
                entity_id: self.execution_id.to_string(),
                reason: "Execution can only start from Pending state".to_string(),
            }),
        }
    }

    /// Complete execution with success
    pub fn complete_success(&mut self, result: ExecutionResult) -> Result<(), DomainError> {
        match self.state {
            ExecutionState::Running => {
                let now = Utc::now();
                self.state = ExecutionState::Succeeded;
                self.completed_at = Some(now);
                self.duration_ms = Some((now - self.started_at).num_milliseconds().max(0) as u64);
                self.result = Some(result);
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Succeeded".to_string(),
                entity_id: self.execution_id.to_string(),
                reason: "Execution must be Running to complete".to_string(),
            }),
        }
    }

    /// Complete execution with failure
    pub fn complete_failure(&mut self, result: ExecutionResult) -> Result<(), DomainError> {
        match self.state {
            ExecutionState::Running => {
                let now = Utc::now();
                self.state = ExecutionState::Failed;
                self.completed_at = Some(now);
                self.duration_ms = Some((now - self.started_at).num_milliseconds().max(0) as u64);
                self.result = Some(result);
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Failed".to_string(),
                entity_id: self.execution_id.to_string(),
                reason: "Execution must be Running to fail".to_string(),
            }),
        }
    }

    /// Mark execution as timed out
    pub fn timeout(&mut self) -> Result<(), DomainError> {
        match self.state {
            ExecutionState::Running | ExecutionState::Pending => {
                let now = Utc::now();
                self.state = ExecutionState::TimedOut;
                self.completed_at = Some(now);
                self.duration_ms = Some((now - self.started_at).num_milliseconds().max(0) as u64);
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "TimedOut".to_string(),
                entity_id: self.execution_id.to_string(),
                reason: "Cannot time out an already completed execution".to_string(),
            }),
        }
    }
}

/// The observed output and status of an action execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout_digest: OutputHash,
    pub stderr_digest: Option<OutputHash>,
    pub output_byte_count: usize,
    pub is_error: bool,
    pub sanitized_preview: String,
}

impl ExecutionResult {
    pub fn success(stdout: &[u8], preview: impl Into<String>) -> Self {
        Self {
            exit_code: 0,
            stdout_digest: OutputHash::compute(stdout),
            stderr_digest: None,
            output_byte_count: stdout.len(),
            is_error: false,
            sanitized_preview: preview.into(),
        }
    }

    pub fn failure(exit_code: i32, stderr: &[u8], preview: impl Into<String>) -> Self {
        Self {
            exit_code,
            stdout_digest: OutputHash::compute(&[]),
            stderr_digest: Some(OutputHash::compute(stderr)),
            output_byte_count: stderr.len(),
            is_error: true,
            sanitized_preview: preview.into(),
        }
    }
}
