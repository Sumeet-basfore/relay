use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::id::{Digest, PrincipalId, SessionId};

/// Lifecycle state for an agent session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Created,
    Active,
    Terminated,
    Closed,
}

/// A stateful connection session between an agent client and Relay
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub session_id: SessionId,
    pub principal_id: PrincipalId,
    pub working_directory: String,
    pub terminal_device: Option<String>,
    pub state: SessionState,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub last_receipt_hash: Option<Digest>,
}

impl Session {
    pub fn new(
        principal_id: PrincipalId,
        working_directory: impl Into<String>,
        terminal_device: Option<String>,
    ) -> Self {
        Self {
            session_id: SessionId::new_v7(),
            principal_id,
            working_directory: working_directory.into(),
            terminal_device,
            state: SessionState::Created,
            started_at: Utc::now(),
            ended_at: None,
            last_receipt_hash: None,
        }
    }

    /// Transitions session from Created to Active
    pub fn activate(&mut self) -> Result<(), DomainError> {
        match self.state {
            SessionState::Created => {
                self.state = SessionState::Active;
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Active".to_string(),
                entity_id: self.session_id.to_string(),
                reason: "Session can only be activated from Created state".to_string(),
            }),
        }
    }

    /// Transitions session from Active to Terminated
    pub fn terminate(&mut self) -> Result<(), DomainError> {
        match self.state {
            SessionState::Active | SessionState::Created => {
                self.state = SessionState::Terminated;
                self.ended_at = Some(Utc::now());
                Ok(())
            }
            SessionState::Terminated | SessionState::Closed => {
                Err(DomainError::InvalidStateTransition {
                    from: format!("{:?}", self.state),
                    to: "Terminated".to_string(),
                    entity_id: self.session_id.to_string(),
                    reason: "Session is already terminated or closed".to_string(),
                })
            }
        }
    }

    /// Transitions session from Terminated to Closed
    pub fn close(&mut self) -> Result<(), DomainError> {
        match self.state {
            SessionState::Terminated => {
                self.state = SessionState::Closed;
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Closed".to_string(),
                entity_id: self.session_id.to_string(),
                reason: "Session must be Terminated before it can be Closed".to_string(),
            }),
        }
    }

    /// Updates the session's hash chain tracking
    pub fn update_receipt_hash(&mut self, receipt_hash: Digest) -> Result<(), DomainError> {
        if self.state != SessionState::Active {
            return Err(DomainError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: "Active".to_string(),
                entity_id: self.session_id.to_string(),
                reason: "Cannot update receipt hash on inactive session".to_string(),
            });
        }
        self.last_receipt_hash = Some(receipt_hash);
        Ok(())
    }
}
