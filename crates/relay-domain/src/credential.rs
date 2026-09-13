use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::DomainError;
use crate::id::{ActionHash, LeaseId, PrincipalId};
use crate::resource::ResourceUri;

/// Provider classification for JIT credentials
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProviderType {
    GithubApp,
    AwsSts,
    PostgresIam,
    KeyringStatic,
    LoopbackProxy,
}

impl fmt::Display for CredentialProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GithubApp => write!(f, "github_app"),
            Self::AwsSts => write!(f, "aws_sts"),
            Self::PostgresIam => write!(f, "postgres_iam"),
            Self::KeyringStatic => write!(f, "keyring_static"),
            Self::LoopbackProxy => write!(f, "loopback_proxy"),
        }
    }
}

impl std::str::FromStr for CredentialProviderType {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "github" | "github_app" => Ok(Self::GithubApp),
            "aws" | "aws_sts" => Ok(Self::AwsSts),
            "postgres" | "postgres_iam" => Ok(Self::PostgresIam),
            "keyring" | "keyring_static" | "default" => Ok(Self::KeyringStatic),
            "loopback" | "loopback_proxy" => Ok(Self::LoopbackProxy),
            other => Err(DomainError::NotFound(format!(
                "Unknown credential provider: {other}"
            ))),
        }
    }
}

/// Lifecycle state for an ephemeral credential lease
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LeaseState {
    Issued,
    Consumed,
    Expired,
    Revoked,
}

/// Execution-bound credential acquisition request.
/// Prevents arbitrary credential lookup by requiring cryptographic proof of action context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub action_hash: ActionHash,
    pub principal: PrincipalId,
    pub resource: ResourceUri,
    pub provider: CredentialProviderType,
    pub key_alias: String,
    pub target_system: String,
    pub scope: String,
    pub ttl_seconds: u32,
}

impl CredentialRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_hash: ActionHash,
        principal: PrincipalId,
        resource: ResourceUri,
        provider: CredentialProviderType,
        key_alias: impl Into<String>,
        target_system: impl Into<String>,
        scope: impl Into<String>,
        ttl_seconds: u32,
    ) -> Self {
        Self {
            action_hash,
            principal,
            resource,
            provider,
            key_alias: key_alias.into(),
            target_system: target_system.into(),
            scope: scope.into(),
            ttl_seconds,
        }
    }
}

/// Non-secret metadata describing an ephemeral credential granted for an action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialLease {
    pub lease_id: LeaseId,
    pub action_hash: ActionHash,
    pub principal: PrincipalId,
    pub provider: CredentialProviderType,
    pub key_identifier: String,
    pub target_system: String,
    pub scoped_resource: String,
    pub state: LeaseState,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl CredentialLease {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_hash: ActionHash,
        principal: PrincipalId,
        provider: CredentialProviderType,
        key_identifier: impl Into<String>,
        target_system: impl Into<String>,
        scoped_resource: impl Into<String>,
        ttl_seconds: u32,
    ) -> Self {
        let now = Utc::now();
        Self {
            lease_id: LeaseId::new_v7(),
            action_hash,
            principal,
            provider,
            key_identifier: key_identifier.into(),
            target_system: target_system.into(),
            scoped_resource: scoped_resource.into(),
            state: LeaseState::Issued,
            issued_at: now,
            expires_at: now + Duration::seconds(ttl_seconds as i64),
        }
    }

    /// Checks if the lease is currently active (issued and not expired)
    pub fn is_active(&self) -> bool {
        self.state == LeaseState::Issued && !self.is_expired()
    }

    /// Mark the lease as consumed by the execution dispatcher
    pub fn consume(&mut self) -> Result<(), DomainError> {
        if self.is_expired() {
            self.state = LeaseState::Expired;
            return Err(DomainError::InvalidStateTransition {
                from: "Expired".to_string(),
                to: "Consumed".to_string(),
                entity_id: self.lease_id.to_string(),
                reason: "Cannot consume an expired credential lease".to_string(),
            });
        }
        match self.state {
            LeaseState::Issued => {
                self.state = LeaseState::Consumed;
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Consumed".to_string(),
                entity_id: self.lease_id.to_string(),
                reason: "Lease has already been consumed or revoked".to_string(),
            }),
        }
    }

    /// Revoke the lease
    pub fn revoke(&mut self) -> Result<(), DomainError> {
        match self.state {
            LeaseState::Issued => {
                self.state = LeaseState::Revoked;
                Ok(())
            }
            state => Err(DomainError::InvalidStateTransition {
                from: format!("{state:?}"),
                to: "Revoked".to_string(),
                entity_id: self.lease_id.to_string(),
                reason: "Only Issued leases can be revoked".to_string(),
            }),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}
