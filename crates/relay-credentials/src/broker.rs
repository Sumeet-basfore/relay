use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use relay_domain::authorization::{PolicyDecision, PolicyDecisionType};
use relay_domain::credential::{
    CredentialLease, CredentialProviderType, CredentialRequest, LeaseState,
};
use relay_domain::error::CredentialError;
use relay_domain::id::LeaseId;
use relay_domain::security::{CredentialLeaseGuard, SecretBuffer};
use relay_domain::traits::{CredentialBroker, CredentialProvider};

/// Production Just-In-Time (JIT) Credential Broker.
/// Enforces policy authorization binding, ActionHash matching, ephemeral single-action leases,
/// and prevents ambient credential accumulation in agent memory.
pub struct JitCredentialBroker {
    providers: Arc<RwLock<HashMap<CredentialProviderType, Arc<dyn CredentialProvider>>>>,
    active_leases: Arc<RwLock<HashMap<LeaseId, CredentialLease>>>,
    min_ttl_seconds: u32,
    max_ttl_seconds: u32,
}

impl JitCredentialBroker {
    pub const DEFAULT_MIN_TTL_SECONDS: u32 = 1;
    pub const DEFAULT_MAX_TTL_SECONDS: u32 = 3600; // 1 hour max lease

    /// Creates a new JIT Credential Broker with default TTL bounds.
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            active_leases: Arc::new(RwLock::new(HashMap::new())),
            min_ttl_seconds: Self::DEFAULT_MIN_TTL_SECONDS,
            max_ttl_seconds: Self::DEFAULT_MAX_TTL_SECONDS,
        }
    }

    /// Configures custom minimum and maximum TTL bounds in seconds.
    pub fn with_ttl_bounds(mut self, min_seconds: u32, max_seconds: u32) -> Self {
        self.min_ttl_seconds = min_seconds;
        self.max_ttl_seconds = max_seconds;
        self
    }

    /// Registers a credential provider implementation for a given provider type.
    pub async fn register_provider(&self, provider: Arc<dyn CredentialProvider>) {
        let mut guard = self.providers.write().await;
        guard.insert(provider.provider_type(), provider);
    }

    /// Acquires an ephemeral lease wrapped in a RAII CredentialLeaseGuard.
    pub async fn acquire_lease_guard(
        &self,
        request: &CredentialRequest,
        decision: &PolicyDecision,
    ) -> Result<(CredentialLease, CredentialLeaseGuard), CredentialError> {
        let (lease, secret) = self.acquire_lease(request, decision).await?;
        let guard = CredentialLeaseGuard::new(lease.lease_id, secret, lease.expires_at);
        Ok((lease, guard))
    }

    /// Returns the number of currently tracked active leases.
    pub async fn active_lease_count(&self) -> usize {
        let guard = self.active_leases.read().await;
        guard.len()
    }

    /// Purges all expired leases from the tracking table.
    pub async fn purge_expired_leases(&self) -> usize {
        let mut guard = self.active_leases.write().await;
        let before = guard.len();
        guard.retain(|_, lease| !lease.is_expired() && lease.state == LeaseState::Issued);
        before - guard.len()
    }
}

impl Default for JitCredentialBroker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialBroker for JitCredentialBroker {
    async fn acquire_lease(
        &self,
        request: &CredentialRequest,
        decision: &PolicyDecision,
    ) -> Result<(CredentialLease, SecretBuffer), CredentialError> {
        // 1. Invariant: Policy decision MUST be explicitly Allow
        match decision.decision {
            PolicyDecisionType::Deny => {
                return Err(CredentialError::AccessDenied {
                    reason: decision
                        .reason
                        .clone()
                        .unwrap_or_else(|| "Denied by Cedar policy".to_string()),
                });
            }
            PolicyDecisionType::ApprovalRequired => {
                return Err(CredentialError::ApprovalRequired {
                    action_hash: request.action_hash.to_hex(),
                });
            }
            PolicyDecisionType::Allow => {}
        }

        // 2. Invariant: ActionHash of request MUST strictly match decision ActionHash (SI-006)
        if request.action_hash != decision.action_hash {
            return Err(CredentialError::ActionHashMismatch {
                request_hash: request.action_hash.to_hex(),
                decision_hash: decision.action_hash.to_hex(),
            });
        }

        // 3. Invariant: Scope must not be empty
        if request.scope.trim().is_empty() {
            return Err(CredentialError::InvalidScope {
                reason: "Credential request scope cannot be empty".to_string(),
            });
        }

        // 4. Invariant: Requested TTL must be within approved bounds
        if request.ttl_seconds < self.min_ttl_seconds || request.ttl_seconds > self.max_ttl_seconds
        {
            return Err(CredentialError::InvalidScope {
                reason: format!(
                    "Requested TTL of {}s is outside allowable bounds [{}s, {}s]",
                    request.ttl_seconds, self.min_ttl_seconds, self.max_ttl_seconds
                ),
            });
        }

        // 5. Lookup the appropriate registered provider
        let provider = {
            let guard = self.providers.read().await;
            guard
                .get(&request.provider)
                .cloned()
                .ok_or_else(|| CredentialError::NotFound {
                    provider: request.provider.to_string(),
                    key_alias: request.key_alias.clone(),
                })?
        };

        // 6. Retrieve the secret material into protected memory
        let secret = provider.get_secret(&request.key_alias).await?;

        // 7. Mint single-action ephemeral lease
        let lease = CredentialLease::new(
            request.action_hash,
            request.principal.clone(),
            request.provider,
            &request.key_alias,
            &request.target_system,
            &request.scope,
            request.ttl_seconds,
        );

        // 8. Register lease in active tracking table
        {
            let mut guard = self.active_leases.write().await;
            guard.insert(lease.lease_id, lease.clone());
        }

        Ok((lease, secret))
    }

    async fn validate_lease(&self, lease: &CredentialLease) -> Result<bool, CredentialError> {
        if lease.is_expired() {
            return Ok(false);
        }

        let guard = self.active_leases.read().await;
        if let Some(stored) = guard.get(&lease.lease_id) {
            Ok(stored.state == LeaseState::Issued
                && !stored.is_expired()
                && stored.action_hash == lease.action_hash)
        } else {
            Ok(false)
        }
    }

    async fn consume_lease(&self, lease_id: &LeaseId) -> Result<(), CredentialError> {
        let mut guard = self.active_leases.write().await;
        let lease = guard
            .get_mut(lease_id)
            .ok_or_else(|| CredentialError::LeaseExhausted {
                reason: format!("Lease {lease_id} not found in active broker store"),
            })?;

        if lease.is_expired() {
            lease.state = LeaseState::Expired;
            return Err(CredentialError::LeaseExpired {
                lease_id: lease_id.to_string(),
            });
        }

        match lease.state {
            LeaseState::Issued => {
                lease.state = LeaseState::Consumed;
                Ok(())
            }
            LeaseState::Consumed => Err(CredentialError::LeaseAlreadyConsumed {
                lease_id: lease_id.to_string(),
            }),
            LeaseState::Revoked => Err(CredentialError::LeaseRevoked {
                lease_id: lease_id.to_string(),
            }),
            LeaseState::Expired => Err(CredentialError::LeaseExpired {
                lease_id: lease_id.to_string(),
            }),
        }
    }

    async fn revoke_lease(&self, lease_id: &LeaseId) -> Result<(), CredentialError> {
        let mut guard = self.active_leases.write().await;
        let lease = guard
            .get_mut(lease_id)
            .ok_or_else(|| CredentialError::LeaseExhausted {
                reason: format!("Lease {lease_id} not found in active broker store"),
            })?;

        lease.state = LeaseState::Revoked;
        Ok(())
    }
}
