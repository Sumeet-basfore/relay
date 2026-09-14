use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use relay_domain::egress::{NetworkEndpoint, ProxyLease, ProxySessionId};
use relay_domain::error::{InvariantViolationError, RelayError};
use relay_domain::id::ActionHash;
use relay_domain::principal::Principal;

/// Default TTL for ephemeral proxy lease tokens (30 seconds per M001/M002 specification)
pub const DEFAULT_PROXY_LEASE_TTL_SECS: u64 = 30;

/// In-memory manager for ephemeral proxy leases and token validation (SI-020)
#[derive(Debug, Clone, Default)]
pub struct ProxySessionManager {
    sessions: Arc<RwLock<HashMap<String, ProxyLease>>>,
}

impl ProxySessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new time-bounded ephemeral proxy lease tied to an ActionHash and Principal (SI-020)
    pub async fn create_lease(
        &self,
        action_hash: ActionHash,
        principal: Principal,
        endpoint: Option<NetworkEndpoint>,
        ttl_seconds: Option<u64>,
    ) -> (ProxySessionId, String) {
        let ttl = ttl_seconds.unwrap_or(DEFAULT_PROXY_LEASE_TTL_SECS);
        let session_id = ProxySessionId::new();
        let token = format!("relay-lease-{}", Uuid::now_v7());

        let lease = ProxyLease::new(
            session_id.clone(),
            token.clone(),
            action_hash,
            principal,
            endpoint,
            ttl,
        );

        let mut lock = self.sessions.write().await;
        lock.insert(token.clone(), lease);

        (session_id, token)
    }

    /// Validate an incoming proxy token against active leases (SI-020)
    pub async fn validate_lease(
        &self,
        token: &str,
        target_endpoint: Option<&NetworkEndpoint>,
    ) -> Result<ProxyLease, RelayError> {
        let mut lock = self.sessions.write().await;
        let lease = lock.get_mut(token).ok_or(RelayError::InvariantViolation(
            InvariantViolationError::EphemeralProxySessionInvalid,
        ))?;

        // Check expiration
        lease.check_expiration();
        if !lease.is_valid() {
            return Err(RelayError::InvariantViolation(
                InvariantViolationError::EphemeralProxySessionInvalid,
            ));
        }

        // Check endpoint restriction if specified on lease
        if let (Some(bound_endpoint), Some(requested_endpoint)) = (&lease.endpoint, target_endpoint)
        {
            if bound_endpoint.host != requested_endpoint.host
                || bound_endpoint.port != requested_endpoint.port
            {
                return Err(RelayError::InvariantViolation(
                    InvariantViolationError::EphemeralProxySessionInvalid,
                ));
            }
        }

        Ok(lease.clone())
    }

    /// Burn / revoke an individual lease token
    pub async fn burn_lease(&self, token: &str) {
        let mut lock = self.sessions.write().await;
        if let Some(lease) = lock.get_mut(token) {
            lease.mark_consumed();
        }
    }

    /// Burn all leases associated with a specific ActionHash upon tool completion
    pub async fn burn_action_leases(&self, action_hash: &ActionHash) {
        let mut lock = self.sessions.write().await;
        for lease in lock.values_mut() {
            if &lease.action_hash == action_hash {
                lease.mark_consumed();
            }
        }
    }

    /// Clean up expired or consumed leases
    pub async fn cleanup(&self) {
        let mut lock = self.sessions.write().await;
        lock.retain(|_, lease| lease.is_valid());
    }
}
