use std::sync::Arc;
use std::time::Duration;

use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::authorization::PolicyDecision;
use relay_domain::credential::{CredentialProviderType, CredentialRequest, LeaseState};
use relay_domain::error::CredentialError;
use relay_domain::id::{ActionHash, Digest, PrincipalId};
use relay_domain::resource::ResourceUri;
use relay_domain::traits::CredentialBroker;

async fn setup_broker_with_fixture() -> (JitCredentialBroker, ActionHash, PrincipalId, ResourceUri)
{
    let broker = JitCredentialBroker::new();
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret("github_token", b"ghp_testtoken12345".to_vec())
        .await;
    broker.register_provider(provider).await;

    let action_hash = ActionHash::from_hex(&"a".repeat(64)).unwrap();
    let principal = PrincipalId::new("principal:agent-007").unwrap();
    let resource = ResourceUri::parse("https://api.github.com/repos/relay/core").unwrap();

    (broker, action_hash, principal, resource)
}

#[tokio::test]
async fn test_lease_issuance_and_binding() {
    let (broker, action_hash, principal, resource) = setup_broker_with_fixture().await;

    let request = CredentialRequest::new(
        action_hash,
        principal.clone(),
        resource.clone(),
        CredentialProviderType::KeyringStatic,
        "github_token",
        "https://api.github.com",
        "repo:write",
        60,
    );

    let decision = PolicyDecision::allow(
        action_hash,
        Digest::compute(b"policy"),
        vec!["permit_rule".to_string()],
    );

    let (lease, secret) = broker
        .acquire_lease(&request, &decision)
        .await
        .expect("Acquire lease should succeed");

    assert_eq!(lease.action_hash, action_hash);
    assert_eq!(lease.principal, principal);
    assert_eq!(lease.state, LeaseState::Issued);
    assert_eq!(lease.scoped_resource, "repo:write");
    assert!(!lease.is_expired());
    assert_eq!(secret.as_bytes(), b"ghp_testtoken12345");

    // Validate in-flight lease
    let is_valid = broker.validate_lease(&lease).await.expect("validate_lease");
    assert!(is_valid);
}

#[tokio::test]
async fn test_action_hash_mismatch_rejection() {
    let (broker, action_hash, principal, resource) = setup_broker_with_fixture().await;

    let request = CredentialRequest::new(
        action_hash,
        principal,
        resource,
        CredentialProviderType::KeyringStatic,
        "github_token",
        "https://api.github.com",
        "repo:write",
        60,
    );

    // Mismatched ActionHash in decision
    let forged_action_hash = ActionHash::from_hex(&"b".repeat(64)).unwrap();
    let decision = PolicyDecision::allow(
        forged_action_hash,
        Digest::compute(b"policy"),
        vec!["permit_rule".to_string()],
    );

    let err = broker
        .acquire_lease(&request, &decision)
        .await
        .expect_err("Should reject mismatched action hash");

    match err {
        CredentialError::ActionHashMismatch {
            request_hash,
            decision_hash,
        } => {
            assert_eq!(request_hash, action_hash.to_hex());
            assert_eq!(decision_hash, forged_action_hash.to_hex());
        }
        other => panic!("Expected ActionHashMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn test_invalid_scope_rejection() {
    let (broker, action_hash, principal, resource) = setup_broker_with_fixture().await;

    let decision = PolicyDecision::allow(
        action_hash,
        Digest::compute(b"policy"),
        vec!["permit_rule".to_string()],
    );

    // 1. Empty scope
    let empty_scope_req = CredentialRequest::new(
        action_hash,
        principal.clone(),
        resource.clone(),
        CredentialProviderType::KeyringStatic,
        "github_token",
        "https://api.github.com",
        "   ",
        60,
    );
    let err = broker
        .acquire_lease(&empty_scope_req, &decision)
        .await
        .unwrap_err();
    assert!(matches!(err, CredentialError::InvalidScope { .. }));

    // 2. TTL = 0
    let zero_ttl_req = CredentialRequest::new(
        action_hash,
        principal.clone(),
        resource.clone(),
        CredentialProviderType::KeyringStatic,
        "github_token",
        "https://api.github.com",
        "repo:read",
        0,
    );
    let err = broker
        .acquire_lease(&zero_ttl_req, &decision)
        .await
        .unwrap_err();
    assert!(matches!(err, CredentialError::InvalidScope { .. }));

    // 3. TTL exceeds maximum (e.g. > 3600)
    let huge_ttl_req = CredentialRequest::new(
        action_hash,
        principal,
        resource,
        CredentialProviderType::KeyringStatic,
        "github_token",
        "https://api.github.com",
        "repo:read",
        100_000,
    );
    let err = broker
        .acquire_lease(&huge_ttl_req, &decision)
        .await
        .unwrap_err();
    assert!(matches!(err, CredentialError::InvalidScope { .. }));
}

#[tokio::test]
async fn test_single_use_lease_consumption_si_006() {
    let (broker, action_hash, principal, resource) = setup_broker_with_fixture().await;

    let request = CredentialRequest::new(
        action_hash,
        principal,
        resource,
        CredentialProviderType::KeyringStatic,
        "github_token",
        "https://api.github.com",
        "repo:read",
        60,
    );

    let decision = PolicyDecision::allow(
        action_hash,
        Digest::compute(b"policy"),
        vec!["permit_rule".to_string()],
    );

    let (mut lease, _secret) = broker
        .acquire_lease(&request, &decision)
        .await
        .expect("Acquire");

    // First consumption in broker
    broker
        .consume_lease(&lease.lease_id)
        .await
        .expect("Consume should succeed");

    // Local model transition
    lease.consume().expect("Local lease consumption");
    assert_eq!(lease.state, LeaseState::Consumed);

    // Validate returns false once consumed
    assert!(!broker.validate_lease(&lease).await.unwrap());

    // Second consumption MUST fail (SI-006: single-use affine token)
    let double_consume = broker.consume_lease(&lease.lease_id).await;
    assert!(matches!(
        double_consume,
        Err(CredentialError::LeaseAlreadyConsumed { .. })
    ));
}

#[tokio::test]
async fn test_lease_revocation() {
    let (broker, action_hash, principal, resource) = setup_broker_with_fixture().await;

    let request = CredentialRequest::new(
        action_hash,
        principal,
        resource,
        CredentialProviderType::KeyringStatic,
        "github_token",
        "https://api.github.com",
        "repo:read",
        60,
    );

    let decision = PolicyDecision::allow(
        action_hash,
        Digest::compute(b"policy"),
        vec!["permit_rule".to_string()],
    );

    let (lease, _secret) = broker.acquire_lease(&request, &decision).await.unwrap();

    // Revoke
    broker
        .revoke_lease(&lease.lease_id)
        .await
        .expect("Revoke should succeed");

    // Validate returns false after revocation
    assert!(!broker.validate_lease(&lease).await.unwrap());

    // Consumption after revocation fails with LeaseRevoked
    let err = broker.consume_lease(&lease.lease_id).await.unwrap_err();
    assert!(matches!(err, CredentialError::LeaseRevoked { .. }));
}

#[tokio::test]
async fn test_lease_expiry_and_purge() {
    let (broker, action_hash, principal, resource) = setup_broker_with_fixture().await;

    let request = CredentialRequest::new(
        action_hash,
        principal,
        resource,
        CredentialProviderType::KeyringStatic,
        "github_token",
        "https://api.github.com",
        "repo:read",
        1, // 1 second TTL
    );

    let decision = PolicyDecision::allow(
        action_hash,
        Digest::compute(b"policy"),
        vec!["permit_rule".to_string()],
    );

    let (lease, _secret) = broker.acquire_lease(&request, &decision).await.unwrap();
    assert!(broker.validate_lease(&lease).await.unwrap());

    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Must report expired
    assert!(lease.is_expired());
    assert!(!broker.validate_lease(&lease).await.unwrap());

    // Consumption of expired lease fails
    let err = broker.consume_lease(&lease.lease_id).await.unwrap_err();
    assert!(matches!(err, CredentialError::LeaseExpired { .. }));

    // Purge sweeps the expired lease
    let purged = broker.purge_expired_leases().await;
    assert_eq!(purged, 1);
    assert_eq!(broker.active_lease_count().await, 0);
}
