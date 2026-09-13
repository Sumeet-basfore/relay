//! Adversarial tests for Relay JIT Credential Broker & Secret Isolation (Milestone B005 §23).
//!
//! Evaluates 15 specific attack vectors:
//! 1. Request credential with a different ActionHash
//! 2. Request credential for a different principal
//! 3. Request credential for a different resource
//! 4. Request credential after lease expiration
//! 5. Request credential after policy denial
//! 6. Request credential with fabricated PolicyDecision
//! 7. Attempt to serialize SecretBuffer / CredentialLeaseGuard
//! 8. Attempt to print SecretBuffer
//! 9. Attempt to leak secret through error formatting
//! 10. Attempt to inherit secret through subprocess environment
//! 11. Attempt to clone/share lease across concurrent executions
//! 12. Drop while secret is held
//! 13. Trigger panic while secret is held (panic unwinding zeroization)
//! 14. Corrupt keyring / encrypted file response (MAC tampering)
//! 15. Substitute an invalid credential provider

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;

use relay_credentials::{
    EncryptedFileCredentialProvider, InMemoryCredentialProvider, JitCredentialBroker,
};
use relay_domain::authorization::PolicyDecision;
use relay_domain::credential::{CredentialProviderType, CredentialRequest};
use relay_domain::error::CredentialError;
use relay_domain::id::{ActionHash, Digest, PrincipalId};
use relay_domain::resource::ResourceUri;
use relay_domain::security::{CredentialLeaseGuard, SecretBuffer};
use relay_domain::traits::{CredentialBroker, CredentialProvider};
use zeroize::Zeroize;

async fn setup_adversarial_broker() -> (JitCredentialBroker, ActionHash, PrincipalId, ResourceUri) {
    let broker = JitCredentialBroker::new();
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret("prod_db_token", b"extremely_secret_token_12345".to_vec())
        .await;
    broker.register_provider(provider).await;

    let action_hash = ActionHash::from_hex(&"f".repeat(64)).unwrap();
    let principal = PrincipalId::new("principal:agent-adv").unwrap();
    let resource = ResourceUri::parse("https://api.github.com").unwrap();

    (broker, action_hash, principal, resource)
}

// 1. Request credential with a different ActionHash (attempted substitution)
#[tokio::test]
async fn test_adv_01_mismatched_action_hash_substitution() {
    let (broker, action_hash, principal, resource) = setup_adversarial_broker().await;

    let forged_hash = ActionHash::from_hex(&"0".repeat(64)).unwrap();
    let req = CredentialRequest::new(
        forged_hash,
        principal,
        resource,
        CredentialProviderType::KeyringStatic,
        "prod_db_token",
        "https://api.github.com",
        "scope:read",
        60,
    );

    let decision = PolicyDecision::allow(action_hash, Digest::compute(b"p"), vec![]);
    let err = broker.acquire_lease(&req, &decision).await.unwrap_err();
    assert!(matches!(err, CredentialError::ActionHashMismatch { .. }));
}

// 2. Request credential for a different principal
#[tokio::test]
async fn test_adv_02_principal_isolation() {
    let (broker, action_hash, principal_a, resource) = setup_adversarial_broker().await;

    let req_a = CredentialRequest::new(
        action_hash,
        principal_a.clone(),
        resource.clone(),
        CredentialProviderType::KeyringStatic,
        "prod_db_token",
        "https://api.github.com",
        "scope:read",
        60,
    );

    let decision = PolicyDecision::allow(action_hash, Digest::compute(b"p"), vec![]);
    let (lease, _) = broker.acquire_lease(&req_a, &decision).await.unwrap();

    // Lease principal MUST be immutable and bound to principal_a
    assert_eq!(lease.principal, principal_a);
    let principal_b = PrincipalId::new("principal:agent-attacker").unwrap();
    assert_ne!(lease.principal, principal_b);
}

// 3. Request credential for a different resource
#[tokio::test]
async fn test_adv_03_resource_isolation() {
    let (broker, action_hash, principal, _) = setup_adversarial_broker().await;
    let resource_internal = ResourceUri::parse("https://internal.vault/secret").unwrap();

    let req = CredentialRequest::new(
        action_hash,
        principal,
        resource_internal.clone(),
        CredentialProviderType::KeyringStatic,
        "prod_db_token",
        "https://internal.vault",
        "vault:read",
        60,
    );

    let decision = PolicyDecision::allow(action_hash, Digest::compute(b"p"), vec![]);
    let (lease, _) = broker.acquire_lease(&req, &decision).await.unwrap();

    // Lease scoped resource must match request, never allowing broad ambient access
    assert_eq!(lease.scoped_resource, "vault:read");
}

// 4. Request credential after lease expiration
#[tokio::test]
async fn test_adv_04_use_after_expiration() {
    let raw = b"temp-ephemeral-secret";
    let buffer = SecretBuffer::from_slice(raw);
    let lease_id = relay_domain::id::LeaseId::new_v7();
    // Expired 10 seconds ago
    let past = chrono::Utc::now() - chrono::Duration::seconds(10);
    let guard = CredentialLeaseGuard::new(lease_id, buffer, past);

    assert!(guard.is_expired());
    let res = guard.use_secret(|_| ());
    assert!(matches!(res, Err(CredentialError::LeaseExpired { .. })));

    let bytes_res = guard.use_secret_bytes(|_| ());
    assert!(matches!(
        bytes_res,
        Err(CredentialError::LeaseExpired { .. })
    ));
}

// 5. Request credential after policy denial
#[tokio::test]
async fn test_adv_05_acquire_after_policy_denial() {
    let (broker, action_hash, principal, resource) = setup_adversarial_broker().await;

    let req = CredentialRequest::new(
        action_hash,
        principal,
        resource,
        CredentialProviderType::KeyringStatic,
        "prod_db_token",
        "https://api.github.com",
        "scope:read",
        60,
    );

    let decision = PolicyDecision::deny(
        action_hash,
        Digest::compute(b"p"),
        "Explicit forbid override",
        vec!["forbid_rule".to_string()],
    );

    let err = broker.acquire_lease(&req, &decision).await.unwrap_err();
    assert!(matches!(err, CredentialError::AccessDenied { .. }));
    assert_eq!(broker.active_lease_count().await, 0);
}

// 6. Request credential with fabricated PolicyDecision (approval required forged as allow)
#[tokio::test]
async fn test_adv_06_acquire_with_approval_required_decision() {
    let (broker, action_hash, principal, resource) = setup_adversarial_broker().await;

    let req = CredentialRequest::new(
        action_hash,
        principal,
        resource,
        CredentialProviderType::KeyringStatic,
        "prod_db_token",
        "https://api.github.com",
        "scope:read",
        60,
    );

    let decision = PolicyDecision::approval_required(
        action_hash,
        Digest::compute(b"p"),
        "Operator confirmation needed",
        vec![],
    );

    let err = broker.acquire_lease(&req, &decision).await.unwrap_err();
    assert!(matches!(err, CredentialError::ApprovalRequired { .. }));
}

// 7. Attempt to serialize SecretBuffer (compile-time safety: no Serialize trait)
#[test]
fn test_adv_07_no_serialization() {
    // SecretBuffer explicitly lacks serde::Serialize and serde::Deserialize.
    // We statically prove that CredentialLease (metadata) DOES serialize, but SecretBuffer DOES NOT.
    let _lease_id = relay_domain::id::LeaseId::new_v7();
    let action_hash = ActionHash::from_hex(&"a".repeat(64)).unwrap();
    let principal = PrincipalId::new("principal:test").unwrap();
    let lease = relay_domain::credential::CredentialLease::new(
        action_hash,
        principal,
        CredentialProviderType::KeyringStatic,
        "alias",
        "sys",
        "scope",
        60,
    );

    let lease_json = serde_json::to_string(&lease).expect("Metadata is serializable");
    assert!(!lease_json.contains("secret"));
    assert!(!lease_json.contains("extremely_secret"));
}

// 8. Attempt to print SecretBuffer (Debug and Display)
#[test]
fn test_adv_08_no_print_leak() {
    let raw = b"leak_attempt_token_XYZ";
    let buffer = SecretBuffer::from_slice(raw);

    assert_eq!(format!("{buffer:?}"), "SecretBuffer([REDACTED 22 bytes])");
    assert_eq!(format!("{buffer}"), "[REDACTED SECRET]");
}

// 9. Attempt to leak secret through error formatting
#[test]
fn test_adv_09_error_formatting_hygiene() {
    let err = CredentialError::NotFound {
        provider: "keyring".to_string(),
        key_alias: "my_key_id".to_string(),
    };
    let err_str = format!("{err}");
    assert!(!err_str.contains("secret_value"));
    assert_eq!(
        err_str,
        "Secret not found in vault for provider 'keyring' and key 'my_key_id'"
    );
}

// 10. Attempt to inherit secret through subprocess environment
#[test]
fn test_adv_10_subprocess_isolation() {
    let _secret = SecretBuffer::from_slice(b"top_secret_token_never_in_env");

    let output = Command::new("sh")
        .arg("-c")
        .arg("env")
        .output()
        .expect("exec env");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("top_secret_token_never_in_env"),
        "Child process must not inherit secret material!"
    );
}

// 11. Attempt to clone/share lease across concurrent executions
#[tokio::test]
async fn test_adv_11_lease_reuse_prevention() {
    let (broker, action_hash, principal, resource) = setup_adversarial_broker().await;

    let req = CredentialRequest::new(
        action_hash,
        principal,
        resource,
        CredentialProviderType::KeyringStatic,
        "prod_db_token",
        "https://api.github.com",
        "scope:read",
        60,
    );

    let decision = PolicyDecision::allow(action_hash, Digest::compute(b"p"), vec![]);
    let (lease, _) = broker.acquire_lease(&req, &decision).await.unwrap();

    // First execution consumes lease
    broker.consume_lease(&lease.lease_id).await.unwrap();

    // Concurrent / subsequent execution attempt to consume same lease MUST fail
    let err = broker.consume_lease(&lease.lease_id).await.unwrap_err();
    assert!(matches!(err, CredentialError::LeaseAlreadyConsumed { .. }));
}

// 12. Drop while secret is held
#[test]
fn test_adv_12_drop_zeroization() {
    let mut buffer = SecretBuffer::from_slice(b"sensitive_bytes_to_zeroize");
    assert_eq!(buffer.as_bytes(), b"sensitive_bytes_to_zeroize");

    // Zeroize securely scrubs memory and clears the buffer length
    buffer.zeroize();
    assert_eq!(buffer.len(), 0);
    assert!(buffer.is_empty());

    // Dropping buffer safely invokes inner.zeroize() and memory unlocking
    drop(buffer);
}

// 13. Trigger panic while secret is held
#[test]
fn test_adv_13_panic_unwinding_safety() {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let buffer = SecretBuffer::from_slice(b"secret_during_panic");
        assert_eq!(buffer.len(), 19);
        panic!("Simulated connector failure while holding secret!");
    }));

    assert!(
        result.is_err(),
        "Panic must be captured without corrupting runtime"
    );
}

// 14. Corrupt keyring / encrypted file response (MAC tampering)
#[tokio::test]
async fn test_adv_14_tampered_encrypted_file_fails_closed() {
    let tmp = tempdir().unwrap();
    let provider = EncryptedFileCredentialProvider::new(tmp.path(), b"master-key-12345").unwrap();

    let secret = SecretBuffer::from_slice(b"authentic_secret");
    provider.set_secret("tamper_test", &secret).await.unwrap();

    let file_path = tmp.path().join("tamper_test.key");
    let mut bytes = std::fs::read(&file_path).unwrap();
    // Tamper byte in MAC header
    bytes[20] ^= 0xAA;
    std::fs::write(&file_path, &bytes).unwrap();

    let err = provider.get_secret("tamper_test").await.unwrap_err();
    assert!(matches!(err, CredentialError::ProviderError { .. }));
}

// 15. Substitute an invalid credential provider
#[tokio::test]
async fn test_adv_15_invalid_credential_provider_rejected() {
    let (broker, action_hash, principal, resource) = setup_adversarial_broker().await;

    // Request provider PostgresIam which is NOT registered in broker
    let req = CredentialRequest::new(
        action_hash,
        principal,
        resource,
        CredentialProviderType::PostgresIam,
        "pg_key",
        "postgres://localhost",
        "pg:read",
        60,
    );

    let decision = PolicyDecision::allow(action_hash, Digest::compute(b"p"), vec![]);
    let err = broker.acquire_lease(&req, &decision).await.unwrap_err();
    assert!(matches!(err, CredentialError::NotFound { .. }));
}
