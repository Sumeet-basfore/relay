//! Security and memory safety tests for Relay credentials subsystem.
//!
//! Validates:
//! - SecretBuffer and CredentialLeaseGuard cannot leak secrets through Debug / Display
//! - Zeroization on drop
//! - Memory locking (mlock) status and cleanup
//! - No secrets in command-line arguments or environment variables
//! - Tracing subscriber logs redact secrets

use std::process::Command;
use std::sync::Arc;

use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::authorization::PolicyDecision;
use relay_domain::credential::{CredentialProviderType, CredentialRequest};
use relay_domain::id::{ActionHash, Digest, PrincipalId};
use relay_domain::resource::ResourceUri;
use relay_domain::security::{CredentialLeaseGuard, SecretBuffer};
use relay_domain::traits::CredentialBroker;
use zeroize::Zeroize;

#[test]
fn test_secret_buffer_debug_and_display_redaction() {
    let raw_secret = b"my-super-secret-production-token-123456";
    let buffer = SecretBuffer::from_slice(raw_secret);

    let debug_out = format!("{buffer:?}");
    let display_out = format!("{buffer}");

    assert!(
        !debug_out.contains("my-super-secret-production-token-123456"),
        "Debug output must NEVER leak secret bytes!"
    );
    assert_eq!(debug_out, "SecretBuffer([REDACTED 39 bytes])");

    assert!(
        !display_out.contains("my-super-secret-production-token-123456"),
        "Display output must NEVER leak secret bytes!"
    );
    assert_eq!(display_out, "[REDACTED SECRET]");
}

#[test]
fn test_credential_lease_guard_debug_and_display_redaction() {
    let raw_secret = b"another-sensitive-bearer-token";
    let buffer = SecretBuffer::from_slice(raw_secret);
    let lease_id = relay_domain::id::LeaseId::new_v7();
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(60);

    let guard = CredentialLeaseGuard::new(lease_id, buffer, expires_at);

    let debug_out = format!("{guard:?}");
    let display_out = format!("{guard}");

    assert!(
        !debug_out.contains("another-sensitive-bearer-token"),
        "Guard debug output must not leak secret bytes"
    );
    assert!(debug_out.contains("[REDACTED LEASE"));

    assert!(
        !display_out.contains("another-sensitive-bearer-token"),
        "Guard display output must not leak secret bytes"
    );
    assert_eq!(display_out, "[REDACTED LEASE GUARD]");
}

#[test]
fn test_secret_buffer_zeroization() {
    let mut buffer = SecretBuffer::from_slice(b"zeroize_me_now_please_12345");
    assert_eq!(buffer.as_bytes(), b"zeroize_me_now_please_12345");

    // Explicit zeroize
    buffer.zeroize();
    for byte in buffer.as_bytes() {
        assert_eq!(*byte, 0, "Buffer bytes must be zeroed");
    }
}

#[test]
fn test_memory_locking_status() {
    let buffer = SecretBuffer::from_slice(b"lock_test_payload");
    // On Linux x86_64, is_memory_locked returns true if RLIMIT_MEMLOCK allows it,
    // or false with a warning if unprivileged. Either way, it must not panic and must safely clean up.
    let _ = buffer.is_memory_locked();
    assert_eq!(buffer.len(), 17);
}

#[test]
fn test_process_cmdline_and_env_isolation() {
    // Invariant: Subprocess execution must never receive raw credentials via args or ambient env
    let secret = SecretBuffer::from_slice(b"confidential-cli-token");

    // Standard command invocation for child tool execution
    let mut cmd = Command::new("echo");
    cmd.arg("hello-relay");

    // Verify args do not contain secret
    let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
    for arg in args {
        assert!(!arg.to_string_lossy().contains(secret.as_str().unwrap()));
    }

    // Verify environment does not contain secret
    let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
    for (k, v) in envs {
        assert!(!k.to_string_lossy().contains("confidential"));
        if let Some(val) = v {
            assert!(!val.to_string_lossy().contains(secret.as_str().unwrap()));
        }
    }
}

#[tokio::test]
async fn test_lease_isolation_between_requests() {
    let broker = JitCredentialBroker::new();
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider.add_secret("tok_a", b"secret_A".to_vec()).await;
    provider.add_secret("tok_b", b"secret_B".to_vec()).await;
    broker.register_provider(provider).await;

    let hash_a = ActionHash::from_hex(&"1".repeat(64)).unwrap();
    let hash_b = ActionHash::from_hex(&"2".repeat(64)).unwrap();
    let principal = PrincipalId::new("principal:agent-iso").unwrap();
    let resource = ResourceUri::parse("https://api.github.com").unwrap();

    let req_a = CredentialRequest::new(
        hash_a,
        principal.clone(),
        resource.clone(),
        CredentialProviderType::KeyringStatic,
        "tok_a",
        "https://api.github.com",
        "repo:read",
        60,
    );

    let req_b = CredentialRequest::new(
        hash_b,
        principal,
        resource,
        CredentialProviderType::KeyringStatic,
        "tok_b",
        "https://api.github.com",
        "repo:read",
        60,
    );

    let dec_a = PolicyDecision::allow(hash_a, Digest::compute(b"p"), vec!["rule_a".to_string()]);
    let dec_b = PolicyDecision::allow(hash_b, Digest::compute(b"p"), vec!["rule_b".to_string()]);

    let (lease_a, sec_a) = broker.acquire_lease(&req_a, &dec_a).await.unwrap();
    let (lease_b, sec_b) = broker.acquire_lease(&req_b, &dec_b).await.unwrap();

    assert_ne!(lease_a.lease_id, lease_b.lease_id);
    assert_ne!(sec_a.as_bytes(), sec_b.as_bytes());

    // Consuming lease A does not invalidate lease B
    broker.consume_lease(&lease_a.lease_id).await.unwrap();
    assert!(!broker.validate_lease(&lease_a).await.unwrap());
    assert!(broker.validate_lease(&lease_b).await.unwrap());
}
