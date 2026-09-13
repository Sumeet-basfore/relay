use tempfile::tempdir;

use relay_credentials::{
    EncryptedFileCredentialProvider, InMemoryCredentialProvider, KeyringCredentialProvider,
};
use relay_domain::credential::CredentialProviderType;
use relay_domain::error::CredentialError;
use relay_domain::security::SecretBuffer;
use relay_domain::traits::CredentialProvider;

#[tokio::test]
async fn test_in_memory_provider_lifecycle() {
    let provider = InMemoryCredentialProvider::new(CredentialProviderType::KeyringStatic);
    assert_eq!(
        provider.provider_type(),
        CredentialProviderType::KeyringStatic
    );

    // Initial state: missing secret returns NotFound
    let missing_res = provider.get_secret("gh_token").await;
    match missing_res {
        Err(CredentialError::NotFound {
            provider,
            key_alias,
        }) => {
            assert_eq!(provider, "keyring_static");
            assert_eq!(key_alias, "gh_token");
        }
        other => panic!("Expected NotFound, got {other:?}"),
    }

    // Set secret
    let raw_secret = b"ghp_testsecret1234567890abcdef";
    let secret_buf = SecretBuffer::from_slice(raw_secret);
    provider
        .set_secret("gh_token", &secret_buf)
        .await
        .expect("set_secret should succeed");

    // Get secret
    let retrieved = provider
        .get_secret("gh_token")
        .await
        .expect("get_secret should succeed");
    assert_eq!(retrieved.as_bytes(), raw_secret);

    // List secrets
    provider
        .set_secret(
            "aws_key",
            &SecretBuffer::from_slice(b"AKIAIOSFODNN7EXAMPLE"),
        )
        .await
        .expect("set_secret aws should succeed");

    let keys = provider
        .list_secrets()
        .await
        .expect("list_secrets should succeed");
    assert_eq!(keys, vec!["aws_key".to_string(), "gh_token".to_string()]);

    // Delete secret
    provider
        .delete_secret("gh_token")
        .await
        .expect("delete_secret should succeed");
    let after_delete = provider.get_secret("gh_token").await;
    assert!(matches!(
        after_delete,
        Err(CredentialError::NotFound { .. })
    ));
}

#[tokio::test]
async fn test_encrypted_file_provider_lifecycle() {
    let tmp = tempdir().expect("tempdir");
    let master_key = b"super-secret-master-key-32-bytes";
    let provider = EncryptedFileCredentialProvider::new(tmp.path(), master_key)
        .expect("EncryptedFileCredentialProvider creation");

    // Verify empty lookup returns NotFound
    let missing = provider.get_secret("database_pwd").await;
    assert!(matches!(missing, Err(CredentialError::NotFound { .. })));

    // Store secret
    let raw_secret = b"postgres://app:secret123@10.0.0.1:5432/db";
    let buf = SecretBuffer::from_slice(raw_secret);
    provider
        .set_secret("database_pwd", &buf)
        .await
        .expect("Store secret");

    // Verify file created with strict 0600 mode on Unix
    let key_file = tmp.path().join("database_pwd.key");
    assert!(key_file.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&key_file).expect("metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Credential file permissions must be 0600, got {mode:o}"
        );
    }

    // Read back secret
    let retrieved = provider
        .get_secret("database_pwd")
        .await
        .expect("Retrieve secret");
    assert_eq!(retrieved.as_bytes(), raw_secret);

    // List secrets
    let keys = provider.list_secrets().await.expect("list_secrets");
    assert_eq!(keys, vec!["database_pwd".to_string()]);

    // Delete secret
    provider
        .delete_secret("database_pwd")
        .await
        .expect("delete");
    assert!(!key_file.exists());
    assert!(matches!(
        provider.get_secret("database_pwd").await,
        Err(CredentialError::NotFound { .. })
    ));
}

#[tokio::test]
async fn test_encrypted_file_provider_tamper_detection() {
    let tmp = tempdir().expect("tempdir");
    let master_key = b"master-key-tamper-test";
    let provider = EncryptedFileCredentialProvider::new(tmp.path(), master_key)
        .expect("EncryptedFileCredentialProvider");

    let buf = SecretBuffer::from_slice(b"plaintext-token-value");
    provider
        .set_secret("tamper_key", &buf)
        .await
        .expect("store");

    let key_file = tmp.path().join("tamper_key.key");
    let mut file_bytes = std::fs::read(&key_file).expect("read raw");

    // Corrupt one byte in the MAC or ciphertext
    let last_idx = file_bytes.len() - 1;
    file_bytes[last_idx] ^= 0xFF;
    std::fs::write(&key_file, &file_bytes).expect("write corrupted");

    // Tampered file MUST fail authentication
    let err = provider.get_secret("tamper_key").await.unwrap_err();
    match err {
        CredentialError::ProviderError { reason } => {
            assert!(
                reason.contains("integrity verification failed"),
                "Expected integrity verification error, got {reason}"
            );
        }
        other => panic!("Expected ProviderError, got {other:?}"),
    }
}

#[tokio::test]
async fn test_keyring_provider_error_hygiene() {
    // Keyring provider with test namespace
    let provider = KeyringCredentialProvider::new("io.relay.test.unit");

    // Looking up non-existent secret in OS keyring
    let res = provider.get_secret("missing_test_key_99999").await;
    match res {
        Err(CredentialError::NotFound {
            provider,
            key_alias,
        }) => {
            assert_eq!(provider, "keyring");
            assert_eq!(key_alias, "missing_test_key_99999");
        }
        Err(CredentialError::KeyringUnavailable { reason }) => {
            // In headless/container environments without D-Bus SecretService daemon,
            // keyring fails gracefully with KeyringUnavailable
            assert!(
                !reason.contains("secret"),
                "Reason must not leak secret material"
            );
        }
        Ok(_) => panic!("Non-existent key should not return Ok"),
        Err(other) => panic!("Unexpected error type: {other:?}"),
    }
}

#[tokio::test]
async fn test_keyring_provider_no_plaintext_in_display_or_debug() {
    let provider = KeyringCredentialProvider::new("io.relay.test.hygiene");
    let secret = SecretBuffer::from_slice(b"super_confidential_token_xyz");

    // Ensure debug/display on provider does not expose secrets
    let dbg_str = format!("{:?}", secret);
    let dsp_str = format!("{}", secret);

    assert!(!dbg_str.contains("super_confidential_token_xyz"));
    assert!(!dsp_str.contains("super_confidential_token_xyz"));
    assert!(dbg_str.contains("[REDACTED 28 bytes]"));
    assert_eq!(dsp_str, "[REDACTED SECRET]");

    // Try set_secret (may succeed if OS keyring is present, or return KeyringUnavailable)
    let _ = provider.set_secret("hygiene_test_key", &secret).await;
}
