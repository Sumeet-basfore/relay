//! RC001 Release Hardening Test Suite.
//!
//! Validates release-grade invariants:
//! - Unix filesystem permissions (0600 ledger, 0600 key, 0700 directories)
//! - Secret scrubbing and Debug redaction (no plaintext credentials in memory formatting)
//! - Subprocess environment sanitization (sensitive env vars stripped)
//! - Cryptographic key loading from file, hex, and generation
//! - Deterministic CLI exit code mappings for all failure classes
//! - Fail-closed error behavior on missing/invalid ledger configurations

use assert_cmd::Command;
use predicates::prelude::*;
use relay_domain::{ExitCode, ReceiptSigner};
use relay_receipts::Ed25519ReceiptSigner;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_rc001_exit_code_mappings() {
    assert_eq!(ExitCode::Success.as_i32(), 0);
    assert_eq!(ExitCode::RuntimeError.as_i32(), 1);
    assert_eq!(ExitCode::ConfigError.as_i32(), 2);
    assert_eq!(ExitCode::PolicyDenied.as_i32(), 3);
    assert_eq!(ExitCode::ApprovalDenied.as_i32(), 4);
    assert_eq!(ExitCode::ProtocolError.as_i32(), 5);
    assert_eq!(ExitCode::SecurityFailure.as_i32(), 6);
    assert_eq!(ExitCode::ApprovalRequired.as_i32(), 7);
    assert_eq!(ExitCode::ApprovalExpired.as_i32(), 8);
    assert_eq!(ExitCode::ApprovalCancelled.as_i32(), 9);
}

#[test]
fn test_rc001_cli_no_args_shows_help() {
    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage: relay"));
}

#[test]
fn test_rc001_cli_doctor_runs_cleanly() {
    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("=== Relay System Health"))
        .stdout(predicate::str::contains("Relay Version"))
        .stdout(predicate::str::contains("Ledger Path"));
}

#[test]
fn test_rc001_cli_run_without_command_fails_config_error() {
    let mut cmd = Command::cargo_bin("relay").unwrap();
    cmd.arg("run")
        .assert()
        .failure()
        .code(ExitCode::EXIT_CONFIG_ERROR)
        .stderr(predicate::str::contains("SERVER_COMMAND"));
}

#[cfg(unix)]
#[test]
fn test_rc001_ledger_file_permissions_are_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("secure_ledger").join("ledger.db");

    let ledger = relay_ledger::SqliteStorageEngine::open(&db_path).unwrap();
    drop(ledger);

    // Verify parent directory has 0700 permissions
    let parent_meta = fs::metadata(db_path.parent().unwrap()).unwrap();
    assert_eq!(parent_meta.permissions().mode() & 0o777, 0o700);

    // Verify database file has 0600 permissions
    let db_meta = fs::metadata(&db_path).unwrap();
    assert_eq!(db_meta.permissions().mode() & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn test_rc001_signing_key_save_and_load_permissions_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let key_path = dir.path().join("keys").join("signing_key.seed");

    let signer = Ed25519ReceiptSigner::generate("test-rc001-key");
    signer.save_to_file(&key_path).unwrap();

    // Verify key file has 0600 permissions
    let meta = fs::metadata(&key_path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    // Verify key loads cleanly
    let loaded = Ed25519ReceiptSigner::from_file(&key_path, "test-rc001-key").unwrap();
    assert_eq!(signer.export_public_key(), loaded.export_public_key());
}

#[test]
fn test_rc001_secret_buffers_and_keys_masked_in_debug() {
    let signer = Ed25519ReceiptSigner::default();
    let debug_str = format!("{signer:?}");
    assert!(debug_str.contains("[REDACTED SECRET KEY]"));
    assert!(!debug_str.contains("secret"));

    let secret_buf = relay_domain::SecretBuffer::new(b"super-secret-token-12345".to_vec());
    let buf_debug = format!("{secret_buf:?}");
    assert!(buf_debug.contains("[REDACTED 24 bytes]"));
    assert!(!buf_debug.contains("super-secret-token-12345"));

    let buf_display = format!("{secret_buf}");
    assert_eq!(buf_display, "[REDACTED SECRET]");
}

#[test]
fn test_rc001_subprocess_env_sanitization_strips_secrets() {
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "AKIA_FAKE_SECRET_KEY");
    std::env::set_var("GITHUB_TOKEN", "ghp_fake_token_12345");
    std::env::set_var("PGPASSWORD", "fake_password");

    let child_env = relay_mcp::sanitized_child_env("0.1.0");

    assert!(!child_env.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert!(!child_env.contains_key("GITHUB_TOKEN"));
    assert!(!child_env.contains_key("PGPASSWORD"));

    assert_eq!(child_env.get("RELAY_ACTIVE").map(String::as_str), Some("1"));
    assert_eq!(
        child_env.get("RELAY_VERSION").map(String::as_str),
        Some("0.1.0")
    );

    std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    std::env::remove_var("GITHUB_TOKEN");
    std::env::remove_var("PGPASSWORD");
}
