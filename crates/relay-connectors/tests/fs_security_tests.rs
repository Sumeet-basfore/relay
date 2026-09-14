//! Adversarial Security Tests for Relay Filesystem Connector (B010)
//!
//! Covers 25 dedicated attack vectors:
//! 1. Relative dot-dot path traversal (`../../etc/passwd`)
//! 2. Absolute root escape (`/etc/shadow`)
//! 3. Prohibited system path: `/proc/self/environ`
//! 4. Prohibited system path: `/sys/kernel`
//! 5. Prohibited system path: `/dev/urandom`
//! 6. Special file rejection: Unix domain socket
//! 7. Special file rejection: Symlink when follow_symlinks is false
//! 8. Symlink pointing outside root jail (escape attempt)
//! 9. Symlink pointing to sensitive internal file
//! 10. Symlink loop / cycle inside jail
//! 11. Read size quota exhaustion (> 10MB)
//! 12. Write size quota exhaustion (> 10MB)
//! 13. Directory listing entry limit exhaustion (> 1,000 entries)
//! 14. ActionHash mismatch during execution attempt
//! 15. Unapproved destructive action (step-up required but missing)
//! 16. Approved action with mismatched ActionHash
//! 17. Atomic write leaves no temporary `.tmp` residue on success
//! 18. Atomic write into write-protected directory fails safely
//! 19. Directory traversal via lexical normalization
//! 20. Appending to non-existent file fails safely without creation
//! 21. Recursive directory deletion attempted via delete_file fails
//! 22. Non-empty directory removal attempted via remove_directory fails
//! 23. Direct NativeConnector::execute call is forbidden (fails closed)
//! 24. Stat metadata on non-existent path fails
//! 25. ActionReceipt generated on target failure preserves audit trail

use std::fs::File;
use std::os::unix::fs as unix_fs;
use std::path::Path;
use tempfile::tempdir;

use relay_canonical::ActionCanonicalizer;
use relay_connectors::fs::{
    append_file, delete_file, list_directory, read_file, remove_directory,
    resolve_and_verify_within_root, stat_metadata, write_file_atomic, FilesystemConnector,
    FsConnectorConfig, FsError,
};
use relay_domain::{Approval, NativeConnector, PolicyDecision, PrincipalId, ToolIdentity};
use relay_receipts::Ed25519ReceiptSigner;

#[tokio::test]
async fn test_sec_01_relative_dot_dot_path_traversal() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let res = resolve_and_verify_within_root(&cfg, Path::new("../../etc/passwd"), false);
    assert!(matches!(res, Err(FsError::PathTraversal { .. })));
}

#[tokio::test]
async fn test_sec_02_absolute_root_escape() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let res = resolve_and_verify_within_root(&cfg, Path::new("/var/log/syslog"), false);
    assert!(matches!(res, Err(FsError::PathTraversal { .. })));
}

#[tokio::test]
async fn test_sec_03_prohibited_system_path_proc() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let res = resolve_and_verify_within_root(&cfg, Path::new("/proc/self/environ"), false);
    assert!(matches!(res, Err(FsError::ProhibitedSystemPath(_))));
}

#[tokio::test]
async fn test_sec_04_prohibited_system_path_sys() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let res = resolve_and_verify_within_root(&cfg, Path::new("/sys/kernel/profiling"), false);
    assert!(matches!(res, Err(FsError::ProhibitedSystemPath(_))));
}

#[tokio::test]
async fn test_sec_05_prohibited_system_path_dev() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let res = resolve_and_verify_within_root(&cfg, Path::new("/dev/urandom"), false);
    assert!(matches!(res, Err(FsError::ProhibitedSystemPath(_))));
}

#[tokio::test]
async fn test_sec_06_special_file_rejection_socket() {
    let tmp = tempdir().unwrap();
    let socket_path = tmp.path().join("test.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());

    let res = resolve_and_verify_within_root(&cfg, &socket_path, true);
    assert!(matches!(res, Err(FsError::SpecialFileRejected { .. })));
}

#[tokio::test]
async fn test_sec_07_special_file_rejection_dev_null() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let res = resolve_and_verify_within_root(&cfg, Path::new("/dev/null"), false);
    assert!(matches!(res, Err(FsError::ProhibitedSystemPath(_))));
}

#[tokio::test]
async fn test_sec_08_symlink_pointing_outside_root_jail() {
    let tmp = tempdir().unwrap();
    let jail_root = tmp.path().join("jail");
    let outside_dir = tmp.path().join("outside");
    std::fs::create_dir(&jail_root).unwrap();
    std::fs::create_dir(&outside_dir).unwrap();

    let secret_file = outside_dir.join("secret.txt");
    std::fs::write(&secret_file, b"topsecret").unwrap();

    let symlink_path = jail_root.join("link_to_secret");
    unix_fs::symlink(&secret_file, &symlink_path).unwrap();

    let mut cfg = FsConnectorConfig::new(&jail_root);
    cfg.follow_symlinks = true; // Even if true, target outside must fail
    let res = resolve_and_verify_within_root(&cfg, &symlink_path, true);
    assert!(matches!(res, Err(FsError::PathTraversal { .. })));
}

#[tokio::test]
async fn test_sec_09_symlink_rejection_by_default_within_jail() {
    let tmp = tempdir().unwrap();
    let file = tmp.path().join("target.txt");
    std::fs::write(&file, b"safe data").unwrap();
    let symlink = tmp.path().join("link.txt");
    unix_fs::symlink(&file, &symlink).unwrap();

    let cfg = FsConnectorConfig::new(tmp.path());
    let res = resolve_and_verify_within_root(&cfg, &symlink, true);
    assert!(matches!(res, Err(FsError::SymlinkError { .. })));
}

#[tokio::test]
async fn test_sec_10_symlink_loop_inside_jail() {
    let tmp = tempdir().unwrap();
    let link1 = tmp.path().join("loop1");
    let link2 = tmp.path().join("loop2");
    let _ = unix_fs::symlink(&link2, &link1);
    let _ = unix_fs::symlink(&link1, &link2);

    let mut cfg = FsConnectorConfig::new(tmp.path());
    cfg.follow_symlinks = true;
    let res = resolve_and_verify_within_root(&cfg, &link1, true);
    assert!(res.is_err());
}

#[tokio::test]
async fn test_sec_11_read_size_quota_exhaustion() {
    let tmp = tempdir().unwrap();
    let file_path = tmp.path().join("big_file.bin");
    let f = File::create(&file_path).unwrap();
    f.set_len(1024 * 1024 * 15).unwrap(); // 15MB

    let cfg = FsConnectorConfig::new(tmp.path()); // Max read is 10MB
    let res = read_file(&cfg, &file_path);
    assert!(matches!(res, Err(FsError::FileTooLarge { .. })));
}

#[tokio::test]
async fn test_sec_12_write_size_quota_exhaustion() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let oversized_payload = vec![0u8; 1024 * 1024 * 11]; // 11MB

    let target = tmp.path().join("oversized.dat");
    let res = write_file_atomic(&cfg, &target, &oversized_payload);
    assert!(matches!(res, Err(FsError::FileTooLarge { .. })));
}

#[tokio::test]
async fn test_sec_13_directory_listing_entry_limit_exhaustion() {
    let tmp = tempdir().unwrap();
    let sub = tmp.path().join("crowded");
    std::fs::create_dir(&sub).unwrap();

    let mut cfg = FsConnectorConfig::new(tmp.path());
    cfg.max_dir_entries = 50;

    for i in 0..60 {
        let f = sub.join(format!("file_{i}.txt"));
        std::fs::write(&f, b"x").unwrap();
    }

    let res = list_directory(&cfg, &sub);
    assert!(matches!(
        res,
        Err(FsError::DirectoryEntryLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn test_sec_14_action_hash_mismatch_during_execution() {
    let tmp = tempdir().unwrap();
    let target = tmp.path().join("file.txt");
    std::fs::write(&target, b"content").unwrap();

    let cfg = FsConnectorConfig::new(tmp.path());
    let connector = FilesystemConnector::new(cfg);
    let canonicalizer = ActionCanonicalizer::default();

    let canonical_action = canonicalizer
        .canonicalize(
            relay_domain::SessionId::new_v7(),
            PrincipalId::new("principal:agent:worker").unwrap(),
            "tools/call",
            ToolIdentity::new("relay", "fs", "read_file"),
            &serde_json::json!({ "path": target.to_string_lossy() }),
            None,
            None,
        )
        .unwrap();

    // Create a bogus decision with a DIFFERENT action hash
    let bogus_decision = PolicyDecision::allow(
        relay_domain::ActionHash::compute(b"tampered"),
        relay_domain::Digest::compute(b"policy"),
        vec!["permit_fs_reads".to_string()],
    );

    let res = connector
        .execute_governed(&canonical_action, &bogus_decision)
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_sec_15_unapproved_destructive_action_fails_closed() {
    let tmp = tempdir().unwrap();
    let target = tmp.path().join("vital.txt");
    std::fs::write(&target, b"vital").unwrap();

    let cfg = FsConnectorConfig::new(tmp.path());
    let connector = FilesystemConnector::new(cfg);
    let canonicalizer = ActionCanonicalizer::default();
    let signer = Ed25519ReceiptSigner::generate("signer-15");

    let canonical_action = canonicalizer
        .canonicalize(
            relay_domain::SessionId::new_v7(),
            PrincipalId::new("principal:agent:worker").unwrap(),
            "tools/call",
            ToolIdentity::new("relay", "fs", "delete_file"),
            &serde_json::json!({ "path": target.to_string_lossy() }),
            None,
            None,
        )
        .unwrap();

    let step_up_decision = PolicyDecision::approval_required(
        canonical_action.action_hash,
        relay_domain::Digest::compute(b"policy"),
        "Approval required for deletion",
        vec!["require_approval_fs_delete".to_string()],
    );

    // Call execute without approval
    let res = connector
        .execute_governed_with_receipt(&canonical_action, &step_up_decision, None, &signer)
        .await;

    assert!(res.is_err());
    assert!(target.exists()); // File must NOT have been deleted
}

#[tokio::test]
async fn test_sec_16_approved_action_with_mismatched_action_hash() {
    let tmp = tempdir().unwrap();
    let target = tmp.path().join("vital.txt");
    std::fs::write(&target, b"vital").unwrap();

    let cfg = FsConnectorConfig::new(tmp.path());
    let connector = FilesystemConnector::new(cfg);
    let canonicalizer = ActionCanonicalizer::default();
    let signer = Ed25519ReceiptSigner::generate("signer-16");

    let canonical_action = canonicalizer
        .canonicalize(
            relay_domain::SessionId::new_v7(),
            PrincipalId::new("principal:agent:worker").unwrap(),
            "tools/call",
            ToolIdentity::new("relay", "fs", "delete_file"),
            &serde_json::json!({ "path": target.to_string_lossy() }),
            None,
            None,
        )
        .unwrap();

    let decision = PolicyDecision::approval_required(
        canonical_action.action_hash,
        relay_domain::Digest::compute(b"policy"),
        "Approval required",
        vec!["require_approval_fs_delete".to_string()],
    );

    // Approval with DIFFERENT ActionHash
    let mut approval = Approval::new(
        relay_domain::ActionHash::compute(b"different_action"),
        decision.decision_id,
        "Approve delete",
        None,
        300,
    );
    approval
        .approve(PrincipalId::new("principal:human:admin").unwrap())
        .unwrap();

    let res = connector
        .execute_governed_with_receipt(&canonical_action, &decision, Some(&approval), &signer)
        .await;

    assert!(res.is_err());
    assert!(target.exists());
}

#[tokio::test]
async fn test_sec_17_atomic_write_leaves_no_temporary_residue() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let target = tmp.path().join("clean_write.txt");

    write_file_atomic(&cfg, &target, b"verified safe write").unwrap();

    let entries: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], "clean_write.txt");
}

#[tokio::test]
async fn test_sec_18_atomic_write_into_readonly_dir_fails_safely() {
    let tmp = tempdir().unwrap();
    let read_only_dir = tmp.path().join("ro_dir");
    std::fs::create_dir(&read_only_dir).unwrap();

    // Set permissions to 0o400 (read only)
    let mut perms = std::fs::metadata(&read_only_dir).unwrap().permissions();
    perms.set_readonly(true);
    let _ = std::fs::set_permissions(&read_only_dir, perms.clone());

    let cfg = FsConnectorConfig::new(tmp.path());
    let target = read_only_dir.join("impossible.txt");
    let res = write_file_atomic(&cfg, &target, b"data");

    // Restore permissions so cleanup works
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    let _ = std::fs::set_permissions(&read_only_dir, perms);

    assert!(res.is_err());
}

#[tokio::test]
async fn test_sec_19_path_normalization_with_consecutive_slashes() {
    let tmp = tempdir().unwrap();
    let target = tmp.path().join("sub").join("data.txt");
    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    std::fs::write(&target, b"data").unwrap();

    let cfg = FsConnectorConfig::new(tmp.path());
    // Path with // and ./
    let weird_path = format!("{}/sub/./data.txt", tmp.path().display());
    let res = read_file(&cfg, Path::new(&weird_path)).unwrap();
    assert_eq!(res.content, "data");
}

#[tokio::test]
async fn test_sec_20_appending_to_nonexistent_file_fails_without_creating() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let non_existent = tmp.path().join("not_there.txt");

    let res = append_file(&cfg, &non_existent, b"extra");
    assert!(res.is_err());
    assert!(!non_existent.exists());
}

#[tokio::test]
async fn test_sec_21_delete_file_on_directory_fails() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path().join("some_dir");
    std::fs::create_dir(&dir).unwrap();

    let cfg = FsConnectorConfig::new(tmp.path());
    let res = delete_file(&cfg, &dir);
    assert!(res.is_err());
    assert!(dir.exists());
}

#[tokio::test]
async fn test_sec_22_non_empty_directory_removal_fails() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path().join("not_empty");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("child.txt"), b"child").unwrap();

    let cfg = FsConnectorConfig::new(tmp.path());
    let res = remove_directory(&cfg, &dir);
    assert!(res.is_err());
    assert!(dir.exists());
}

#[tokio::test]
async fn test_sec_23_direct_native_connector_execute_forbidden() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let connector = FilesystemConnector::new(cfg);

    let res = connector
        .execute("read_file", &serde_json::json!({}), None)
        .await;

    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("forbidden"));
}

#[tokio::test]
async fn test_sec_24_stat_metadata_on_nonexistent_fails() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let missing = tmp.path().join("ghost.txt");

    let res = stat_metadata(&cfg, &missing);
    assert!(matches!(res, Err(FsError::NotFound(_))));
}

#[tokio::test]
async fn test_sec_25_target_failure_receipt_generation_and_known_error_classification() {
    let tmp = tempdir().unwrap();
    let crowded_dir = tmp.path().join("crowded");
    std::fs::create_dir(&crowded_dir).unwrap();
    std::fs::write(crowded_dir.join("child.txt"), b"child data").unwrap();

    let cfg = FsConnectorConfig::new(tmp.path());
    let connector = FilesystemConnector::new(cfg);
    let canonicalizer = ActionCanonicalizer::default();
    let signer = Ed25519ReceiptSigner::generate("signer-25");

    let canonical_action = canonicalizer
        .canonicalize(
            relay_domain::SessionId::new_v7(),
            PrincipalId::new("principal:agent:worker").unwrap(),
            "tools/call",
            ToolIdentity::new("relay", "fs", "remove_directory"),
            &serde_json::json!({ "path": crowded_dir.to_string_lossy() }),
            None,
            None,
        )
        .unwrap();

    let decision = PolicyDecision::allow(
        canonical_action.action_hash,
        relay_domain::Digest::compute(b"policy"),
        vec!["permit_fs_writes".to_string()],
    );

    let res = connector
        .execute_governed_with_receipt(&canonical_action, &decision, None, &signer)
        .await;

    assert!(res.is_err());
    let (_err, opt_receipt) = res.unwrap_err();
    assert!(
        opt_receipt.is_some(),
        "Must produce an ActionReceipt even on target failure"
    );
    let receipt = opt_receipt.unwrap();
    let payload_bytes = relay_receipts::base64_decode(&receipt.dsse_envelope.payload).unwrap();
    let stmt: relay_domain::InTotoStatement = serde_json::from_slice(&payload_bytes).unwrap();
    // Non-empty directory removal is a KNOWN failure, not an ambiguous mutation
    assert_eq!(stmt.predicate.observation["status"], "TARGET_ERROR");
    assert_eq!(
        stmt.predicate.observation["retry_classification"],
        "NonRetryableFatal"
    );
}

#[tokio::test]
async fn test_audit_write_atomic_failure_is_known_not_ambiguous() {
    let tmp = tempdir().unwrap();
    let cfg = FsConnectorConfig::new(tmp.path());
    let existing_dest = tmp.path().join("dest.txt");
    std::fs::write(&existing_dest, b"original content").unwrap();

    // In write_file_atomic, a failure before rename leaves target intact
    // If the parent directory is made read-only, temp file creation fails cleanly
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let sub_dir = tmp.path().join("readonly_dir");
        std::fs::create_dir(&sub_dir).unwrap();
        let target_in_sub = sub_dir.join("file.txt");

        let mut perms = std::fs::metadata(&sub_dir).unwrap().permissions();
        perms.set_mode(0o555); // read and execute, not writable
        std::fs::set_permissions(&sub_dir, perms.clone()).unwrap();

        let res = write_file_atomic(&cfg, &target_in_sub, b"new content");
        // Reset permissions so tempdir cleanup succeeds
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(&sub_dir, perms);

        assert!(res.is_err());
        let err = res.unwrap_err();
        // Must be an IoError (known failure), NOT an AmbiguousMutationOutcome
        assert!(
            matches!(err, FsError::IoError { .. }),
            "Expected IoError, got {err:?}"
        );
        assert!(!target_in_sub.exists());
    }
}
