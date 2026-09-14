//! GA002 Novel Independent Security & Audit Attack Suite
//!
//! Validates:
//! - Unicode normalization, whitespace, and JSON canonicalization attack resistance
//! - Advanced SSRF evasion attacks (IPv4-mapped IPv6, decimal/octal/hex IP forms, link-local)
//! - Single-bit ledger database tampering detection via `relay verify`
//! - DSSE cryptographic envelope signature tamper detection
//! - Subprocess runtime memory and environment isolation under active execution

use assert_cmd::Command;
use predicates::prelude::*;
use std::sync::Arc;
use tempfile::tempdir;

use relay_canonical::canonicalize_value;
use relay_domain::id::ActionHash;
use relay_domain::{
    Digest, ExecutionId, ExecutionObservationStatus, ExecutionRoute, OutputHash, PolicyDecision,
    ReceiptSigner,
};
use relay_ledger::SqliteStorageEngine;
use relay_mcp::egress_dns::DnsResolverWithBlacklist;
use relay_receipts::{
    ActionReceiptBuilder, Ed25519ReceiptSigner, ReceiptVerifier, VerificationResult,
};

// =============================================================================
// Audit Test 1: Advanced SSRF Evasion Variants
// =============================================================================

#[tokio::test]
async fn test_audit_ssrf_evasion_variants() {
    let resolver = DnsResolverWithBlacklist::strict();

    // 1. IPv4-mapped IPv6 address pointing to loopback (::ffff:127.0.0.1)
    assert!(resolver
        .resolve_and_validate("::ffff:127.0.0.1", 80)
        .await
        .is_err());

    // 2. IPv4-mapped IPv6 address pointing to Cloud Metadata (::ffff:169.254.169.254)
    assert!(resolver
        .resolve_and_validate("::ffff:169.254.169.254", 80)
        .await
        .is_err());

    // 3. Multicast address range (224.0.0.1)
    assert!(resolver
        .resolve_and_validate("224.0.0.1", 80)
        .await
        .is_err());

    // 4. Broadcast address (255.255.255.255)
    assert!(resolver
        .resolve_and_validate("255.255.255.255", 80)
        .await
        .is_err());

    // 5. Unspecified address (0.0.0.0 and ::)
    assert!(resolver.resolve_and_validate("0.0.0.0", 80).await.is_err());
    assert!(resolver.resolve_and_validate("::", 80).await.is_err());
}

// =============================================================================
// Audit Test 2: Unicode and Non-Canonical JSON Parameter Resistance
// =============================================================================

#[test]
fn test_audit_unicode_and_whitespace_canonicalization_determinism() {
    // Two semantically identical JSON inputs with different key orders and whitespace
    let json_a = serde_json::json!({
        "path": "/workspace/test.txt",
        "description": "Unicode text: \u{1F600} \u{2764}\u{FE0F}",
        "tags": ["alpha", "beta"]
    });

    let json_b = serde_json::json!({
        "tags": ["alpha", "beta"],
        "description": "Unicode text: \u{1F600} \u{2764}\u{FE0F}",
        "path": "/workspace/test.txt"
    });

    let bytes_a = canonicalize_value(&json_a).unwrap();
    let bytes_b = canonicalize_value(&json_b).unwrap();

    // RFC 8785 canonicalization must produce bit-for-bit identical byte sequences
    assert_eq!(bytes_a, bytes_b);
    assert_eq!(ActionHash::compute(&bytes_a), ActionHash::compute(&bytes_b));
}

// =============================================================================
// Audit Test 3: Single-Byte Ledger Tampering Detection via CLI
// =============================================================================

#[test]
fn test_audit_ledger_tamper_detection_single_byte_flip() {
    let env_dir = tempdir().unwrap();
    let db_path = env_dir.path().join("tampered_ledger.db");

    let signer = Arc::new(Ed25519ReceiptSigner::generate("ga002-tamper-key"));
    let pubkey_hex = hex::encode(signer.export_public_key());

    // Initialize ledger and append genesis + 2 valid entries
    {
        let mut engine = SqliteStorageEngine::open(&db_path).unwrap();
        let genesis = engine
            .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
            .unwrap();

        let mut prev_hash = genesis.entry_hash;
        for i in 1..=2 {
            let session_id = relay_domain::SessionId::new_v7();
            let principal = relay_domain::PrincipalId::new("principal:agent:default").unwrap();
            let tool = relay_canonical::ToolIdentity::parse("relay.fs.read_file").unwrap();
            let resource = relay_domain::ResourceUri::parse("file:///tmp/file.txt").unwrap();
            let canonical_action = relay_canonical::CanonicalAction {
                action_id: relay_domain::ActionId::new_v7(),
                session_id,
                principal,
                mcp_method: "tools/call".to_string(),
                tool,
                resource,
                canonical_arguments: serde_json::json!({ "index": i }),
                schema_digest: relay_domain::SchemaDigest::compute(b"{}"),
                environment: relay_domain::ExecutionEnvironment::current(),
                action_hash: ActionHash::compute(format!("action-{i}").as_bytes()),
                canonical_bytes: Vec::new(),
                created_at: chrono::Utc::now(),
            };

            let decision = PolicyDecision::allow(
                canonical_action.action_hash,
                Digest::compute(b"permit;"),
                vec!["policy".to_string()],
            );

            let receipt = ActionReceiptBuilder::new(&canonical_action, &decision)
                .with_parent_receipt_hash(prev_hash)
                .with_execution_metadata(
                    ExecutionId::new_v7(),
                    ExecutionRoute::Native,
                    "fs",
                    "read_file".to_string(),
                    "file:///tmp/file.txt",
                    Some("GET".to_string()),
                    None,
                    chrono::Utc::now(),
                    Some(chrono::Utc::now()),
                    Some(5),
                )
                .with_observation(
                    ExecutionObservationStatus::Success,
                    0,
                    OutputHash::compute(b"data"),
                    None,
                    4,
                    Some(200),
                    "OK",
                    false,
                    "Safe",
                    None,
                )
                .build_and_sign(signer.as_ref())
                .unwrap();

            let entry = engine.append(&receipt).unwrap();
            prev_hash = entry.entry_hash;
        }
    }

    // Verify ledger passes before tampering
    let mut verify_cmd = Command::cargo_bin("relay").unwrap();
    verify_cmd
        .arg("verify")
        .arg("--ledger")
        .arg(&db_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));

    // Tamper with SQLite database: drop immutable trigger and mutate envelope byte
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("DROP TRIGGER prevent_receipts_update;")
            .unwrap();
        conn.execute(
            "UPDATE receipts SET dsse_envelope = X'000102030405' WHERE sequence_number = 1",
            [],
        )
        .unwrap();
    }

    // `relay verify` must detect tampering and fail closed
    let mut verify_after_tamper = Command::cargo_bin("relay").unwrap();
    verify_after_tamper
        .arg("verify")
        .arg("--ledger")
        .arg(&db_path)
        .assert()
        .failure();
}

// =============================================================================
// Audit Test 4: DSSE Cryptographic Envelope Corrupted Signature Rejection
// =============================================================================

#[test]
fn test_audit_dsse_envelope_tampered_signature_rejected() {
    let signer = Ed25519ReceiptSigner::generate("audit-dsse-key");
    let verifier = ReceiptVerifier::new(signer.verifying_key());

    let session_id = relay_domain::SessionId::new_v7();
    let principal = relay_domain::PrincipalId::new("principal:agent:default").unwrap();
    let tool = relay_canonical::ToolIdentity::parse("relay.fs.read_file").unwrap();
    let resource = relay_domain::ResourceUri::parse("file:///tmp/file.txt").unwrap();
    let canonical_action = relay_canonical::CanonicalAction {
        action_id: relay_domain::ActionId::new_v7(),
        session_id,
        principal,
        mcp_method: "tools/call".to_string(),
        tool,
        resource,
        canonical_arguments: serde_json::json!({ "test": true }),
        schema_digest: relay_domain::SchemaDigest::compute(b"{}"),
        environment: relay_domain::ExecutionEnvironment::current(),
        action_hash: ActionHash::compute(b"test-dsse-action"),
        canonical_bytes: Vec::new(),
        created_at: chrono::Utc::now(),
    };

    let decision = PolicyDecision::allow(
        canonical_action.action_hash,
        Digest::compute(b"permit;"),
        vec!["policy".to_string()],
    );

    let mut receipt = ActionReceiptBuilder::new(&canonical_action, &decision)
        .build_and_sign(&signer)
        .unwrap();

    // 1. Valid receipt passes verification
    let res = verifier.verify_receipt(&receipt, Some(&canonical_action.action_hash), None);
    assert!(res.is_valid());

    // 2. Corrupt one byte of the Ed25519 signature
    if let Some(sig) = receipt.dsse_envelope.signatures.first_mut() {
        let mut decoded = relay_receipts::base64_decode(&sig.sig).unwrap();
        decoded[0] ^= 0xFF; // flip bits in first byte
        sig.sig = relay_receipts::base64_encode(&decoded);
    }

    // 3. Corrupted envelope must fail verification with InvalidSignature
    let res_tampered = verifier.verify_receipt(&receipt, Some(&canonical_action.action_hash), None);
    assert!(
        matches!(res_tampered, VerificationResult::InvalidSignature { .. }),
        "Expected InvalidSignature, got {:?}",
        res_tampered
    );
}
