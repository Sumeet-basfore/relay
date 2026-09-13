//! Schema validation, error rejection, and policy digest integrity tests for Relay.
//!
//! Validates:
//! - Strict schema compilation and error rejection
//! - Invalid policy syntax failure
//! - Schema violation failure (unknown actions / unknown entity types)
//! - Cryptographic PolicySetDigest determinism and tamper-evidence (SI-010)
//! - Multi-file directory loading determinism

use relay_domain::PolicyError;
use relay_policy::{default_schema, parse_schema, CedarPolicyEngine, PolicyLoader};
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_invalid_schema_syntax_rejected() {
    let bad_schema = "namespace Relay { this is not valid cedar schema syntax }";
    let res = parse_schema(bad_schema);
    assert!(res.is_err());
    match res.err().unwrap() {
        PolicyError::SchemaError(err) => {
            assert!(!err.is_empty());
        }
        other => panic!("Expected PolicyError::SchemaError, got: {other:?}"),
    }
}

#[test]
fn test_invalid_policy_syntax_rejected() {
    let schema = default_schema().expect("schema");
    let bad_policy = "permit(principal, action, resource) where { bad_syntax }";
    let res = PolicyLoader::load_from_str(bad_policy, &schema);
    assert!(res.is_err());
    match res.err().unwrap() {
        PolicyError::InitializationFailed(err) => {
            assert!(!err.is_empty());
        }
        other => panic!("Expected PolicyError::InitializationFailed, got: {other:?}"),
    }
}

#[test]
fn test_schema_violation_unknown_action_rejected() {
    let schema = default_schema().expect("schema");
    // Action "unregistered.fake_action" does not exist in schema
    let invalid_policy = r#"
    permit (
        principal,
        action == Relay::Action::"unregistered.fake_action",
        resource
    );
    "#;

    let res = PolicyLoader::load_from_str(invalid_policy, &schema);
    assert!(res.is_err());
    match res.err().unwrap() {
        PolicyError::SchemaError(err) => {
            assert!(
                err.contains("unregistered.fake_action") || err.contains("validation failed"),
                "Error was: {err}"
            );
        }
        other => panic!("Expected PolicyError::SchemaError, got: {other:?}"),
    }
}

#[test]
fn test_schema_violation_unknown_entity_type_rejected() {
    let schema = default_schema().expect("schema");
    // Principal type "BogusAgent" does not exist in schema
    let invalid_policy = r#"
    permit (
        principal == Relay::BogusAgent::"agent-1",
        action == Relay::Action::"fs.read",
        resource
    );
    "#;

    let res = PolicyLoader::load_from_str(invalid_policy, &schema);
    assert!(res.is_err());
    match res.err().unwrap() {
        PolicyError::SchemaError(err) => {
            assert!(!err.is_empty());
        }
        other => panic!("Expected PolicyError::SchemaError, got: {other:?}"),
    }
}

#[test]
fn test_policy_digest_tamper_detection_si_010() {
    let policy_v1 = r#"
    @id("p1")
    permit (
        principal,
        action == Relay::Action::"fs.read",
        resource
    );
    "#;

    // Slight alteration (modifying action or comments)
    let policy_v2 = r#"
    @id("p1")
    permit (
        principal,
        action == Relay::Action::"fs.write",
        resource
    );
    "#;

    let engine_v1 = CedarPolicyEngine::from_str(policy_v1, None).expect("v1");
    let engine_v2 = CedarPolicyEngine::from_str(policy_v2, None).expect("v2");

    assert_ne!(
        engine_v1.policy_digest(),
        engine_v2.policy_digest(),
        "Modified policy must produce distinct SHA-256 PolicySetDigest (SI-010)"
    );
}

#[test]
fn test_directory_loading_deterministic_order() {
    let schema = default_schema().expect("schema");
    let temp = tempdir().expect("tempdir");
    let dir = temp.path();

    // Create 3 policy files with different alphabetical names
    let file_b = dir.join("b_policies.cedar");
    let mut f_b = std::fs::File::create(&file_b).unwrap();
    writeln!(
        f_b,
        "@id(\"b\") permit(principal, action == Relay::Action::\"github.read\", resource);"
    )
    .unwrap();

    let file_a = dir.join("a_policies.cedar");
    let mut f_a = std::fs::File::create(&file_a).unwrap();
    writeln!(
        f_a,
        "@id(\"a\") permit(principal, action == Relay::Action::\"fs.read\", resource);"
    )
    .unwrap();

    let file_c = dir.join("c_policies.cedar");
    let mut f_c = std::fs::File::create(&file_c).unwrap();
    writeln!(
        f_c,
        "@id(\"c\") permit(principal, action == Relay::Action::\"postgres.read\", resource);"
    )
    .unwrap();

    let (policies_1, digest_1) = PolicyLoader::load_from_dir(dir, &schema).expect("load 1");
    let (policies_2, digest_2) = PolicyLoader::load_from_dir(dir, &schema).expect("load 2");

    assert_eq!(
        digest_1, digest_2,
        "Directory loading must be strictly deterministic"
    );
    assert_eq!(policies_1.policies().count(), 3);
    assert_eq!(policies_2.policies().count(), 3);
}
