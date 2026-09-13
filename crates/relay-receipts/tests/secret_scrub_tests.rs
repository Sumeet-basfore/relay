mod common;

use common::*;
use relay_receipts::{ActionReceiptBuilder, ReceiptError};

#[test]
fn test_prohibited_secret_patterns_rejected_before_signing() {
    let patterns = [
        ("ghp_1234567890abcdefghijklmnopqrstuvwxyz", "ghp_"),
        ("gho_1234567890abcdefghijklmnopqrstuvwxyz", "gho_"),
        ("github_pat_11ABCD_efgh1234567890", "github_pat_"),
        ("sk-proj-abcdef1234567890abcdef1234567890", "sk-proj-"),
        ("AKIAIOSFODNN7EXAMPLE", "AKIA"),
        (
            "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk",
            "BEGIN PRIVATE KEY",
        ),
        (
            "Authorization: Bearer my-secret-token",
            "Authorization: Bearer",
        ),
    ];

    let signer = create_test_signer();

    for (secret_leak, pattern_prefix) in patterns {
        let (mut action, _action_hash) = create_test_action();
        action.canonical_arguments = serde_json::json!({
            "owner": "octocat",
            "repo": "Hello-World",
            "leaked_data": secret_leak
        });
        let new_hash =
            relay_domain::ActionHash::compute(serde_json::to_string(&action).unwrap().as_bytes());
        action.action_hash = new_hash;

        let decision = create_test_decision(new_hash, true);
        let builder = ActionReceiptBuilder::new(&action, &decision);

        let err = builder.build_and_sign(&signer).unwrap_err();
        match err {
            ReceiptError::ProhibitedSecretDetected(pattern) => {
                assert!(
                    pattern.contains(pattern_prefix),
                    "Expected pattern {} in error, got {}",
                    pattern_prefix,
                    pattern
                );
            }
            other => panic!(
                "Expected ProhibitedSecretDetected for pattern {}, got {:?}",
                pattern_prefix, other
            ),
        }
    }
}

#[test]
fn test_benign_similar_strings_are_not_falsely_rejected() {
    let benign_strings = [
        "github.com",
        "github_actions",
        "gh_prefix_without_p",
        "authorization_required_false",
        "bearer_of_good_news",
        "akiatype_not_secret",
        "sk-standard-not-proj",
        "BEGIN PUBLIC KEY",
    ];

    let signer = create_test_signer();

    for benign in benign_strings {
        let (mut action, _action_hash) = create_test_action();
        action.canonical_arguments = serde_json::json!({
            "owner": "octocat",
            "repo": "Hello-World",
            "normal_data": benign
        });
        let new_hash =
            relay_domain::ActionHash::compute(serde_json::to_string(&action).unwrap().as_bytes());
        action.action_hash = new_hash;

        let decision = create_test_decision(new_hash, true);
        let builder = ActionReceiptBuilder::new(&action, &decision);

        let res = builder.build_and_sign(&signer);
        assert!(
            res.is_ok(),
            "Benign string '{}' must not be falsely rejected: {:?}",
            benign,
            res
        );
    }
}
