mod common;

use common::*;
use relay_domain::{
    ApprovalState, ExecutionId, ExecutionObservationStatus, ExecutionRoute, OutputHash,
};
use relay_receipts::{ActionReceiptBuilder, ReceiptError};

#[test]
fn test_valid_receipt_from_allowed_action() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let signer = create_test_signer();

    let execution_id = ExecutionId::new_v7();
    let started_at = chrono::Utc::now();
    let completed_at = started_at + chrono::Duration::milliseconds(45);

    let builder = ActionReceiptBuilder::new(&action, &decision)
        .with_execution_metadata(
            execution_id,
            ExecutionRoute::Native,
            "github",
            "create_issue",
            action.resource.as_str(),
            Some("POST".to_string()),
            Some("https://api.github.com/repos/octocat/Hello-World/issues".to_string()),
            started_at,
            Some(completed_at),
            Some(45),
        )
        .with_observation(
            ExecutionObservationStatus::Success,
            0,
            OutputHash::compute(b"{\"id\": 101, \"number\": 1}"),
            None,
            30,
            Some(201),
            "GitHub create_issue succeeded (HTTP 201)",
            false,
            "IdempotentSafeToRetry",
            None,
        );

    let receipt = builder
        .build_and_sign(&signer)
        .expect("Receipt build must succeed");

    assert_eq!(receipt.action_id, action.action_id);
    assert_eq!(receipt.session_id, action.session_id);
    assert_eq!(receipt.action_hash, action_hash);
    assert_eq!(
        receipt.dsse_envelope.payload_type,
        "application/vnd.in-toto+json"
    );
    assert_eq!(receipt.dsse_envelope.signatures.len(), 1);
    assert_eq!(
        receipt.dsse_envelope.signatures[0].keyid,
        "test-ed25519-signer-v1"
    );

    // Verify in-toto statement matches
    let domain = builder.build_domain().unwrap();
    assert_eq!(domain.proposal.principal, action.principal);
    assert_eq!(domain.proposal.tool_name, "create_issue");
    assert_eq!(
        domain.policy.decision,
        relay_domain::PolicyDecisionType::Allow
    );
    assert_eq!(
        domain.observation.status,
        ExecutionObservationStatus::Success
    );
    assert_eq!(domain.observation.response_status_code, Some(201));
    assert!(!domain.observation.is_ambiguous_mutation);
}

#[test]
fn test_denied_action_fails_closed() {
    let (action, action_hash) = create_test_action();
    let deny_decision = create_test_decision(action_hash, false);
    let signer = create_test_signer();

    let builder = ActionReceiptBuilder::new(&action, &deny_decision);
    let err = builder.build_and_sign(&signer).unwrap_err();

    match err {
        ReceiptError::UnauthorizedExecution { decision } => {
            assert_eq!(decision, "Deny");
        }
        other => panic!("Expected UnauthorizedExecution, got: {:?}", other),
    }
}

#[test]
fn test_action_with_valid_approval() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let approval = create_test_approval(action_hash, ApprovalState::Approved);
    let signer = create_test_signer();

    let builder = ActionReceiptBuilder::new(&action, &decision).with_approval(Some(&approval));

    let receipt = builder
        .build_and_sign(&signer)
        .expect("Should build receipt with approval");
    let domain = builder.build_domain().unwrap();

    let approval_ev = domain.approval.expect("ApprovalEvidence must be present");
    assert_eq!(approval_ev.approval_id, approval.approval_id.to_string());
    assert_eq!(approval_ev.decision, "Approved");
    assert_eq!(
        approval_ev.approver.as_str(),
        "principal:human:security-lead"
    );
    assert_eq!(receipt.action_hash, action_hash);
}

#[test]
fn test_action_with_credential_lease_metadata_only() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let lease = create_test_lease(action_hash, &action.principal, &action.resource);
    let _signer = create_test_signer();

    let builder = ActionReceiptBuilder::new(&action, &decision).with_credential_lease(Some(&lease));

    let domain = builder.build_domain().unwrap();
    let lease_ev = domain
        .credential_lease
        .as_ref()
        .expect("CredentialLeaseEvidence must be present");

    assert_eq!(lease_ev.lease_id, lease.lease_id.to_string());
    assert_eq!(lease_ev.key_alias, "github_keyring_token");
    assert_eq!(lease_ev.provider, "KeyringStatic");

    // Verify statement JCS does not contain secret values
    let statement = domain.to_in_toto_statement().unwrap();
    let json_str = serde_json::to_string(&statement).unwrap();
    assert!(!json_str.contains("secret"));
    assert!(!json_str.contains("token_value"));
}

#[test]
fn test_action_with_failed_execution() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let signer = create_test_signer();

    let builder = ActionReceiptBuilder::new(&action, &decision).with_observation(
        ExecutionObservationStatus::TargetError,
        1,
        OutputHash::compute(b"{\"message\": \"Repository not found\"}"),
        None,
        34,
        Some(404),
        "GitHub create_issue failed (HTTP 404: Not Found)",
        false,
        "NonRetryableFatal",
        Some("NotFound".to_string()),
    );

    let receipt = builder
        .build_and_sign(&signer)
        .expect("Should build receipt for failed execution");
    let domain = builder.build_domain().unwrap();

    assert_eq!(
        domain.observation.status,
        ExecutionObservationStatus::TargetError
    );
    assert_eq!(domain.observation.exit_code, 1);
    assert_eq!(domain.observation.response_status_code, Some(404));
    assert_eq!(domain.observation.error_class, Some("NotFound".to_string()));
    assert!(!domain.observation.is_ambiguous_mutation);
    assert_eq!(receipt.action_hash, action_hash);
}

#[test]
fn test_action_with_ambiguous_mutation() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let signer = create_test_signer();

    // Mutating action timed out -> must produce AmbiguousMutation receipt (SI-015)
    let builder = ActionReceiptBuilder::new(&action, &decision).with_observation(
        ExecutionObservationStatus::Timeout,
        1,
        OutputHash::compute(b""),
        None,
        0,
        None,
        "Request timed out after 5000ms; remote mutation outcome unknown",
        true, // is_ambiguous_mutation
        "AmbiguousRequiresVerification",
        Some("AmbiguousMutationOutcome".to_string()),
    );

    let domain = builder.build_domain().unwrap();
    assert_eq!(
        domain.observation.status,
        ExecutionObservationStatus::AmbiguousMutation
    );
    assert!(domain.observation.is_ambiguous_mutation);
    assert_eq!(
        domain.observation.retry_classification,
        "AmbiguousRequiresVerification"
    );
    assert_eq!(
        domain.observation.error_class,
        Some("AmbiguousMutationOutcome".to_string())
    );

    let receipt = builder
        .build_and_sign(&signer)
        .expect("Should sign ambiguous mutation receipt");
    assert_eq!(receipt.action_hash, action_hash);
}
