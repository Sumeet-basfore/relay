mod common;

use common::*;
use relay_domain::{ActionHash, ApprovalState, Digest, PrincipalId, ResourceUri};
use relay_receipts::{ActionReceiptBuilder, ReceiptError};

#[test]
fn test_action_hash_mismatch_between_action_and_decision() {
    let (action, _action_hash) = create_test_action();
    let mismatched_hash = ActionHash::compute(b"different_action");
    let decision = create_test_decision(mismatched_hash, true);
    let signer = create_test_signer();

    let builder = ActionReceiptBuilder::new(&action, &decision);
    let err = builder.build_and_sign(&signer).unwrap_err();

    match err {
        ReceiptError::ActionHashMismatch { expected, actual } => {
            assert_eq!(expected, action.action_hash.to_hex());
            assert_eq!(actual, mismatched_hash.to_hex());
        }
        other => panic!("Expected ActionHashMismatch, got: {:?}", other),
    }
}

#[test]
fn test_action_hash_mismatch_between_action_and_approval() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let mismatched_hash = ActionHash::compute(b"different_approval_hash");
    let approval = create_test_approval(mismatched_hash, ApprovalState::Approved);
    let signer = create_test_signer();

    let builder = ActionReceiptBuilder::new(&action, &decision).with_approval(Some(&approval));

    let err = builder.build_and_sign(&signer).unwrap_err();

    match err {
        ReceiptError::BindingMismatch {
            field,
            expected,
            actual,
        } => {
            assert_eq!(field, "approval.action_hash");
            assert_eq!(expected, action.action_hash.to_hex());
            assert_eq!(actual, mismatched_hash.to_hex());
        }
        other => panic!("Expected BindingMismatch, got: {:?}", other),
    }
}

#[test]
fn test_action_hash_mismatch_between_action_and_lease() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let mismatched_hash = ActionHash::compute(b"different_lease_hash");
    let lease = create_test_lease(mismatched_hash, &action.principal, &action.resource);
    let signer = create_test_signer();

    let builder = ActionReceiptBuilder::new(&action, &decision).with_credential_lease(Some(&lease));

    let err = builder.build_and_sign(&signer).unwrap_err();

    match err {
        ReceiptError::BindingMismatch {
            field,
            expected,
            actual,
        } => {
            assert_eq!(field, "lease.action_hash");
            assert_eq!(expected, action.action_hash.to_hex());
            assert_eq!(actual, mismatched_hash.to_hex());
        }
        other => panic!("Expected BindingMismatch, got: {:?}", other),
    }
}

#[test]
fn test_policy_digest_recording_and_matching() {
    let (action, action_hash) = create_test_action();
    let policy_bytes = b"permit(principal == Agent::\"test\", action, resource);";
    let policy_digest = Digest::compute(policy_bytes);
    let decision = relay_domain::PolicyDecision::allow(
        action_hash,
        policy_digest,
        vec!["policy-001".to_string()],
    );
    let signer = create_test_signer();

    let builder = ActionReceiptBuilder::new(&action, &decision);
    let receipt = builder.build_and_sign(&signer).unwrap();
    let domain = builder.build_domain().unwrap();

    assert_eq!(domain.policy.policy_digest, policy_digest);
    assert_eq!(domain.policy.determining_policies, vec!["policy-001"]);
    assert_eq!(receipt.action_hash, action_hash);
}

#[test]
fn test_lease_principal_and_resource_validation() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let _signer = create_test_signer();

    // In-domain check: lease matches action
    let matching_lease = create_test_lease(action_hash, &action.principal, &action.resource);
    assert_eq!(matching_lease.principal, action.principal);
    assert_eq!(matching_lease.scoped_resource, action.resource.as_str());

    // Divergent principal
    let foreign_principal = PrincipalId::new("principal:agent:evil-twin").unwrap();
    let mismatched_principal_lease =
        create_test_lease(action_hash, &foreign_principal, &action.resource);
    assert_ne!(mismatched_principal_lease.principal, action.principal);

    // Divergent resource
    let foreign_resource = ResourceUri::parse("github://github.com/evil/malicious").unwrap();
    let mismatched_resource_lease =
        create_test_lease(action_hash, &action.principal, &foreign_resource);
    assert_ne!(
        mismatched_resource_lease.scoped_resource,
        action.resource.as_str()
    );

    // Both build_domain and build_and_sign enforce lease.action_hash
    let builder =
        ActionReceiptBuilder::new(&action, &decision).with_credential_lease(Some(&matching_lease));
    assert!(builder.build_domain().is_ok());
}
