mod common;

use common::*;
use relay_credentials::{InMemoryCredentialProvider, JitCredentialBroker};
use relay_domain::{
    CredentialBroker, CredentialProviderType, CredentialRequest, Digest, ExecutionId,
    ExecutionObservationStatus, ExecutionRoute, InTotoStatement, OutputHash, PolicyEngine,
};
use relay_policy::CedarPolicyEngine;
use relay_receipts::{
    base64_decode, ActionReceiptBuilder, Ed25519ReceiptSigner, ReceiptError, ReceiptVerifier,
};
use std::sync::Arc;

#[tokio::test]
async fn test_end_to_end_governed_pipeline_to_verified_receipt() {
    // 1. Setup Cedar Policy Engine
    let cedar_engine = CedarPolicyEngine::default_engine().expect("Default policy engine");

    // 2. Setup Credential Broker with vaulted secret
    let broker = Arc::new(JitCredentialBroker::new());
    let provider = Arc::new(InMemoryCredentialProvider::new(
        CredentialProviderType::KeyringStatic,
    ));
    provider
        .add_secret(
            "github_token",
            b"ghp_test_secret_never_leaked_to_receipt".to_vec(),
        )
        .await;
    broker.register_provider(provider).await;

    // 3. Create CanonicalAction
    let (action, action_hash) = create_test_action();

    // 4. Evaluate Cedar Policy
    let auth_req = action.to_authorization_request().expect("To auth request");
    let decision = cedar_engine
        .evaluate(&auth_req)
        .await
        .expect("Policy evaluation must succeed");
    assert!(
        decision.is_allowed(),
        "Default policy should allow create_issue"
    );
    assert_eq!(decision.action_hash, action_hash);

    // 5. Acquire Credential Lease
    let cred_req = CredentialRequest::new(
        action_hash,
        action.principal.clone(),
        action.resource.clone(),
        CredentialProviderType::KeyringStatic,
        "github_token",
        "github",
        action.resource.as_str(),
        60,
    );
    let (lease, secret) = broker
        .acquire_lease(&cred_req, &decision)
        .await
        .expect("Should acquire credential lease");

    // Verify secret is present in SecretBuffer
    secret.expose_scoped(|bytes| {
        assert_eq!(bytes, b"ghp_test_secret_never_leaked_to_receipt");
    });

    // 6. Simulate Execution & Observation
    let execution_id = ExecutionId::new_v7();
    let started_at = chrono::Utc::now();
    let completed_at = started_at + chrono::Duration::milliseconds(32);
    let response_body = b"{\"id\": 1, \"number\": 42, \"state\": \"open\"}";
    let response_digest = OutputHash::compute(response_body);

    // 7. Consume lease immediately (single-action bound)
    broker
        .consume_lease(&lease.lease_id)
        .await
        .expect("Consume lease");
    drop(secret);

    // 8. Signer and Builder assembly
    let signer = Ed25519ReceiptSigner::generate("relay-gateway-signer-v1");

    let builder = ActionReceiptBuilder::new(&action, &decision)
        .with_credential_lease(Some(&lease))
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
            Some(32),
        )
        .with_observation(
            ExecutionObservationStatus::Success,
            0,
            response_digest,
            None,
            response_body.len(),
            Some(201),
            "GitHub create_issue succeeded (HTTP 201)",
            false,
            "IdempotentSafeToRetry",
            None,
        );

    let receipt = builder
        .build_and_sign(&signer)
        .expect("Should build and sign receipt");

    // 9. Independent Public Key Verification
    let verifier = ReceiptVerifier::new(signer.verifying_key());
    let verify_res =
        verifier.verify_receipt(&receipt, Some(&action_hash), Some(&decision.policy_digest));
    assert!(
        verify_res.is_valid(),
        "Receipt verification must succeed: {:?}",
        verify_res
    );

    // 10. Audit in-toto Statement and ensure Zero Secret Leakage
    let payload_bytes = base64_decode(&receipt.dsse_envelope.payload).unwrap();
    let statement: InTotoStatement = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(statement.subject[0].name, action.resource.as_str());
    assert_eq!(
        statement.subject[0].digest.get("sha256").unwrap(),
        &action_hash.to_hex()
    );
    assert_eq!(receipt.receipt_hash, Digest::compute(&payload_bytes));

    let statement_json = String::from_utf8(payload_bytes).unwrap();
    assert!(!statement_json.contains("ghp_test_secret_never_leaked_to_receipt"));
    assert!(!statement_json.contains("never_leaked"));
    assert!(statement_json.contains(&lease.lease_id.to_string()));
    assert!(statement_json.contains("github_token")); // Key alias is metadata, safe
}

#[tokio::test]
async fn test_ambiguous_mutation_pipeline_receipt() {
    let (action, action_hash) = create_test_action();
    let decision = create_test_decision(action_hash, true);
    let signer = create_test_signer();

    // Mutating request timed out in flight -> unknown remote state
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

    let receipt = builder
        .build_and_sign(&signer)
        .expect("Must generate receipt for ambiguous mutation");
    let verifier = ReceiptVerifier::new(signer.verifying_key());
    let verify_res = verifier.verify_receipt(&receipt, Some(&action_hash), None);
    assert!(verify_res.is_valid());

    let payload_bytes = base64_decode(&receipt.dsse_envelope.payload).unwrap();
    let statement: InTotoStatement = serde_json::from_slice(&payload_bytes).unwrap();

    let obs = statement.predicate.observation;
    assert_eq!(obs.get("status").unwrap(), "AMBIGUOUS_MUTATION");
    assert_eq!(obs.get("is_ambiguous_mutation").unwrap(), true);
    assert_eq!(
        obs.get("retry_classification").unwrap(),
        "AmbiguousRequiresVerification"
    );
}

#[tokio::test]
async fn test_policy_denial_prevents_receipt_production() {
    let (action, action_hash) = create_test_action();
    let deny_decision = create_test_decision(action_hash, false);
    let signer = create_test_signer();

    let builder = ActionReceiptBuilder::new(&action, &deny_decision);
    let err = builder.build_and_sign(&signer).unwrap_err();

    match err {
        ReceiptError::UnauthorizedExecution { decision } => {
            assert_eq!(decision, "Deny");
        }
        other => panic!("Expected UnauthorizedExecution on Deny, got: {:?}", other),
    }
}
