mod common;

use common::*;
use relay_domain::{
    Approval, CredentialLease, CredentialProviderType, DecisionId, ExecutionId,
    ExecutionObservationStatus, ExecutionRoute, Ledger, OutputHash, PrincipalId, ResourceUri,
};
use relay_ledger::SqliteLedger;
use relay_receipts::ActionReceiptBuilder;

#[tokio::test]
async fn test_end_to_end_pipeline_to_ledger_verification() {
    let ledger = SqliteLedger::in_memory().unwrap();
    let signer = create_test_signer();
    let pubkey_bytes: [u8; 32] = signer.export_public_key().try_into().unwrap();
    let pubkey_hex = hex::encode(pubkey_bytes);

    // 1. Genesis initialization
    let genesis = ledger
        .initialize_genesis("01918a20-4321-7000-8000-000000000001", &pubkey_hex)
        .await
        .unwrap();

    // 2. Step 1: Normal authorized read action (get_repo)
    let (action1, action_hash1) = create_test_action("get_repo");
    let decision1 = create_test_decision(action_hash1);
    let builder1 = ActionReceiptBuilder::new(&action1, &decision1)
        .with_parent_receipt_hash(genesis.entry_hash)
        .with_execution_metadata(
            ExecutionId::new_v7(),
            ExecutionRoute::Native,
            "github",
            "get_repo",
            action1.resource.as_str(),
            Some("GET".to_string()),
            Some("https://api.github.com/repos/octocat/Hello-World".to_string()),
            chrono::Utc::now(),
            Some(chrono::Utc::now()),
            Some(18),
        )
        .with_observation(
            ExecutionObservationStatus::Success,
            0,
            OutputHash::compute(b"{\"name\": \"Hello-World\"}"),
            None,
            24,
            Some(200),
            "Repository fetched successfully",
            false,
            "SafeToRetry",
            None,
        );

    let receipt1 = builder1.build_and_sign(&signer).unwrap();
    let entry1 = ledger.append(&receipt1).await.unwrap();

    // 3. Step 2: Sensitive action requiring JIT credential lease and human approval
    let (action2, action_hash2) = create_test_action("delete_branch");
    let decision2 = create_test_decision(action_hash2);

    let mut approval = Approval::new(
        action_hash2,
        DecisionId::new_v7(),
        "Approve branch deletion",
        Some("operator-cli".to_string()),
        120,
    );
    let approver = PrincipalId::new("principal:human:security-lead").unwrap();
    approval.approve(approver).unwrap();

    let lease_resource = ResourceUri::parse("github://github.com/octocat/Hello-World").unwrap();
    let lease = CredentialLease::new(
        action_hash2,
        action2.principal.clone(),
        CredentialProviderType::KeyringStatic,
        "github_admin_token",
        "github",
        lease_resource.as_str(),
        30,
    );

    let builder2 = ActionReceiptBuilder::new(&action2, &decision2)
        .with_parent_receipt_hash(entry1.entry_hash)
        .with_approval(Some(&approval))
        .with_credential_lease(Some(&lease))
        .with_execution_metadata(
            ExecutionId::new_v7(),
            ExecutionRoute::Native,
            "github",
            "delete_branch",
            action2.resource.as_str(),
            Some("DELETE".to_string()),
            Some("https://api.github.com/repos/octocat/Hello-World/branches/test".to_string()),
            chrono::Utc::now(),
            Some(chrono::Utc::now()),
            Some(35),
        )
        .with_observation(
            ExecutionObservationStatus::Success,
            0,
            OutputHash::compute(b""),
            None,
            0,
            Some(204),
            "Branch deleted successfully",
            false,
            "NotSafeToRetry",
            None,
        );

    let receipt2 = builder2.build_and_sign(&signer).unwrap();
    let entry2 = ledger.append(&receipt2).await.unwrap();

    // 4. Verify ledger state
    assert_eq!(ledger.count().await.unwrap(), 3);
    assert_eq!(entry1.sequence_number.as_u64(), 1);
    assert_eq!(entry2.sequence_number.as_u64(), 2);
    assert_eq!(entry2.previous_receipt_hash, entry1.entry_hash);

    // 5. Full cryptographic verification
    let report = ledger.verify(Some(&pubkey_bytes)).await.unwrap();
    assert!(report.status.is_valid());
    assert_eq!(report.total_verified_entries, 3);
    assert_eq!(report.head_sequence, 2);
    assert_eq!(report.head_hash, entry2.entry_hash.to_hex());

    // 6. Verify querying receipt by ID
    let queried_r2 = ledger
        .get_receipt_by_id(&receipt2.receipt_id)
        .await
        .unwrap();
    assert!(queried_r2.is_some());
    let r2 = queried_r2.unwrap();
    assert_eq!(r2.receipt_id, receipt2.receipt_id);
    assert_eq!(r2.action_id, action2.action_id);
}
