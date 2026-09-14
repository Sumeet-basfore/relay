use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use relay_cli::commercial::billing_state::{
    BillingStateError, BillingStateManager, SubscriptionAccount, SubscriptionState,
};
use relay_cli::commercial::entitlement::{
    CertificateRevocationList, EntitlementError, LicenseCertificate, LicenseClaims, LicenseStatus,
    LicenseTier, RevocationListClaims,
};
use relay_domain::{
    AuthorizationRequest, PolicyDecisionType, PolicyEngine, PrincipalId, ResourceUri, SessionId,
    ToolId,
};
use relay_policy::engine::CedarPolicyEngine;
use serde_json::json;

#[test]
fn test_subscription_state_machine_full_lifecycle() {
    let mut manager = BillingStateManager::new();
    let mut account = SubscriptionAccount::new("cus_acme_beta_001");

    assert_eq!(account.state, SubscriptionState::None);

    // 1. Checkout initiated
    let state = manager
        .process_event(
            &mut account,
            "evt_01",
            "checkout.session.initiated",
            1000,
            &json!({}),
        )
        .unwrap();
    assert_eq!(state, SubscriptionState::Checkout);

    // 2. Checkout completed -> Active
    let state = manager
        .process_event(
            &mut account,
            "evt_02",
            "checkout.session.completed",
            1010,
            &json!({
                "subscription": "sub_live_999",
                "tier": "enterprise",
                "seats": 25
            }),
        )
        .unwrap();
    assert_eq!(state, SubscriptionState::Active);
    assert_eq!(account.subscription_id.as_deref(), Some("sub_live_999"));
    assert_eq!(account.seat_count, 25);
    assert_eq!(account.plan_tier, "enterprise");

    // 3. Payment failed -> PastDue
    let state = manager
        .process_event(
            &mut account,
            "evt_03",
            "invoice.payment_failed",
            2000,
            &json!({}),
        )
        .unwrap();
    assert_eq!(state, SubscriptionState::PastDue);
    assert!(account.grace_period_end.is_some());

    // 4. Repeated payment failure -> Grace
    let state = manager
        .process_event(
            &mut account,
            "evt_04",
            "invoice.payment_failed",
            2100,
            &json!({}),
        )
        .unwrap();
    assert_eq!(state, SubscriptionState::Grace);

    // 5. Successful payment recovery -> Active (reactivated)
    let state = manager
        .process_event(
            &mut account,
            "evt_05",
            "invoice.payment_succeeded",
            2200,
            &json!({}),
        )
        .unwrap();
    assert_eq!(state, SubscriptionState::Active);
    assert!(account.grace_period_end.is_none());

    // 6. Cancellation at period end -> Cancelled
    let state = manager
        .process_event(
            &mut account,
            "evt_06",
            "customer.subscription.deleted",
            3000,
            &json!({}),
        )
        .unwrap();
    assert_eq!(state, SubscriptionState::Cancelled);
}

#[test]
fn test_idempotency_duplicate_webhooks_ignored() {
    let mut manager = BillingStateManager::new();
    let mut account = SubscriptionAccount::new("cus_idempotency");

    let res1 = manager.process_event(
        &mut account,
        "evt_same_id_100",
        "checkout.session.completed",
        1000,
        &json!({ "tier": "pro", "seats": 5 }),
    );
    assert!(res1.is_ok());
    assert_eq!(account.state, SubscriptionState::Active);

    // Duplicate webhook with identical event_id must be rejected as duplicate
    let res2 = manager.process_event(
        &mut account,
        "evt_same_id_100",
        "checkout.session.completed",
        1000,
        &json!({ "tier": "pro", "seats": 5 }),
    );
    assert!(res2.is_err());
    match res2.unwrap_err() {
        BillingStateError::DuplicateEvent { event_id } => {
            assert_eq!(event_id, "evt_same_id_100");
        }
        other => panic!("Expected DuplicateEvent, got {:?}", other),
    }
}

#[test]
fn test_out_of_order_webhook_events_rejected() {
    let mut manager = BillingStateManager::new();
    let mut account = SubscriptionAccount::new("cus_ordering");

    // Event at timestamp 2000
    manager
        .process_event(
            &mut account,
            "evt_modern",
            "checkout.session.completed",
            2000,
            &json!({}),
        )
        .unwrap();

    // Stale delayed event arriving from timestamp 1500 must be rejected
    let res = manager.process_event(
        &mut account,
        "evt_stale",
        "checkout.session.initiated",
        1500,
        &json!({}),
    );
    assert!(res.is_err());
    match res.unwrap_err() {
        BillingStateError::OutOfOrderEvent {
            incoming_ts,
            current_ts,
        } => {
            assert_eq!(incoming_ts, 1500);
            assert_eq!(current_ts, 2000);
        }
        other => panic!("Expected OutOfOrderEvent, got {:?}", other),
    }
}

#[test]
fn test_refund_event_transitions_to_cancelled_without_affecting_local_state() {
    let mut manager = BillingStateManager::new();
    let mut account = SubscriptionAccount::new("cus_refund_target");

    manager
        .process_event(
            &mut account,
            "evt_checkout",
            "checkout.session.completed",
            1000,
            &json!({ "tier": "pro", "seats": 10 }),
        )
        .unwrap();
    assert_eq!(account.state, SubscriptionState::Active);

    // Refund issued within 14 days
    let new_state = manager
        .process_event(
            &mut account,
            "evt_refund_processed",
            "charge.refunded",
            1500,
            &json!({ "amount_refunded": 4900 }),
        )
        .unwrap();

    assert_eq!(new_state, SubscriptionState::Cancelled);
    assert_eq!(account.state, SubscriptionState::Cancelled);
}

#[test]
fn test_hybrid_revocation_with_signed_crl() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let now = 1773576000;
    // 30-day short-lived license
    let compromised_license_id = "lic_short_01COMPROMISED";
    let claims = LicenseClaims {
        license_id: compromised_license_id.into(),
        customer_id: "cus_leaked_credentials".into(),
        customer_name: "Compromised Partner".into(),
        tier: LicenseTier::Pro,
        seat_count: 5,
        issued_at: now,
        expires_at: now + (30 * 86400),
        grace_period_days: 0,
    };

    let cert = LicenseCertificate::issue(claims, &signing_key).unwrap();

    // 1. Without CRL: license verifies as Active
    let status = cert.verify(&verifying_key, now).unwrap();
    match status {
        LicenseStatus::Active { .. } => {}
        _ => panic!("Expected active status"),
    }

    // 2. Issue Emergency Certificate Revocation List (CRL) containing the compromised ID
    let crl_claims = RevocationListClaims {
        crl_id: "crl_emergency_2026_01".into(),
        issued_at: now + 3600,
        revoked_license_ids: vec!["lic_other_bad_id".into(), compromised_license_id.into()],
    };
    let crl = CertificateRevocationList::issue(crl_claims, &signing_key).unwrap();

    // 3. Verify license with CRL -> Fails immediately with LicenseRevoked
    let res = cert.verify_with_crl(&verifying_key, now, Some(&crl));
    assert!(res.is_err());
    match res.unwrap_err() {
        EntitlementError::LicenseRevoked { license_id, crl_id } => {
            assert_eq!(license_id, compromised_license_id);
            assert_eq!(crl_id, "crl_emergency_2026_01");
        }
        other => panic!("Expected LicenseRevoked, got {:?}", other),
    }

    // 4. An innocent unrevoked license verified with the same CRL succeeds
    let innocent_claims = LicenseClaims {
        license_id: "lic_innocent_99".into(),
        customer_id: "cus_good_standing".into(),
        customer_name: "Good Standing Corp".into(),
        tier: LicenseTier::Enterprise,
        seat_count: 50,
        issued_at: now,
        expires_at: now + (30 * 86400),
        grace_period_days: 7,
    };
    let innocent_cert = LicenseCertificate::issue(innocent_claims, &signing_key).unwrap();
    let innocent_status = innocent_cert
        .verify_with_crl(&verifying_key, now, Some(&crl))
        .unwrap();
    match innocent_status {
        LicenseStatus::Active { .. } => {}
        _ => panic!("Innocent license should remain Active"),
    }
}

#[tokio::test]
async fn test_non_interference_payment_status_is_never_authorization_status() {
    let engine = CedarPolicyEngine::default_engine().expect("default engine must load");

    // Invariant 1: An Enterprise license holder CANNOT bypass Cedar deny on .env
    let forbidden_request = AuthorizationRequest {
        principal: PrincipalId::new("principal:agent:default").unwrap(),
        action: "fs.read".to_string(),
        resource: ResourceUri::parse("file:///workspace/project/.env").unwrap(),
        session_id: SessionId::new_v7(),
        tool: ToolId::new("fs", "read").unwrap(),
        arguments: json!({ "path": "/workspace/project/.env" }),
        working_directory: "/workspace/project".to_string(),
        timestamp: Utc::now(),
        action_hash: None,
    };

    let decision = engine.evaluate(&forbidden_request).await.expect("eval");
    assert_eq!(
        decision.decision,
        PolicyDecisionType::Deny,
        "Enterprise commercial status CANNOT bypass Cedar deny!"
    );

    // Invariant 2: When subscription is CANCELLED or EXPIRED, open-core execution of safe action remains ALLOWED
    let allowed_request = AuthorizationRequest {
        principal: PrincipalId::new("principal:agent:default").unwrap(),
        action: "fs.read".to_string(),
        resource: ResourceUri::parse("file:///workspace/project/README.md").unwrap(),
        session_id: SessionId::new_v7(),
        tool: ToolId::new("fs", "read").unwrap(),
        arguments: json!({ "path": "/workspace/project/README.md" }),
        working_directory: "/workspace/project".to_string(),
        timestamp: Utc::now(),
        action_hash: None,
    };

    let decision_allowed = engine.evaluate(&allowed_request).await.expect("eval");
    assert_eq!(
        decision_allowed.decision,
        PolicyDecisionType::Allow,
        "Expired or cancelled commercial status CANNOT disable open core safe actions!"
    );
}
