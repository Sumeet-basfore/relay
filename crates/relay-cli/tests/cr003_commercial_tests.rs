use chrono::Utc;
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use relay_cli::commercial::billing_webhook::{StripeWebhookVerifier, WebhookError};
use relay_cli::commercial::entitlement::{
    EntitlementError, LicenseCertificate, LicenseClaims, LicenseStatus, LicenseTier,
};
use relay_domain::{
    AuthorizationRequest, PolicyDecisionType, PolicyEngine, PrincipalId, ResourceUri, SessionId,
    ToolId,
};
use relay_policy::engine::CedarPolicyEngine;
use serde_json::json;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[test]
fn test_offline_license_issuance_and_verification() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let now = 1773576000; // 2026-03-15
    let claims = LicenseClaims {
        license_id: "lic_ent_01JXYZ".into(),
        customer_id: "cus_acme_corp".into(),
        customer_name: "Acme Cybernetics, Inc.".into(),
        tier: LicenseTier::Enterprise,
        seat_count: 50,
        issued_at: now - 86400,
        expires_at: now + (365 * 86400),
        grace_period_days: 7,
    };

    let cert = LicenseCertificate::issue(claims.clone(), &signing_key)
        .expect("License issuance should succeed");

    // Pure offline verification
    let status = cert
        .verify(&verifying_key, now)
        .expect("Verification must succeed offline");

    match status {
        LicenseStatus::Active { seconds_remaining } => {
            assert_eq!(seconds_remaining, 365 * 86400);
        }
        _ => panic!("Expected Active license status"),
    }
}

#[test]
fn test_tampered_license_signature_rejected() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let now = 1773576000;
    let claims = LicenseClaims {
        license_id: "lic_pro_123".into(),
        customer_id: "cus_hacker".into(),
        customer_name: "Evil Corp".into(),
        tier: LicenseTier::Pro,
        seat_count: 5,
        issued_at: now,
        expires_at: now + (30 * 86400),
        grace_period_days: 3,
    };

    let mut cert = LicenseCertificate::issue(claims, &signing_key).unwrap();

    // Adversary attempts to increase seat count from 5 to 500
    cert.claims.seat_count = 500;

    let res = cert.verify(&verifying_key, now);
    assert!(res.is_err());
    match res.unwrap_err() {
        EntitlementError::InvalidSignature => {}
        other => panic!("Expected InvalidSignature, got {:?}", other),
    }
}

#[test]
fn test_expired_license_enters_grace_period_and_expires() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let expiry = 1773500000;
    let claims = LicenseClaims {
        license_id: "lic_grace_test".into(),
        customer_id: "cus_demo".into(),
        customer_name: "Demo LLC".into(),
        tier: LicenseTier::Pro,
        seat_count: 10,
        issued_at: expiry - (30 * 86400),
        expires_at: expiry,
        grace_period_days: 7, // 7 days grace = 604,800s
    };

    let cert = LicenseCertificate::issue(claims, &signing_key).unwrap();

    // 1. Check inside grace period (2 days after expiry)
    let check_time_grace = expiry + (2 * 86400);
    let status = cert.verify(&verifying_key, check_time_grace).unwrap();
    match status {
        LicenseStatus::GracePeriod {
            seconds_remaining_in_grace,
        } => {
            assert_eq!(seconds_remaining_in_grace, 5 * 86400);
        }
        _ => panic!("Expected GracePeriod status"),
    }

    // 2. Check after grace period lapses (8 days after expiry)
    let check_time_lapsed = expiry + (8 * 86400);
    let res = cert.verify(&verifying_key, check_time_lapsed);
    assert!(res.is_err());
    match res.unwrap_err() {
        EntitlementError::LicenseExpired { .. } => {}
        other => panic!("Expected LicenseExpired, got {:?}", other),
    }
}

#[tokio::test]
async fn test_payment_status_is_not_authorization_status_invariant() {
    // Invariant: Core Cedar policy enforcement does not bend to commercial license state.
    let engine = CedarPolicyEngine::default_engine().expect("default engine must load");

    // Even with a valid, top-tier multi-seat Enterprise license:
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let enterprise_claims = LicenseClaims {
        license_id: "lic_ent_billion_dollar".into(),
        customer_id: "cus_mega_vip".into(),
        customer_name: "Mega Corp".into(),
        tier: LicenseTier::Enterprise,
        seat_count: 10000,
        issued_at: 1000,
        expires_at: 2000000000,
        grace_period_days: 30,
    };
    let _enterprise_cert = LicenseCertificate::issue(enterprise_claims, &signing_key).unwrap();

    // 1. Authorization check on forbidden action (reading .env) must still be DENIED!
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

    let decision_forbidden = engine
        .evaluate(&forbidden_request)
        .await
        .expect("evaluation");
    assert_eq!(
        decision_forbidden.decision,
        PolicyDecisionType::Deny,
        "Enterprise license MUST NOT authorize forbidden .env read action!"
    );

    // 2. Permitted action (reading README.md) remains authorized regardless of license status
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

    let decision_allowed = engine.evaluate(&allowed_request).await.expect("evaluation");
    assert_eq!(
        decision_allowed.decision,
        PolicyDecisionType::Allow,
        "Cedar permitted README.md read should remain authorized"
    );
}

#[test]
fn test_stripe_webhook_valid_signature_accepted() {
    let secret = "whsec_test_secret_key_12345";
    let now = 1773576000;
    let payload = br#"{"id":"evt_test_checkout","type":"checkout.session.completed","data":{"customer":"cus_test99"}}"#;

    // Build valid Stripe signature header: t=<now>,v1=<hmac>
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(now.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let signature_hex = hex::encode(mac.finalize().into_bytes());

    let header = format!("t={},v1={}", now, signature_hex);

    let event = StripeWebhookVerifier::verify(payload, &header, secret, now, 300)
        .expect("Valid webhook must be accepted");

    assert_eq!(event.id, "evt_test_checkout");
    assert_eq!(event.event_type, "checkout.session.completed");
}

#[test]
fn test_stripe_webhook_replay_attack_rejected() {
    let secret = "whsec_test_secret_key_12345";
    let now = 1773576000;
    let stale_time = now - 305; // 305 seconds ago (> 300s window)
    let payload = br#"{"id":"evt_replay","type":"checkout.session.completed","data":{}}"#;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(stale_time.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let signature_hex = hex::encode(mac.finalize().into_bytes());

    let header = format!("t={},v1={}", stale_time, signature_hex);

    let res = StripeWebhookVerifier::verify(payload, &header, secret, now, 300);
    assert!(res.is_err());
    match res.unwrap_err() {
        WebhookError::TimestampOutOfTolerance { skew_seconds, .. } => {
            assert_eq!(skew_seconds, 305);
        }
        other => panic!("Expected TimestampOutOfTolerance, got {:?}", other),
    }
}

#[test]
fn test_stripe_webhook_invalid_signature_rejected() {
    let secret = "whsec_test_secret_key_12345";
    let now = 1773576000;
    let payload = br#"{"id":"evt_spoof","type":"checkout.session.completed","data":{}}"#;
    let header = format!(
        "t={},v1=deadbeefcafebabe00112233445566778899aabbccddeeff",
        now
    );

    let res = StripeWebhookVerifier::verify(payload, &header, secret, now, 300);
    assert!(res.is_err());
    match res.unwrap_err() {
        WebhookError::InvalidSignature => {}
        other => panic!("Expected InvalidSignature, got {:?}", other),
    }
}

#[test]
fn test_untrusted_client_claims_rejected() {
    // Verify untrusted client parameters are recognized as spoofing attempts
    assert!(StripeWebhookVerifier::is_untrusted_client_claim(
        "https://relay.dev/app?payment_success=true"
    ));
    assert!(StripeWebhookVerifier::is_untrusted_client_claim(
        "https://relay.dev/app?status=paid&seat=100"
    ));
    assert!(StripeWebhookVerifier::is_untrusted_client_claim(
        "https://relay.dev/app?licensed=true"
    ));
    assert!(!StripeWebhookVerifier::is_untrusted_client_claim(
        "https://relay.dev/app?session_id=cs_123"
    ));
}
