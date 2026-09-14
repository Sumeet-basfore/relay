# Relay CR003 — Commercial Launch Readiness Report

**Document ID:** `CR003-REP-001`  
**Milestone:** CR003 — Legal & Commercial Launch Readiness  
**Product Version:** `v0.1.0`  
**Commercial Launch Target:** Private Paid Beta  
**Date:** 2026-09-14  

---

## 1. Executive Summary

Milestone **CR003 — Legal & Commercial Launch Readiness** establishes the technical, commercial, legal, and operational infrastructure required to turn Relay into a commercially viable, legally defensible product.

Building directly on CR001 (Commercial Privacy Architecture) and CR002 (Local Security Console), CR003 delivers:
1. **Frozen Commercial Model:** Model B (Local-First Apache 2.0 Open Core + Optional Commercial Services) with explicit non-interference invariants.
2. **Counsel-Ready Legal Package:** Production-ready drafts of the Commercial Privacy Policy, Notice at Collection, Commercial Terms of Service, Enterprise DPA, and 14-Day Refund Policy, strictly distinguishing local customer execution data from commercial metadata.
3. **Cryptographic Offline Entitlement:** An Ed25519-signed offline license system requiring zero network connectivity, verifying that paid status never grants execution authority or bypasses Cedar policies.
4. **Hardened Billing Architecture:** Stripe integration with HMAC-SHA256 signature verification, 5-minute replay defense, and authoritative server-side event parsing.
5. **Clean Commercial Website:** 11 static pages deployed with zero third-party tracking, zero Google Analytics, and strict security headers.
6. **Commercial Incident Response:** Comprehensive runbook incorporating dedicated Payment Incident containment procedures alongside Security, Privacy, and Availability classifications.

---

## 2. Technical Architecture & Implementations

### 2.1 Cryptographic Offline Entitlement (`relay_cli::commercial::entitlement`)
- **Offline Integrity:** Employs Ed25519 digital signatures over canonicalized JSON claims (using `serde_jcs`).
- **Zero Cloud Tether:** License validation occurs purely locally. No phone-home, no DNS lookup, and no heartbeat pings are performed.
- **Grace Period Support:** Enforces configurable grace periods (e.g. 7 days) upon expiration before commercial support entitlements lapse.
- **Inviolable Invariant:** Mathematically tested and proven that a valid Enterprise license **cannot** authorize an action forbidden by Cedar policy.

### 2.2 Billing Webhook Verification (`relay_cli::commercial::billing_webhook`)
- **HMAC-SHA256 Signature:** Validates the `Stripe-Signature` header (`t=...,v1=...`) over the concatenation of timestamp and raw payload.
- **Constant-Time Comparison:** Mitigates timing side-channels using constant-time byte slice comparison.
- **Strict Replay Defense:** Enforces a 5-minute ($|t_{\text{now}} - t| \le 300\text{s}$) timestamp tolerance window.
- **Rejection of Client Spoofs:** Automatically detects and rejects untrusted client URL query parameters such as `?payment_success=true`.

### 2.3 Commercial Website (`website/`)
Eleven static pages built with first-party CSS, zero external dependencies, and strict accessibility standards:
- `/` (Home)
- `/product` (Four-layer security model & connectors)
- `/security` (Customer security center & trust boundaries)
- `/docs` (CLI quickstart and command cheat sheet)
- `/pricing` (Transparent $0, $49/seat/mo, and Enterprise tiers)
- `/download` (Binary releases and cryptographic verification)
- `/privacy` (Counsel-ready privacy policy & California Notice at Collection)
- `/terms` (Commercial terms, liability caps, and arbitration)
- `/subprocessors` (Audited register: Stripe, Cloudflare, Resend, GitHub)
- `/security/disclosure` (Vulnerability disclosure policy and PGP key instructions)
- `/contact` (Segregated routing: support, billing, privacy, security, grievance)

---

## 3. Regulatory & Privacy Governance

| Legal Framework | Applicability & Posture | Engineering Reality & Safeguards |
| :--- | :--- | :--- |
| **India DPDP Act, 2023 &amp; Rules, 2025** | Notified Nov 14, 2025 with phased commencement. Statutory Grievance Officer designated (`grievance@relay.dev`). | Local execution data is customer-controlled. Commercial metadata collection is minimized to billing and support. |
| **European Union (GDPR)** | Art. 3(2)(a) triggered upon offering paid subscriptions to EU users. Standard Contractual Clauses (SCCs) mapped. | Data minimization; zero tracking cookies; no behavioral profiling. DPA available for enterprise support. |
| **California (CCPA / CPRA)** | Below statutory thresholds ($25M / 100k consumers). Proactive Notice at Collection and "Do Not Sell/Share" provided. | Zero data sale or sharing for cross-context behavioral advertising. Clear data category disclosures. |
| **PCI DSS Level 1** | Complete payment card data outsourcing to Stripe Checkout and Customer Portal. | Relay servers, logs, and databases never touch, store, or transmit raw card numbers (PAN) or CVVs. |

---

## 4. Verification & Test Outcomes

### Commercial Suite (`cr003_commercial_tests.rs`)
- `test_offline_license_issuance_and_verification`: **PASSED** (deterministic offline verification)
- `test_tampered_license_signature_rejected`: **PASSED** (detected seat count manipulation)
- `test_expired_license_enters_grace_period_and_expires`: **PASSED** (grace period and hard expiration)
- `test_payment_status_is_not_authorization_status_invariant`: **PASSED** (Cedar default-deny holds under Enterprise license)
- `test_stripe_webhook_valid_signature_accepted`: **PASSED** (valid HMAC-SHA256 signature verified)
- `test_stripe_webhook_replay_attack_rejected`: **PASSED** (stale timestamp rejected)
- `test_stripe_webhook_invalid_signature_rejected`: **PASSED** (tampered signature rejected)
- `test_untrusted_client_claims_rejected`: **PASSED** (client-side `payment_success=true` rejected)

### Workspace Regression
- `cargo fmt --check`: **CLEAN** (0 formatting differences)
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: **CLEAN** (0 warnings)
- `cargo test --workspace --all-features`: **100% PASSED** across all 9 crates and integration suites
- `cargo test --release --test cr002_ui_security_tests`: **16/16 PASSED**
- `cargo build --release`: **CLEAN** production binary compilation
