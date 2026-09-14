# Relay PB001 — Private Paid Beta Operations Report

**Document ID:** `PB001-REP-001`  
**Milestone:** PB001 — Private Paid Beta & Production Operations  
**Product Target:** Relay `v0.1.0`  
**Date:** 2026-09-14  

---

## 1. Milestone Overview

Milestone **PB001 — Private Paid Beta & Production Operations** operationalizes the commercial launch surface established in CR003. It validates that Relay is commercially operable with real design partner customers under strict security, privacy, and non-interference boundaries.

### Core Invariants Enforced:
1. **Separation of Concerns:**
   $$\text{Payment Status} \neq \text{Authorization Status}$$
   Commercial license entitlements govern access to customer support SLAs, commercial updates, and team management tools. They **never** grant execution authority or override Cedar default-deny policies.
2. **Local-First Customer Sovereignty:**
   The entire Relay execution runtime, OS keyring vault, action receipts, and SQLite ledger remain exclusively on the customer's machine. Zero execution data enters Relay commercial systems.
3. **Counsel Gate Compliance:**
   The engineering product is verified as `TECHNICAL BETA READY`. Open public billing is held at `LEGAL APPROVAL PENDING` while final corporate identity documents complete formal registration.

---

## 2. Technical Systems Implemented & Verified

### 2.1 Production Billing State Machine (`relay_cli::commercial::billing_state`)
- Implements the complete authoritative lifecycle:
  $$\text{NONE} \longrightarrow \text{CHECKOUT} \longrightarrow \text{ACTIVE} \longrightarrow \text{PAST\_DUE} \longrightarrow \text{GRACE} \longrightarrow \text{CANCELLED / EXPIRED}$$
- **Idempotent Webhook Processing:** Enforces unique event deduplication via `event.id`.
- **Out-of-Order Rejection:** Prevents stale network packets from regressing account state using monotonic event timestamps.
- **Dunning Grace Period:** Enforces a 7-day operational grace period before active license support lapses.
- **Refund Handling:** Verified that processing `charge.refunded` transitions commercial status to `Cancelled` without deleting or modifying customer-local ledger databases or DSSE receipts.

### 2.2 Hybrid Entitlement & Revocation Engine (`relay_cli::commercial::entitlement`)
- **Offline Ed25519 Signatures:** Canonical JSON claims are digitally signed and verified locally with zero network phone-home pings.
- **30-Day Term Limits:** Standard commercial licenses are issued with rolling 30-day terms to limit exposure windows.
- **Emergency Certificate Revocation List (CRL):** Allows immediate invalidation of compromised license IDs via digitally signed CRL manifests without requiring an online DRM daemon.

### 2.3 Production Operations & Incident Preparedness
- **Customer Support Runbook (`pb001-support-runbook.md`):** Complete workflows for installation, billing, licensing, privacy, and cancellation, enforcing a strict zero-secret mandate.
- **Tabletop Simulations (`pb001-incident-tabletop.md`):** Executed and verified two operational security tabletop exercises (credential exposure containment and forged license rejection).
- **Customer Feedback Framework (`pb001-feedback-program.md`):** Structured 7-dimension measurement matrix operating without client-side telemetry.
- **Onboarding Guide (`private-beta-onboarding.md`):** Eleven-step, local-first guide from invitation to local security console inspection.

---

## 3. Test Suites & Verification Results

### PB001 Production Operations Suite (`pb001_production_operations_tests.rs`)
1. `test_subscription_state_machine_full_lifecycle`: **PASSED** (Checkout -> Active -> PastDue -> Grace -> Reactivated -> Cancelled)
2. `test_idempotency_duplicate_webhooks_ignored`: **PASSED** (Duplicate event ID rejected)
3. `test_out_of_order_webhook_events_rejected`: **PASSED** (Stale timestamp rejected)
4. `test_refund_event_transitions_to_cancelled_without_affecting_local_state`: **PASSED** (Local receipts remain intact)
5. `test_hybrid_revocation_with_signed_crl`: **PASSED** (Compromised license rejected; unrevoked license remains Active)
6. `test_non_interference_payment_status_is_never_authorization_status`: **PASSED** (Cedar default-deny holds under Enterprise license; open core remains active when license is cancelled)

### Full Workspace Test Suite
- `cargo fmt --check`: **CLEAN** (0 formatting differences)
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: **CLEAN** (0 warnings)
- `cargo test --workspace --all-features`: **100% PASSED** across all 9 crates and integration test suites
- `cargo build --release`: **CLEAN** release compilation in `target/release/relay`
