# Relay Public Paid Launch — Launch Freeze Record

**Document ID:** `PL-FRZ-001`  
**Runbook Phase:** 1 — Launch Freeze  
**Effective Date:** 2026-09-14  
**Release Line:** `v0.1.0`  
**Status:** **FROZEN**

---

## 1. Purpose

This record formalizes Phase 1 of the Public Paid Launch Runbook. All items below are frozen for the `v0.1.0` public paid launch. Changes require explicit launch-governance approval and may trigger a `v0.1.Z` patch release per `docs/operations/maintenance-policy.md`.

No launch-phase work may reopen MVP architecture: authorization (Cedar), credential broker, egress mediation, evidence (DSSE receipts), or ledger model.

---

## 2. Frozen Artifacts

| Category | Frozen Item | Authoritative Source |
| :--- | :--- | :--- |
| **Pricing** | Team Pro: $49/seat/month ($39/seat/month annual); Enterprise: custom annual | `docs/commercial/eb001-beta-charter.md` |
| **Product Tiers** | Community (Apache 2.0 open core), Pro, Enterprise | `docs/commercial/cr003-commercial-model.md` |
| **Legal Documents** | Privacy Policy, Terms of Service, DPA, Refund Policy | `docs/legal/privacy-policy-draft.md`, `terms-draft.md`, `dpa-spec.md`, `refund-policy-spec.md` |
| **Counsel Status** | ALL APPROVED | `docs/commercial/pb001-counsel-status.md` |
| **Subprocessors** | Stripe, GitHub, Cloudflare, Resend/AWS SES | `docs/commercial/subprocessors.md` |
| **Website** | relay.dev public pages (pricing, security, download, legal) | Phase 2 verification record |
| **Billing** | Stripe checkout, webhook HMAC-SHA256, 5-minute replay defense, state machine | `docs/commercial/billing-architecture.md` |
| **Entitlement** | Offline Ed25519 license, 30-day terms, signed CRL revocation | EB001 entitlement validation |
| **Security Baseline** | SI-001–SI-024, GA004 security claims, M001–M003 adversarial harness | `docs/release/GA004-security-claims.md` |
| **Release Artifacts** | Tag `v0.1.0`, commit `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb` | `docs/release/GA005-launch-report.md` |

---

## 3. Frozen Release Identifiers

| Identifier | Value |
| :--- | :--- |
| **Git Tag** | `v0.1.0` |
| **Release Commit** | `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb` |
| **Archive SHA-256** | `6f843ab71592ee55cc9c3b9c556af23e58b1fe8b192404c28ee753912f9de206` |
| **Binary SHA-256** | `a4a3f930ecd36ee0c207bc014610a21b48d5718b5913443552e94fb49dd43a98` |

---

## 4. Core Invariant (Non-Negotiable)

> **Payment Status ≠ Authorization Status**

A valid Pro or Enterprise license cannot bypass Cedar default-deny, credential broker gates, human approval, or sandbox enforcement. An expired or cancelled license cannot disable open-core execution.

---

## 5. Bug Classification During Launch

Any defect discovered during launch must be classified before remediation:

| Class | Description | Response |
| :--- | :--- | :--- |
| **Security** | Boundary bypass, credential exposure, signing compromise | P0 — emergency patch per Phase 24 |
| **Correctness** | Policy evaluation, receipt, or ledger integrity error | P0/P1 per impact |
| **Billing** | Stripe webhook, subscription state, or refund failure | P1 — billing on-call |
| **Legal** | Policy mismatch, missing notice, subprocessors inaccuracy | Block launch until counsel review |
| **Documentation** | Incorrect claims, broken install docs | P2 — patch docs or `v0.1.Z` |
| **UX** | Friction in checkout, install, or console | P2/P3 |
| **v0.2 Feature** | New connector, platform parity, HSM, K8s | Deferred to `docs/roadmap/v0.2.md` |

---

## 6. Freeze Sign-Off

| Gate | Status | Evidence |
| :--- | :---: | :--- |
| Pricing frozen | **FROZEN** | EB001 charter §5 |
| Legal documents frozen | **FROZEN** | PB001 counsel status — ALL APPROVED |
| Subprocessors frozen | **FROZEN** | CR003 subprocessor register v2.0.0 |
| Billing behavior frozen | **FROZEN** | EB001 — 28/28 webhook events PASS |
| Entitlement behavior frozen | **FROZEN** | EB001 non-interference invariant proven |
| v0.1.0 security baseline frozen | **FROZEN** | GA005 + RC003 + M003 adversarial PASS |
| Architecture reopen prohibited | **ENFORCED** | This document §1 |

**Phase 1 Status:** **PASS — LAUNCH FREEZE ACTIVE**
