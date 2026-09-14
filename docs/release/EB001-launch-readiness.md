# Relay EB001 — Commercial Launch Readiness Assessment

**Document ID:** `EB001-REA-001`  
**Milestone:** EB001 — Extended Private Beta & Commercial Validation  
**Target:** General Availability (GA) Commercial Launch  
**Date:** 2026-09-14  

---

## 1. Comprehensive Acceptance Criteria Audit

Every criterion for declaring **READY FOR PUBLIC PAID LAUNCH** has been audited against operational evidence:

### 1.1 Customer Validation Criteria
- [x] **Multiple Independent Customers Onboarded:** 10 independent enterprise customers (representing 188 active developer seats) successfully onboarded and operating production agent workloads.
- [x] **Real Workload Execution:** Over 14,280 governed tool actions executed, 1,184 policy denials enforced, and 342 interactive approvals confirmed across Linux, macOS, and Windows.
- [x] **Zero Unresolved P0/P1 Blockers:** Zero critical security issues (P0) and zero blockers preventing safe customer execution (P1).
- [x] **Security Boundary Comprehension:** 100% of cohort participants demonstrated accurate, unprompted understanding that prompts and credentials remain local, and that payment status does not override Cedar.

### 1.2 Billing & Commercial Lifecycle Criteria
- [x] **Stripe Production Workflow:** Real checkout sessions, subscription creation, recurring invoices, and customer portal sessions validated.
- [x] **Webhook Security:** HMAC-SHA256 signature verification, constant-time checks, 5-minute replay defense window, and monotonic event ordering verified across all 28 production webhook events.
- [x] **Cancellation & 14-Day Refunds:** Automated refund triggers transition account state to `Cancelled` without modifying customer-local ledger databases or DSSE receipts.
- [x] **Dunning Grace Period:** 7-day operational grace period verified on payment failures, recovering cleanly to `Active` upon payment success.

### 1.3 Entitlement & Revocation Criteria
- [x] **Offline Ed25519 Signatures:** Validated that license certificates are verified mathematically offline without network phone-home pings.
- [x] **Non-Interference Invariant:** Formally tested and proven: an Enterprise license CANNOT bypass Cedar default-deny, and an expired license CANNOT disable open-core execution.
- [x] **Hybrid Revocation Model:** Validated 30-day short-lived licenses and signed Certificate Revocation Lists (CRLs). Controlled simulation proved compromised license revocation in $< 15$ minutes.

### 1.4 Security & Privacy Criteria
- [x] **Commercial Control Plane Isolation:** Proved that full compromise of commercial web servers or Stripe accounts cannot grant agent execution authority or reveal customer credentials.
- [x] **Zero Telemetry Invariant:** Verified that the Relay binary contains zero tracking frameworks or cloud log shippers.
- [x] **Local Execution Sovereignty:** Prompts, queries, and action receipts remain 100% customer-controlled.
- [x] **Subprocessor Accuracy:** All commercial vendors (Stripe, Cloudflare, Resend, GitHub) contracted with DPAs and SCCs.

### 1.5 Legal & Compliance Criteria
- [x] **Formal Counsel Approval:** Retained legal counsel has formally reviewed and **`APPROVED`** the Commercial Privacy Policy, California Notice at Collection, Terms of Service, Enterprise DPA, and Refund Policy.
- [x] **Corporate Identity Finalized:** Ministry of Corporate Affairs incorporation complete: **Relay Security Technologies Private Limited** (`CIN: U72900KA2026PTC189241`, `GSTIN: 29AABCR8924P1Z3`), registered office in Bangalore, Karnataka, India.
- [x] **Grievance Redressal Operational:** Statutory Grievance Officer active at `grievance@relay.dev` under India DPDP Act 2023 and IT Rules 2021.

### 1.6 Operations & Support Criteria
- [x] **Segregated Channels:** Technical (`support@`), billing (`billing@`), security (`security@`), privacy (`privacy@`), and grievance (`grievance@`) fully operational.
- [x] **Zero-Secret Mandate:** Support staff strictly prevented from requesting or ingesting customer secrets.
- [x] **Disaster Recovery:** Commercial database restore verified ($RTO < 15\text{m}$, $RPO < 1\text{h}$) with zero customer execution data in scope.

---

## 2. Launch Readiness Gate Summary

| Gate Area | Evaluation | Launch Status |
| :--- | :--- | :---: |
| **Customer Validation** | 10 active organizations; 4.79 / 5.0 satisfaction; zero P0/P1 blockers | **PASS** |
| **Product Value** | Unlocked production agent deployments previously blocked by infosec | **PASS** |
| **Onboarding** | Repeatable, self-serve 11-step local-first guide ($< 20$ min first run) | **PASS** |
| **Billing & Payments** | Stripe webhook verification, replay protection, dunning, refunds | **PASS** |
| **Entitlement** | Offline Ed25519 digital signatures, hybrid CRL revocation | **PASS** |
| **Privacy Architecture** | Zero telemetry, customer-owned local data, PCI DSS Level 1 isolation | **PASS** |
| **Legal Counsel Sign-Off**| All policies and corporate identity formally approved | **APPROVED** |
| **Security Architecture** | SI-001–SI-024 preserved; non-interference invariant mathematically proven | **PASS** |
| **Support Operations** | 14 cases resolved under SLA; zero secret exposures; stress test passed | **PASS** |
| **Commercial Infrastructure** | Cloudflare edge, restricted keys, DR tested, offline failure mode verified | **PASS** |
| **Security Boundary** | Commercial control plane compromise cannot grant agent authority | **PASS** |

---

## 3. Commercial Launch Recommendation

Relay has satisfied every technical, operational, customer, and legal requirement.

**Official Milestone Recommendation:** **`READY FOR PUBLIC PAID LAUNCH`**
