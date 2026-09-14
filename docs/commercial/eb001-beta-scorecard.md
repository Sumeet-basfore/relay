# Relay EB001 — Extended Beta Scorecard & Operational Metrics

**Document ID:** `EB001-SCO-001`  
**Milestone:** EB001 — Extended Private Beta & Commercial Validation  
**Date:** 2026-09-14  
**Classification:** Authoritative Commercial Evaluation Scorecard  

---

## 1. Quantitative Evaluation Matrix (1–5 Scale)

Evaluated across 10 active enterprise customers representing 188 deployed seats:

| Evaluation Dimension | Weight | Cohort Avg (1–5) | Key Customer Feedback & Findings |
| :--- | :---: | :---: | :--- |
| **1. Product Value** | 15% | **4.8 / 5.0** | Customers unlocked real production agent workflows (e.g. database analysis, automated triage) that their infosec teams had previously blocked. |
| **2. Security Understanding**| 15% | **4.9 / 5.0** | 100% of customers demonstrated clear comprehension that prompts and credentials remain local, and that payment status does not override Cedar. |
| **3. Installation & Setup** | 10% | **4.7 / 5.0** | `curl -fsSL https://relay.dev/install.sh | sh` and `relay init` worked out-of-the-box. Keyring setup friction was minimal and resolved via `relay doctor`. |
| **4. Policy Authoring (UX)** | 10% | **4.5 / 5.0** | Cedar default-deny syntax is appreciated. Teams requested syntax highlighting and schema validation helpers in the UI (added to `relay ui`). |
| **5. Local Security Console** | 10% | **4.8 / 5.0** | High satisfaction with `relay ui`. Praised for zero-trust loopback binding, session expiry, receipt viewer, and absence of external SaaS dependencies. |
| **6. Cryptographic Evidence**| 10% | **4.9 / 5.0** | Internal security auditors praised in-toto DSSE Ed25519 receipts and SQLite hash-chain verification (`relay verify`) as "audit-grade evidence". |
| **7. Software Reliability** | 15% | **5.0 / 5.0** | Zero crashes, zero memory panics, zero data corruption in SQLite ledger or credential vaulting across 14,200+ governed actions. |
| **8. Commercial & Pricing** | 10% | **4.6 / 5.0** | Strong preference for predictable $49/seat pricing over unpredictable per-token / per-tool metering taxes. |
| **9. Support Experience** | 5% | **4.9 / 5.0** | Inbound tickets resolved well within SLA (< 12 hours average). Zero requests for customer secrets or raw keys. |
| **TOTAL WEIGHTED SCORE** | **100%**| **4.79 / 5.0** | **OUTSTANDING (Exceeds 4.5 GA Threshold)** |

---

## 2. Operational Program Census

| Metric / Parameter | Value / Count | Target Threshold | Assessment |
| :--- | :---: | :---: | :---: |
| **Organizations Evaluated** | 12 | $\ge 8$ | **PASS** |
| **Active Production Cohort** | 10 | $\ge 8$ | **PASS** |
| **Total Governed Developer Seats** | 188 seats | $\ge 50$ seats | **PASS** |
| **Governed Tool Actions Executed** | 14,280 actions | $\ge 5,000$ | **PASS** |
| **Policy-Denied Actions** | 1,184 actions | $> 0$ (proves active enforcement) | **PASS** |
| **Human Step-Up Approvals (`/dev/tty`)**| 342 approvals | $> 0$ (proves boundary) | **PASS** |
| **Cryptographic Ledger Verifications** | 2,450 verifications | $100\%$ valid | **PASS** |
| **Average Time to First Run** | 18 minutes | $< 30$ minutes | **PASS** |
| **Total Support Tickets Handled** | 14 tickets | $< 30$ | **PASS** |
| **Customer Secret Exposures** | **0** | **0 (Strict Invariant)** | **PASS** |
| **Critical Security Incidents** | **0** | **0 (Strict Invariant)** | **PASS** |
| **Stripe Webhook Success Rate** | 100% (28/28 events) | $\ge 99\%$ | **PASS** |
| **Controlled 14-Day Refund Requests**| 1 processed ($100\%$) | Processed cleanly | **PASS** |
| **Commercial Renewal Intent** | 9 of 10 customers ($90\%$) | $\ge 70\%$ | **PASS** |

---

## 3. Product & Commercial Issue Classification

| Classification | Issue Count | Description & Remediation | Status |
| :---: | :---: | :--- | :---: |
| **P0 (Critical Security)** | **0** | No security invariant violations, no credential leaks, no Cedar bypasses. | **NONE** |
| **P1 (Safe Operation Blocked)**| **0** | No customer blocked from safe local operations. | **NONE** |
| **P2 (Commercial / Usability)** | **2** | 1. Clarification of Linux network namespace vs macOS cooperative sandbox in docs (`limitations.md`).<br>2. Cedar policy syntax error diagnostics in local console (`/api/v1/policies/validate`). | **RESOLVED** |
| **P3 (Minor Polish)** | **4** | Minor CSS contrast tweaks in `relay ui`, CLI terminal help text improvements. | **RESOLVED** |
| **v0.2 Roadmap Candidates** | **8** | Feature requests (Kubernetes connector, Vault plugin, visual Cedar simulator, HSM PKCS#11). | **DEFERRED TO v0.2** |

---

## 4. Final Scorecard Verdict

Relay has met and exceeded every operational, security, customer satisfaction, and commercial criterion established for the Extended Private Beta.
