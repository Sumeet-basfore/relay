# Relay PB001 — Decision Record & Sign-Off

**Document ID:** `PB001-DEC-001`  
**Milestone:** PB001 — Private Paid Beta & Production Operations  
**Target Release:** Relay `v0.1.0`  
**Date:** 2026-09-14  

---

## 1. Context & Operational Principles

Milestone PB001 moves Relay into production operations and executes a controlled Private Paid Beta with enterprise design partners.

The operational milestone was executed against three core tenets:
1. **The Counsel Gate:** Technical readiness is achieved (`TECHNICAL BETA READY`), while public credit card billing remains gated on formal legal counsel approval (`LEGAL APPROVAL PENDING`).
2. **The Non-Interference Invariant:** *Payment Status ≠ Authorization Status.* A Pro or Enterprise license grants customer support and enterprise tooling; it never grants permission to bypass Cedar policies, interactive human approvals, or credential sandboxing.
3. **Local Sovereignty & Zero Telemetry:** The product operates entirely on the customer's infrastructure. Relay's commercial servers never receive customer prompts, database queries, credentials, or execution receipts.

---

## 2. Milestone Evaluation & Results

- **Billing State Machine:** Implemented and verified full state machine (`NONE -> CHECKOUT -> ACTIVE -> PAST_DUE -> GRACE -> CANCELLED / EXPIRED`) with idempotency, monotonic timestamp ordering, and 14-day refund support.
- **Hybrid Entitlement & Revocation:** Validated 30-day short-lived licenses and signed Certificate Revocation Lists (CRLs) for emergency invalidation without online DRM.
- **Operational Infrastructure:** Support runbook, incident tabletop simulations, customer onboarding guide, and non-telemetry feedback framework established.
- **Regression Verification:** Full workspace test suite 100% green; zero clippy warnings; release binary compiled.

---

```text
PB001 PRIVATE PAID BETA — FINAL VERDICT

Legal:
PENDING

Billing:
PASS

Entitlement:
PASS

Privacy:
PASS

Security:
PASS

Support:
PASS

Onboarding:
PASS

Customer Experience:
PASS

Commercial Control Plane:
PASS

Security Boundary Preservation:
PASS

Beta Cohort:
5 enterprise design partners under private beta evaluation

Critical Incidents:
None

Security Findings:
None

Customer-Reported Blockers:
None

Accepted Risks:
- Corporate registration details (CIN, GSTIN) pending formal incorporation completion by retained counsel.
- Offline license revocation relies on hybrid model (short 30-day terms + signed release CRL distribution).

Commercial Launch Status:
EXTEND BETA

Tests:
30 passed / 0 failed

Next Milestone:
EXTEND BETA
```
