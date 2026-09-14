# Relay CR003 — Decision Record & Sign-Off

**Document ID:** `CR003-DEC-001`  
**Milestone:** CR003 — Legal & Commercial Launch Readiness  
**Target Release:** Relay `v0.1.0`  
**Date:** 2026-09-14  

---

## 1. Context & Architectural Principles

Relay Milestone CR003 establishes the operational, technical, legal, and security infrastructure required to commercialize Relay under **Model B (Local-First Apache 2.0 Open Core + Optional Commercial Services)**.

The milestone was executed against strict engineering invariants:
1. **Local-First Autonomy:** The core software remains 100% functional, self-contained, and air-gapped without requiring cloud communication or license keys.
2. **Non-Interference Invariant:** *Payment status is never authorization status.* A commercial license key cannot override Cedar default-deny policies, credential isolation, or interactive approvals.
3. **PCI Isolation & Data Minimization:** Cardholder data is outsourced entirely to Stripe. Local execution data (prompts, tool calls, receipts) is never collected by Relay commercial infrastructure.

---

## 2. Milestone Evaluation & Results

All 40 phases of CR003 have been completed:
- Commercial model frozen and open-core boundary audited (100% Apache-2.0).
- Counsel package and counsel-ready drafts generated for Privacy Policy, Notice at Collection, Terms of Service, DPA, and Refund Policy.
- Offline Ed25519 entitlement engine implemented and tested.
- Stripe billing webhook signature verification with 5-minute replay defense implemented and tested.
- Commercial static website deployed across 11 privacy-preserving pages.
- Incident response runbook expanded with Payment Incident procedures.
- Private Paid Beta strategy adopted to ensure controlled validation with design partners before open public checkout.

---

```text
CR003 LEGAL & COMMERCIAL LAUNCH — FINAL VERDICT

Commercial Model:
FINALIZED

Billing:
PASS

Entitlement:
PASS

Privacy Architecture:
PASS

Privacy Documentation:
COUNSEL READY

Terms:
COUNSEL READY

DPA:
COUNSEL READY

Website:
PASS

Security:
PASS

Support:
PASS

Incident Response:
PASS

India Privacy:
COUNSEL REVIEW REQUIRED

International Privacy:
COUNSEL REVIEW REQUIRED

Commercial Security Boundary:
The commercial control plane (website, billing, email, accounts) possesses zero inbound access, zero code execution authority, and zero credential visibility over customer-local Relay instances. Payment status is never authorization status; a valid license cannot bypass Cedar policies, and an expired license never disables open-core execution.

Known Limitations:
- Corporate registration details (CIN, GSTIN, registered office address) require finalization upon formal corporate incorporation.
- Public billing checkout is gated on formal legal counsel approval of draft policies.
- Offline license revocation requires distribution of Certificate Revocation Lists (CRLs) or short validity durations (e.g. 30 days).

Blocking Issues:
None (Zero technical or engineering blocking issues).

Required Counsel Decisions:
- Final legal approval of Commercial Privacy Policy and California Notice at Collection.
- Final legal approval of Commercial Terms of Service and liability cap enforceability.
- Final legal approval of Enterprise Data Processing Addendum (DPA) and Standard Contractual Clauses.
- Population and confirmation of statutory corporate identity details and Grievance Officer registration.

Required Engineering Work:
- Automated Certificate Revocation List (CRL) distribution mechanism for offline enterprise licenses.
- Deployment of self-service Stripe webhook receiver in production hosting environment.

Commercial Launch Status:
READY FOR PRIVATE PAID BETA

Tests:
24 passed / 0 failed

Next Milestone:
PAID BETA
```
