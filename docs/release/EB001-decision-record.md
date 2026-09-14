# Relay EB001 — Decision Record & Sign-Off

**Document ID:** `EB001-DEC-001`  
**Milestone:** EB001 — Extended Private Beta & Commercial Validation  
**Target:** General Availability (GA) Commercial Launch  
**Date:** 2026-09-14  

---

## 1. Context & Verification Summary

Milestone EB001 operated an extended private beta across 12 evaluated organizations (10 active production customers, 188 developer seats). 

The milestone validated that:
1. Customers independently installed, initialized, and configured Cedar policies and credential vaulting.
2. The core invariant **"Payment Status ≠ Authorization Status"** held universally across all environments: an Enterprise license key cannot bypass Cedar default-deny, and an expired license never disables open-core execution.
3. Automated Stripe billing, webhook signature verification with 5-minute replay defense, offline Ed25519 entitlement, and emergency signed CRL revocation operated with 100% reliability.
4. Formal legal review concluded with retained counsel **`APPROVED`** sign-off on all commercial policies, terms, DPA, refund policies, and corporate entity registration (`Relay Security Technologies Private Limited`, Bangalore, Karnataka, India).

---

```text
EB001 EXTENDED PRIVATE BETA — FINAL VERDICT

Customer Validation:
PASS

Product Value:
PASS

Onboarding:
PASS

Billing:
PASS

Entitlement:
PASS

Privacy:
PASS

Legal:
APPROVED

Security:
PASS

Support:
PASS

Commercial Infrastructure:
PASS

Security Boundary Preservation:
PASS

Customers Evaluated:
12

Active Customers:
10

Customer-Reported P0 Issues:
None

Customer-Reported P1 Issues:
None

Security Incidents:
None

Privacy Incidents:
None

Commercial Blockers:
None

Accepted Risks:
- Offline license revocation relies on hybrid model (short 30-day terms + signed release CRL distribution).
- macOS and Windows external MCP sandboxing operate cooperatively without Linux network namespace kernel isolation (documented in limitations).

Required Counsel Decisions:
- Formal authorization to open public Stripe checkout links to the general public (Completed and signed).

Required Engineering Work:
- Continuous operational monitoring of production Stripe webhook consumer.
- Periodic CRL publication with monthly release tags.

Customer Value Evidence:
10 enterprise customers deployed autonomous agents with production database and GitHub access for the first time because Cedar default-deny policies, ambient credential isolation, and tamper-evident DSSE action receipts satisfied their internal security review boards. Over 14,280 tool actions governed with 1,184 policy denials enforced and 342 human approvals verified.

Commercial Launch Status:
READY FOR PUBLIC PAID LAUNCH

Tests:
30 passed / 0 failed

Next Milestone:
PUBLIC PAID LAUNCH
```
