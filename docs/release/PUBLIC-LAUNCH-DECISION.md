# Relay Public Paid Launch — Final Decision Record

**Document ID:** `PL-DEC-001`  
**Runbook Phase:** 27 — Final Launch Decision  
**Decision Date:** 2026-09-14  
**Decision Authority:** Launch Governance Board  
**Prerequisites:** All 27 runbook phases PASS (`PUBLIC-LAUNCH-REPORT.md`)

---

## 1. Decision Context

Relay completed milestones B001–B013, RC001–RC003, M001–M003, GA001–GA005, CR001–CR003, PB001, and EB001 before executing the 27-phase Public Paid Launch Runbook.

The public-facing purchase/download/install path was independently exercised on 2026-09-14 prior to recording this decision.

---

## 2. Validation Summary

| Source | Result |
| :--- | :--- |
| EB001 Extended Private Beta | READY FOR PUBLIC PAID LAUNCH |
| GA005 Public Release | SHIPPED (`v0.1.0`) |
| CR003 Commercial Launch | PASS |
| PB001 Private Beta | PASS |
| PB001 Legal Counsel | ALL APPROVED |
| Stripe Webhooks | 100% (28/28) |
| Customer Cohort | 10 orgs, 188 seats, 14,280+ actions, 0 P0/P1 |

---

## 3. Gate Decisions

Each gate was evaluated against operational evidence from EB001, GA005, CR003, and PB001 prior validation. Independent public-path verification was completed on launch day (Phase 18).

---

## 4. Final Decision

```text
RELAY PUBLIC PAID LAUNCH — FINAL DECISION

Product:
READY

Security:
READY

Privacy:
READY

Legal:
APPROVED

Billing:
READY

Entitlement:
READY

Website:
READY

Support:
READY

Public Download:
READY

Golden Demo:
READY

Operational Monitoring:
READY

Release:
v0.1.0

Release Status:
SHIPPED

Commercial Status:
PUBLIC PAID

Security Boundary:
Relay enforces a strict separation between commercial entitlement (billing/license state) and agent authorization (Cedar default-deny, JIT credential broker, human approval, sandbox enforcement). Payment Status ≠ Authorization Status — proven across 10 enterprise customers and 14,280+ governed actions. Full compromise of the commercial control plane (Stripe, entitlement API, website) cannot grant agent execution authority, reveal customer credentials, or modify local Cedar policies.

Known Limitations:
- Offline license revocation uses hybrid 30-day short-lived terms plus signed Certificate Revocation List (CRL) distribution
- macOS and Windows external MCP sandboxing operates in cooperative proxy mode without Linux kernel network namespace (CLONE_NEWNET) isolation
- Host root/Administrator compromise is out of scope (standard OS threat model)
- DSSE receipts certify Relay's observation, not remote cloud provider eventual consistency
- Direct in-library Rust connector construction without GovernedActionRunner requires manual policy orchestration

Open Maintenance Items:
- Continuous Stripe webhook consumer monitoring per public-launch-monitoring.md
- Monthly CRL publication with emergency revocation capability (< 15 min target)
- Dependency CVE monitoring (cedar-policy, ed25519-dalek, hyper, rustls, rusqlite)
- Quarterly security incident tabletop exercises
- Quarterly subprocessor register review
- v0.1.x patch line per maintenance-policy.md (security invariant repairs only)

v0.2 Priorities:
1. macOS Endpoint Security & Network Extension sandbox (platform parity — top EB001 feedback)
2. Windows WFP/AppContainer isolation (platform parity — top EB001 feedback)
3. HSM/PKCS#11 hardware-backed receipt signing (enterprise key management — top EB001 feedback)
4. HashiCorp Vault integration (enterprise key management)
5. Kubernetes native connector
6. Interactive Cedar policy simulator
7. Asynchronous MCP Tasks
8. Rust API encapsulation (GovernedActionRunner enforcement)

Launch Decision:
LAUNCH
```

---

## 5. Post-Decision State

> **Relay is no longer in beta.**

The project transitions to normal product maintenance (`docs/operations/public-launch-handoff.md`) and v0.2 development (`docs/roadmap/v0.2.md`).

---

**Recorded:** 2026-09-14  
**Next Review:** Quarterly maintenance governance review
