# CR001 — Commercial Privacy & Legal Readiness Report

**Milestone:** CR001  
**Release Baseline:** Relay `v0.1.0` (GA005 public launch complete)  
**Report Date:** 2026-09-14  
**Author:** Relay Engineering / Commercial Readiness  

---

## 1. Executive Summary

CR001 establishes the commercial privacy, data governance, and legal-document architecture required before charging customers or launching paid Relay services. All claims in this milestone are grounded in the shipped v0.1.0 implementation and explicitly distinguish **shipped**, **planned**, and **TBD** states.

**Key outcome:** Engineering documentation is sufficient for qualified counsel review. Paid commercial launch remains blocked pending legal drafting, vendor selection, and billing implementation.

---

## 2. Milestone Scope Completed

| Phase | Deliverable | Status |
|:---|:---|:---|
| 1 — Product boundary | `docs/commercial/product-boundary.md` | ✓ |
| 2–3 — Data inventory & flows | `docs/commercial/data-flow.md` | ✓ |
| 6 — Telemetry decision | Option A documented | ✓ |
| 8 — Website data map | `docs/commercial/website-data-map.md` | ✓ (planned) |
| 18 — Subprocessors | `docs/commercial/subprocessors.md` | ✓ (template) |
| 19 — Security overview | `docs/commercial/security-overview.md` | ✓ |
| 13 — India privacy | `docs/commercial/privacy-india.md` | ✓ |
| 27 — Privacy threat model | `docs/commercial/privacy-threat-model.md` | ✓ |
| 28–29 — UI boundary | `docs/commercial/ui-data-boundary.md` | ✓ |
| 30 — Security requirements | `docs/commercial/security-requirements.md` | ✓ |
| 21–22 — Legal specs | `privacy-policy-spec.md`, `terms-spec.md` | ✓ |
| 32 — Counsel package | `docs/legal/counsel-package.md` | ✓ |
| 24–25 — Incident response | `incident-response.md` updated | ✓ |
| 31 — Commercial model | Model B selected | ✓ |
| 33 — Cross-check | This report | ✓ |

---

## 3. Implementation Ground Truth (v0.1.0)

Verified against codebase and existing GA documentation:

| Claim | Evidence |
|:---|:---|
| Local-first Rust binary, Apache 2.0 | `Cargo.toml`, public repo |
| No product telemetry | No telemetry endpoints in `crates/` |
| No phone-home in binary | No Relay infra URLs in runtime code paths |
| No automatic update checks | Binary has no updater; manual install only |
| `relay doctor` local-only | `crates/relay-cli/src/doctor.rs` — filesystem/config checks only |
| `install.sh` GitHub download | User-initiated; `install.sh` lines 60–79 |
| Local data: ledger, keys, keyring, policies | `config.rs`, `A006-persistence-and-storage.md` |
| MCP/receipts processed locally | Architecture docs + GA004 claims |
| Connectors to user targets | GitHub/Postgres connectors; not Relay infra |
| v0.2 deferred: ledger sync, telemetry | `docs/roadmap/v0.2.md` |
| Security contact | `security@relay.dev` in `SECURITY.md` |

---

## 4. Commercial Architecture Decision

**Model B — Local-first open core + optional future hosted management**

- Open-source core remains Apache 2.0
- Primary value: local binary (authority + credential isolation + evidence)
- CR002: optional local UI (paid potential)
- Hosted management: optional future layer, opt-in only
- No multi-tenant SaaS in v0.1.0

---

## 5. Telemetry Decision

**Option A — No Product Telemetry** selected for v0.1.0 binary.

Documented in `product-boundary.md` §8 and `data-flow.md` §8.

---

## 6. Cross-Check Results (Phase 33)

| Check | Result |
|:---|:---|
| Implementation ↔ data flows | **Pass** — docs match v0.1.0 behavior |
| Privacy ↔ security architecture | **Pass** — local-first preserved |
| Commercial model ↔ legal specs | **Pass with conditions** — billing/website TBD |
| Public claims ↔ architecture | **Pass** — no false compliance claims added |
| Subprocessors ↔ actual vendors | **Incomplete** — only GitHub confirmed |

**No contradictions requiring architecture changes identified.** Documentation gaps are explicitly marked TBD rather than falsely resolved.

---

## 7. Blocking Issues for Paid Launch

1. Final Privacy Policy and Terms (legal draft from specs)
2. Billing provider selection and PCI scope separation
3. Subprocessor inventory completion when vendors chosen
4. Website deployment with cookie/consent strategy
5. Grievance/privacy contact establishment (India)
6. Account system security design (if accounts required for paid tier)

---

## 8. Accepted Risks

1. Customer local ledger may contain third-party personal data in tool arguments — customer responsibility
2. GitHub download logs contain IP/User-Agent outside Relay control
3. Security email retention policy undefined pending counsel
4. macOS/Windows sandbox parity lower than Linux — documented in security claims
5. No formal penetration test certificate for procurement

---

## 9. Deliverables Index

```text
docs/commercial/product-boundary.md
docs/commercial/data-flow.md
docs/commercial/website-data-map.md
docs/commercial/subprocessors.md
docs/commercial/security-overview.md
docs/commercial/privacy-india.md
docs/commercial/privacy-threat-model.md
docs/commercial/security-requirements.md
docs/commercial/ui-data-boundary.md

docs/legal/privacy-policy-spec.md
docs/legal/terms-spec.md
docs/legal/counsel-package.md

docs/security/incident-response.md  # updated
docs/release/CR001-commercial-readiness-report.md
```

Embedded in `data-flow.md`:
- Complete data inventory table
- Retention matrix
- Jurisdiction applicability matrix
- Privacy/security responsibility matrix

---

## 10. CR001 Final Verdict

```text
CR001 COMMERCIAL PRIVACY & LEGAL READINESS — FINAL VERDICT

Commercial Model:
Model B — Local-first open core + optional future hosted management

Data Architecture:
PASS WITH CONDITIONS

Privacy Architecture:
PASS

Security Architecture:
PASS

India Privacy Readiness:
ASSESSED

International Privacy Readiness:
ASSESSED

Legal Document Readiness:
READY FOR COUNSEL

Billing Readiness:
FAIL

UI Data Boundary:
DEFINED

Subprocessor Inventory:
INCOMPLETE

Commercial Security Claims:
PASS

Blocking Issues:
- Final Privacy Policy and Terms legal text not drafted
- Billing/payment architecture not implemented
- Subprocessor vendors not selected (website, email, payment, hosting)
- Public website not deployed
- Grievance/privacy contact not established
- Account/entitlement system not designed

Accepted Risks:
- Customer-controlled local ledger may contain third-party PII in tool arguments
- GitHub release CDN logs outside Relay control
- Security report email retention undefined
- Non-Linux sandbox parity limitations
- No SOC 2 / ISO certification

Required Legal Review:
- DPDP Act/Rules applicability and notice/consent requirements
- Privacy Policy and Terms drafting from engineering specs
- Breach notification obligation mapping (Phase 25 record template)
- Payment processor DPA and cross-border transfer assessment
- GDPR/CPRA trigger analysis if EU/US commercial targeting confirmed
- Commercial license overlay for CR002 vs Apache 2.0 core

Required Engineering Work:
- CR002 Local Security Console (next milestone)
- Billing integration (processor TBD)
- Website with documented data map
- Account system (if required for paid tier)
- Populate subprocessor register on vendor selection

Commercial Launch Status:
READY FOR COUNSEL

Next Milestone:
CR002 — Local Security Console / Commercial UI
```

---

*This report does not declare legal or regulatory compliance. CR001 makes the product accurate enough for qualified counsel to review and specific enough for engineering to implement without guessing.*
