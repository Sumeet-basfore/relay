# Relay Commercial Security Requirements

**Document ID:** `CR001-CSR-001`  
**Version:** `1.0.0`  
**Status:** Requirements Checklist  
**Last Updated:** 2026-09-14  

---

## 1. Purpose

Define security and privacy requirements gating commercial launch phases. Requirements are classified by milestone; none imply current certification.

---

## 2. Required Before Paid Launch

| ID | Requirement | Status (v0.1.0) | Owner |
|:---|:---|:---|:---|
| CSR-01 | Privacy Policy (final legal text) | **Spec only** (`privacy-policy-spec.md`) | Legal |
| CSR-02 | Terms of Service (final legal text) | **Spec only** (`terms-spec.md`) | Legal |
| CSR-03 | Public security page | **Docs exist**; website TBD | Marketing + Eng |
| CSR-04 | Vulnerability disclosure (`security@relay.dev`) | **Active** (`SECURITY.md`) | Security |
| CSR-05 | Data inventory documented | **Complete** (`data-flow.md`) | Engineering |
| CSR-06 | Retention matrix documented | **Complete** (`data-flow.md`) | Engineering |
| CSR-07 | Subprocessor inventory | **Template** — vendors TBD | Legal + Ops |
| CSR-08 | Billing data architecture | **Not implemented** | Legal + Eng |
| CSR-09 | Payment processor with PCI scope separation | **Not selected** | Legal |
| CSR-10 | Incident response (security + privacy) | **Updated** (`incident-response.md`) | Security |
| CSR-11 | No false compliance claims | **Verified** in CR001 docs | Engineering |
| CSR-12 | Telemetry decision documented | **Option A** documented | Engineering |
| CSR-13 | Product boundary documented | **Complete** | Product |
| CSR-14 | Account security (if accounts) | **N/A** — no accounts | Engineering |
| CSR-15 | Counsel review of public policies | **Pending** | Legal |

**Paid launch gate:** CSR-01, CSR-02, CSR-08, CSR-09, CSR-07 (populated), CSR-15 must be **Complete**.

---

## 3. Required Before Enterprise Sales

| ID | Requirement | Status | Notes |
|:---|:---|:---|:---|
| ENT-01 | Data Processing Addendum (DPA) template | Not drafted | When hosted services exist |
| ENT-02 | SLA / support terms | Not drafted | TBD |
| ENT-03 | Enterprise security questionnaire responses | Partial — use `security-overview.md` | Expand per RFP |
| ENT-04 | Security addendum | Not drafted | Counsel |
| ENT-05 | Subprocessor change notification process | **Drafted** in `subprocessors.md` | Operationalize |
| ENT-06 | Access control documentation (hosted) | N/A until hosted | CR002+ |
| ENT-07 | Audit log policy (hosted) | N/A until hosted | — |
| ENT-08 | Customer shared-responsibility model | **Complete** (`data-flow.md` §7) | — |

---

## 4. Future (Do Not Claim Today)

| ID | Requirement | Target | Current Status |
|:---|:---|:---|:---|
| FUT-01 | SOC 2 Type II | Post-revenue | **Not started** |
| FUT-02 | ISO 27001 | Post-revenue | **Not started** |
| FUT-03 | External penetration test | Pre-enterprise or annual | GA002 audit completed; not pen test |
| FUT-04 | Formal compliance certifications | Customer-driven | **None** |
| FUT-05 | Bug bounty program | Scale-dependent | **Not started** |

---

## 5. v0.1.0 Binary Security Invariants (Must Preserve)

Commercial features must not violate:

| Invariant | Requirement |
|:---|:---|
| SI-001 | No ambient agent credentials |
| SI-002–004 | Default deny + complete mediation |
| SI-007–008 | Secret scrubbing before receipt signing |
| SI-013 | Ledger hash chain integrity |
| SI-019–024 | Egress mediation and sandbox (Linux) |
| CR-TELEM | No product telemetry without explicit re-decision |
| CR-NOPHONE | No automatic phone-home in binary |

---

## 6. CR002 Local UI Requirements (Planned)

| ID | Requirement | Reference |
|:---|:---|:---|
| UI-01 | Bind to localhost by default | `ui-data-boundary.md` |
| UI-02 | No credential rendering | `ui-data-boundary.md` |
| UI-03 | Least-privilege data display | `ui-data-boundary.md` |
| UI-04 | No cloud sync without opt-in | `product-boundary.md` |
| UI-05 | Session expiration for local UI | `ui-data-boundary.md` |

---

## 7. Verification

| Phase | Verification |
|:---|:---|
| v0.1.0 shipped | GA002 audit, GA004 security claims, CR001 cross-check |
| Pre-paid launch | Counsel sign-off on CSR-01–15 |
| Pre-enterprise | ENT-01–08 + FUT-03 as needed |

---

## 8. Related Documents

- `docs/release/CR001-commercial-readiness-report.md`
- `docs/commercial/security-overview.md`
- `docs/legal/counsel-package.md`
