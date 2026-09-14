# India Privacy Applicability Analysis

**Document ID:** `CR001-IN-001`  
**Version:** `1.0.0`  
**Status:** Applicability Analysis — **NOT a compliance declaration**  
**Company Jurisdiction:** India (Relay operated from India per CR001 brief)  
**Last Updated:** 2026-09-14  

---

## 1. Disclaimer

This document analyzes **potential applicability** of India's Digital Personal Data Protection Act, 2023 (DPDP Act) and notified Digital Personal Data Protection Rules, 2025 (DPDP Rules) to Relay product flows.

It does **not** state that Relay is DPDP compliant. Final legal conclusions require qualified Indian counsel review at commercial launch.

---

## 2. Regulatory Framework Summary

| Instrument | Status (as of 2026-09-14) | Relevance |
|:---|:---|:---|
| DPDP Act, 2023 | Enacted | Governs processing of digital personal data in India |
| DPDP Rules, 2025 | Notified 14 November 2025 | Operational rules; phased implementation timeline applies |
| Data Protection Board | Framework establishing | Enforcement body (implementation ongoing) |

**Action for counsel:** Verify which rule provisions are in force on the actual commercial launch date.

---

## 3. Relay Product Flows & Personal Data

### 3.1 v0.1.0 Local Binary (Primary Product Today)

| Processing Activity | Personal Data Involved? | Relay Role (Analysis) |
|:---|:---|:---|
| Binary execution on customer machine | Tool args may contain PII if agent includes them | **Likely not Data Fiduciary** for customer-local processing — customer operates infrastructure |
| Ledger/receipt storage | May contain identifiers in tool metadata | Stored on **customer device**; Relay software provider only |
| `relay doctor` | Prints local paths to stdout | No transmission to Relay |
| No telemetry | None collected by Relay | Minimal Relay-side processing |

**Preliminary analysis:** For pure local binary distribution without Relay-operated backend, Relay's direct collection of personal data from end-users is **minimal**. Primary processing occurs on customer-controlled systems.

### 3.2 User-Initiated Downloads via GitHub

| Activity | Data | Analysis |
|:---|:---|:---|
| `install.sh` fetch | IP/User-Agent logged by GitHub | GitHub is independent controller/processor; not Relay-operated logging |

### 3.3 Security Reports (`security@relay.dev`)

| Activity | Data | Analysis |
|:---|:---|:---|
| Vulnerability email | Reporter name, email, report content | **Likely Data Fiduciary** for this limited purpose — security coordination |
| Retention | TBD | Counsel must define retention and notice |

### 3.4 Planned Website, Accounts, Billing (Not Live)

| Activity | Data | Analysis |
|:---|:---|:---|
| Account registration | Email, name | **Likely Data Fiduciary** when implemented |
| Billing | Email, payment metadata | Fiduciary + payment processor as processor |
| Support tickets | Contact info, message content | **Likely Data Fiduciary** |
| Marketing newsletter | Email (opt-in) | **Likely Data Fiduciary** if launched |

---

## 4. Applicability by DPDP Concept (Indicative)

The following maps DPDP concepts to Relay flows for **counsel review**. Wording is intentionally non-conclusive.

| DPDP Concept | Potential Application | Relay v0.1.0 | Planned Commercial |
|:---|:---|:---|:---|
| **Data Fiduciary** | Entity determining purpose/means of processing | Limited (security reports) | Expands with website/accounts |
| **Data Principal** | Individual whose data is processed | Security reporters; future customers | End-users of customer deployments (indirect) |
| **Consent** | Valid consent for specified purpose | N/A for binary; required for marketing/optional services | Required analysis at launch |
| **Notice** | Privacy notice before collection | N/A for binary | Privacy Policy required before website accounts |
| **Purpose limitation** | Process only for stated purpose | Engineering controls: no telemetry | Policy drafting required |
| **Data minimization** | Adequate, relevant, limited | Strong for binary (local-first) | Must be designed into website |
| **Retention limits** | Delete when purpose fulfilled | Customer-controlled local data | Retention matrix TBD |
| **Security safeguards** | Reasonable security measures | Documented in security baseline | Extend to hosted infra |
| **Significant Data Fiduciary** | Enhanced obligations for large platforms | **Unlikely at current scale** — counsel to reassess | Reassess at growth |
| **Cross-border transfer** | Restrictions on transfers outside India | Minimal today | Depends on vendor regions (TBD) |
| **Children's data** | Enhanced protections | Product not directed at children | Terms should state age requirement |
| **Grievance redressal** | Mechanism for complaints | **Not implemented** | Required before commercial launch |
| **Breach notification** | Notify Board and principals | Internal process TBD (see incident-response.md) | Counsel to define timelines |

---

## 5. Key Questions for Counsel

1. Is Relay a Data Fiduciary for security vulnerability reports received at `security@relay.dev`?
2. When customers deploy Relay locally, who is fiduciary for tool argument data containing personal data of third parties?
3. What notice and consent mechanisms are required before launching accounts/billing from India?
4. Which DPDP Rules provisions are enforceable on the target commercial launch date?
5. Are cross-border transfers triggered by GitHub hosting, payment processors, or email providers?
6. Is appointment of a Data Protection Officer required at current/projected scale?
7. What breach notification obligations apply to security incidents vs privacy incidents?

---

## 6. Engineering Controls Aligned with DPDP Principles (Not Compliance)

These technical choices support privacy-by-design regardless of legal classification:

| Principle | Relay v0.1.0 Implementation |
|:---|:---|
| Minimization | No product telemetry; no automatic cloud sync |
| Purpose limitation | Binary processes data only for governed execution |
| Storage limitation | Customer controls ledger retention |
| Security | SI-001–SI-024 invariants; local encryption via OS |
| Transparency | Open-source core; documented data flows |

---

## 7. International Overlap (Brief — Not Compliance Analysis)

| Framework | Trigger | v0.1.0 Binary | At Commercial Launch |
|:---|:---|:---|:---|
| GDPR | EU offering/monitoring | Low direct applicability | Reassess if EU marketing/accounts |
| California CPRA | Revenue/volume thresholds | Likely out of scope | Reassess with billing |
| HIPAA | Healthcare data processing | Not designed for HIPAA | Customer responsibility |

See `docs/commercial/data-flow.md` jurisdiction matrix.

---

## 8. Recommended Pre-Launch Actions

| Action | Owner | Status |
|:---|:---|:---|
| Engage Indian privacy counsel | Legal | **Required before paid launch** |
| Define grievance contact | Legal/Ops | TBD |
| Draft Privacy Policy from spec | Legal | See `privacy-policy-spec.md` |
| Breach notification playbook | Legal + Security | Phase 25 in incident-response.md |
| Vendor DPA review (India transfers) | Legal | Blocked on vendor selection |

---

## 9. Related Documents

- `docs/commercial/data-flow.md`
- `docs/legal/privacy-policy-spec.md`
- `docs/legal/counsel-package.md`
- `docs/security/incident-response.md`
