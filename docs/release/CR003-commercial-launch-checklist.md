# Relay CR003 — Commercial Launch Checklist

**Document ID:** `CR003-CHK-001`  
**Milestone:** CR003 — Legal & Commercial Launch Readiness  
**Target:** Private Paid Beta Commercial Launch  
**Date:** 2026-09-14  

---

## 1. Checklist Matrix

| Track | Item | Description / Reference | Owner | Status | Gate Condition |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Legal** | **Commercial Privacy Policy** | Draft matching CR001/CR002 architecture (`privacy-policy-draft.md`) | Legal Counsel | `COUNSEL_READY` | Formal legal sign-off required prior to public billing |
| **Legal** | **Notice at Collection** | California CCPA & general collection notice embedded in policy | Legal Counsel | `COUNSEL_READY` | Present on signup/checkout |
| **Legal** | **Commercial Terms of Service** | Terms covering subscriptions, liability cap, arbitration (`terms-draft.md`) | Legal Counsel | `COUNSEL_READY` | Formal legal sign-off required |
| **Legal** | **Data Processing Addendum** | Enterprise DPA with Standard Contractual Clauses (`dpa-spec.md`) | Legal Counsel | `COUNSEL_READY` | Available on demand for enterprise |
| **Legal** | **Refund & Cancellation Policy** | 14-day satisfaction guarantee and dunning terms (`refund-policy-spec.md`) | Legal Counsel | `COUNSEL_READY` | Publicly linked |
| **Legal** | **Open Core Boundary** | Audit confirming 100% Apache-2.0 codebase (`open-core-model.md`) | Eng Lead | `VERIFIED` | Root LICENSE present; no proprietary shims |
| **Legal** | **Corporate Identity** | Entity registration & statutory contact placeholders (`company-information.md`) | Finance/Legal | `PENDING_INCORP` | Finalize CIN, GSTIN upon registration |
| **Business** | **Commercial Model** | Model B specification frozen (`cr003-commercial-model.md`) | Product Lead | `FINALIZED` | Free open core + paid support/entitlements |
| **Business** | **Pricing Model** | Non-metered seat pricing defined ($0, $49/seat/mo, Enterprise) | Product Lead | `FINALIZED` | No per-prompt or per-tool tax |
| **Business** | **Billing Provider** | Stripe Checkout & Customer Portal integrated (`billing-architecture.md`) | Eng Lead | `INTEGRATED` | Zero cardholder data stored by Relay |
| **Business** | **Tax Compliance** | Indirect tax (GST/VAT) calculation via Stripe Tax | Finance | `CONFIGURED` | Reverse-charge B2B enabled |
| **Business** | **Customer Support Routing** | Segregated email queues (`support@`, `billing@`, `privacy@`, `security@`) | Operations | `OPERATIONAL` | Credential scrubbing mandated |
| **Technical** | **Commercial Website** | 11 static pages deployed (`website/`) with zero third-party tracking | Frontend Eng | `DEPLOYED` | Strict CSP, no cookies, no Google Analytics |
| **Technical** | **Billing Webhook Security** | HMAC-SHA256 signature verification & 5-min replay protection | Backend Eng | `VERIFIED` | Unit & integration tests passing (100%) |
| **Technical** | **Offline Entitlement Engine** | Ed25519 digital signature license verification (`entitlement.rs`) | Cryptography Eng| `VERIFIED` | Zero phone-home requirement verified |
| **Technical** | **Non-Interference Invariant**| "Payment status is not authorization status" tested against Cedar PDP | Security Eng | `VERIFIED` | License state cannot override Cedar |
| **Technical** | **Local Console Boundary** | `relay ui` loopback-only with session auth & anti-DNS rebinding | Security Eng | `VERIFIED` | CR002 security suite passing (16/16) |
| **Security** | **Incident Response Runbook**| Runbook updated with Payment Incident procedures (`incident-response.md`) | Security Lead | `OPERATIONAL` | Runbooks 1–4 + Payment Runbook active |
| **Security** | **Commercial Threat Model** | 10 commercial attack vectors assessed (`cr003-threat-model.md`) | Security Lead | `ASSESSED` | Control plane compromise cannot grant agent authority |
| **Security** | **Vulnerability Disclosure** | Public disclosure guidelines & PGP key instructions (`SECURITY.md`) | Security Lead | `PUBLISHED` | 48h ack, 7-day triage target |
| **Compliance**| **India DPDP Alignment** | Launch timeline mapped to phased DPDP Rules, 2025; Grievance channel | Privacy Eng | `ASSESSED` | Review required with Indian counsel |
| **Compliance**| **GDPR & CCPA Scoping** | Territorial scope, SCCs, and consumer rights mapped | Privacy Eng | `ASSESSED` | Subprocessors audited with SCCs |

---

## 2. Gate Decision for Paid Launch

- **Phase 38 Pre-Paid Launch Review:** All engineering and technical security gates are `PASS`.
- **Phase 39 Beta Recommendation:** Commercial operations will launch as a **Private Paid Beta** with selected enterprise design partners before open public checkout.
