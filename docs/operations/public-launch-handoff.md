# Relay Public Paid Launch — Maintenance Handoff

**Document ID:** `PL-HND-001`  
**Runbook Phase:** 25 — Maintenance Transition  
**Effective Date:** 2026-09-14  
**From:** Public Paid Launch Team  
**To:** Long-Term Maintenance & Operations Team  
**Release:** Relay `v0.1.0` (Public Paid)

---

## 1. Handoff Summary

Relay has completed the 27-phase Public Paid Launch Runbook. Ownership transitions from launch execution to **normal product maintenance** under the `v0.1.x` release line.

**Relay is no longer in beta.** Commercial status is **PUBLIC PAID**.

This document supplements — and does not replace — the foundational maintenance handoff:
- `docs/operations/v0.1.0-maintenance-handoff.md` — build reproduction, golden demo, adversarial harness, security triage
- `docs/operations/maintenance-policy.md` — patch criteria, release cadence, dependency monitoring, emergency security procedure

---

## 2. Launch Completion Evidence

| Milestone | Status | Authoritative Record |
| :--- | :---: | :--- |
| EB001 Extended Private Beta | PASS | `docs/release/EB001-decision-record.md` |
| GA005 Public Release | SHIPPED | `docs/release/GA005-launch-report.md` |
| CR003 Commercial Launch | PASS | `docs/release/CR003-decision-record.md` |
| PB001 Private Beta Operations | PASS | `docs/release/PB001-decision-record.md` |
| Public Paid Launch (27 phases) | PASS | `docs/release/PUBLIC-LAUNCH-REPORT.md` |
| Final Launch Decision | LAUNCH | `docs/release/PUBLIC-LAUNCH-DECISION.md` |

### EB001 Validation Summary (Launch Baseline)
- 10 active organizations, 188 seats
- 14,280+ governed actions; 1,184 policy denials; 342 human approvals; 2,450 receipt verifications
- 0 P0, 0 P1, 0 security incidents, 0 privacy incidents
- Stripe webhook 100% (28/28); legal ALL APPROVED

---

## 3. Ongoing Maintenance Responsibilities

### 3.1 Release Line (`v0.1.x`)

Per `docs/operations/maintenance-policy.md`:

| Activity | Cadence | Owner | Reference |
| :--- | :--- | :--- | :--- |
| Security patches (`v0.1.Z`) | As needed (< 72h for critical) | Release Eng | `maintenance-policy.md` §4 |
| Maintenance patches | Monthly or as needed | Release Eng | `maintenance-policy.md` §2 |
| Dependency CVE monitoring | Continuous | Security Eng | `maintenance-policy.md` §3 |
| CRL publication | Monthly + emergency | Cryptography Eng | Phase 14 runbook |
| Golden demo regression | Per patch | QA | `v0.1.0-maintenance-handoff.md` §2.2 |
| Adversarial harness | Per security patch | Security Eng | `v0.1.0-maintenance-handoff.md` §2.3 |

**Feature freeze:** No new connectors, breaking policy changes, or protocol expansions in `v0.1.x`. New features belong in `docs/roadmap/v0.2.md`.

### 3.2 Commercial Operations

| Activity | Cadence | Owner | Reference |
| :--- | :--- | :--- | :--- |
| Stripe webhook monitoring | Continuous | Billing Eng | `public-launch-monitoring.md` §3 |
| Entitlement issuance & revocation | Per subscription event | Billing Eng | `public-launch-monitoring.md` §4 |
| Billing support (`billing@`) | Business hours + on-call | Operations | `pb001-support-runbook.md` |
| Refund & cancellation processing | Per request | Operations | `refund-policy-spec.md` |
| Subprocessor register review | Quarterly | Privacy Eng | `subprocessors.md` |

### 3.3 Security & Privacy

| Activity | Cadence | Owner | Reference |
| :--- | :--- | :--- | :--- |
| Vulnerability triage (`security@`) | 48h acknowledgment SLA | Security Eng | `incident-response.md` |
| Privacy requests (`privacy@`) | Per statutory deadline | Privacy Eng | `privacy-india.md` |
| Grievance redressal (`grievance@`) | DPDP timelines | Grievance Officer | `pb001-counsel-status.md` |
| Incident tabletop exercises | Quarterly | Security Lead | `pb001-incident-tabletop.md` |
| Signing-key & CRL integrity | Continuous | Cryptography Eng | `incident-response.md` §2 |

### 3.4 Customer Support

| Activity | Cadence | Owner | Reference |
| :--- | :--- | :--- | :--- |
| Technical support (`support@`) | Pro 24h / Enterprise 4h SLA | Support Lead | `pb001-support-runbook.md` |
| Zero-Secret Mandate enforcement | Continuous | All support staff | `pb001-support-runbook.md` |
| Onboarding guide maintenance | Per release | Product | `private-beta-onboarding.md` |
| Launch FAQ updates | As needed | Product | `public-launch-faq.md` |

---

## 4. Frozen Launch Artifacts (Do Not Drift)

The following remain frozen per `docs/release/public-launch-freeze.md` unless a `v0.1.Z` patch or counsel-approved update is issued:

- Pricing: Pro $49/seat/month ($39 annual); Enterprise custom annual
- Legal documents (Privacy, Terms, DPA, Refund) — ALL APPROVED
- Subprocessors: Stripe, GitHub, Cloudflare, Resend/AWS SES
- Core invariant: **Payment Status ≠ Authorization Status**
- Certified release: tag `v0.1.0`, archive SHA `6f843ab7…`, binary SHA `a4a3f930…`

---

## 5. Incident Classification (Post-Launch)

Per Public Paid Launch Runbook Phase 23:

| Class | Definition | Response |
| :--- | :--- | :--- |
| **P0** | Security bypass, credential exposure, corrupted release artifact | Emergency patch < 72h |
| **P1** | Customers cannot safely operate or purchase Relay | Priority engineering |
| **P2** | Major usability/business problem | Scheduled fix |
| **P3** | Minor issue | Backlog |
| **v0.2** | Feature request | Roadmap only |

Only P0/P1 automatically trigger emergency engineering response.

---

## 6. First 72-Hour Watch (Completed)

Phase 22 first-72-hour watch concluded 2026-09-17 with:
- 0 P0 incidents
- 0 P1 incidents
- 0 billing failures
- 0 entitlement mismatches
- 0 security reports requiring emergency response

Ongoing monitoring continues per `public-launch-monitoring.md`.

---

## 7. v0.2 Development Handoff

Feature development transitions to `docs/roadmap/v0.2.md` §3 (EB001-Informed Prioritization). The maintenance team retains veto authority on any change that would affect the `v0.1.x` security baseline or commercial invariant.

---

## 8. Key Contacts

| Function | Contact |
| :--- | :--- |
| Technical support | `support@relay.dev` |
| Billing | `billing@relay.dev` |
| Security | `security@relay.dev` |
| Privacy | `privacy@relay.dev` |
| Grievance (India DPDP) | `grievance@relay.dev` |

**Company:** Relay Security Technologies Private Limited, Bangalore, Karnataka, India

---

**Phase 25 Status:** **PASS — MAINTENANCE HANDOFF COMPLETE**
