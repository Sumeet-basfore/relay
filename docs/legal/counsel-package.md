# Relay Legal Counsel Review Package — CR003

**Document ID:** `CR003-LCP-001`  
**Version:** `2.0.0`  
**Prepared:** 2026-09-14  
**Target:** Relay Commercial Launch (CR003)  
**Status:** Complete Counsel Review Package  
**Notice:** This package consolidates verified engineering facts, architecture specifications, draft policies, and legal boundaries for review by external legal counsel. Engineering does not make final legal determinations.

---

## 1. Executive Summary & Review Objectives

Relay is transitioning from an open-source research and engineering distribution (`v0.1.0`) into a commercial product operating under **Model B (Local-First Apache 2.0 Open Core + Optional Commercial Services)**.

The purpose of this package is to provide qualified counsel with everything required to finalize:
1. Public Commercial Privacy Policy & Notice at Collection
2. Commercial Terms of Service
3. Data Processing Addendum (DPA)
4. Refund & Cancellation Policy
5. India DPDP Rules, 2025 compliance posture and grievance setup
6. Cross-border transfer mechanisms (GDPR SCCs)

---

## 2. Definitive Separation: Facts vs. Questions vs. Counsel Decisions

To prevent engineering from inadvertently assuming legal responsibilities, this package strictly categorizes all disclosures:

```text
┌────────────────────────┐      ┌────────────────────────┐      ┌────────────────────────┐
│    ENGINEERING FACT    │ ──►  │     LEGAL QUESTION     │ ──►  │    COUNSEL DECISION    │
│  (Immutable technical  │      │  (Regulatory/statutory │      │ (Legal determination & │
│   reality of codebase) │      │   interpretation issue)│      │  formal document edit) │
└────────────────────────┘      └────────────────────────┘      └────────────────────────┘
```

### 2.1 Engineering Facts (Verified by Architecture & Test Suites)
- **FACT-1:** Relay `v0.1.0` binary transmits zero product telemetry, collects zero prompts, and syncs zero tool arguments to Relay cloud infrastructure.
- **FACT-2:** All cryptographic action receipts (Ed25519 DSSE envelopes) and audit ledger records are stored strictly in a local SQLite file on the customer's machine.
- **FACT-3:** Target credentials (e.g. database passwords, GitHub PATs) are bound to the host operating system keyring and are never exposed to LLM prompts, tool subprocesses, or network requests to Relay.
- **FACT-4:** The Local Security Console (`relay ui`) binds strictly to loopback `127.0.0.1`, enforces anti-DNS rebinding `Host` header checks, requires ephemeral CLI-issued session tokens, and serves bundled static assets without external CDNs.
- **FACT-5:** Commercial entitlements are implemented as **offline Ed25519 signed license tokens**. Relay binaries verify licenses mathematically offline without network phone-home pings.
- **FACT-6:** *Payment status is not authorization status.* An enterprise license cannot bypass Cedar policies, approval prompts, or sandboxes. An expired license does not disable open-core execution.
- **FACT-7:** Relay never touches, stores, or handles credit card numbers or CVVs. All cardholder payment flows are handled by Stripe under PCI DSS Level 1.
- **FACT-8:** Stripe webhooks are verified on Relay's server using HMAC-SHA256 signatures, constant-time equality checks, and a 5-minute timestamp replay defense window. Client-side success redirects are never trusted.

### 2.2 Legal Questions for Counsel
- **Q-1 (Corporate Identity):** What is the exact registered legal entity name, corporate identification number (CIN), and registered address to insert into the Privacy Policy and Terms?
- **Q-2 (India DPDP Implementation):** The Digital Personal Data Protection Rules, 2025 were notified on November 14, 2025 with phased commencement dates. Which specific operational requirements are legally enforceable on our commercial launch date?
- **Q-3 (Statutory Grievance Officer):** Does the designation of `grievance@relay.dev` and a physical address in Bangalore satisfy the grievance redressal mechanism required under Rule 11 of the DPDP Rules, 2025 and IT Rules, 2021?
- **Q-4 (GDPR Territorial Scope):** As an Indian entity offering paid software subscriptions globally via the web, does Relay trigger GDPR Article 3(2)(a) (offering goods/services to EU data subjects), and are Standard Contractual Clauses (SCCs) sufficient for transfers to our US subprocessors (Stripe, Cloudflare, Resend)?
- **Q-5 (California CCPA/CPRA Scope):** Given that Relay does not currently meet the $25M revenue or 100k consumer data thresholds, does counsel recommend publishing our proactive Notice at Collection and "Do Not Sell/Share" statement as drafted?
- **Q-6 (Open Core Trademark & Licensing):** Does the commercial terms overlay preserve the Apache 2.0 grant while cleanly protecting the "Relay" trademark and proprietary rights to commercial services and SLAs?
- **Q-7 (Consumer Law & Refund Terms):** Does the 14-day money-back satisfaction guarantee satisfy Indian Consumer Protection (E-Commerce) Rules, 2020 and European consumer cancellation directives?

### 2.3 Required Counsel Decisions
- **DECISION-1:** Approve or modify draft [`docs/legal/privacy-policy-draft.md`](file:///home/sumeet/relay/docs/legal/privacy-policy-draft.md).
- **DECISION-2:** Approve or modify draft [`docs/legal/terms-draft.md`](file:///home/sumeet/relay/docs/legal/terms-draft.md).
- **DECISION-3:** Approve or modify draft [`docs/legal/dpa-spec.md`](file:///home/sumeet/relay/docs/legal/dpa-spec.md).
- **DECISION-4:** Approve or modify draft [`docs/legal/refund-policy-spec.md`](file:///home/sumeet/relay/docs/legal/refund-policy-spec.md).
- **DECISION-5:** Finalize statutory corporate identity placeholders in [`docs/legal/company-information.md`](file:///home/sumeet/relay/docs/legal/company-information.md).
- **DECISION-6:** Issue formal authorization to commence commercial transactions.

---

## 3. Commercial Launch Document Inventory

| Milestone Deliverable | Document Path | Operational Status |
| :--- | :--- | :--- |
| **Commercial Model** | [`docs/commercial/cr003-commercial-model.md`](file:///home/sumeet/relay/docs/commercial/cr003-commercial-model.md) | Frozen & Specified |
| **Open Core License Boundary** | [`docs/legal/open-core-model.md`](file:///home/sumeet/relay/docs/legal/open-core-model.md) | 100% Apache-2.0 Audited |
| **Company Legal Information** | [`docs/legal/company-information.md`](file:///home/sumeet/relay/docs/legal/company-information.md) | Placeholders Defined |
| **Commercial Privacy Policy** | [`docs/legal/privacy-policy-draft.md`](file:///home/sumeet/relay/docs/legal/privacy-policy-draft.md) | Counsel-Ready Draft |
| **Commercial Terms of Service** | [`docs/legal/terms-draft.md`](file:///home/sumeet/relay/docs/legal/terms-draft.md) | Counsel-Ready Draft |
| **Commercial Security Addendum** | [`docs/legal/security-addendum-spec.md`](file:///home/sumeet/relay/docs/legal/security-addendum-spec.md) | Architecture Grounded |
| **Data Processing Addendum (DPA)** | [`docs/legal/dpa-spec.md`](file:///home/sumeet/relay/docs/legal/dpa-spec.md) | Ready for Enterprise Use |
| **Refund & Cancellation Policy** | [`docs/legal/refund-policy-spec.md`](file:///home/sumeet/relay/docs/legal/refund-policy-spec.md) | Commercial Spec Complete |
| **Commercial Subprocessors** | [`docs/commercial/subprocessors.md`](file:///home/sumeet/relay/docs/commercial/subprocessors.md) | Audited (Stripe, Cloudflare, Resend, GitHub) |
| **Billing Architecture** | [`docs/commercial/billing-architecture.md`](file:///home/sumeet/relay/docs/commercial/billing-architecture.md) | Verified Webhook Spec |
| **Security Architecture** | [`docs/commercial/commercial-security-architecture.md`](file:///home/sumeet/relay/docs/commercial/commercial-security-architecture.md) | Verified Trust Boundaries |
| **Commercial Threat Model** | [`docs/commercial/cr003-threat-model.md`](file:///home/sumeet/relay/docs/commercial/cr003-threat-model.md) | 10 Threats Assessed |
| **Incident Response Runbook** | [`docs/security/incident-response.md`](file:///home/sumeet/relay/docs/security/incident-response.md) | Security/Privacy/Billing Segregated |

---

## 4. Counsel Review & Execution Protocol

Counsel should review the documents in the following sequence:
1. **Repository & License:** Review [`open-core-model.md`](file:///home/sumeet/relay/docs/legal/open-core-model.md) to confirm open-source separation and trademark clarity.
2. **Privacy & Data Governance:** Review [`privacy-policy-draft.md`](file:///home/sumeet/relay/docs/legal/privacy-policy-draft.md) against `docs/commercial/data-flow.md` to confirm alignment with DPDP Rules, 2025 and GDPR.
3. **Commercial Contracts:** Review [`terms-draft.md`](file:///home/sumeet/relay/docs/legal/terms-draft.md) and [`refund-policy-spec.md`](file:///home/sumeet/relay/docs/legal/refund-policy-spec.md) for commercial enforceability and liability caps.
4. **Security & DPA:** Review [`security-addendum-spec.md`](file:///home/sumeet/relay/docs/legal/security-addendum-spec.md) and [`dpa-spec.md`](file:///home/sumeet/relay/docs/legal/dpa-spec.md) for enterprise sales readiness.
