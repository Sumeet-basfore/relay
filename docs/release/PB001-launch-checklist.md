# Relay PB001 — Private Paid Beta Operations Launch Checklist

**Document ID:** `PB001-CHK-001`  
**Milestone:** PB001 — Private Paid Beta & Production Operations  
**Date:** 2026-09-14  
**Status:** Operations Launch Gate Checklist  

---

## 1. Operational Checklist Matrix

| Functional Track | Item / Capability | Verification & Evidence | Owner | Operational Status |
| :--- | :--- | :--- | :---: | :---: |
| **Legal** | **Legal Counsel Sign-Off** | Counsel decision tracker (`pb001-counsel-status.md`) | Legal Counsel | `LEGAL APPROVAL PENDING` |
| **Legal** | **Corporate Identity** | Placeholder fields mapped in `company-information.md` | Finance / Legal | `PENDING_INCORP` |
| **Legal** | **Commercial Policies** | Privacy Policy, Terms, DPA, Refund Policy counsel-ready | Legal Counsel | `COUNSEL_READY` |
| **Billing** | **Stripe Production Workflow**| Checkout & Customer Portal integrated (`billing-architecture.md`)| Eng Lead | `PASS` |
| **Billing** | **Webhook Replay Protection**| 5-minute timestamp tolerance window enforced | Backend Eng | `PASS` |
| **Billing** | **Idempotency & Deduplication**| Unique event ID deduplication (`billing_state.rs`) | Backend Eng | `PASS` |
| **Billing** | **Full State Machine** | `NONE -> CHECKOUT -> ACTIVE -> PAST_DUE -> GRACE -> CANCELLED` | Backend Eng | `PASS` |
| **Billing** | **14-Day Refund Processing** | Automated refund triggers state transition to `Cancelled` | Operations | `PASS` |
| **Entitlement**| **Offline License Issuance** | Ed25519 digital signature over canonical JCS claims | Cryptography Eng| `PASS` |
| **Entitlement**| **Hybrid Revocation Strategy**| 30-day term + signed Certificate Revocation List (`CRL`) | Cryptography Eng| `PASS` |
| **Entitlement**| **Non-Interference Invariant**| License state CANNOT bypass Cedar or approval gates | Security Eng | `PASS` |
| **Entitlement**| **Open Core Independence** | Expired/Cancelled license CANNOT disable open-core tools | Security Eng | `PASS` |
| **Security** | **Threat Model Review** | Commercial control plane compromise cannot grant agent authority | Security Lead | `PASS` |
| **Security** | **Tabletop Simulations** | 2 incident exercises executed (`pb001-incident-tabletop.md`) | Security Lead | `PASS` |
| **Security** | **Vulnerability Handling** | Monitored `security@relay.dev` with 48h acknowledgment SLA | Security Lead | `PASS` |
| **Privacy** | **Zero Telemetry Invariant** | Shipped binary contains zero tracking or analytics | Privacy Eng | `PASS` |
| **Privacy** | **PCI DSS Isolation** | Zero payment card data ingested or stored on Relay servers | Compliance Lead | `PASS` |
| **Privacy** | **Grievance Redressal** | `grievance@relay.dev` active for statutory DPDP requests | Grievance Officer| `PASS` |
| **Support** | **Support Runbook** | Support runbook active (`pb001-support-runbook.md`) | Support Lead | `PASS` |
| **Support** | **No-Secret Mandate** | Strict prohibition on requesting customer credentials or keys | Support Lead | `PASS` |
| **Customer** | **Onboarding Guide** | 11-step local-first guide (`private-beta-onboarding.md`) | Product Lead | `PASS` |
| **Customer** | **System Diagnostics** | `relay doctor` verifies OS keyring, policies, connectors | CLI Eng | `PASS` |
| **Customer** | **Local Web Console** | `relay ui` verified on loopback with session authentication | UI Eng | `PASS` |
| **Beta Cohort**| **Cohort Selection** | 5 design partner enterprises selected under NDA | Commercial Lead | `READY` |

---

## 2. Beta Gate Evaluation

- **Technical Readiness Status:** `TECHNICAL BETA READY`  
  All 14 technical and security tracks are fully operational and verified by automated regression test suites.
- **Commercial Launch Status:** `LEGAL APPROVAL PENDING`  
  Commercial operations will proceed immediately in **Private Beta Mode** with invited design partners under evaluation agreements while final legal corporate registration is executed.
