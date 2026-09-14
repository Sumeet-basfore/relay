# Terms of Service — Engineering Specification for Counsel

**Document ID:** `CR001-LTS-001`  
**Version:** `1.0.0`  
**Status:** SPECIFICATION — Not final legal text  
**Last Updated:** 2026-09-14  

---

## 1. Purpose

Provide counsel with product-accurate facts to draft Terms of Service / Terms of Use covering open-source software, planned commercial offerings, and customer responsibilities.

---

## 2. Parties & Scope

| Field | Value |
|:---|:---|
| Provider | Legal entity TBD (India-operated) |
| Software | Relay MCP Security Gateway v0.1.0+ |
| Open-source license | Apache License 2.0 (core) |
| Commercial services | Planned — not yet offered |
| Website | Planned — not yet live |

Terms should distinguish:
1. **Open-source software use** (Apache 2.0 governs code)
2. **Commercial services** (subscriptions, support, CR002 UI — separate terms layer)

---

## 3. Service Description

Accurate description for counsel:

> Relay is a local-first software product that interposes between AI agents and MCP tools to enforce Cedar security policies, isolate credentials, and produce cryptographically signed action receipts stored in a local append-only ledger.

**Not a service today:** Relay does not operate a hosted execution environment in v0.1.0.

---

## 4. Open-Source Components

| Topic | Fact |
|:---|:---|
| License | Apache 2.0 per `Cargo.toml` and repo |
| Source availability | Public GitHub repository |
| Warranty disclaimer | Apache 2.0 §7 disclaimer applies to software |
| Contributions | Subject to project CLA/DCO if adopted TBD |
| Third-party licenses | See `docs/release/THIRD-PARTY-LICENSES.md` |

Counsel to clarify relationship between Apache license and any commercial overlay.

---

## 5. Commercial Components (Planned)

| Component | Description | Availability |
|:---|:---|:---|
| CR002 Local Security Console | Local UI for policy/receipt management | Planned |
| Support tiers | Priority security response | Planned |
| Optional hosted management | Fleet/policy sync | Planned / deferred |
| Subscriptions | Recurring billing | Not implemented |

Terms must not describe commercial features as currently available unless explicitly marked beta.

---

## 6. Account Responsibilities (When Accounts Launch)

Specify user obligations:

- Accurate registration information
- Credential confidentiality for account login
- Prompt breach notification
- Compliance with acceptable use
- Responsibility for users they invite (team plans TBD)

---

## 7. Acceptable Use

Prohibited uses (counsel to expand):

- Circumventing Relay security boundaries for unauthorized access
- Using Relay to attack third-party systems
- Violating applicable law
- Reverse engineering **only if** permitted/restricted per commercial license overlay (Apache 2.0 permits; commercial add-ons may differ)

---

## 8. Customer Content & Data

| Topic | Specification |
|:---|:---|
| Customer content | Policies, ledger data, secrets stored locally by customer |
| Relay access | No access to customer local data in v0.1.0 |
| Hosted data (future) | Scope TBD in DPA |
| Backup responsibility | Customer (`docs/operations/backup-and-recovery.md`) |

---

## 9. Subscriptions, Pricing & Taxes (Planned)

| Topic | Status |
|:---|:---|
| Pricing | TBD |
| Billing cycle | TBD |
| Free tier / open source | Core remains Apache 2.0 |
| Taxes (GST India, VAT, sales tax) | Counsel + finance TBD |
| Price changes | Notice period TBD |

---

## 10. Cancellation & Refunds (Planned)

| Topic | Specification |
|:---|:---|
| Cancellation | Self-service portal TBD |
| Refund policy | TBD — counsel + finance |
| Effect on local software | Local binary continues under Apache 2.0 regardless of subscription |
| Data after cancellation | Account data deletion TBD; local data unaffected |

---

## 11. Intellectual Property

| Topic | Fact |
|:---|:---|
| Relay trademarks | TBD — counsel to register/protect |
| Customer policies | Customer retains ownership of Cedar policies they author |
| Feedback | License grant TBD |
| Apache 2.0 patent grant | Applies to open-source distribution |

---

## 12. Confidentiality

Relevant for enterprise customers and security reports:

- Security vulnerability reports handled confidentially until coordinated disclosure
- Enterprise NDAs / confidentiality terms TBD

---

## 13. Security Responsibilities (Shared Responsibility)

Incorporate from `docs/commercial/data-flow.md` §7:

**Relay:** authorization boundary, credential isolation, evidence integrity (software)  
**Customer:** host OS, policy authoring, signing key custody, target permissions, local data

---

## 14. Disclaimers (Facts for Counsel)

Engineering facts supporting disclaimers:

- Software provided without hosted SLA in v0.1.0
- Security depends on customer policy configuration
- Relay does not guarantee remote cloud state consistency
- Not designed for HIPAA/regulated healthcare without separate agreement
- No compliance certifications held

---

## 15. Limitation of Liability & Indemnification

**Counsel to draft.** Engineering inputs:

- Maximum liability caps common for SMB SaaS TBD
- Indemnification for customer misuse of connectors TBD
- Exclusion of consequential damages standard TBD

---

## 16. Termination

| Scenario | Effect |
|:---|:---|
| Customer stops using software | Local Apache 2.0 rights persist |
| Subscription termination | Commercial features disabled; local core remains |
| Provider termination of service | Notice period TBD for hosted components |
| Material breach | Standard remedies TBD |

---

## 17. Governing Law & Dispute Resolution

| Topic | Recommendation for Counsel |
|:---|:---|
| Governing law | India (company operated from India) |
| Jurisdiction / arbitration | TBD — counsel |
| EU consumer rights | Assess if EU customers targeted |

---

## 18. Miscellaneous

Counsel to include standard provisions:

- Entire agreement
- Severability
- Assignment
- Force majeure
- Notices
- Export control (encryption — Relay uses standard crypto)

---

## 19. Related Documents

- `docs/legal/privacy-policy-spec.md`
- `docs/commercial/product-boundary.md`
- `docs/legal/counsel-package.md`
- `LICENSE` / Apache 2.0 text in repository
