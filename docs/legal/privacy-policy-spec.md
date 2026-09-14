# Privacy Policy — Engineering Specification for Counsel

**Document ID:** `CR001-LPP-001`  
**Version:** `1.0.0`  
**Status:** SPECIFICATION — Not final legal text  
**Last Updated:** 2026-09-14  

---

## 1. Purpose

Provide counsel with accurate facts to draft a public Privacy Policy. This is an engineering specification, not publishable legal language.

---

## 2. Data Controller Identity

| Field | Value |
|:---|:---|
| Product name | Relay |
| Legal entity name | **TBD — counsel to confirm** |
| Country of operation | India |
| Privacy contact email | **TBD — recommend dedicated privacy@ relay.dev** |
| Security contact | `security@relay.dev` (operational) |
| Website | **Not yet live — TBD** |

---

## 3. Scope of Policy

The Privacy Policy must cover distinct product surfaces:

| Surface | Status | Policy Section Needed |
|:---|:---|:---|
| Relay open-source / binary (v0.1.0) | Shipped | Local processing disclosure |
| Relay website | Planned | Collection, cookies, accounts |
| Billing / subscriptions | Planned | Payment processor reference |
| Support | Planned | Ticket data handling |
| Security reporting | Active | Limited email processing |
| Future hosted services | Planned | Opt-in cloud processing |

---

## 4. Categories of Personal Data

### 4.1 Data Relay Does NOT Collect (v0.1.0 Binary)

- Product telemetry
- Automatic usage analytics
- Agent prompts (as dedicated collection)
- Automatic upload of tool arguments, receipts, or ledger
- Automatic update check metadata to Relay servers

### 4.2 Data Processed Locally (Customer-Controlled)

Counsel should clarify Relay is **software**; customer is responsible for local data:

- Tool names and arguments (may contain personal data if agent includes it)
- Policy decisions and audit receipts
- Filesystem paths and SQL queries in receipts
- Timestamps and execution metadata

### 4.3 Data Relay May Collect Directly (Current & Planned)

| Category | Examples | Status |
|:---|:---|:---|
| Contact | Email, name | Planned (accounts, support) |
| Account | User ID, org name | Planned |
| Billing | Email, subscription ID, invoice refs | Planned — card data at processor only |
| Communications | Support tickets, security reports | Partial (security email active) |
| Technical (website) | IP, User-Agent, cookies | Planned |
| Marketing | Newsletter email | Planned / optional |

---

## 5. Sources of Data

| Source | Data |
|:---|:---|
| User directly | Account signup, support forms, security emails |
| Automatic (website only) | Server logs, session cookies |
| Third parties | OAuth provider (if used), payment processor webhooks |
| **Not from Relay binary** | No automatic collection from local installations |

---

## 6. Purposes of Processing

| Purpose | Data Used | Legal Basis (counsel to assign) |
|:---|:---|:---|
| Provide Relay software | None collected by Relay for local binary | N/A / software license |
| Security vulnerability response | Reporter email, report content | Legitimate interest / legal obligation TBD |
| Account management | Account identifiers | Contract TBD |
| Billing | Subscription metadata | Contract TBD |
| Website operation | Logs, cookies | Legitimate interest / consent TBD |
| Support | Ticket content | Contract / legitimate interest TBD |
| Marketing | Email | Consent TBD |
| Legal compliance | As required | Legal obligation TBD |

---

## 7. Data Sharing & Processors

Policy must reference `docs/commercial/subprocessors.md` (updated before launch).

**Confirmed today:**
- GitHub (release hosting — user-initiated downloads)

**TBD before launch:** hosting, CDN, payment, email, auth providers

Policy must state:
- Relay does **not** sell personal data (intent — counsel to phrase)
- Relay does **not** receive local execution data from binary by default

---

## 8. International Transfers

Counsel to address when vendors selected:

- Storage regions of cloud providers
- Payment processor locations
- Email provider locations
- Mechanisms: SCCs, adequacy, consent under DPDP/GDPR as applicable

---

## 9. Retention

Reference `docs/commercial/data-flow.md` retention matrix.

Key counsel points:

- Local ledger retention: **customer-controlled**
- Security reports: retention TBD
- Account data: account lifetime + statutory periods TBD
- Billing records: statutory tax retention TBD

---

## 10. Security Safeguards

Reference `docs/commercial/security-overview.md`:

- Local-first architecture
- Credential isolation (SI-001)
- Encryption at rest via OS keyring and file permissions
- Signed audit ledger
- No telemetry in v0.1.0 binary

**Do not claim certification.**

---

## 11. User Rights (Framework-Neutral Spec)

Policy should describe mechanisms for:

| Right | Local Binary Data | Relay-Held Data (Future) |
|:---|:---|:---|
| Access | Customer manages local files | Account portal / request process TBD |
| Correction | Customer edits local config | Account settings TBD |
| Deletion | Customer deletes `.relay/`, keyring secrets | Account deletion TBD |
| Export | `relay verify`, ledger file copy | Export API TBD |
| Withdraw consent | N/A for binary | Marketing unsubscribe TBD |
| Grievance (India) | **TBD — required before launch** | DPO/grievance officer TBD |

**Critical honesty:** Policy must not promise Relay can delete data on customer machines.

---

## 12. Children

Recommend statement: Relay is not directed at children under 18 (age TBD by counsel). No knowing collection from children.

---

## 13. Automated Decision-Making

Relay uses deterministic Cedar policies, not ML profiling of individuals. Counsel to assess if policy evaluation constitutes automated decision-making under applicable law.

---

## 14. Changes to Policy

Specify:
- Version date on policy
- Notice mechanism (website banner, email for account holders)
- Material change notification period TBD

---

## 15. Jurisdiction-Specific Sections (Counsel Drafting)

| Jurisdiction | Spec Input Document |
|:---|:---|
| India (DPDP) | `privacy-india.md` |
| EU (GDPR) | `data-flow.md` jurisdiction matrix — if EU targeting confirmed |
| California (CPRA) | `data-flow.md` — if thresholds met |

---

## 16. Related Documents

- `docs/commercial/data-flow.md`
- `docs/commercial/subprocessors.md`
- `docs/legal/terms-spec.md`
- `docs/legal/counsel-package.md`
