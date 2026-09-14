# Relay Data-Flow Architecture

**Document ID:** `CR001-DF-001`  
**Version:** `1.0.0`  
**Status:** Engineering Specification  
**Applies To:** Relay `v0.1.0` + planned commercial surfaces  
**Last Updated:** 2026-09-14  

---

## 1. Purpose

Map every material data flow for Relay's commercial product boundary. This document is the source of truth for privacy policy drafting, subprocessor selection, and customer trust materials.

---

## 2. Architecture Overview

### 2.1 v0.1.0 Shipped Flow (Local-First)

```text
                    ┌──────────────────┐
                    │   AI Agent       │
                    │ (Claude/Cursor)  │
                    └────────┬─────────┘
                             │ stdio MCP JSON-RPC
                             ▼
                    ┌──────────────────┐
                    │   relay binary   │◄── Cedar policies (local)
                    │  (local process) │
                    └────────┬─────────┘
           ┌─────────────────┼─────────────────┐
           ▼                 ▼                 ▼
    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
    │ .relay/     │   │ OS Keyring  │   │ Connectors  │
    │ ledger.db   │   │ secrets     │   │ (user cfg)  │
    └─────────────┘   └─────────────┘   └──────┬──────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    ▼                          ▼                          ▼
             GitHub API                  PostgreSQL                   External MCP
         (customer PAT)               (customer DB)              (mediated egress)
```

**No arrow exists from `relay binary` to Relay-operated cloud services in v0.1.0.**

### 2.2 Planned Commercial Flow (Not Live)

```text
User ──► Website (TBD) ──► Account System (TBD) ──► Billing Provider (TBD)
                              │
                              └──► Optional Hosted Management (TBD, opt-in)

Local Agent ──► relay ──► Local Ledger
                │
                └──► CR002 Local UI (localhost only, planned)
```

---

## 3. Complete Data Inventory

### 3.1 Relay Binary (v0.1.0 — Shipped)

| Data | Source | Purpose | Location | Retention | Sensitive? | Leaves Device? | Processor |
|:---|:---|:---|:---|:---|:---|:---|:---|
| MCP JSON-RPC frames | Agent via stdio | Tool mediation | Process memory | Session | Medium | No (Relay infra) | Customer (local) |
| Tool names | MCP `tools/call` | Authorization, receipts | Ledger + memory | Until customer deletes ledger | Low–Medium | Only via user connectors | Customer (local) |
| Tool arguments (canonical JCS) | MCP payload | Policy eval, receipt payload | Ledger (scrubbed) | Until customer deletes ledger | **High** | Only via user connectors | Customer (local) |
| ActionHash / receipt IDs | Relay canonicalization | Tamper-evident audit | `.relay/ledger.db` | Customer-controlled | Medium | No (default) | Customer (local) |
| Cedar policy text & hashes | Local policy dir | Authorization | Disk + ledger snapshots | Customer-controlled | Medium | No (default) | Customer (local) |
| Policy decisions (allow/deny) | Cedar PEP | Audit evidence | Ledger receipts | Customer-controlled | Medium | No (default) | Customer (local) |
| DSSE envelopes & signatures | Receipt engine | Non-repudiation | `.relay/ledger.db` | Customer-controlled | Medium | No (default) | Customer (local) |
| Ed25519 signing key (private) | Generated at init | Receipt signing | OS keyring / `signing_key.seed` | Until rotation | **Secret** | No | Customer (local) |
| Target credentials (PAT, DB pass) | User via `relay secret set` | JIT connector auth | OS keyring | Until user deletes | **Secret** | To user-configured targets only | Customer (local) |
| Filesystem paths | Tool args / connector | Path authorization | Receipts (may be scrubbed) | Customer-controlled | **High** | Via filesystem connector only | Customer (local) |
| SQL query text | Postgres connector | Query governance | Receipts (scrubbed) | Customer-controlled | **High** | To customer DB only | Customer (local) |
| GitHub resource metadata | GitHub connector | API governance | Receipts | Customer-controlled | Medium | To GitHub API only | Customer + GitHub |
| Approval records | `/dev/tty` human gate | Authorization audit | Ledger | Customer-controlled | Medium | No | Customer (local) |
| Host OS / arch | Runtime | Diagnostics | `relay doctor` stdout only | Ephemeral (print) | Low | No | Customer (local) |
| Ledger file permissions | Filesystem | Security diagnostics | `relay doctor` stdout | Ephemeral | Low | No | Customer (local) |
| Egress proxy lease tokens | Relay MCP | Subprocess auth | Volatile memory (30s TTL) | Seconds | **Secret** | Loopback only | Customer (local) |
| Resolved IP addresses | Egress DNS (external MCP) | Anti-SSRF pinning | Volatile memory | Session | Medium | To authorized endpoints only | Customer (local) |
| Agent prompts | Not directly collected | N/A | Not stored by Relay telemetry | N/A | **High** if in tool args | May transit via tool args | Customer (local) |

### 3.2 Install Script (User-Initiated)

| Data | Source | Purpose | Location | Retention | Sensitive? | Leaves Device? | Processor |
|:---|:---|:---|:---|:---|:---|:---|:---|
| HTTP request (download) | User runs `install.sh` | Binary distribution | GitHub CDN logs | GitHub retention policy | Low | Yes → GitHub | GitHub (third party) |
| IP address, User-Agent | Network stack | CDN/server logs | GitHub infrastructure | GitHub policy | Low | Yes → GitHub | GitHub |
| SHA256 checksum verification | Local file | Integrity check | Local temp dir | Deleted after install | Low | No | Customer (local) |

### 3.3 Security Reporting

| Data | Source | Purpose | Location | Retention | Sensitive? | Leaves Device? | Processor |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Vulnerability report content | Reporter email | Security response | Company email system (TBD) | TBD — counsel review | Medium–High | Yes → `security@relay.dev` | Relay (India) |
| Reporter contact info | Reporter | Coordination | Internal ticket system (TBD) | TBD | Medium | Yes | Relay (India) |

### 3.4 Planned Website (Not Live — TBD)

| Data | Source | Purpose | Location | Retention | Sensitive? | Leaves Device? | Processor |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Email address | Sign-up form | Account creation | TBD | TBD | Medium | Yes | TBD |
| IP address | HTTP request | Security, abuse prevention | TBD CDN/host | TBD | Low | Yes | TBD |
| Cookies / session tokens | Browser | Authentication | TBD | TBD | Medium | Yes | TBD |
| Analytics events | Browser JS | Usage measurement | TBD (prefer none/minimal) | TBD | Low | Yes if enabled | TBD |
| Support ticket content | Contact form | Customer support | TBD | TBD | Medium–High | Yes | TBD |

### 3.5 Planned Billing (Not Live — TBD)

| Data | Source | Purpose | Location | Retention | Sensitive? | Leaves Device? | Processor |
|:---|:---|:---|:---|:---|:---|:---|:---|
| Customer name / email | Checkout | Invoicing | Payment processor + Relay CRM (TBD) | Statutory + contract | Medium | Yes | TBD processor |
| Payment card data | Checkout | Payment | **Payment processor vault only** | Processor policy | **Secret** | Yes → processor | TBD (Stripe/Razorpay/etc.) |
| Subscription ID / plan | Billing system | Entitlement | Relay backend (TBD) | Contract lifetime | Medium | Yes | Relay (TBD) |
| Billing address | Checkout | Tax/invoicing | Processor + Relay (TBD) | Statutory | Medium | Yes | TBD |

---

## 4. Data Classification Scheme

| Class | Definition | Examples | Default Transmission |
|:---|:---|:---|:---|
| **Public** | Published intentionally | README, release notes, SHA256SUMS | Public repos |
| **Internal** | Operational, non-customer | Build CI logs (GitHub Actions) | GitHub (dev infra) |
| **Confidential** | Customer or deployment specific | Policy files, ledger contents, org repo names | Local only (v0.1.0) |
| **Secret** | Credential / key material | PATs, DB passwords, signing seeds | Never to Relay infra |
| **Highly Sensitive Execution Data** | Agent/tool execution context | Tool args, SQL, paths, receipt payloads | Local only; opt-in cloud TBD |

---

## 5. Retention Matrix

| Data | Default Retention | Customer-Controlled? | Deletion Mechanism |
|:---|:---|:---|:---|
| Ledger & receipts (`.relay/ledger.db`) | Indefinite until deleted | **Yes** | Delete file; `relay init` for fresh ledger |
| Signing key | Until rotation | **Yes** | Delete `signing_key.seed`; regenerate |
| OS keyring secrets | Until `relay secret delete` | **Yes** | Keyring API / CLI |
| Cedar policies | Until user removes | **Yes** | Filesystem delete |
| MCP session data (memory) | Process lifetime | N/A (ephemeral) | Process exit |
| Credential leases | ≤30 seconds | N/A (ephemeral) | Auto-expire (`defaults.md`) |
| `relay doctor` output | Not persisted | N/A | Terminal scrollback only |
| Install script temp files | Install duration | **Yes** | `mktemp` cleanup in `install.sh` |
| Security reports (email) | TBD — counsel | Partial | Internal process TBD |
| Website account data | TBD | TBD (planned) | TBD |
| Billing records | TBD — statutory | Partial | TBD |
| Telemetry | **Not collected** | N/A | N/A |
| Crash reports | **Not collected** | N/A | N/A |
| Hosted policies (future) | TBD | TBD | TBD |
| Centralized receipts (future) | TBD | TBD | TBD |

**Important:** Relay (the company) cannot delete data residing solely on customer-owned infrastructure. Privacy rights requests for local-only data must be handled by the customer or documented as out of Relay's control.

---

## 6. Jurisdiction Applicability Matrix

This matrix identifies **potential applicability** for counsel review. It is **not** a compliance declaration.

| Jurisdiction / Framework | Relay v0.1.0 Binary | Planned Website/Billing | Applicability Trigger | Current Assessment |
|:---|:---|:---|:---|:---|
| **India — DPDP Act 2023 / Rules 2025** | Low direct collection by Relay | Higher if accounts launched | Company operated from India | See `privacy-india.md` |
| **EU — GDPR** | Unlikely controller for local binary alone | Possible if EU users targeted | Offering goods/services to EU | Applicability TBD at launch |
| **US — California CPRA** | Unlikely for binary alone | Possible at revenue threshold | CA residents + thresholds | Applicability TBD at launch |
| **Sector — HIPAA** | Not applicable to product design | N/A unless healthcare customer BAA | Customer use case | Not designed as HIPAA tool |
| **SOC 2 / ISO 27001** | Not certified | Not certified | Customer procurement | Future consideration only |

---

## 7. Privacy / Security Responsibility Matrix

### 7.1 Local Relay Deployment (v0.1.0)

| Responsibility | Relay (Software) | Customer (Operator) |
|:---|:---|:---|
| Authorization boundary (Cedar PEP) | ✓ Provides | Configures policies |
| Credential isolation from agent | ✓ Enforces (SI-001) | Stores secrets in keyring |
| Governed execution mediation | ✓ Enforces | Selects connectors/targets |
| Evidence integrity (DSSE + ledger) | ✓ Provides | Protects ledger file & signing key |
| Host OS security | — | ✓ Full responsibility |
| Target service permissions | — | ✓ PAT scopes, DB roles |
| Local data retention & deletion | — | ✓ Owns `.relay/` directory |
| Backup & disaster recovery | — | ✓ See ops guide |
| Network egress to GitHub/Postgres | Mediates per policy | ✓ Configures targets |
| Product telemetry to Relay | ✓ None implemented | N/A |

### 7.2 Planned Hosted Components (TBD)

| Responsibility | Relay Operator | Customer |
|:---|:---|:---|
| Hosted infrastructure security | ✓ (when built) | — |
| Account system availability | ✓ (when built) | Credential hygiene |
| Hosted data encryption | ✓ (when built) | Classification of uploaded policies |
| Policy content | — | ✓ Authoring responsibility |
| Connected target systems | — | ✓ Authorization |

---

## 8. Telemetry Decision (CR001 Phase 6)

**Decision: Option A — No Product Telemetry (v0.1.0 binary)**

| Option | Status | Rationale |
|:---|:---|:---|
| A — No telemetry | **Selected for v0.1.0** | Strongest privacy posture; matches local-first thesis; no commercial need for usage data yet |
| B — Opt-in minimal telemetry | Deferred | May reconsider for CR002 or hosted services with explicit consent |
| C — Required telemetry | Rejected | No product justification; contradicts trust model |

Deferred to v0.2 roadmap: optional operational telemetry remains **out of scope** unless explicitly re-decided with counsel approval.

---

## 9. Update Mechanism (CR001 Phase 7)

| Behavior | v0.1.0 Status |
|:---|:---|
| Automatic update checks in binary | **None** |
| Background download | **None** |
| Update server operated by Relay | **None** |
| User-initiated install via `install.sh` | Downloads from GitHub Releases |
| Signature/checksum verification | SHA256SUMS checked by install script when available |
| Version metadata transmitted to Relay | **None** |

Updates are **manual and user-initiated**. Any future update channel must not transmit execution data.

---

## 10. Flow Separation Summary

| Category | v0.1.0 |
|:---|:---|
| **Local-only data** | MCP messages, receipts, ledger, policies, credentials, doctor output |
| **Optional cloud data** | None from binary; future hosted management (opt-in, TBD) |
| **Mandatory cloud data** | None for binary operation |
| **Third-party data** | User-configured GitHub/Postgres/external MCP targets |

---

## 11. Related Documents

- `docs/commercial/product-boundary.md`
- `docs/commercial/privacy-india.md`
- `docs/commercial/subprocessors.md`
- `docs/commercial/privacy-threat-model.md`
- `docs/architecture/A006-persistence-and-storage.md`
