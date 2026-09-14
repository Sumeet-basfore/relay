# Relay Privacy Threat Model

**Document ID:** `CR001-PTM-001`  
**Version:** `1.0.0`  
**Status:** Engineering Threat Model  
**Applies To:** Relay v0.1.0 + planned commercial surfaces  
**Last Updated:** 2026-09-14  

---

## 1. Scope

This model complements the security threat model (`docs/security/threat-model.md`) by focusing on **privacy failures**: unauthorized collection, excessive retention, unintended disclosure, and loss of user control over personal and sensitive execution data.

---

## 2. Assets

| Asset | Sensitivity | Location (v0.1.0) |
|:---|:---|:---|
| Tool arguments & SQL | High | Local ledger (scrubbed), process memory |
| Agent prompts (if in args) | High | Process memory; may appear in receipts |
| Target credentials | Secret | OS keyring, volatile leases |
| Receipts & ledger | Medium–High | `.relay/ledger.db` |
| Cedar policies | Medium | Local filesystem |
| Signing keys | Secret | Keyring / seed file |
| Customer account PII | Medium | **Not collected (v0.1.0)** — future website |
| Billing data | Medium–Secret | **Not collected (v0.1.0)** — future processor |
| Security report emails | Medium | Company mailbox (TBD) |

---

## 3. Threat Catalog

| ID | Threat | Description | v0.1.0 Control | Owner | Residual Risk |
|:---|:---|:---|:---|:---|:---|
| P-01 | Unnecessary collection | Relay collects data beyond execution need | No telemetry; local processing only | Engineering | **Low** for binary |
| P-02 | Telemetry leakage | Usage data sent to Relay without consent | Option A: no telemetry implemented | Engineering | **Low** |
| P-03 | Prompt leakage | Agent prompts exfiltrated to Relay cloud | No cloud pipeline | Engineering | **Low** |
| P-04 | Tool argument leakage | Args sent to Relay infrastructure | Args stay local; connectors user-configured | Engineering | **Low** |
| P-05 | Receipt leakage | Ledger synced to Relay without opt-in | No sync in v0.1.0 | Engineering | **Low** (v0.1.0) |
| P-06 | Credential capture | Relay stores/sends credentials to infra | SI-001; keyring only; scrubber | Engineering | **Low** |
| P-07 | Excessive retention | Data kept beyond purpose | Customer controls ledger deletion | Customer + docs | **Medium** — customer ops dependent |
| P-08 | Doctor phone-home | Diagnostics transmit data externally | Local-only checks (`doctor.rs`) | Engineering | **Low** |
| P-09 | Update checker leakage | Version checks expose IP/usage | No auto-update in binary | Engineering | **Low** |
| P-10 | Support log leakage | Support staff access unredacted PII | Not operational yet | Ops (TBD) | **TBD** at launch |
| P-11 | Employee access abuse | Internal access to customer cloud data | No hosted customer data (v0.1.0) | Ops | **Low** (v0.1.0) |
| P-12 | Subprocessor compromise | Vendor breach exposes website/billing data | Vendors not selected | Legal + Security | **TBD** |
| P-13 | Cross-customer leakage | Multi-tenant data mix (hosted) | Not applicable v0.1.0 | Engineering | **N/A** until hosted |
| P-14 | UI over-display | CR002 UI shows raw secrets/prompts | Spec in `ui-data-boundary.md` | Engineering (CR002) | **Medium** until CR002 built |
| P-15 | Local network exposure | UI/API bound to `0.0.0.0` | CR002 spec: localhost default | Engineering (CR002) | **TBD** |
| P-16 | Clipboard leakage | UI copies secrets to clipboard | CR002 spec: avoid credential copy | Engineering (CR002) | **TBD** |
| P-17 | Billing data leakage | Payment data stored by Relay | Outsource to processor (planned) | Legal | **TBD** |
| P-18 | Account takeover | Stolen session accesses hosted account | No accounts v0.1.0 | Engineering (TBD) | **N/A** |
| P-19 | Incorrect deletion | Failed erasure on request | Local: customer deletes files; cloud: TBD | Ops + Legal | **Medium** |
| P-20 | Install script logging | Install transmits execution metadata to Relay | Only GitHub CDN; not Relay-operated | Engineering | **Low** |

---

## 4. STRIDE-Privacy Mapping (Selected)

| STRIDE | Privacy Manifestation | Primary Control |
|:---|:---|:---|
| **Information Disclosure** | Receipt/arg leakage to cloud | Local-first architecture |
| **Tampering** | Ledger altered to hide processing | Hash chain + DSSE signatures |
| **Repudiation** | Deny processing occurred | Signed receipts |
| **Denial of Service** | N/A privacy-primary | — |
| **Elevation** | Access hosted customer data | No hosted data v0.1.0 |
| **Spoofing** | Fake telemetry endpoint | No telemetry endpoints |

---

## 5. Future Risk: v0.2 Deferred Features

| Feature | Privacy Risk | Required Mitigation |
|:---|:---|:---|
| Remote ledger sync | Centralizes execution history | Opt-in only; explicit disclosure; encryption in transit |
| Telemetry (if added) | Usage profiling | Opt-in; no execution content; counsel review |
| Hosted management | Multi-tenant PII | Tenant isolation; DPA; access logging |

See `docs/roadmap/v0.2.md`.

---

## 6. Control Verification Checklist

| Control | Verification Method | v0.1.0 Result |
|:---|:---|:---|
| No telemetry HTTP endpoints | Code search + network test | Pass |
| Doctor local-only | Code review `doctor.rs` | Pass |
| Credentials not in ledger | SI-007 tests + scrubber | Pass |
| No auto-update | Code search | Pass |
| Install script destination | Review `install.sh` | GitHub only (user-initiated) |

---

## 7. Related Documents

- `docs/security/threat-model.md`
- `docs/commercial/data-flow.md`
- `docs/commercial/ui-data-boundary.md`
- `docs/commercial/product-boundary.md`
