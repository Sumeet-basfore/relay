# Relay Commercial Product Boundary

**Document ID:** `CR001-PB-001`  
**Version:** `1.0.0`  
**Status:** Engineering Specification (Pre-Commercial Launch)  
**Applies To:** Relay `v0.1.0` and planned commercial extensions  
**Last Updated:** 2026-09-14  

---

## 1. Purpose

This document defines what Relay ships today, what may be sold commercially in the future, and what data crosses organizational boundaries. It is an engineering and commercial-readiness specification—not a legal contract or compliance declaration.

---

## 2. Commercial Architecture Decision

**Selected Model: Model B — Local-first open core + optional future hosted management**

| Layer | Status (v0.1.0) | Commercial Intent |
|:---|:---|:---|
| **Open-source core** | Shipped (`Apache-2.0`) | Remains free; source at `github.com/relay-security/relay` |
| **Local binary** | Shipped (`relay` CLI) | Primary product surface; no account required |
| **Local UI (CR002)** | Planned | Optional paid/local management console |
| **Hosted management** | Planned / TBD | Optional future service; not in v0.1.0 |
| **Accounts & billing** | Not implemented | Required before paid launch; architecture TBD |
| **Public website** | Not implemented | Planned; see `website-data-map.md` |

Relay does **not** implement Model C (cloud team product as primary) or Model D (centralized evidence by default) in v0.1.0.

---

## 3. What Users Install (v0.1.0)

### 3.1 Relay Binary

- **Artifact:** Standalone Rust binary (`relay`), version `0.1.0`
- **License:** Apache 2.0 (workspace `Cargo.toml`)
- **Distribution:** GitHub Releases tarballs + `install.sh` (user-initiated download)
- **Runtime:** Local process; stdio MCP gateway between agent and governed tools

### 3.2 Local Persistent State

| Component | Default Path | Purpose |
|:---|:---|:---|
| Audit ledger | `.relay/ledger.db` (configurable) | Append-only SQLite hash-chain of DSSE receipts |
| Signing key seed | `~/.config/relay/signing_key.seed` | Ed25519 receipt signing (mode `0600`) |
| OS keyring secrets | Platform keyring via `keyring-rs` | Vaulted target credentials (GitHub PAT, Postgres, etc.) |
| Policy bundle | `policies/` or `~/.config/relay/policies/` | Cedar authorization policies |
| Configuration | `~/.config/relay/relay.toml` | Local security and storage settings |

See `docs/operations/backup-and-recovery.md` for full inventory.

### 3.3 What the Binary Does Not Include

- No product telemetry
- No phone-home or automatic update checks
- No license activation server calls
- No Relay-operated cloud backend
- No user accounts or authentication to Relay infrastructure

These behaviors were verified by code review of `crates/relay-cli/` and workspace-wide search for telemetry/analytics endpoints (none found in v0.1.0).

---

## 4. What Users Pay For (Planned — Not Yet Available)

Paid functionality is **not implemented** in v0.1.0. Planned commercial offerings under Model B:

| Offering | Description | Data Boundary |
|:---|:---|:---|
| **CR002 Local Security Console** | Local-only UI for policy simulation, receipt verification, ledger status | Localhost-bound; no cloud sync by default |
| **Support tiers** | Priority vulnerability response, deployment assistance | Support interactions may create personal data; TBD |
| **Optional hosted management** | Fleet policy distribution, centralized audit ingestion | Opt-in only; deferred to post-v0.1.0 |
| **Enterprise integrations** | Vault plugins, SIEM connectors | Customer-configured; see v0.2 roadmap |

**Billing, subscriptions, and payment processing:** PLANNED / TBD. No payment processor integrated.

---

## 5. What Remains Local

Under v0.1.0, the following remain on the customer's machine unless the customer explicitly configures outbound connectors:

| Data Category | Local Processing | Leaves Device? |
|:---|:---|:---|
| MCP JSON-RPC messages | Yes | No (to Relay infrastructure) |
| Tool names and arguments | Yes (canonicalized, scrubbed for receipts) | Only to user-configured targets |
| Cedar policy evaluations | Yes | No |
| DSSE action receipts | Yes (signed, ledger-appended) | No |
| Target credentials | OS keyring / secure memory only | Only to user-configured targets at execution time |
| Agent prompts | Not collected by Relay telemetry | May appear in tool args if agent passes them |
| `relay doctor` output | Printed to stdout only | No |

**User-configured outbound flows** (not Relay infrastructure):

- **GitHub connector:** HTTPS to `api.github.com` (or enterprise GitHub) using customer PAT
- **PostgreSQL connector:** TCP to customer database host
- **External MCP subprocess egress:** Mediated through loopback proxy (`127.0.0.1`) with Cedar authorization

---

## 6. What Communicates with Relay Infrastructure

### 6.1 v0.1.0 Binary: Nothing Automatic

The `relay` binary performs **zero** network calls to Relay-operated services during normal operation, diagnostics, or error handling.

### 6.2 User-Initiated Distribution Only

| Action | Initiator | Destination | Data Transmitted |
|:---|:---|:---|:---|
| `install.sh` download | User | `github.com/relay-security/relay/releases/` | HTTP request metadata (IP, User-Agent) logged by GitHub, not Relay |
| Manual release download | User | Same | Same |
| Security vulnerability report | User | `security@relay.dev` | Contents of reporter's email |
| Public GitHub issues/PRs | User | GitHub | User-provided content |

### 6.3 Planned (Not Live)

| Surface | Status | Notes |
|:---|:---|:---|
| Commercial website | PLANNED / TBD | See `website-data-map.md` |
| Account system | PLANNED / TBD | Not required for v0.1.0 binary |
| Billing portal | PLANNED / TBD | Payment processor TBD |
| Hosted management API | PLANNED / TBD | Deferred; v0.2 roadmap mentions optional ledger sync |

---

## 7. Open Source vs Commercial Boundary

```text
┌─────────────────────────────────────────────────────────────────────┐
│                    APACHE 2.0 OPEN SOURCE CORE                       │
│  relay-domain, relay-policy, relay-mcp, relay-connectors,           │
│  relay-receipts, relay-ledger, relay-credentials, relay-cli         │
│  Cedar PEP · credential broker · DSSE receipts · SQLite ledger      │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │  same security invariants
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│              PLANNED COMMERCIAL LAYER (NOT IN v0.1.0)               │
│  CR002 local UI · support · optional hosted management · billing    │
│  Must not weaken local-first defaults or exfiltrate execution data  │
└─────────────────────────────────────────────────────────────────────┘
```

Commercial components must preserve:

- SI-001 through SI-024 security invariants (see `docs/security/security-invariants.md`)
- No credential transmission to Relay-operated telemetry systems
- Opt-in only for any cloud synchronization of execution history

---

## 8. Privacy by Default (v0.1.0)

These defaults reflect **actual v0.1.0 behavior**, not aspirational policy:

| Control | Default | Implementation Reference |
|:---|:---|:---|
| Product telemetry | **OFF** (not implemented) | No telemetry code in binary |
| Prompt collection | **OFF** | Relay does not operate a prompt telemetry pipeline |
| Tool argument exfiltration to Relay | **OFF** | Args processed locally; scrubbed before receipt signing |
| Credential collection by Relay | **NEVER** to Relay infra | JIT lease to connectors only; SI-001 |
| Local receipts | **ON** | Every governed action produces DSSE receipt |
| Local ledger | **ON** | Append-only SQLite at configured path |
| Cloud synchronization | **OFF** | Not implemented; deferred v0.2 |
| Automatic update checks | **OFF** | Binary does not check for updates |
| `relay doctor` phone-home | **OFF** | Local filesystem and config checks only (`doctor.rs`) |

---

## 9. Explicit Non-Claims

Relay v0.1.0 documentation and this specification do **not** claim:

- GDPR, DPDP, SOC 2, HIPAA, or ISO 27001 compliance
- "Zero data" or "we collect no data" (local ledger and receipts store execution metadata)
- "Fully private" (user-configured connectors transmit data to third parties)
- Certification of any kind

---

## 10. Related Documents

- `docs/commercial/data-flow.md` — Full data inventory and flow diagrams
- `docs/commercial/ui-data-boundary.md` — CR002 UI constraints
- `docs/commercial/security-overview.md` — Customer-facing security summary
- `docs/roadmap/v0.2.md` — Deferred features (ledger sync, telemetry)
- `docs/release/CR001-commercial-readiness-report.md` — Milestone verdict
