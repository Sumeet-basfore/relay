# Relay GA001 Scope Freeze & Baseline Specification

**Document ID:** `REL-FRZ-GA001`  
**Milestone:** `GA001 — General Availability Release Engineering`  
**Date:** 2026-09-14  
**Status:** Frozen Scope Baseline  
**Target Release:** `v0.1.0`  

---

## 1. Executive Summary

Milestone GA001 establishes an immutable scope freeze for Relay v0.1.0. All research (M001), architecture, implementation (B001–B013, M002), and adversarial validation (RC001–RC003, M003) phases are complete.

No new product features, architectural expansions, or connector additions are permitted for the v0.1.0 General Availability release.

---

## 2. Frozen Capabilities & Subsystems

| Subsystem | Frozen Architecture & Behavior | Enforcement Invariants |
|:---|:---|:---:|
| **MCP Gateway** | Bounded stdio framing (MAX_FRAME_SIZE: 1MB), strict JSON parser, duplicate key rejection, startup timeout (5s), graceful shutdown (500ms SIGTERM → SIGKILL). | `SI-009`, `SI-014` |
| **Canonicalization** | RFC 8785 JSON Canonicalization Scheme (JCS), deterministic parameter sorting, NaN/Infinity rejection, canonical `ActionHash` computation. | `SI-009` |
| **Policy Engine (Cedar PEP)** | In-process AWS Cedar authorization engine, compiled schema validation (`Relay::NetworkEndpoint`, `Relay::Filesystem`, `Relay::Postgres`, `Relay::GitHub`), default-deny, immutable policy digest. | `SI-002`, `SI-003`, `SI-010` |
| **Approval Provider** | Local `/dev/tty` interactive approval gate with detailed context view, 30s timeout, non-interactive/headless fail-closed blocking (`EXIT_APPROVAL_REQUIRED: 10`). | `SI-004`, `SI-011`, `SI-012` |
| **Credential Broker** | Single-action ephemeral credential leases, zero ambient target tokens in subprocess context (`env_clear()`), zeroization on drop (`SecretBuffer`). | `SI-001`, `SI-006`, `SI-008`, `SI-018` |
| **Native Connectors** | Governed Filesystem (path traversal protection, symlink escape defense, size bounds), PostgreSQL (strict SQL parser, AST whitelist, read-only vs mutation scoping), GitHub (REST API, scoped PAT). | `SI-002`, `SI-003` |
| **External MCP Mediation** | In-process loopback HTTP forward proxy & HTTPS `CONNECT` tunnel, pre-DNS blacklist (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`), RFC 1918 filtering, socket IP pinning. | `SI-019`, `SI-021`, `SI-022` |
| **Subprocess Sandbox** | Linux unprivileged User & Network Namespaces (`CLONE_NEWUSER \| CLONE_NEWNET`, `ENETUNREACH` for raw sockets, fail-closed `pre_exec`), macOS/Windows Managed Cooperative Proxy Mode. | `SI-023`, `SI-024` |
| **Action Receipts** | In-toto v0.1 DSSE envelope format, Ed25519 cryptographic signing, deterministic RFC 9598 Pre-Authentication Encoding (PAE), regex-based secret scrubber before signing. | `SI-007`, `SI-008`, `SI-015` |
| **Audit Ledger** | SQLite append-only database, Merkle-linked SHA-256 hash chaining (`parent_hash` → `entry_hash`), tamper detection on load. | `SI-013`, `SI-014` |
| **CLI Surface** | `relay doctor`, `relay run`, `relay verify`, `relay receipt`, `relay policy`, `relay --version`, `relay --help`. | Deterministic Exit Codes |

---

## 3. Work Item Classification

### 3.1. GA Blocker Items (Included & Completed in GA001)
- Release binary compilation with hardened release profile (`opt-level = 3`, `lto = true`, `panic = "abort"`, `codegen-units = 1`, `strip = true`).
- Cryptographic SHA-256 checksum generation and detached manifest.
- Non-root, safe shell installer (`install.sh`) with signature & checksum validation.
- End-to-end GA release smoke test across the entire governed lifecycle.
- Complete public documentation link, license, and attribution audit.

### 3.2. Deferred to Future Releases (v0.2+)
- Long-running asynchronous MCP Task lease management.
- Dynamic kernel network mediation for macOS (Endpoint Security framework) and Windows (WFP driver).
- Hardware security module (HSM) / PKCS#11 key storage providers.
- Multi-party quorum approvals on `/dev/tty` or webhooks.
- Remote telemetry / distributed ledger replication.

### 3.3. Rejected Architectural Proposals
- *Dynamic Linker Interception (`LD_PRELOAD` / `DYLD_INSERT_LIBRARIES`):* Defeated by statically linked binaries and macOS SIP.
- *Permissive Fallback on Sandbox Setup Failure:* Violates fail-closed security invariant `SI-024`.
- *In-memory Policy Cache without ActionHash Verification:* Violates `SI-002` and allows TOCTOU authorization confusion.

---

## 4. Scope Freeze Certification

$$\text{Release Scope Status: } \mathbf{FROZEN\ FOR\ v0.1.0\ GA}$$
