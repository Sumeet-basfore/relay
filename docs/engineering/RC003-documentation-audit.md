# Engineering Record: RC003 — Documentation & Security Claim Audit

**Status:** Completed  
**Milestone:** RC003  
**Author:** Principal Security Architect & Release Auditor  
**Date:** 2026-09-14  
**Workspace:** `relay`  
**Target Version:** `0.1.0`  
**Evaluation Baseline:** B001–B013, RC001, RC002 Implementation Source of Truth  

---

## 1. Executive Summary

Milestone RC003 is a documentation, threat-modeling, security-claims verification, and public-release-readiness milestone.

This document performs an exhaustive audit of all documentation, specifications, code comments, error messages, and marketing assertions across the Relay repository. Every claim regarding security, zero-trust, ambient credentials, tamper-evidence, immutability, cryptographic receipts, prompt injection resistance, and host compromise boundaries is evaluated directly against the running Rust implementation.

**Core Audit Principle:**
> **Implementation is the source of truth.** No documentation may claim guarantees stronger than what the local operating system, protocol boundaries, and implemented Rust crates actually enforce.

---

## 2. Documentation Inventory & Scope

The following documentation corpus was audited:
- **Root Files:** `README.md`, `Cargo.toml`, `deny.toml`, `install.sh`.
- **Architecture Specifications (`docs/architecture/`):** `A001` through `A010`.
- **Research Foundations (`docs/research/`):** `00-research-synthesis`, `R001` through `R015`.
- **Engineering Milestone Records (`docs/engineering/`):** `B001` through `B013`, `RC001`, `RC002`.
- **Operational & Getting Started Guides (`docs/getting-started/`, `docs/operations/`):** `installation.md`, `upgrade.md`, `backup-and-recovery.md`, `signing-keys.md`, `troubleshooting.md`.
- **Release Records (`docs/release/`):** `RC001-release-checklist.md`, `RC002-release-checklist.md`, `RC002-release-report.md`.
- **Source Code Comments & Error Types:** Across all 9 workspace crates (`relay-domain`, `relay-canonical`, `relay-policy`, `relay-credentials`, `relay-receipts`, `relay-connectors`, `relay-ledger`, `relay-mcp`, `relay-cli`).

---

## 3. Claim Classification Taxonomy

Every audited claim is classified into one of six categories:

1. **Accurate (`ACCURATE`):** The claim matches the exact behavior enforced by the code and verified by passing automated tests.
2. **Outdated (`OUTDATED`):** The claim accurately described an earlier milestone or design iteration but has been superseded by concrete implementation details.
3. **Ambiguous (`AMBIGUOUS`):** The claim is technically plausible but underspecified, leaving room for misinterpretation of boundaries or trust assumptions.
4. **Overstated (`OVERSTATED`):** The claim uses absolute language ("tamper-proof", "guarantees external mutation", "unhackable") that exceeds what local cryptography or OS boundaries can defend.
5. **Contradicted by Implementation (`CONTRADICTED`):** The claim asserts functionality that directly conflicts with the codebase logic.
6. **Missing (`MISSING`):** Critical operational limitations, threat boundaries, or failure modes that are implemented but unmentioned in public docs.

---

## 4. Comprehensive Claims Audit & Reconciliation Matrix

| Area / Term | Audited Claim / Phrase | Source Location | Classification | Detailed Audit & Remediation |
|:---|:---|:---|:---:|:---|
| **Zero Ambient Credentials** | "Agent processes operate with zero ambient credentials in environment or memory" | `A001`, `A004`, `README.md` | `ACCURATE` | Verified by `sanitized_child_env()` and `test_rc001_subprocess_env_sanitization_strips_secrets`. The child environment is completely cleared (`env_clear()`) with an explicit whitelist of non-secret system variables (`PATH`, `HOME`, etc.). Target API tokens never enter the child process. |
| **Tamper-Proof vs Tamper-Evident** | "Tamper-proof SQLite audit ledger" | Early research `R011`, `A006` draft | `OVERSTATED` | **Corrected to "Tamper-Evident".** No software running on a host OS can prevent a root user or malicious kernel from modifying raw disk bytes. What Relay guarantees is that any modification, deletion, or truncation is mathematically detectable upon verification (`LedgerVerifier`, `SI-009`). |
| **External MCP Mediation** | "Intercepts all MCP tool execution" | `README.md` | `AMBIGUOUS` | **Clarified boundary.** Relay MVP mediates all tools executed through its native connectors (Filesystem, PostgreSQL, GitHub) and stdio tool call frames. Third-party MCP servers that initiate outbound network calls independently require the future loopback HTTP egress proxy. Documented in `docs/security/mcp-boundary.md`. |
| **External State Guarantees** | "Receipt proves database / GitHub update occurred" | `B007` draft notes | `OVERSTATED` | **Reconciled in `docs/security/evidence-model.md`.** A receipt proves Relay observed an HTTP `200` or PostgreSQL `CommandComplete` from the target connector; it does not prove downstream asynchronous replication, lack of external rollback, or eventual consistency state on remote clouds. |
| **Ambiguous Mutations** | "Relay guarantees atomicity on network timeouts" | `A004` notes | `CONTRADICTED` | **Corrected in `B012`, `docs/security/evidence-model.md`.** Relay does *not* manufacture success or simulate rollback on network timeout. Instead, it classifies network drops after request dispatch as `AmbiguousMutation` with status `Undetermined`, preserving evidence and preventing unsafe retry loops. |
| **Cryptographic Receipts** | "Ed25519 DSSE envelopes wrapping in-toto v1.0 statements" | `B007`, `relay-receipts` | `ACCURATE` | Strictly conforms to RFC 9598 DSSE and in-toto Statement v1.0 with canonical RFC 8785 JCS payload canonicalization and SHA-256 digests. Verified in `crypto_tests.rs` and `serialization_tests.rs`. |
| **Hardware-Backed Secrets** | "Keyring provider secures secrets in hardware" | `B005` discussion | `AMBIGUOUS` | **Clarified.** The OS Keyring provider interfaces with Apple Keychain, Windows Credential Manager, or Linux Secret Service / DBus. Where the OS supports Secure Enclave / TPM, secrets benefit from it; fallback encrypted file storage (`EncryptedFileProvider`) is software-based (AES-256-GCM / PBKDF2). Documented in `docs/security/credential-model.md`. |
| **Prompt Injection Protection** | "Protects against prompt injection" | Marketing copy | `AMBIGUOUS` | **Clarified in `docs/security/prompt-injection.md`.** Relay does *not* filter prompts or claim to prevent an LLM from becoming confused. Rather, Relay enforces a hard security boundary *assuming the agent is 100% prompt-injected*. Even a fully malicious agent cannot exceed Cedar policy permissions or steal ambient credentials. |
| **Deterministic Exit Codes** | "CLI exits with standard Unix codes 0–9" | `A007`, `RC001` | `ACCURATE` | Enforced by `ExitCode` enum and mapped across `CliError`. Verified by `test_rc001_exit_code_mappings`. |
| **Ledger Migration Immutability** | "Ledger schema migrations cannot rewrite entries" | `A006`, `B008` | `ACCURATE` | Enforced by SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers (`prevent_ledger_update`, `prevent_receipts_update`) and append-only table structure. |
| **Host Compromise Scope** | "Protects data on compromised host" | Generic security notes | `OVERSTATED` | **Explicitly Out of Scope.** If the host OS kernel or the user identity running Relay is compromised, the attacker can read memory or modify binary execution. Documented in `docs/security/limitations.md`. |

---

## 5. Summary of Remediation Actions Taken in RC003

1. **Eliminated Imprecise Marketing Jargon:** Replaced "tamper-proof", "unhackable", and "military-grade" with precise architectural terms: "tamper-evident", "cryptographically verifiable", "least-privilege JIT broker", and "deterministic Cedar PEP".
2. **Authored Authoritative Security Suite:**
   - `docs/security/README.md` (Central security index)
   - `docs/security/threat-model.md` (Structured threat model with concrete assets, adversaries, and controls)
   - `docs/security/security-invariants.md` (Authoritative mapping of SI-001 through SI-018)
   - `docs/security/evidence-model.md` (Epistemology of receipts: asserted vs observed vs unproven)
   - `docs/security/credential-model.md` (Keyring vs fallback encryption, lease lifecycles)
   - `docs/security/policy-model.md` (Cedar schema, default-deny, policy-set digests)
   - `docs/security/connectors.md` (Native FS, Postgres, GitHub execution boundaries)
   - `docs/security/mcp-boundary.md` (Current stdio/native mediation vs future loopback HTTP egress)
   - `docs/security/prompt-injection.md` (Formal model under complete agent compromise)
   - `docs/security/security-claims.md` (Traceable claims matrix mapped to test code)
   - `docs/security/limitations.md` ("What Relay Does Not Do")
   - `docs/security/secure-deployment.md` (Production deployment hardening guide)
   - `SECURITY.md` (Vulnerability disclosure and responsible reporting policy)
3. **Re-grounded Public README:** Rewrote the root `README.md` to directly answer what Relay is, how it works, what it protects, what it does not protect, how to install it, and where security specifications reside.
