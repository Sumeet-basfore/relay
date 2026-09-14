# Release Report: Relay RC003 — Security Documentation, Threat Model & Public Release Readiness

**Document ID:** `REL-REP-003`  
**Milestone:** `RC003`  
**Version:** `0.1.0-RC003`  
**Date:** 2026-09-14  
**Author:** Principal Security Architect & Release Auditor  
**Evaluation Verdict:** `PASS` (Documentation) / `PASS` (Threat Model) / `PASS` (Security Claims) / `READY` (Public Release)  

---

## 1. Executive Summary

Milestone RC003 establishes the complete, authoritative, and verified security documentation package for Relay MVP.

RC003 ensures that any independent security engineer, enterprise auditor, or prospective user can accurately understand Relay's exact trust boundaries, threat model, security invariants, credential isolation mechanics, evidence semantics, and operational limitations without requiring tribal knowledge from the implementation team.

---

## 2. Completed Phase Deliverables

1. **Phase 1 — Documentation & Claim Audit (`docs/engineering/RC003-documentation-audit.md`):** Complete repository scan and claim classification against running code.
2. **Phase 2 — Security Boundary Canonicalization (`docs/security/README.md`):** Established unified, authoritative boundary dividing Trusted, Untrusted, and Out-of-Scope components.
3. **Phase 3 — Threat Model (`docs/security/threat-model.md`):** Structured threat model mapping 8 system assets and 9 adversary profiles to concrete controls and residual risks.
4. **Phase 4 — Security Invariants (`docs/security/security-invariants.md`):** Authoritative specification and test traceability for invariants SI-001 through SI-018.
5. **Phase 5 — Trust-Boundary Diagram (`docs/security/README.md`):** Architectural visualization of the enforcement pipeline from untrusted agent to target execution.
6. **Phase 6 — Evidence & Receipt Model (`docs/security/evidence-model.md`):** Strict epistemological separation of asserted vs. observed vs. unproven facts and ambiguous mutation semantics.
7. **Phase 7 — Credential Security Model (`docs/security/credential-model.md`):** JIT lease lifecycle, memory zeroization (`mlock`/`zeroize`), and provider distinction (OS Keyring vs Encrypted File).
8. **Phase 8 — Policy Security Model (`docs/security/policy-model.md`):** AWS Cedar v4.0 entity schema, strict default-deny, deterministic policy digests (SI-010).
9. **Phase 9 — Native Connector Security (`docs/security/connectors.md`):** In-process execution boundaries for Filesystem (root jail), PostgreSQL (SQL AST), and GitHub (API bounds).
10. **Phase 10 — MCP Mediation Boundary (`docs/security/mcp-boundary.md`):** Current stdio/native mediation scope vs. future loopback HTTP egress roadmap.
11. **Phase 11 — Prompt Injection Model (`docs/security/prompt-injection.md`):** Action-boundary enforcement under 100% agent subversion.
12. **Phase 12 — Security Claims Matrix (`docs/security/security-claims.md`):** 13 verified public claims mapped directly to unit/integration test evidence.
13. **Phase 13 — What Relay Does Not Do (`docs/security/limitations.md`):** Explicit documentation of non-goals and out-of-scope boundaries.
14. **Phase 14 — Secure Deployment Guide (`docs/security/secure-deployment.md`):** Hardened operational configuration and Unix permissions (`0600`/`0700`).
15. **Phase 15–18 — Public README & Vulnerability Disclosure (`README.md`, `SECURITY.md`, `v0.1.0-release-notes.md`):** Production-ready public interface and disclosure protocol.
16. **Phase 19–22 — Security Checklist & Review Package (`docs/release/RC003-security-review-checklist.md`):** 100% passing audit gates.
17. **Phase 23 — Full Regression Verification:** All 315 tests passing across the 9 workspace crates.

---

## 3. Authoritative Final Verdict

```text
================================================================================
RC003 SECURITY & PUBLIC RELEASE READINESS — FINAL VERDICT
================================================================================

Documentation:
PASS

Threat Model:
PASS

Security Claims:
PASS

Public Release Readiness:
READY

Security Boundary:
Relay is a local-first zero-trust execution boundary interposed between an untrusted AI agent process and Model Context Protocol (MCP) tools. Relay enforces deterministic AWS Cedar authorization, prevents target API credentials from entering agent memory or subprocess environments, and generates cryptographically signed RFC 9598 DSSE / in-toto Action Receipts recorded into an append-only SQLite hash-chain ledger.

Major Claims Validated:
- Zero ambient target credentials in agent environment and context (SI-001)
- Deterministic Cedar policy evaluation with default-deny and sub-2ms latency (SI-002, SI-003)
- Cryptographic human approval binding to ActionHash on /dev/tty (SI-004)
- RFC 8785 JCS payload canonicalization and SQL AST normalization (SI-005, SI-013)
- Single-action, ephemeral JIT credential leasing with automatic zeroization (SI-006, SI-017)
- Ed25519 DSSE + in-toto v1.0 Action Receipts with secret scrubbing (SI-007, SI-009)
- Append-only SQLite hash-chain ledger with offline forensic verifier (SI-009)
- Explicit classification of ambiguous mutations on network timeouts (SI-015)
- Deterministic Unix CLI exit codes 0 through 9 across all error classes (SI-014)

Claims Removed or Corrected:
- Corrected "tamper-proof ledger" to "tamper-evident ledger" (SI-009)
- Clarified that receipts prove Relay's observation, not permanent remote cloud state
- Clarified that third-party MCP subprocess HTTP egress proxy is deferred to a future milestone
- Removed marketing claims ("unhackable", "military-grade") in favor of precise threat boundaries

Known Limitations:
- Does not defend against host OS kernel or root-level compromise
- Does not replace database-native access controls (GRANT/REVOKE, RLS) or GitHub branch protections
- Does not mediate arbitrary outbound network sockets opened by third-party external MCP binaries
- Master key security for EncryptedFileProvider depends on host environment variables in headless CI

Open Security Risks:
- None within the documented MVP trust boundary.

Blocking Issues:
- None. All release gates and security checklists are satisfied.

Tests:
315 passed / 0 failed (100% pass across 9 workspace crates)

Recommended Next Milestone:
M001 — Loopback HTTP Egress Proxy & External Third-Party MCP Network Mediation
================================================================================
```
