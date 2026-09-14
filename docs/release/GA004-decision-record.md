# GA004 Architecture & Release Decision Record: Final Ship Gate & v0.1.0 Certification

* **Status:** APPROVED
* **Date:** 2026-09-14
* **Deciders:** Principal Security Architect, Lead Systems Engineer, Release Gatekeeper
* **Subject:** Final Technical Ship Gate for Relay v0.1.0 General Availability

---

## Context & Decision Drivers

Relay has completed all engineering milestones (B001–B013), release hardening cycles (RC001–RC003), external MCP egress proxy and sandboxing integrations (M001–M003), release engineering (GA001), independent security audit (GA002), and golden reference deployment (GA003).

Milestone GA004 serves as the final technical ship gate to certify the exact release artifact (`dist/relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`) for public distribution.

---

## Certification Analysis

1. **Exact Artifact Integrity:** The release package `dist/relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz` and binary were verified bit-for-bit with SHA-256 digests recorded in `dist/SHA256SUMS` and `release/v0.1.0/RELEASE-MANIFEST.md`.
2. **Security Invariant Registry:** Reconciled all 24 security invariants (SI-001 through SI-024) into `docs/release/GA004-invariant-registry.md`, confirming 100% enforcement.
3. **Zero Absolute Ship Blockers:** All 11 absolute ship blockers evaluated to clear pass.
4. **Automated Test Matrix:** 380 passed tests across all 9 crates, with clean formatting and clippy (`-D warnings`).
5. **Freeze Guarantee:** Source tree, release manifests, security claims, and known limitations are completely frozen.

---

GA004 FINAL SHIP GATE — v0.1.0

Source Freeze:
FROZEN

Final Commit:
0360a95f74c33a9fc3d7628876dd9bb7d307e2bb

Artifact Certification:
PASS

Supply Chain:
PASS

Installation:
PASS

Upgrade / Recovery:
PASS

Native Execution:
PASS

External MCP:
PASS

Credential Isolation:
PASS

Authorization:
PASS

Linux Security Boundary:
PASS

Cross-Platform Qualification:
PASS

Evidence:
PASS

Ledger:
PASS

Documentation:
PASS

Independent Security Status:
PASS

Release Decision:
SHIP

Final Version:
v0.1.0

Final Artifact SHA-256:
6f843ab71592ee55cc9c3b9c556af23e58b1fe8b192404c28ee753912f9de206

Blocking Issues:
- None

Accepted Risks:
- Host OS root/kernel compromise is outside the software security boundary (mitigated via unprivileged service accounts).
- macOS and Windows operate in Managed Cooperative Proxy Mode (mitigated via container/VM sandboxes for untrusted third-party servers).
- Remote cloud provider eventual consistency on network drop cannot be proven locally (mitigated via explicit AmbiguousMutation epistemology).
- Direct in-library Rust connector usage outside the CLI requires embedding GovernedActionRunner (mitigated by binary-enforced CLI architecture).

Known Limitations:
- Single-host local-first deployment scope (no multi-node consensus in v0.1.0).
- External MCP proxy mediation supports HTTP/HTTPS protocols (arbitrary binary TCP tunneling requires NetNS isolation on Linux).

Security Boundary:
Under complete prompt-injection compromise of the agent, the agent cannot obtain ambient credentials, bypass Cedar authorization, escape network sandbox boundaries, or mutate state without generating tamper-evident cryptographic evidence.

Tests:
380 passed / 0 failed

Next Milestone:
GA005 — v0.1.0 Public Launch & Maintenance Handoff
