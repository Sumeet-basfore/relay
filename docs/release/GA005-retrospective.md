# GA005 — Engineering & Release Retrospective: Relay v0.1.0

**Project:** Relay — Local-First Zero-Trust MCP Security Gateway & Credential Broker  
**Release:** `v0.1.0` (GA)  
**Date:** September 2026  

---

## 1. What Was Built & Validated

Relay was engineered across 23 rigorous milestone cycles:
1. **Foundation & Core Architecture (B001–B004):** Bounded MCP framing, deterministic RFC 8785 JSON canonicalization, and AWS Cedar policy integration.
2. **Credential Brokerage & Governed Connectors (B005–B010):** Single-action JIT credential leasing, memory zeroization, native Filesystem root containment, PostgreSQL AST validation, and GitHub API mediation.
3. **Approvals, Evidence & Ledgers (B011–B013):** `/dev/tty` out-of-band interactive human step-up gating, RFC 9598 DSSE Action Receipts, and append-only SQLite hash-chain ledgers with write-once immutability triggers.
4. **Release Hardening & Packaging (RC001–RC003):** Strict permission hardening (0600/0700), binary hardening (PIE, stack canaries, full RELRO, NX stack), and reproducible release pipelines.
5. **External MCP Egress Mediation (M001–M003):** In-process loopback forward proxy, Linux Network Namespace isolation (`CLONE_NEWNET`), anti-SSRF filters (SI-022), and action-bound session tokens.
6. **General Availability & Independent Certification (GA001–GA005):** Independent threat modeling, complete mediation mapping, 7-scene Golden Demo, authoritative invariant registry, and public launch handoff.

---

## 2. Key Architecture Insights & Validated Hypotheses

1. **Deterministic Cedar PEP vs. LLM Self-Policing:** Relying on declarative, formal logic policies (Cedar) rather than LLM prompts completely neutralizes indirect prompt injection attacks against tools.
2. **Ambient Credential Elimination:** By holding target credentials exclusively inside Relay's transient zeroized broker and injecting them just-in-time, agent compromise yields zero persistent credentials.
3. **Linux Network Namespaces for MCP:** Unprivileged `CLONE_NEWNET` namespaces provide clean, lightweight, kernel-enforced network isolation for external tool subprocesses without requiring Docker or heavyweight VMs.
4. **Cryptographic Attestations (DSSE + SQLite):** Combining in-toto statement generation with local hash-chain storage enables instant mathematical tamper-detection without requiring remote blockchain networks.

---

## 3. Key Lessons Learned & v0.2 Priorities

* **Cross-Platform Sandboxing:** While Linux provides native network namespaces, macOS and Windows operate in cooperative proxy mode. Future v0.2 work will explore macOS Network Extension and Windows AppContainer sandboxes.
* **Asynchronous Execution:** v0.1.0 focuses on synchronous request-response MCP tool execution; long-running background tasks will be designed in v0.2.
