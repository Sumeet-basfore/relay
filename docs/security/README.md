# Relay Security Documentation Package

**Status:** Authoritative Security Architecture Specification  
**Version:** `0.1.0` (Relay MVP)  
**Baseline:** B001–B013, RC001–RC003  

---

## 1. Overview

Relay is a **local-first, zero-trust MCP Security Gateway and Credential Broker** delivered as a lightweight Rust binary.

Relay intercepts Model Context Protocol (MCP) tool executions, deterministically authorizes actions using AWS Cedar policies, injects vaulted credentials just-in-time into isolated execution contexts, and produces cryptographically signed in-toto/DSSE evidence recorded in an append-only SQLite hash-chain ledger.

### Core Architectural Axiom:
$$\text{Security Boundary} = \text{Authority (Cedar PEP)} + \text{Credential Isolation (JIT Broker)} + \text{Evidence (DSSE/Ledger)}$$

---

## 2. Navigation Index

This security documentation suite is organized for independent security engineers, auditors, and systems architects:

| Document | Description | Key Topics |
|:---|:---|:---|
| **[Threat Model](threat-model.md)** | Comprehensive threat model and adversary analysis | Assets, adversaries, attack vectors, controls, and residual risks |
| **[Security Invariants](security-invariants.md)** | Formal security contract (SI-001 through SI-018) | Non-negotiable behavioral guarantees, enforcement points, and test mappings |
| **[Evidence & Receipt Model](evidence-model.md)** | Epistemology and semantics of Action Receipts | Asserted vs. observed facts, RFC 9598 DSSE, in-toto v1.0, ambiguous mutations |
| **[Credential Security Model](credential-model.md)** | Secrets management and ambient credential elimination | JIT leasing, OS Keyring integration, memory zeroization, fallback encryption |
| **[Policy Security Model](policy-model.md)** | Deterministic authorization with AWS Cedar | Entity schema, default-deny, policy-set digests (SI-010), step-up approvals |
| **[Native Connector Boundaries](connectors.md)** | Execution boundaries for native connectors | Filesystem root jail, PostgreSQL AST canonicalization, GitHub API boundaries |
| **[MCP Mediation Boundary](mcp-boundary.md)** | Scope of MCP protocol mediation | Stdio framing, native connector routing, external MCP egress roadmap |
| **[Prompt Injection Model](prompt-injection.md)** | Security posture under full agent compromise | Hard boundary assumptions, prompt neutrality, deterministic enforcement |
| **[Security Claims Matrix](security-claims.md)** | Verification matrix mapping claims to tests | Claim -> Implementation -> Automated Test -> Residual Limitation |
| **[What Relay Does Not Do](limitations.md)** | Explicit out-of-scope boundaries and non-goals | Host compromise, kernel security, remote state guarantees, physical attacks |
| **[Secure Deployment Guide](secure-deployment.md)** | Production deployment and hardening guidance | Permissions, non-interactive mode, key rotation, backup security |
| **[Security Disclosure Policy](../../SECURITY.md)** | Vulnerability reporting and disclosure | Scope, report process, responsible disclosure protocols |

---

## 3. Canonical Security Boundary

Relay establishes an explicit division of trust on the host system:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                   UNTRUSTED                                      │
│  - AI Agent (LLM, prompt context, tool argument selection, inference loops)      │
│  - MCP Client & Stdio Framing                                                    │
│  - External Network Content & Retrieved Context                                  │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ stdio (JSON-RPC)
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                RELAY TRUST BOUNDARY                              │
│  - Strict JSON Parser & Canonicalizer (RFC 8785 JCS, SQL AST, FS Path Jail)      │
│  - Deterministic Policy Engine (AWS Cedar PEP, Default-Deny, Policy Digest)      │
│  - Interactive Approval Gate (/dev/tty Direct Prompt, Nonce-Bound)               │
│  - JIT Credential Broker (OS Keyring, Ephemeral Memory Lease, Auto-Zeroize)      │
│  - Native Connectors (In-Process FS, PostgreSQL, GitHub)                         │
│  - Evidence Engine (Ed25519 DSSE RFC 9598 + in-toto v1.0, Append-Only Ledger)   │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ Controlled In-Process Execution
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                 TARGET SYSTEMS                                   │
│  - Local Filesystem (Restricted to Root Jail)                                    │
│  - PostgreSQL Database (Authenticated via JIT Credential)                        │
│  - GitHub API (TLS-Encrypted, Authenticated via JIT PAT)                         │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Trusted:
1. Host OS kernel process isolation and memory protection.
2. Relay binary integrity and execution permissions.
3. Cryptographic primitives (Ed25519, SHA-256, AES-256-GCM).
4. Configured Cedar policies and node signing key custody.
5. Human operator on the direct terminal (`/dev/tty`).

### Untrusted:
1. Agent prompts, instructions, context window, and generated arguments.
2. Third-party MCP client and tool implementations.
3. Network input returned from remote endpoints.

### Out of Scope:
1. Root-level or kernel-level host compromise.
2. Direct physical memory acquisition attacks (Cold boot, DMA).
3. Out-of-band modifications to external databases or GitHub directly bypassing Relay.
