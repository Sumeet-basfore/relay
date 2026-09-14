# Architecture Decision Record: M003 — External MCP Adversarial Validation & Governed Lifecycle Integration

**Document ID:** `ADR-M003-001`  
**Milestone:** `M003`  
**Date:** 2026-09-14  
**Author:** Principal Security Architect & Lead Protocol Engineer  
**Status:** Approved Architectural Decision & Adversarial Validation Record  

---

## 1. Context & Motivation

Following the implementation of the in-process loopback HTTP egress proxy and Linux network namespace sandbox in Milestone M002, Milestone **M003** was commissioned as an adversarial integration gate.

The primary objective of M003 was to prove that the assembled external-MCP and native connector execution paths preserve Relay's formal security invariants under hostile conditions, including full prompt-injection compromise of the agent and an adversarial MCP subprocess.

---

## 2. Integrated Security Architecture

The validated Relay execution architecture maintains complete policy enforcement, credential isolation, and cryptographic auditability across the entire lifecycle:

```text
Untrusted Agent
      ↓
Relay MCP Gateway (Strict JSON Framing & Duplicate Key Check)
      ↓
Action Canonicalization (JCS / RFC 8785 → ActionHash)
      ↓
Cedar Authorization (Deterministic Policy Engine PEP)
      ↓
Approval Provider (/dev/tty Step-Up Approval if required)
      ↓
Ephemeral Proxy Session (30s TTL, ActionHash-bound, Single-Use Burning)
      ↓
External MCP Process (Sanitized Environment, Zero Ambient Secrets)
      ↓
Linux Sandbox / Cooperative Proxy (CLONE_NEWUSER | CLONE_NEWNET)
      ↓
Relay Egress Proxy (Loopback-only, Pre-DNS Blacklist, IP Pinning)
      ↓
Destination Authorization (Cedar NetworkEndpoint Allowlisting)
      ↓
JIT Credential Injection (Vaulted Secrets injected upstream)
      ↓
Remote Target (External API / Database / Service)
      ↓
Action Receipt (Ed25519 DSSE / in-toto Envelope with Secret Scrubbing)
      ↓
SQLite Ledger (Append-Only Merkle Hash-Chain)
```

---

## 3. Invariant Verification & Adversarial Audit Summary

- **Credential Isolation:** Proved target API keys are physically absent from child process memory and environment. Subprocesses only observe ephemeral lease tokens (`RELAY_PROXY_AUTH`).
- **Session Lifecycle:** Proved token forgery, replay, cross-action reuse, and post-completion reuse fail closed with HTTP 407 / `EphemeralProxySessionInvalid`.
- **Destination Allowlisting:** Proved SSRF metadata attacks (`169.254.169.254`, `metadata.google.internal`), private RFC 1918 subnets, and DNS rebinding attacks are defeated via pre-DNS filtering and socket IP pinning.
- **Linux Network Sandbox:** Proved unprivileged User & Network Namespaces (`CLONE_NEWUSER | CLONE_NEWNET`) block 100% of raw outbound sockets (`ENETUNREACH`) across the entire descendant process tree (`MCP -> child -> grandchild`).
- **Evidence & Ledger Integrity:** Proved ambiguous mutations, execution failures, and policy denials produce unambiguous receipts and immutable ledger entries with zero secret leakage.

---

## 4. Final Verdict Record

```text
M003 EXTERNAL MCP ADVERSARIAL VALIDATION — FINAL VERDICT

Integration:
PASS

Credential Isolation:
PASS

Proxy Session Security:
PASS

Destination Security:
PASS

Linux Sandbox:
PASS

Evidence Integrity:
PASS

Concurrency:
PASS

Adversarial Security:
PASS

Release Readiness:
READY

Strongest Attacker Capability:
Within the documented Linux trust boundary, an adversarial MCP subprocess with arbitrary native code execution cannot observe target API credentials, cannot open direct raw network sockets (ENETUNREACH), cannot connect to unapproved destinations or private/metadata endpoints, cannot extend authority past the synchronous tool execution window, and cannot forge or replay proxy lease tokens. On macOS and Windows, a malicious binary calling raw socket syscalls directly can bypass the cooperative environment proxy, but still cannot obtain vaulted upstream credentials.

Linux Security Boundary:
Complete kernel-enforced network mediation via unprivileged User & Network Namespaces (CLONE_NEWUSER | CLONE_NEWNET) combined with loopback-only HTTP/HTTPS forward proxy, pre-DNS blacklisting, socket IP pinning, and Cedar destination allowlisting.

macOS/Windows Residual Boundary:
Managed Cooperative Proxy Mode enforcing zero ambient credentials, Cedar destination authorization, and session lease lifetimes for standard HTTP/HTTPS library clients; raw-socket syscall bypass remains an explicitly documented platform boundary.

Confirmed Bypasses:
None within the documented trust boundary.

Expected Limitations:
- macOS/Windows raw socket syscall bypass without kernel network filters (Documented in docs/security/limitations.md).
- Long-running asynchronous MCP Tasks outliving the synchronous action lifecycle are unsupported and fail closed upon session lease burning.

BLOCKER Findings:
None.

HIGH Findings:
None.

Accepted Risks:
- Cooperative proxy mediation on macOS and Windows platforms where OS-level network namespace sandboxing is unavailable without root kernel extensions.

Tasks / Async Status:
Unsupported. Relay explicitly rejects indefinite background MCP Tasks that attempt network access after the synchronous tool call settles. Sessions are burned on tool completion, failing closed against delayed or asynchronous activity.

Tests:
341 passed / 0 failed (100% green across all 9 crates, including 15 M003 adversarial tests and 11 M002 egress security tests).

Recommended Next Milestone:
GA001 — General Availability Release & Production Distribution
```
