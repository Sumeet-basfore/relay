# Security Architecture Review: M001 — External MCP Egress & HTTP Mediation

**Document ID:** `SEC-REV-M001`  
**Date:** 2026-09-14  
**Evaluator:** Principal Security Architect  
**Status:** Approved Security Architecture Review  

---

## 1. Executive Summary

This security review evaluates the proposed external MCP HTTP egress mediation architecture developed during research milestone M001.

The objective of this review is to determine whether the proposed architecture satisfies Relay's core criteria:
1. Compatibility with the current 2026 MCP specification (Streamable HTTP, `Mcp-Method`, `Mcp-Name`).
2. Preservation of all formal Security Invariants (SI-001 through SI-018).
3. Clear, defensible delineation between hard OS-enforced sandboxing and cooperative application proxying.
4. JIT credential isolation without ambient subprocess secret exposure.
5. Deterministic authorization using AWS Cedar.
6. Operationally viable performance and failure semantics.

---

## 2. Invariant Compliance Audit

| Invariant | Requirement | M001 Architecture Compliance | Evaluation |
|:---|:---|:---|:---:|
| **SI-001** | Zero ambient target credentials in agent/subprocess context | Subprocess receives only ephemeral proxy lease token ($T_{\text{lease}}$); real target credentials remain inside Relay. | `PASS` |
| **SI-002** | Authorization precedes execution | Cedar evaluates destination and tool policy before proxy forwards upstream HTTP connection. | `PASS` |
| **SI-003** | Denied actions are never dispatched | Denied destinations return HTTP `403 Forbidden`; no upstream socket created. | `PASS` |
| **SI-006** | Single-action credential lease scope | Proxy lease token is time-bounded (30s TTL) and burned upon tool call completion. | `PASS` |
| **SI-007** | Target secrets do not leak into receipts | Secret scrubber inspects proxy receipts before DSSE signing. | `PASS` |
| **SI-008** | Target secrets masked in logs/traces | Headers scrubbed before debug tracing; credentials stored in `SecretBuffer`. | `PASS` |
| **SI-014** | All failures fail closed | Proxy unreachable or invalid lease immediately aborts connection (HTTP 407 / 502). | `PASS` |
| **SI-015** | Explicit uncertainty for ambiguous mutations | Timeout during upstream HTTP POST records `AmbiguousMutation` in ledger. | `PASS` |
| **SI-018** | Subprocesses receive zero ambient network tokens | Subprocess environment sanitized via `env_clear()` and whitelisting. | `PASS` |

---

## 3. Adversarial Analysis & Bypass Findings

1. **Direct Raw Socket Bypass:**
   - *Finding:* On macOS and Windows without kernel drivers, an adversarial binary calling `socket(AF_INET, SOCK_STREAM)` directly can bypass `HTTP_PROXY`.
   - *Resolution:* Relay implements **Enforced Sandbox Mode** via Linux User/Network Namespaces (`CLONE_NEWUSER | CLONE_NEWNET`), completely blocking raw socket egress on Linux, while explicitly documenting the cooperative boundary on macOS/Windows.
2. **Cloud Metadata Exfiltration (SSRF):**
   - *Finding:* Malicious MCP servers could attempt to steal cloud credentials via `169.254.169.254` or `fd00:ec2::254`.
   - *Resolution:* Relay proxy enforces pre-resolution IP blacklisting, blocking all link-local, private, and metadata IP addresses by default.
3. **Action-to-Network Correlation:**
   - *Finding:* Generic HTTP clients with connection pooling cannot be cryptographically bound 1:1 at the packet level to a single JSON-RPC frame.
   - *Resolution:* Relay adopts an **Ephemeral Time-Bounded Proxy Session Model** where lease tokens are active only during the authorized tool invocation window.

---

## 4. Overall Review Verdict

$$\text{Verdict: } \mathbf{APPROVED\ WITH\ CONDITIONS\ (DECISION\ B)}$$

The M001 architecture establishes a mathematically sound, defensible, and operationally viable design for external MCP HTTP mediation, paving the way for implementation in milestone M002.
