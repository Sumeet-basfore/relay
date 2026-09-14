# Architecture Decision Record: M001 — External MCP Egress & HTTP Mediation Research Gate

**Document ID:** `ADR-M001-001`  
**Milestone:** `M001`  
**Date:** 2026-09-14  
**Author:** Principal Security Architect & Lead Protocol Engineer  
**Status:** Approved Architectural Decision  

---

## 1. Context & Motivation

Relay MVP (B001–B013, RC001–RC003) successfully governs native in-process tool executions for Filesystem, PostgreSQL, and GitHub.

The primary architectural gap addressed in milestone M001 is:
> Third-party MCP servers executed as child subprocesses may establish outbound HTTP/HTTPS network connections to external services. Without mediation, these subprocesses either require ambient credentials or execute outside Relay's policy boundary.

---

## 2. Research Summary & Options Evaluated

Six architectural alternatives were researched against the 2026 Model Context Protocol specification:
1. **Option A: Cooperative Environment Proxy (`HTTP_PROXY` / `HTTPS_PROXY`):** Non-root, cross-platform, but bypassable via direct raw sockets.
2. **Option B: Explicit Local Forward Proxy:** Tool-specific configuration, transparent inspection, same raw socket bypass.
3. **Option C: Transparent Network Interception (eBPF / `nftables`):** Hard containment, but requires root (`CAP_NET_ADMIN`) privileges.
4. **Option D: OS Sandbox + Loopback Proxy (Linux User & Network Namespaces):** Non-root unprivileged hard containment on Linux; prevents 100% of raw sockets.
5. **Option E: Containerized Sidecar Model:** Heavyweight external dependency (Docker/Podman).
6. **Option F: Dynamic Linker Interception (`LD_PRELOAD`):** Defeated by static binaries and macOS SIP.

---

## 3. Formal Architectural Decision

**Decision:** **`DECISION B — IMPLEMENT WITH CONDITIONS`**

### Rationale:
Relay will implement a **Tiered External MCP Mediation Architecture**:
1. **Core Ephemeral Forward Proxy (G1 Credential Isolation):** Spawns an in-process HTTP forward proxy on `127.0.0.1:<ephemeral_port>`. Subprocesses receive single-use, time-bounded lease tokens. Real target credentials remain vaulted inside Relay and are injected dynamically into upstream HTTPS requests.
2. **Linux Enforced Sandbox Mode (G2 Destination Allowlisting):** On Linux, child subprocesses are isolated within unprivileged User and Network Namespaces (`CLONE_NEWUSER | CLONE_NEWNET`), completely eliminating raw socket bypass.
3. **Managed Cooperative Mode (macOS / Windows):** On macOS and Windows, Relay injects standard proxy environment variables and enforces destination allowlisting for all compliant HTTP/HTTPS clients, with explicit documentation of the un-sandboxed raw socket boundary.
4. **Ephemeral Session Correlation (G3 Action Binding):** Correlates outbound traffic to active tool calls via time-bounded lease tokens (TTL: 30s) burned upon tool call completion.

---

## 4. Final Decision Specification

```text
================================================================================
M001 EXTERNAL MCP MEDIATION — FINAL DECISION
================================================================================

MCP Protocol Baseline:
Model Context Protocol Specification Revision 2026-07-28 (Streamable HTTP, Stdio, Mcp-Method, Mcp-Name header-based routing)

Security Goal:
Prevent third-party MCP subprocesses from observing target API credentials, enforce deterministic AWS Cedar destination allowlisting, and correlate outbound network activity with authorized tool actions.

Architecture Evaluated:
- Option A: Cooperative Environment Proxy (HTTP_PROXY / HTTPS_PROXY)
- Option B: Explicit Local Forward Proxy (127.0.0.1:<port>)
- Option C: Transparent Network Interception (nftables / eBPF / WFP)
- Option D: OS Sandbox + Loopback Proxy (Linux unprivileged user & network namespaces)
- Option E: Containerized Sidecar Model (Docker / Podman)
- Option F: Dynamic Linker Interception (LD_PRELOAD / DYLD_INSERT_LIBRARIES)

Research:
PASS

Threat Model:
PASS

Prototype:
PASS

Bypass Findings:
- Cooperative application proxying (HTTP_PROXY) can be bypassed by an adversarial binary calling raw socket syscalls (socket(AF_INET, SOCK_STREAM)) on macOS and Windows without kernel drivers.
- Complete unprivileged raw-socket prevention is achievable on Linux using unprivileged User & Network Namespaces (CLONE_NEWUSER | CLONE_NEWNET).
- Action-to-network packet binding cannot be 1:1 cryptographically proven for generic HTTP clients with connection pooling; defensible correlation requires ephemeral time-bounded proxy lease tokens.
- Cloud metadata service access (169.254.169.254 / IMDSv2) and private RFC 1918 subnets require pre-DNS IP blocking.

Credential Mediation:
FULLY ENFORCED across all platforms. Real target credentials never enter the subprocess environment or memory; Relay injects vaulted secrets just-in-time into upstream HTTPS headers upon validating ephemeral proxy lease tokens.

Destination Mediation:
HARD ENFORCED on Linux (via netns isolation); MANAGED COOPERATIVE on macOS and Windows (via proxy env vars and Cedar endpoint evaluation).

Action Binding:
ENFORCED via Ephemeral Time-Bounded Proxy Sessions. Lease tokens are active exclusively during the authorized tool call execution window (30s TTL) and burned on completion.

Platform Support:
- Linux: Full Enforced Sandbox Mode (Zero Raw Sockets)
- macOS: Managed Cooperative Proxy Mode
- Windows: Managed Cooperative Proxy Mode

Decision:
IMPLEMENT WITH CONDITIONS

Security Boundary:
Relay mediates external MCP subprocess network egress via an in-process loopback HTTP forward proxy with dynamic JIT credential injection and AWS Cedar destination allowlisting. On Linux, raw socket bypass is completely eliminated via unprivileged Network Namespaces; on macOS and Windows, mediation operates in Managed Cooperative Mode for standard HTTP/HTTPS clients with documented residual risks for raw sockets.

Known Limitations:
- Raw socket evasion is possible on macOS and Windows if an untrusted MCP binary bypasses HTTP_PROXY.
- Long-running background Tasks require explicit asynchronous lease management.
- Direct out-of-band external network connections made by other processes outside Relay are not mediated.

Blocking Issues:
None. Research gate is complete; architecture specifications and threat models are validated.

Recommended Next Milestone:
M002 — In-Process Loopback HTTP Egress Proxy & Linux Network Namespace Sandbox Implementation
================================================================================
```
