# Relay Secure Defaults Specification

**Document ID:** `SEC-DEF-001`  
**Version:** `0.1.0`  
**Date:** 2026-09-14  
**Status:** Frozen Default Configuration Baseline  

---

## 1. Executive Summary

Relay is designed on the principle of **Zero-Trust Secure Defaults**: every configuration setting, timeout, permission, network route, and execution policy defaults to the most restrictive, fail-closed state.

No security guarantee depends on the user remembering to configure an optional hardening flag.

---

## 2. Comprehensive Defaults Inventory

| Subsystem | Configuration Parameter | Default Value | Classification | Invariant & Security Rationale |
|:---|:---|:---:|:---:|:---|
| **Policy Engine** | Default Authorization Action | `DENY` | `Security-Critical` | `SI-002`, `SI-003`: Any unpermitted principal, tool, or action is strictly rejected. |
| **Approval Provider** | Non-Interactive / Headless Mode | `FAIL CLOSED` (`EXIT_APPROVAL_REQUIRED: 10`) | `Security-Critical` | `SI-004`, `SI-011`: Human approval cannot be bypassed by running in a non-TTY environment. |
| **Approval Provider** | Approval Timeout | `30 seconds` | `Safety-Oriented` | Prevents indefinite hangs while holding execution locks. |
| **Subprocess Environment** | Environment Sanitization | `env_clear()` + Whitelist | `Security-Critical` | `SI-001`, `SI-018`: Prevents ambient host secrets (e.g. `GITHUB_TOKEN`, `PGPASSWORD`) from entering child memory. |
| **Proxy Session** | Lease Token TTL | `30 seconds` | `Security-Critical` | `SI-006`, `SI-020`: Bounded single-action window; tokens are burned upon action completion. |
| **Proxy Session** | Token Entropy | `256-bit UUIDv7` | `Security-Critical` | `SI-020`: Cryptographically unguessable proxy lease identifiers. |
| **Egress Proxy** | Listener Binding Address | `127.0.0.1:<ephemeral>` | `Security-Critical` | `SI-019`: Never binds to external or non-loopback network interfaces. |
| **Egress Proxy** | TCP Backlog | `128` | `Performance / DoS` | Bounded connection queue preventing memory exhaustion. |
| **Egress DNS** | Pre-Resolution Blacklist | `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal` | `Security-Critical` | `SI-021`: Blocks SSRF cloud metadata credential exfiltration before DNS queries occur. |
| **Egress DNS** | IP Range Filtering | RFC 1918 Private, Loopback, Link-Local | `Security-Critical` | `SI-021`: Prevents internal intranet pivot attacks and SSRF. |
| **Egress DNS** | DNS Pinning | Pinned `SocketAddr` | `Security-Critical` | `SI-021`: Eliminates TOCTOU DNS rebinding between authorization and connection. |
| **Egress Headers** | Hop-by-Hop Stripping | Strips `Proxy-Authorization`, `Proxy-Connection`, etc. | `Security-Critical` | `SI-022`: Eliminates proxy header leakage and request smuggling. |
| **Egress Headers** | CRLF Injection Check | Rejected on `\r`, `\n`, `\0` | `Security-Critical` | `SI-022`: Rejects HTTP request/response splitting attempts. |
| **Linux Sandbox** | Namespace Isolation | `CLONE_NEWUSER \| CLONE_NEWNET` | `Security-Critical` | `SI-023`: Eliminates 100% of raw outbound sockets with `ENETUNREACH`. |
| **Linux Sandbox** | Failure Behavior | `ABORT EXECUTION` (`PermissionDenied`) | `Security-Critical` | `SI-024`: Never falls back to unconstrained subprocess execution. |
| **Filesystem Connector** | Working Directory Jail | Current Working Directory | `Security-Critical` | Path canonicalization and symlink verification prevent directory traversal (`..`). |
| **Filesystem Connector** | Max Read Size | `10 MB` | `Safety-Oriented` | Prevents OOM crashes from reading unbounded special files (e.g. `/dev/urandom`). |
| **Filesystem Connector** | Max Write Size | `10 MB` | `Safety-Oriented` | Prevents disk exhaustion attacks. |
| **PostgreSQL Connector** | Read-Only Enforcement | AST-level SQL validation | `Security-Critical` | Parses SQL statements with `sqlparser` and forbids DDL/DML in read contexts. |
| **Action Receipts** | Secret Scrubbing | Regex-based active pattern scrubber | `Security-Critical` | `SI-007`, `SI-008`: Rejects signing if target secrets appear in receipt payload. |
| **Action Receipts** | Signing Key Storage | Restrictive `0600` Permissions | `Security-Critical` | Key material zeroized on drop (`zeroize::Zeroize`). |
| **Audit Ledger** | Hash Chaining | SHA-256 Merkle link | `Security-Critical` | `SI-013`: Parent hash binding detects any retroactive ledger tampering. |
| **Audit Ledger** | Database Permissions | `0600` (User read/write only) | `Security-Critical` | Disallows multi-user tampering of SQLite audit database. |
| **MCP Gateway** | Max Frame Size | `1 MB` (`1,048,576 bytes`) | `Safety-Oriented` | Rejects oversized JSON-RPC frames to prevent DoS. |
| **MCP Gateway** | Startup Timeout | `5.0 seconds` | `Safety-Oriented` | Detects and terminates hung subprocess initializations. |
| **MCP Gateway** | Shutdown Grace Period | `500 ms` (SIGTERM → SIGKILL) | `Safety-Oriented` | Ensures deterministic child process termination without zombie processes. |

---

## 3. Defaults Classification Breakdown

```text
┌────────────────────────────────────────────────────────┐
│ Total Audited Default Parameters: 26                  │
├────────────────────────────────────────────────────────┤
│ 🔒 Security-Critical (Fail-Closed & Invariants):    19 │
│ 🛡️ Safety-Oriented (Resource & Hang Protection):     6 │
│ ⚡ Performance / DoS Mitigation:                      1 │
└────────────────────────────────────────────────────────┘
```

---

## 4. Certification

All default settings have been empirically verified through automated test suites and adversarial campaigns. No configuration options exist in Relay that permit a silent fail-open security state.
