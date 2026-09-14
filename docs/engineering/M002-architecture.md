# Milestone M002 — In-Process Loopback HTTP Egress Proxy & Linux Network Namespace Sandbox Architecture

**Document ID:** `ENG-M002-001`  
**Milestone:** `M002`  
**Status:** Completed & Fully Verified  
**Date:** 2026-09-14  
**Author:** Lead Systems & Protocol Security Engineer  

---

## 1. Executive Summary

Milestone `M002` implements the external MCP network egress mediation architecture approved in `M001`. Relay extends its zero-trust boundary from native in-process tool executions (Filesystem, PostgreSQL, GitHub) to arbitrary third-party MCP subprocesses.

The system delivers:
1. **In-Process Loopback HTTP Forward Proxy (`relay-mcp::egress_proxy`):** Binds ephemeral loopback addresses (`127.0.0.1:0`), terminates HTTP forward requests and HTTPS `CONNECT` tunnels, and evaluates Cedar policy destination allowlists.
2. **Ephemeral Proxy Session Engine (`relay-mcp::egress_session`):** Manages single-use and time-bounded proxy lease tokens (default 30s TTL) cryptographically bound to `ActionHash` and `Principal` (SI-020).
3. **Vaulted JIT Upstream Credential Injection (`relay-mcp::egress_injector`):** Injects target API credentials into upstream HTTPS request headers while ensuring child subprocesses only observe ephemeral proxy tokens and never hold ambient secrets (SI-021).
4. **Secure DNS Resolver & IP Pinning (`relay-mcp::egress_dns`):** Pre-evaluates hostnames and blocks cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`), loopback, and RFC 1918 private subnets prior to connection, pinning resolved IP addresses to prevent DNS rebinding attacks (SI-022).
5. **Linux Unprivileged Network Namespace Sandbox (`relay-mcp::egress_sandbox`):** Spawns child processes in isolated user and network namespaces (`CLONE_NEWUSER | CLONE_NEWNET`), eliminating 100% of raw socket egress paths at the kernel syscall boundary (SI-023).
6. **Managed Cooperative Mode (macOS / Windows):** Injects standardized proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `RELAY_PROXY_AUTH`, `NO_PROXY`) for compliant MCP servers, documenting raw socket residual risks.
7. **Fail-Closed Sandbox Invariant (SI-024):** If platform sandbox initialization fails, Relay immediately aborts execution and refuses to spawn unsandboxed child processes.

---

## 2. Architecture & Data Flow

```text
+-----------------------------------------------------------------------------------------+
|                                      RELAY PROCESS                                      |
|                                                                                         |
|  +-----------------------+     +-----------------------+     +-----------------------+  |
|  |   JIT Credential      |     |     Cedar Policy      |     |  Proxy Session Mgr    |  |
|  |     Vault / Broker    |     |      PDP Engine       |     |  (30s TTL, ActionHash)|  |
|  +-----------+-----------+     +-----------+-----------+     +-----------+-----------+  |
|              |                             |                             |              |
|              +----------------------+      |      +----------------------+              |
|                                     v      v      v                                     |
|                       +-----------------------------------+                             |
|                       |   In-Process Egress Proxy Server  |                             |
|                       |  (127.0.0.1:<port> / Unix Socket) |                             |
|                       +-----------------+-----------------+                             |
|                                         ^                                               |
+-----------------------------------------|-----------------------------------------------+
                                          | HTTP / CONNECT (Proxy-Auth: <lease_token>)
                                          | (Sanitized Env: HTTP_PROXY, HTTPS_PROXY)
+-----------------------------------------|-----------------------------------------------+
|  CHILD MCP SUBPROCESS                   |                                               |
|  (Linux NetNS Sandbox: CLONE_NEWNET)    |                                               |
|                                         |                                               |
|  [ MCP Server Binary ] -----------------+                                               |
|          |                                                                              |
|          X (Raw Socket: socket(AF_INET, SOCK_STREAM) -> ENETUNREACH / Blocked by Kernel)|
+-----------------------------------------------------------------------------------------+
```

---

## 3. Platform Breakdown

### 3.1. Linux (Full Enforced Sandbox Mode)
- **Mechanism:** `libc::unshare(CLONE_NEWUSER | CLONE_NEWNET)` during child process creation (`CommandExt::pre_exec`).
- **User Mapping:** Current UID/GID mapped to container UID 0 via `/proc/self/uid_map` and `/proc/self/gid_map`.
- **Egress Containment:** Inside the isolated network namespace, no default route or physical network interface exists. Any attempt to open a raw TCP/UDP socket to external IP addresses fails immediately with `ENETUNREACH`.
- **Mediation Path:** Subprocess communicates exclusively with Relay's loopback forward proxy.

### 3.2. macOS & Windows (Managed Cooperative Proxy Mode)
- **Mechanism:** Environment variable injection (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `RELAY_PROXY_AUTH`, `NO_PROXY`).
- **Target Compliance:** Supported by standard HTTP/HTTPS client libraries (`reqwest`, `curl`, `requests`, `urllib3`, `axios`, `fetch`).
- **Residual Risk:** An adversarial binary executing raw socket system calls (`socket()`, `connect()`) without consulting environment variables bypasses proxy mediation. This limitation is explicitly documented in `docs/security/limitations.md`.

---

## 4. Security Invariants Implemented

| ID | Title | Summary |
|:---|:---|:---|
| **SI-019** | External Destination Authorization | Outbound connections require prior Cedar policy permit on destination endpoint. |
| **SI-020** | Ephemeral Proxy Lease Binding | Leases are bound to `ActionHash`, `Principal`, and 30s TTL, burned on completion. |
| **SI-021** | Vaulted Credential Injection | Real credentials remain inside Relay and are injected upstream; child only holds lease token. |
| **SI-022** | Pre-DNS Blacklist & IP Pinning | Cloud metadata (`169.254.169.254`), RFC 1918 subnets, and loopback blocked before DNS/socket creation. |
| **SI-023** | Linux NetNS Raw Socket Containment | Linux user & network namespaces eliminate 100% of raw socket bypass attempts. |
| **SI-024** | Fail-Closed Sandbox Initialization | Failure to initialize the sandbox causes immediate execution abort. |

---

## 5. Verification & Test Results

Milestone M002 is verified by 11 targeted egress security tests in `crates/relay-mcp/tests/m002_egress_security_tests.rs`:
- Cloud metadata blocking (IPv4 IMDS, IPv6 AWS IMDS, Google internal metadata hostname)
- RFC 1918 and loopback IP blocking
- Ephemeral lease token creation, validation, expiration, and burning
- Hop-by-hop header stripping and sanitization
- Upstream credential injection without child leakage
- In-process HTTP forward proxy end-to-end request handling
- Unauthenticated proxy request rejection (HTTP 407)
- HTTPS `CONNECT` bidirectional tunneling
- Cedar policy destination allowlist and denial (HTTP 403)
- Platform sandbox mode detection
- Linux Network Namespace raw socket blocking (`ENETUNREACH`)

All 326 workspace tests pass cleanly with zero warnings under `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`.
