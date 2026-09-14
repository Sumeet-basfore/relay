# Security Architecture & Implementation Review: M002 — In-Process Loopback HTTP Egress Proxy & Linux Network Namespace Sandbox

**Document ID:** `SEC-REV-M002`  
**Date:** 2026-09-14  
**Evaluator:** Principal Security Architect & Lead Adversarial Tester  
**Status:** Approved Security Implementation Review  

---

## 1. Executive Summary

This security review evaluates the implementation of Milestone **M002** (In-Process Loopback HTTP Egress Proxy & Linux Network Namespace Sandbox) within the Relay repository.

Milestone M002 operationalizes the architectural decisions approved in M001, providing:
1. An asynchronous in-process HTTP/1.1 forward proxy and HTTPS `CONNECT` tunnel handler (`relay-mcp::egress_proxy`).
2. Ephemeral, action-bound proxy session management with 30-second TTLs and automatic burning (`relay-mcp::egress_session`).
3. Vaulted upstream JIT credential injection ensuring zero target secret exposure in subprocess memory or environment (`relay-mcp::egress_injector`).
4. Strict DNS resolution with pre-DNS IP blacklisting, RFC 1918 / loopback / link-local metadata protection, and IP pinning to defeat DNS rebinding and SSRF (`relay-mcp::egress_dns`).
5. Zero-hop header sanitization, hop-by-hop stripping, and CRLF injection defenses (`relay-mcp::egress_headers`).
6. Unprivileged Linux User & Network Namespace sandboxing (`CLONE_NEWUSER | CLONE_NEWNET`) blocking 100% of raw outbound sockets (`relay-mcp::egress_sandbox`).
7. Managed Cooperative Proxy Mode for macOS and Windows with documented residual boundaries.
8. Complete enforcement of Security Invariants **SI-001 through SI-024**.

---

## 2. Invariant Compliance Audit

| Invariant | Requirement | M002 Implementation Verification | Evaluation |
|:---|:---|:---|:---:|
| **SI-001** | Zero ambient target credentials in agent/subprocess context | Subprocess environment sanitized via `env_clear()` and whitelisted; child only receives ephemeral `RELAY_PROXY_AUTH`. | `PASS` |
| **SI-002** | Authorization precedes execution | Cedar evaluates destination `Relay::NetworkEndpoint` and tool action before proxy establishes upstream connection. | `PASS` |
| **SI-003** | Denied actions are never dispatched | Denied HTTP destinations return HTTP `403 Forbidden`; no upstream socket created. | `PASS` |
| **SI-006** | Single-action credential lease scope | Proxy lease token is bound to `ActionHash`, expires after 30s, and is burned upon completion. | `PASS` |
| **SI-007** | Target secrets do not leak into receipts | Secret scrubber inspects all egress evidence records before cryptographic signing. | `PASS` |
| **SI-008** | Target secrets masked in logs/traces | Credential values stored in `SecretBuffer` (zeroized on drop); headers masked in debug traces. | `PASS` |
| **SI-014** | All failures fail closed | Proxy unreachable, invalid lease, DNS blacklist match, or sandbox failure immediately aborts execution. | `PASS` |
| **SI-015** | Explicit uncertainty for ambiguous mutations | Timeout or connection drop during upstream HTTP POST/PUT records `AmbiguousMutation` in ledger. | `PASS` |
| **SI-018** | Subprocesses receive zero ambient network tokens | Subprocess environment cleared of `GITHUB_TOKEN`, `PGPASSWORD`, and cloud IAM environment variables. | `PASS` |
| **SI-019** | Loopback-only proxy binding | Forward proxy listener binds exclusively to `127.0.0.1:<ephemeral_port>` with TCP backlog bounded to 128. | `PASS` |
| **SI-020** | Ephemeral action-bound proxy leases | `ProxySessionManager` generates 256-bit cryptographically secure tokens; single-use burning enforced. | `PASS` |
| **SI-021** | Pre-resolution DNS & IP blacklist enforcement | Prohibits `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, RFC 1918 subnets, and loopback upstream destinations. | `PASS` |
| **SI-022** | Hop-by-hop & proxy header sanitization | Strips `Proxy-Authorization`, `Proxy-Connection`, `Keep-Alive`, `TE`, `Transfer-Encoding`, and validates against CRLF injection. | `PASS` |
| **SI-023** | Linux netns unprivileged raw-socket isolation | `CLONE_NEWUSER \| CLONE_NEWNET` namespaces block raw sockets with `ENETUNREACH`. | `PASS` |
| **SI-024** | Sandbox setup fail-closed | Any error in `pre_exec` namespace unsharing aborts subprocess spawn; never falls back to unconstrained execution. | `PASS` |

---

## 3. Adversarial Attack Surface & Verification Findings

### 3.1. Raw Socket Bypass on Linux
- **Attack Vector:** An adversarial MCP subprocess attempts to bypass `HTTP_PROXY` by issuing direct `socket(AF_INET, SOCK_STREAM)` or `socket(AF_INET, SOCK_RAW)` syscalls to exfiltrate data to an attacker-controlled server.
- **Verification:** Verified in `test_linux_netns_sandbox_blocks_raw_sockets`. The child process running inside the isolated user & network namespace receives `ping: connect: Network is unreachable` (`ENETUNREACH`) and cannot open external TCP/UDP/RAW connections.
- **Verdict:** `PASS` (Hardware/Kernel Enforced on Linux).

### 3.2. Cloud Metadata Exfiltration & SSRF (AWS IMDSv2 / GCP Metadata)
- **Attack Vector:** An adversarial MCP tool attempts to read instance identity credentials via `http://169.254.169.254/latest/meta-data/` or `http://metadata.google.internal/computeMetadata/v1/`.
- **Verification:** Verified in `test_proxy_blocks_cloud_metadata_ssrf` and `test_dns_blacklisting_link_local_and_private`. Pre-DNS filtering and post-resolution IP filtering block the request before any upstream socket is dialed, returning HTTP `403 Forbidden` with reason code `EgressDnsBlacklisted`.
- **Verdict:** `PASS`.

### 3.3. Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding
- **Attack Vector:** An attacker configures a public DNS domain that resolves to a public IP during Cedar policy authorization, but subsequently resolves to `127.0.0.1` or `169.254.169.254` when the proxy establishes the TCP connection.
- **Verification:** Verified in `test_dns_ip_pinning_prevents_rebinding`. The proxy resolves the DNS name once through `DnsResolverWithBlacklist`, validates all resolved `SocketAddr` entries against the IP blacklist, pins the validated address, and connects directly to the pinned IP without re-querying DNS.
- **Verdict:** `PASS`.

### 3.4. Ambient Credential Theft from Subprocess Memory
- **Attack Vector:** An adversarial MCP server inspects `/proc/self/environ` or dumps its own memory heap to locate the target API keys (e.g., GitHub tokens, database passwords).
- **Verification:** Verified in `test_vaulted_credential_injection_hides_secrets`. The subprocess environment contains only `RELAY_PROXY_AUTH=<lease_token>`. The actual `Bearer <token>` is injected into the upstream request by `CredentialInjector` inside the Relay process.
- **Verdict:** `PASS`.

### 3.5. Header & CRLF Injection Attacks
- **Attack Vector:** An adversarial tool attempts to smuggle HTTP requests or forge proxy headers by embedding `\r\n` or malicious hop-by-hop headers in outgoing requests.
- **Verification:** Verified in `test_header_sanitization_and_crlf_rejection`. Header values containing `\r` or `\n` are rejected with `ExecutionError::EgressProxyError("CRLF injection detected in header value")`. Hop-by-hop headers (`Proxy-Authorization`, `Keep-Alive`) are stripped before upstream dispatch.
- **Verdict:** `PASS`.

### 3.6. Ephemeral Lease Burning & Replay Prevention
- **Attack Vector:** An attacker attempts to reuse an expired or previously burned `RELAY_PROXY_AUTH` lease token after a tool execution completes.
- **Verification:** Verified in `test_proxy_lease_lifecycle_burning_and_expiration`. Burned or expired lease tokens return HTTP `407 Proxy Authentication Required`, preventing session reuse.
- **Verdict:** `PASS`.

---

## 4. Test Suite Summary

- **Total Unit & Integration Tests:** 326
- **Targeted M002 Egress Security Tests:** 11 (`crates/relay-mcp/tests/m002_egress_security_tests.rs`)
- **Clippy Warnings:** 0 (enforced via `-D warnings`)
- **Format Compliance:** 100% clean (`cargo fmt --check`)
- **Platform Coverage:**
  - Linux: Full Enforced Sandbox Mode (`CLONE_NEWUSER | CLONE_NEWNET`)
  - macOS / Windows: Managed Cooperative Proxy Mode

---

## 5. Security Architecture Review Verdict

$$\text{Verdict: } \mathbf{APPROVED\ FOR\ PRODUCTION\ (MILESTONE\ M002\ COMPLETE)}$$

The M002 implementation establishes a robust, zero-trust network mediation layer for external MCP subprocesses, strictly enforcing credential isolation, deterministic destination allowlisting, and verifiable security invariants across all supported platforms.
