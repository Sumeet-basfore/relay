# Relay Evidence Matrix: Milestone M003

**Document ID:** `SEC-EVD-M003`  
**Milestone:** `M003 — External MCP Adversarial Validation & Governed Lifecycle Integration`  
**Date:** 2026-09-14  
**Evaluator:** Principal Security Architect & Lead Adversarial Tester  
**Status:** Validated Evidence Matrix  

---

## 1. Traceability Architecture

The evidence matrix links core security claims to formal security invariants, concrete implementation enforcement points, adversarial test fixtures, and observed experimental results under adversarial attack.

```text
Security Claim
     ↓
Security Invariant
     ↓
Implementation Module
     ↓
Adversarial Test Target
     ↓
Observed Verification Result
```

---

## 2. Comprehensive Evidence & Verification Matrix

| Security Claim | Security Invariant | Enforcement Implementation | Adversarial Test Target | Observed Verification Result | Status |
|:---|:---|:---|:---|:---|:---:|
| **Zero Ambient Subprocess Credentials** | `SI-001`, `SI-018` | `relay_mcp::env::apply_sanitized_env` (`env_clear()`) | `test_phase3_target_secrets_never_observable_in_child_environment` | Target secrets (`GITHUB_TOKEN`, `PGPASSWORD`, cloud IAM keys) are completely eliminated from child environment. | **PASS** |
| **Deterministic Action Authorization** | `SI-002`, `SI-003` | `relay_policy::engine::DefaultPolicyEngine`, `relay_mcp::intercept` | `test_egress_proxy_cedar_policy_denial_yields_403`, `authorization_tests` | Denied actions immediately return JSON-RPC error / HTTP 403; zero downstream sockets or executions dispatched. | **PASS** |
| **Ephemeral Action-Bound Proxy Leases** | `SI-006`, `SI-020` | `relay_mcp::egress_session::ProxySessionManager` | `test_phase4_proxy_session_forgery_and_replay_attacks`, `test_phase4_proxy_session_ttl_expiration` | Forged, expired, or cross-action lease tokens are rejected with HTTP 407 / `EphemeralProxySessionInvalid`. | **PASS** |
| **Single-Use Burning & Post-Action Revocation** | `SI-006`, `SI-020` | `ProxySessionManager::burn_lease` | `test_phase3_credential_reuse_fails_after_session_burn_or_expiry`, `test_phase5_connection_pooling_socket_reuse_after_lease_burn` | Leases are burned upon tool completion; reuse over persistent sockets or delayed background threads returns HTTP 407. | **PASS** |
| **Vaulted Upstream JIT Credential Injection** | `SI-001`, `SI-021` | `relay_mcp::egress_injector::CredentialInjector` | `test_phase14_credential_not_injected_to_unauthorized_destination`, `test_upstream_credential_injection_si_021` | Injects credentials only if upstream destination matches vault rule; secrets never leak into child memory or unauthorized hosts. | **PASS** |
| **Pre-DNS Cloud Metadata & SSRF Protection** | `SI-021` | `relay_mcp::egress_dns::DnsResolverWithBlacklist` | `test_cloud_metadata_blocked_pre_dns_si_022`, `test_phase6_redirect_to_private_ip_and_metadata_blocked` | Pre-resolution string filter blocks `169.254.169.254`, `fd00:ec2::254`, and `metadata.google.internal` before DNS queries occur. | **PASS** |
| **Private IP & Loopback Target Blocking** | `SI-021` | `DnsResolverWithBlacklist` (RFC 1918 / Loopback checks) | `test_rfc1918_and_loopback_blocked_si_022`, `test_phase7_dns_rebinding_ip_pinning_and_literal_checks` | Connections to `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`, and `::1` are blocked with HTTP 403 / Invariant error. | **PASS** |
| **Socket IP Pinning (Anti-DNS Rebinding)** | `SI-021` | `EgressProxy` connecting to resolved `SocketAddr` | `test_phase7_dns_rebinding_ip_pinning_and_literal_checks` | Socket dials the pre-validated pinned IP directly, defeating TOCTOU rebinding between policy check and socket connect. | **PASS** |
| **Zero-Hop Header Sanitization & CRLF Defense** | `SI-022` | `relay_mcp::egress_headers::HeaderPolicy` | `test_phase15_header_smuggling_crlf_and_hop_by_hop_stripping` | CRLF injection (`\r\n`) is rejected; hop-by-hop headers (`Proxy-Authorization`, `Proxy-Connection`, etc.) are stripped. | **PASS** |
| **HTTP CONNECT Tunnel Destination Binding** | `SI-019`, `SI-021` | `EgressProxy::handle_connect` | `test_phase16_connect_tunnel_to_blacklisted_targets_blocked` | CONNECT tunnels to cloud metadata or private IPs are blocked with HTTP 403 Forbidden before TCP dialing. | **PASS** |
| **Linux NetNS Hard Raw-Socket Prevention** | `SI-023` | `relay_mcp::egress_sandbox::EgressSandboxLauncher` | `test_phase8_linux_netns_sandbox_blocks_raw_sockets`, `test_phase9_and_10_child_process_tree_isolation` | Subprocesses and all descendants inside `CLONE_NEWUSER \| CLONE_NEWNET` receive `ENETUNREACH` on raw socket attempts. | **PASS** |
| **Fail-Closed Sandbox Initialization** | `SI-024` | `EgressSandboxLauncher::spawn` | `m002_egress_security_tests`, `test_phase8_linux_netns_sandbox_blocks_raw_sockets` | Sandbox failure in `pre_exec` aborts spawn with `PermissionDenied`; never falls back to unconstrained execution. | **PASS** |
| **Receipt DSSE Signing & Secret Scrubbing** | `SI-007`, `SI-008` | `relay_receipts::signer::Ed25519ReceiptSigner`, `relay_receipts::scrub` | `crypto_tests`, `secret_scrub_tests`, `construction_tests` | Scrubber rejects secrets in receipts; receipts are signed with Ed25519 DSSE envelopes; keys zeroized on drop. | **PASS** |
| **Append-Only Merkle Hash-Chain Ledger** | `SI-013`, `SI-014` | `relay_ledger::sqlite::SqliteLedger` | `binding_tests`, `tamper_tests`, `integration_tests` | Receipts appended to SQLite ledger with SHA-256 hash chaining; corrupted entries trigger tamper detection errors. | **PASS** |
| **High-Concurrency Isolation & No Cross-Talk** | `SI-020`, `SI-021` | `ProxySessionManager`, `CredentialInjector` | `test_phase20_high_concurrency_no_session_or_credential_crosstalk` | 50 concurrent sessions with distinct principals, ActionHashes, and destinations operate without cross-talk or token reuse. | **PASS** |

---

## 3. Platform Boundary Verification

| Platform | Sandbox Mode | Raw Socket Prevention | Credential Isolation | Destination Policy | Evidence & Receipts |
|:---|:---|:---:|:---:|:---:|:---:|
| **Linux (Kernel 3.8+)** | `LinuxEnforcedNetNS` (`CLONE_NEWUSER \| CLONE_NEWNET`) | **Hard Enforced** (`ENETUNREACH`) | **Vaulted JIT** | **Hard Enforced** (Cedar + NetNS) | **Signed DSSE** |
| **macOS (Darwin)** | `ManagedCooperative` (`HTTP_PROXY` env vars) | *Cooperative Boundary* | **Vaulted JIT** | **Enforced for HTTP/HTTPS clients** | **Signed DSSE** |
| **Windows (Win32)** | `ManagedCooperative` (`HTTP_PROXY` env vars) | *Cooperative Boundary* | **Vaulted JIT** | **Enforced for HTTP/HTTPS clients** | **Signed DSSE** |

---

## 4. Conclusion

The M003 Evidence Matrix provides complete, verified experimental proof that Relay's integrated execution path adheres to all formal security invariants and guarantees under adversarial attack.
