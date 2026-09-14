# Relay Formal Security Invariants

**Document ID:** `SEC-INV-001`  
**Version:** `0.1.0`  
**Author:** Principal Security Architect  
**Status:** Authoritative Contract  

---

## 1. Security Invariants Summary Matrix

Relay enforces 18 non-negotiable formal security invariants derived from `A004`:

| ID | Invariant Summary | Primary Enforcement Point | Test Verification | Failure Code |
|:---|:---|:---|:---|:---:|
| **SI-001** | Zero target credentials in agent environment/memory | Ingress Subprocess Env Sanitizer (`relay-mcp`) | `rc001_hardening_tests::test_rc001_subprocess_env_sanitization_strips_secrets` | N/A (Sanitized) |
| **SI-002** | Authorization strictly precedes execution | Coordinator Dispatcher State Machine (`relay-connectors`) | `golden_path_security_tests::test_sec_01_cedar_deny_prevents_connector_dispatch` | `3` (PolicyDenied) |
| **SI-003** | Denied actions are never dispatched to targets | Coordinator Policy Gate (`relay-connectors`) | `authorization_tests::test_strict_default_deny_unpermitted_action` | `3` (PolicyDenied) |
| **SI-004** | Human approval is cryptographically bound to `ActionHash` | Interactive TTY Interceptor (`relay-mcp`) | `binding_tests::test_action_hash_mismatch_between_action_and_approval` | `4` / `6` |
| **SI-005** | Authorized payload is byte-for-byte identical to executed payload | In-Memory Canonical Action Wrapper | `jcs_rfc8785_tests::test_rfc8785_canonicalization_determinism` | `-32602` |
| **SI-006** | Credential lease is single-use and bound to exact action | JIT Credential Broker (`relay-credentials`) | `lease_tests::test_single_use_lease_consumption_si_006` | `6` (SecurityFailure) |
| **SI-007** | Target secrets never enter persistent ledger storage | Scrubber Filter (`relay-receipts/scrub.rs`) | `secret_scrub_tests::test_prohibited_secret_patterns_rejected_before_signing` | `6` (SecurityFailure) |
| **SI-008** | Target secrets never leak in logs, traces, or debug formatters | `SecretBuffer` & Custom `Debug` Formatters | `rc001_hardening_tests::test_rc001_secret_buffers_and_keys_masked_in_debug` | N/A (Redacted) |
| **SI-009** | Receipt evidence tampering is mathematically detectable | SQLite SHA-256 Hash Chain (`relay-ledger`) | `tamper_detection_tests::test_payload_tamper_detection` | `6` (SecurityFailure) |
| **SI-010** | Active policy-set digest is recorded in decision and receipt | Cedar Engine Wrapper (`relay-policy`) | `schema_validation_tests::test_policy_digest_tamper_detection_si_010` | `6` (SecurityFailure) |
| **SI-011** | Tool identity resolution is unambiguous and non-spoofable | Tool Identity Resolver (`relay-canonical`) | `tool_identity_tests::test_tool_identity_strict_parsing` | `-32602` |
| **SI-012** | Resource URI is normalized prior to policy evaluation | Resource Canonicalizers (`relay-canonical`) | `resource_tests::test_fs_path_lexical_canonicalization` | `-32602` |
| **SI-013** | Duplicate JSON keys or formatting anomalies fail closed | Strict JSON Deserializer (`relay-canonical`) | `duplicate_keys_tests::test_duplicate_key_rejection` | `-32600` |
| **SI-014** | All security-critical errors fail closed | Universal Dispatcher Error Handler | `adversarial_campaign_tests::test_adv_01_fail_closed_on_panic` | Non-Zero Exit |
| **SI-015** | Relay does not claim successful mutation on timeout/uncertainty | Receipt Engine Epistemology Model | `construction_tests::test_action_with_ambiguous_mutation` | `-32010` |
| **SI-016** | Replay of historical nonces or receipt IDs is rejected | SQLite Monotonic State Tracker | `append_tests::test_duplicate_sequence_rejection` | `6` (SecurityFailure) |
| **SI-017** | Memory pages containing secrets are zeroized on drop | `zeroize::Zeroize` RAII Hooks | `keyring_tests::test_keyring_provider_no_plaintext_in_display_or_debug` | N/A (Zeroized) |
| **SI-018** | Subprocesses spawned by Relay receive zero ambient network tokens | Subprocess Spawn Filter (`relay-mcp`) | `rc001_hardening_tests::test_rc001_subprocess_env_sanitization_strips_secrets` | N/A (Sanitized) |
| **SI-019** | External Egress Destination Authorization | Cedar PDP Egress Evaluator (`relay-mcp::egress_proxy`) | `m002_egress_security_tests::test_egress_proxy_cedar_policy_denial_yields_403` | `403 Forbidden` |
| **SI-020** | Ephemeral Proxy Session Binding (ActionHash + 30s TTL) | Proxy Session Manager (`relay-mcp::egress_session`) | `m002_egress_security_tests::test_proxy_lease_lifecycle_and_invalidation_si_020` | `407 Auth Required` |
| **SI-021** | Vaulted Upstream Credential Injection (Subprocess Isolation) | Credential Injector (`relay-mcp::egress_injector`) | `m002_egress_security_tests::test_upstream_credential_injection_si_021` | `6` (SecurityFailure) |
| **SI-022** | Cloud Metadata & Private IP Pre-DNS Blocking (SSRF/Rebinding) | Secure DNS Resolver (`relay-mcp::egress_dns`) | `m002_egress_security_tests::test_cloud_metadata_blocked_pre_dns_si_022` | `403 Forbidden` |
| **SI-023** | Linux Unprivileged Network Namespace Isolation (Raw Sockets Blocked) | NetNS Sandbox Launcher (`relay-mcp::egress_sandbox`) | `m002_egress_security_tests::test_linux_netns_blocks_raw_socket_si_023` | `ENETUNREACH` |
| **SI-024** | Fail-Closed Sandbox Initialization | Platform Sandbox Launcher (`relay-mcp::egress_sandbox`) | `m002_egress_security_tests::test_platform_sandbox_launcher_modes` | `6` (SecurityFailure) |

---

## 2. Invariant Specifications & Enforcement Architecture

### SI-001: Zero Target Credentials in Agent Context
- **Statement:** The agent client process, context window, standard input/output streams, and child environment must never receive, observe, or store target service credentials (API tokens, database passwords, private keys).
- **Enforcement Location:** `crates/relay-mcp/src/gateway.rs` via `sanitized_child_env()`.
- **Failure Behavior:** If environment sanitization fails, subprocess launch is aborted immediately.

---

### SI-002: Authorization Strictly Precedes Execution
- **Statement:** No target connector (Filesystem, PostgreSQL, GitHub) or MCP tool may be invoked or dispatched until the Cedar policy engine has evaluated the canonical authorization request and returned an explicit `Allow` decision.
- **Enforcement Location:** `crates/relay-connectors/src/coordinator.rs` in `GovernedActionRunner::run_action()`.
- **Failure Behavior:** Execution terminates; no network or I/O request is dispatched to the target system.

---

### SI-004: Approval Bound to `ActionHash`
- **Statement:** Step-up interactive approvals are cryptographically bound to the SHA-256 `ActionHash` of the canonical RFC 8785 JCS action representation. An approval cannot be applied to a mutated payload, transferred between tools, or reused across sessions.
- **Enforcement Location:** `crates/relay-domain/src/approval.rs` and `crates/relay-connectors/src/coordinator.rs`.
- **Failure Behavior:** Terminated with `GovernedActionError::ApprovalDenied` or `ActionHashMismatch`.

---

### SI-006: Single-Action Credential Lease Scope
- **Statement:** Credential leases generated by the JIT Credential Broker exist exclusively in transient memory for the execution duration of a single authorized action. Leases are single-use, non-transferable, and automatically invalidated and zeroized upon action completion or drop.
- **Enforcement Location:** `crates/relay-credentials/src/broker.rs` and `crates/relay-domain/src/credentials.rs`.
- **Failure Behavior:** Second acquisition attempt returns `CredentialError::LeaseAlreadyConsumed`.

---

### SI-009: Tamper-Evident Ledger Integrity
- **Statement:** All Action Receipts are recorded into an append-only SQLite ledger chained via SHA-256 hashes ($H_i = \text{SHA256}(i \parallel H_{i-1} \parallel \text{PayloadHash}_i)$). Any modification, deletion, reordering, or truncation of historical records is mathematically detectable during verification.
- **Enforcement Location:** `crates/relay-ledger/src/verifier.rs` and SQLite triggers (`prevent_ledger_update`, `prevent_receipts_update`).
- **Failure Behavior:** `LedgerVerifier` flags `BrokenChain`, `SequenceGap`, or `PayloadHashMismatch` and terminates with `ExitCode::SecurityFailure` (`6`).

---

### SI-015: Explicit Uncertainty on Ambiguous External Mutations
- **Statement:** Relay must never manufacture a successful execution outcome or assert that a remote mutation completed if a network disconnection or timeout occurred after request dispatch. Such outcomes must be recorded as `AmbiguousMutation` with status `Undetermined`.
- **Enforcement Location:** `crates/relay-connectors/src/coordinator.rs` and `crates/relay-receipts/src/builder.rs`.
- **Failure Behavior:** Returns JSON-RPC error code `-32010` (`Ambiguous Mutation`) and signs a receipt certifying the uncertainty.

---

### SI-019: External Egress Destination Authorization
- **Statement:** Outbound network requests initiated by external MCP servers must be evaluated against the Cedar Policy PDP before connection or proxy tunnel establishment. Unpermitted destinations are rejected with HTTP 403 Forbidden.
- **Enforcement Location:** `crates/relay-mcp/src/egress_proxy.rs` in `EgressProxy::evaluate_policy()`.
- **Failure Behavior:** Connection aborted; HTTP 403 Forbidden returned to client.

---

### SI-020: Ephemeral Proxy Session Binding
- **Statement:** Proxy lease tokens are cryptographically generated UUID v7 tokens, strictly time-bounded (30s TTL default), bound to an `ActionHash` and `Principal`, and burned immediately upon action completion.
- **Enforcement Location:** `crates/relay-mcp/src/egress_session.rs` in `ProxySessionManager`.
- **Failure Behavior:** Expired or reused tokens return HTTP 407 Proxy Authentication Required.

---

### SI-021: Vaulted Upstream Credential Injection
- **Statement:** Upstream target credentials (e.g. GitHub PATs, API keys) remain vaulted inside Relay and are injected dynamically into upstream HTTPS request headers. Child subprocesses only hold ephemeral proxy tokens and never observe real secrets.
- **Enforcement Location:** `crates/relay-mcp/src/egress_injector.rs` in `CredentialInjector`.
- **Failure Behavior:** Secret injection failure terminates request; secrets are zeroized on drop.

---

### SI-022: Cloud Metadata & Private IP Pre-DNS Blocking
- **Statement:** Outbound requests resolving to cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`), loopback addresses, or private RFC 1918 subnets are blocked before socket dispatch to prevent SSRF and DNS rebinding attacks. Resolved IP addresses are pinned for upstream connections.
- **Enforcement Location:** `crates/relay-mcp/src/egress_dns.rs` in `DnsResolverWithBlacklist`.
- **Failure Behavior:** Raises `InvariantViolationError::BlockedMetadataOrPrivateIp` and returns HTTP 403 Forbidden.

---

### SI-023: Linux Unprivileged Network Namespace Containment
- **Statement:** On Linux, external MCP subprocesses are executed in isolated unprivileged User and Network Namespaces (`CLONE_NEWUSER | CLONE_NEWNET`), eliminating 100% of raw socket egress paths (`ENETUNREACH`). All outbound traffic is forced through Relay's loopback proxy.
- **Enforcement Location:** `crates/relay-mcp/src/egress_sandbox.rs` in `EgressSandboxLauncher::spawn()`.
- **Failure Behavior:** Direct network connections fail immediately at the kernel syscall boundary.

---

### SI-024: Fail-Closed Sandbox Initialization
- **Statement:** If the operating system sandbox fails to initialize (e.g., unprivileged user namespaces disabled in the Linux kernel), Relay must fail closed immediately and refuse to spawn the child process unsandboxed.
- **Enforcement Location:** `crates/relay-mcp/src/egress_sandbox.rs` in `EgressSandboxLauncher::spawn()`.
- **Failure Behavior:** Aborts subprocess execution with `ExecutionError::SandboxSetupFailed`.
